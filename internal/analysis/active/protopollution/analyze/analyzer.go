// Package analyze implements the active analysis logic for detecting client-side
// prototype pollution vulnerabilities.
package analyze

import (
	"context"
	_ "embed" // Required for go:embed
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

const (
	ModuleName             = "PrototypePollutionAnalyzer"
	jsCallbackName         = "__scalpel_protopollution_proof"
	placeholderCanary      = "{{SCALPEL_CANARY}}"
	placeholderCallback    = "{{SCALPEL_CALLBACK}}"
	findingChannelBuffer   = 10 // A decent buffer for handling bursts of events from the browser.
)

//go:embed shim.js
var protoPollutionShim string

// Analyzer manages the configuration and browser interaction for prototype pollution detection.
// This is a long-lived, stateless component that can be shared across many analysis tasks.
type Analyzer struct {
	logger  *zap.Logger
	browser schemas.BrowserManager
	config  config.ProtoPollutionConfig
}

// PollutionProofEvent is the data structure received from the JS shim when a potential vulnerability is found.
// It's enhanced with Vector and StackTrace for more precise and actionable evidence.
type PollutionProofEvent struct {
	Source     string `json:"source"`
	Canary     string `json:"canary"`
	Vector     string `json:"vector"`
	StackTrace string `json:"stackTrace"`
}

// analysisContext holds the state for a single, concurrent analysis task.
// It is created for the duration of one Analyze call and then discarded.
type analysisContext struct {
	taskID      string
	targetURL   string
	canary      string
	findingChan chan schemas.Finding
	logger      *zap.Logger
}

// NewAnalyzer creates a new, reusable analyzer instance using the centralized application configuration.
func NewAnalyzer(logger *zap.Logger, browserManager schemas.BrowserManager, cfg config.ProtoPollutionConfig) *Analyzer {
	// If the configuration provides an invalid duration, fall back to a sane default.
	if cfg.WaitDuration <= 0 {
		cfg.WaitDuration = 8 * time.Second
	}

	return &Analyzer{
		logger:  logger.Named("pp_analyzer"),
		browser: browserManager,
		config:  cfg,
	}
}

// Analyze executes the prototype pollution check against a given URL.
// It orchestrates the creation of a browser session and an analysis context to perform the check.
func (a *Analyzer) Analyze(ctx context.Context, taskID, targetURL string) ([]schemas.Finding, error) {

	// 1. Initialize an isolated context for this specific task. This makes the process thread safe.
	aCtx := &analysisContext{
		taskID:      taskID,
		targetURL:   targetURL,
		canary:      "sclp_" + uuid.New().String()[:8], // Generate a unique canary for this run.
		findingChan: make(chan schemas.Finding, findingChannelBuffer),
		// Create a logger with context for this specific task, which makes debugging much easier.
		logger: a.logger.With(zap.String("taskID", taskID), zap.String("target", targetURL)),
	}

	// 2. Acquire a browser session. We don't need any special persona or taint config for this analyzer.
	session, err := a.browser.NewAnalysisContext(ctx, nil, schemas.Persona{}, "", "")
	if err != nil {
		return nil, fmt.Errorf("could not initialize browser analysis context: %w", err)
	}
	defer session.Close(ctx)

	// 3. Instrument the browser session with our shim and callbacks.
	if err := a.instrumentSession(ctx, session, aCtx); err != nil {
		return nil, fmt.Errorf("failed to instrument browser session: %w", err)
	}

	// 4. Navigate to the target and let the fun begin.
	aCtx.logger.Info("Navigating and monitoring.", zap.Duration("wait_duration", a.config.WaitDuration))
	if err := session.Navigate(ctx, targetURL); err != nil {
		// Navigation errors are often not fatal; the page might have loaded enough for our purposes.
		aCtx.logger.Debug("Navigation completed (or failed gracefully)", zap.Error(err))
	}

	// 5. Wait for asynchronous events to be captured by our shim.
	// Use time.NewTimer instead of time.After to properly handle context cancellation and avoid resource leaks.
	timer := time.NewTimer(a.config.WaitDuration)
	select {
	case <-timer.C:
		aCtx.logger.Info("Monitoring period finished.")
	case <-ctx.Done():
		// Ensure the timer is stopped if the context is cancelled.
		if !timer.Stop() {
			// If Stop() returns false, the timer already fired, so we must drain the channel.
			<-timer.C
		}
		aCtx.logger.Info("Analysis context cancelled during monitoring.")
		err = ctx.Err() // Capture the cancellation error to return it.
	}

	// 6. Collect any findings that our callback handler has queued up.
	close(aCtx.findingChan)
	var findings []schemas.Finding
	for f := range aCtx.findingChan {
		findings = append(findings, f)
	}

	return findings, err
}

// instrumentSession prepares the browser session by exposing callbacks and injecting the shim.
func (a *Analyzer) instrumentSession(ctx context.Context, session schemas.SessionContext, aCtx *analysisContext) error {
	// This handler is a closure that captures the analysis context (`aCtx`).
	// When the browser calls back, this function will execute with the correct state.
	handler := func(event PollutionProofEvent) {
		aCtx.handlePollutionProof(event)
	}
	if err := session.ExposeFunction(ctx, jsCallbackName, handler); err != nil {
		return fmt.Errorf("failed to expose proof function: %w", err)
	}

	// Generate the specialized JS shim with the unique canary for this run.
	shimScript := a.generateShim(aCtx.canary)

	// Inject the shim to run on all future pages in this session.
	if err := session.InjectScriptPersistently(ctx, shimScript); err != nil {
		return fmt.Errorf("failed to inject pp shim: %w", err)
	}

	return nil
}

// handlePollutionProof is the callback triggered from the browser's JS environment.
// It runs concurrently and operates on the specific analysisContext for the task.
func (aCtx *analysisContext) handlePollutionProof(event PollutionProofEvent) {
	// First things first, make sure this isn't a stray callback from another run.
	if event.Canary != aCtx.canary {
		aCtx.logger.Warn("Received proof with mismatched canary. Discarding.")
		return
	}

	vulnerabilityName, cwe, severity := determineVulnerability(event.Source)

	aCtx.logger.Warn("Vulnerability detected!",
		zap.String("type", vulnerabilityName),
		zap.String("source", event.Source),
		zap.String("vector", event.Vector))

	desc := fmt.Sprintf(
		"A client-side vulnerability (%s) was detected via the '%s' source. Vector details: '%s'. This may lead to Cross-Site Scripting, Denial of Service, or application logic bypasses.",
		vulnerabilityName, event.Source, event.Vector,
	)

	// Serialize the enhanced event, including the stack trace, as JSON string evidence.
	evidenceBytes, _ := json.Marshal(event)
	evidence := string(evidenceBytes)

	finding := schemas.Finding{
		ID:        uuid.New().String(),
		TaskID:    aCtx.taskID,
		Target:    aCtx.targetURL, // Add the target to the finding for clear association.
		Timestamp: time.Now().UTC(),
		Module:    ModuleName,
		Vulnerability: schemas.Vulnerability{
			Name:        vulnerabilityName,
			Description: desc,
		},
		Severity:       severity,
		Description:    desc,
		Evidence:       evidence,
		Recommendation: getRecommendation(vulnerabilityName),
		CWE:            cwe,
	}

	// Use a non-blocking send to the channel. If the channel is full, we drop the finding
	// instead of blocking the browser driver, which could cause deadlocks.
	select {
	case aCtx.findingChan <- finding:
	default:
		aCtx.logger.Error("Finding channel buffer full. Dropping finding. This may indicate a system overload.")
	}
}

// generateShim prepares the JavaScript payload using fast string replacement.
func (a *Analyzer) generateShim(canary string) string {
	// We start with the embedded shim content.
	shim := protoPollutionShim
	// This is much more efficient than using html/template for simple substitutions.
	shim = strings.ReplaceAll(shim, placeholderCanary, canary)
	shim = strings.ReplaceAll(shim, placeholderCallback, jsCallbackName)
	return shim
}

// determineVulnerability is a helper to categorize the finding based on its source.
func determineVulnerability(source string) (name string, cwe []string, severity schemas.Severity) {
	if strings.Contains(source, "DOM_Clobbering") {
		return "DOM Clobbering", []string{"CWE-1339"}, schemas.SeverityMedium
	}
	// Default to the most common case.
	return "Client-Side Prototype Pollution", []string{"CWE-1321"}, schemas.SeverityHigh
}

// getRecommendation provides tailored advice based on the vulnerability type.
func getRecommendation(vulnerabilityName string) string {
	if vulnerabilityName == "DOM Clobbering" {
		return "Avoid using `id` attributes on elements that match global variable names. Sanitize HTML to prevent injection of elements with conflicting `id`s. Always declare variables with `const`, `let`, or `var` to avoid accidental global scope assignment."
	}
	return "Audit client-side JavaScript for unsafe recursive merge functions, property definition by path, and object cloning logic. Sanitize user input before it is used in these operations. As a defense-in-depth measure, consider freezing the Object prototype using `Object.freeze(Object.prototype)`."
}