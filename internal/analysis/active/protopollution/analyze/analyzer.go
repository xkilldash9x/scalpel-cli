// Package proto implements the active analysis logic for detecting client-side
// prototype pollution vulnerabilities.
package proto

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
	ModuleName          = "PrototypePollutionAnalyzer"
	jsCallbackName      = "__scalpel_protopollution_proof"
	placeholderCanary   = "{{SCALPEL_CANARY}}"
	placeholderCallback = "{{SCALPEL_CALLBACK}}"
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
// REFACTOR: This context no longer manages a finding channel or waitgroup.
// It now holds a reference to the session context to report findings directly.
type analysisContext struct {
	ctx       context.Context // The parent context for the analysis.
	session   schemas.SessionContext
	taskID    string
	targetURL string
	canary    string
	logger    *zap.Logger
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
// REFACTOR: This function's signature has changed. It no longer returns a slice of findings.
// Instead, it reports findings via the session context and returns only an error.
func (a *Analyzer) Analyze(ctx context.Context, taskID, targetURL string) error {
	// 1. Acquire a browser session. We pass `nil` for the findings channel as it's no longer used by this analyzer.
	session, err := a.browser.NewAnalysisContext(ctx, nil, schemas.Persona{}, "", "", nil)
	if err != nil {
		return fmt.Errorf("could not initialize browser analysis context: %w", err)
	}
	defer session.Close(ctx)

	// 2. Initialize an isolated context for this specific task.
	aCtx := &analysisContext{
		ctx:       ctx,
		session:   session,
		taskID:    taskID,
		targetURL: targetURL,
		canary:    "sclp_" + uuid.New().String()[:8], // Generate a unique canary for this run.
		logger:    a.logger.With(zap.String("taskID", taskID), zap.String("target", targetURL)),
	}

	// 3. Instrument the browser session with our shim and callbacks.
	if err := a.instrumentSession(ctx, session, aCtx); err != nil {
		return fmt.Errorf("failed to instrument browser session: %w", err)
	}

	// 4. Navigate to the target.
	aCtx.logger.Info("Navigating and monitoring.", zap.Duration("wait_duration", a.config.WaitDuration))
	if err := session.Navigate(ctx, targetURL); err != nil {
		// Navigation errors are often not fatal; the page might have loaded enough for our purposes.
		aCtx.logger.Debug("Navigation completed (or failed gracefully)", zap.Error(err))
	}

	// 5. Wait for asynchronous events to be captured by our shim.
	timer := time.NewTimer(a.config.WaitDuration)
	select {
	case <-timer.C:
		aCtx.logger.Info("Monitoring period finished.")
	case <-ctx.Done():
		if !timer.Stop() {
			// This is necessary to safely drain the timer if it has already fired.
			<-timer.C
		}
		aCtx.logger.Info("Analysis context cancelled during monitoring.")
		return ctx.Err()
	}

	// 6. Findings are reported by the callback handler directly. Nothing to collect here.
	return nil
}

// instrumentSession prepares the browser session by exposing callbacks and injecting the shim.
func (a *Analyzer) instrumentSession(ctx context.Context, session schemas.SessionContext, aCtx *analysisContext) error {
	// The handler is now a method on analysisContext, which closes over the necessary state.
	// This avoids complex parameter passing for the callback.
	if err := session.ExposeFunction(ctx, jsCallbackName, aCtx.handlePollutionProof); err != nil {
		return fmt.Errorf("failed to expose proof function: %w", err)
	}

	shimScript := a.generateShim(aCtx.canary)

	if err := session.InjectScriptPersistently(ctx, shimScript); err != nil {
		return fmt.Errorf("failed to inject pp shim: %w", err)
	}

	return nil
}

// handlePollutionProof is the callback triggered from the browser's JS environment.
func (aCtx *analysisContext) handlePollutionProof(event PollutionProofEvent) {
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

	evidenceBytes, _ := json.Marshal(event)
	evidence := string(evidenceBytes)

	finding := schemas.Finding{
		ID:        uuid.New().String(),
		TaskID:    aCtx.taskID,
		Target:    aCtx.targetURL,
		ObservedAt: time.Now().UTC(),
		Module:    ModuleName,
		VulnerabilityName: vulnerabilityName,
		Severity:          severity,
		Description:       desc,
		Evidence:          json.RawMessage(evidence),
		Recommendation: getRecommendation(vulnerabilityName),
		CWE:            cwe,
	}

	// REFACTOR: Instead of writing to a channel, use the session's AddFinding method.
	// This standardizes the finding submission process across all analyzers.
	if err := aCtx.session.AddFinding(aCtx.ctx, finding); err != nil {
		aCtx.logger.Error("Failed to submit finding", zap.Error(err))
	}
}

// generateShim prepares the JavaScript payload using fast string replacement.
func (a *Analyzer) generateShim(canary string) string {
	shim := protoPollutionShim
	shim = strings.ReplaceAll(shim, placeholderCanary, canary)
	shim = strings.ReplaceAll(shim, placeholderCallback, jsCallbackName)
	return shim
}

// determineVulnerability is a helper to categorize the finding based on its source.
func determineVulnerability(source string) (name string, cwe []string, severity schemas.Severity) {
	if strings.Contains(source, "DOM_Clobbering") {
		return "DOM Clobbering", []string{"CWE-1339"}, schemas.SeverityMedium
	}
	return "Client-Side Prototype Pollution", []string{"CWE-1321"}, schemas.SeverityHigh
}

// getRecommendation provides tailored advice based on the vulnerability type.
func getRecommendation(vulnerabilityName string) string {
	if vulnerabilityName == "DOM Clobbering" {
		return "Avoid using `id` attributes on elements that match global variable names. Sanitize HTML to prevent injection of elements with conflicting `id`s. Always declare variables with `const`, `let`, or `var` to avoid accidental global scope assignment."
	}
	return "Audit client-side JavaScript for unsafe recursive merge functions, property definition by path, and object cloning logic. Sanitize user input before it is used in these operations. As a defense-in-depth measure, consider freezing the Object prototype using `Object.freeze(Object.prototype)`."
}
