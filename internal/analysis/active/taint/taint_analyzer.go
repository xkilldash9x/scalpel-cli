// Filename: taint_analyzer.go
// File: internal/analysis/active/taint/analyzer.go
package taint

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"

	// Added strconv for stack trace parsing
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	// Import core for unified definitions and helpers (Step 1)
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	// Import the static package (Step 3)
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/static/javascript"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
)

//go:embed taint_shim.js
var taintShimFS embed.FS

const taintShimFilename = "taint_shim.js"

// Canary format: SCALPEL_{Prefix}_{Type}_{UUID_Short}
var canaryRegex = regexp.MustCompile(`SCALPEL_[A-Z0-9]+_[A-Z_]+_[a-f0-9]{8}`)

// Regex for extracting file/line/col from a JavaScript stack trace line (Heuristic for correlation).
// Example match: (http://example.com/app.js:15:10) or at http://example.com/app.js:15:10
var stackTraceLocationRegex = regexp.MustCompile(`(?:\(|at\s+)(https?://[^:]+):(\d+):(\d+)`)

// HumanoidProvider defines an interface for duck-typing the SessionContext
// to check if it provides access to the Humanoid controller.
type HumanoidProvider interface {
	GetHumanoid() *humanoid.Humanoid
}

// Analyzer orchestrates the Hybrid IAST process. It manages dynamic probe injection,
// event collection, static analysis of loaded scripts, and correlation.
type Analyzer struct {
	config           Config
	reporter         ResultsReporter
	oastProvider     OASTProvider
	oastConfigured   bool // Flag to indicate if OAST is available.
	logger           *zap.Logger
	shimTemplate     string
	activeProbes     map[string]ActiveProbe
	probesMutex      sync.RWMutex
	eventsChan       chan Event
	rulesMutex       sync.RWMutex
	validTaintFlows  map[TaintFlowPath]bool
	wg               sync.WaitGroup
	producersWG      sync.WaitGroup
	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc

	// Store session-specific, randomized callback names.
	jsCallbackSinkEventName      string
	jsCallbackExecutionProofName string
	jsCallbackShimErrorName      string

	// Hybrid IAST Integration
	jsFingerprinter *javascript.Fingerprinter
	// staticFindings stores results from SAST engine. Key is filename/URL.
	staticFindings map[string][]javascript.StaticFinding
	findingsMutex  sync.RWMutex
}

// NewAnalyzer creates and initializes a new taint Analyzer instance.
func NewAnalyzer(config Config, reporter ResultsReporter, oastProvider OASTProvider, logger *zap.Logger) (*Analyzer, error) {
	taskLogger := logger.Named("taint_analyzer").With(zap.String("task_id", config.TaskID))

	// Read the raw template content directly
	templateBytes, err := taintShimFS.ReadFile(taintShimFilename)
	if err != nil {
		taskLogger.Error("Failed to read embedded taint shim file.", zap.Error(err))
		return nil, fmt.Errorf("failed to read embedded shim: %w", err)
	}
	templateContent := string(templateBytes)

	// Apply robust defaults for performance and stability.
	config = applyConfigDefaults(config)

	// Create a local copy of the global taint flow rules.
	localValidTaintFlows := make(map[TaintFlowPath]bool, len(ValidTaintFlows))
	for k, v := range ValidTaintFlows {
		localValidTaintFlows[k] = v
	}

	// Single, upfront check for OAST provider.
	oastConfigured := oastProvider != nil
	if !oastConfigured {
		taskLogger.Info("No OAST provider configured; out-of-band tests will be skipped.")
	}

	// Generate unique callback names for this analysis session.
	shortID := uuid.New().String()[:8]
	sinkCallbackName := fmt.Sprintf("%s_%s", JSCallbackSinkEvent, shortID)
	proofCallbackName := fmt.Sprintf("%s_%s", JSCallbackExecutionProof, shortID)
	errorCallbackName := fmt.Sprintf("%s_%s", JSCallbackShimError, shortID)

	// Initialize the JavaScript fingerprinter (SAST engine)
	jsFingerprinter := javascript.NewFingerprinter(taskLogger)

	return &Analyzer{
		config:          config,
		reporter:        reporter,
		oastProvider:    oastProvider,
		oastConfigured:  oastConfigured,
		logger:          taskLogger,
		activeProbes:    make(map[string]ActiveProbe),
		eventsChan:      make(chan Event, config.EventChannelBuffer),
		shimTemplate:    templateContent,
		validTaintFlows: localValidTaintFlows,

		// Store the generated unique names.
		jsCallbackSinkEventName:      sinkCallbackName,
		jsCallbackExecutionProofName: proofCallbackName,
		jsCallbackShimErrorName:      errorCallbackName,

		// Hybrid IAST Initialization
		jsFingerprinter: jsFingerprinter,
		staticFindings:  make(map[string][]javascript.StaticFinding),
	}, nil
}

// -- Hybrid IAST: Static Analysis Execution --

// HandleScriptLoaded (New Method) is the entry point for the SAST engine when a script is loaded.
// This method is expected to be called by the infrastructure managing the SessionContext
// (e.g., the browser controller) when it intercepts a script load.
func (a *Analyzer) HandleScriptLoaded(url, content string) {
	// Run analysis asynchronously to avoid blocking the browser instrumentation/event loop.
	go func() {
		// The SAST analysis runs independently of the main analysis context timeout.
		_, err := a.runStaticAnalysis(url, content)
		if err != nil {
			// Error already logged in runStaticAnalysis
			return
		}
		// Findings are stored and will be used during the Smart Probing phase and Correlation.
	}()
}

// runStaticAnalysis performs static analysis on provided content (e.g., intercepted JS file).
func (a *Analyzer) runStaticAnalysis(filename, content string) ([]javascript.StaticFinding, error) {
	if content == "" {
		return nil, nil
	}

	// Simple caching based on filename/URL to avoid re-analyzing static assets.
	a.findingsMutex.RLock()
	if findings, exists := a.staticFindings[filename]; exists {
		a.findingsMutex.RUnlock()
		return findings, nil
	}
	a.findingsMutex.RUnlock()

	a.logger.Debug("Running static analysis (SAST) on script", zap.String("filename", filename), zap.Int("size", len(content)))

	// Run the analysis (AST parsing + Taint tracking)
	findings, err := a.jsFingerprinter.Analyze(filename, content)
	if err != nil {
		// Log as warn, as SAST failure shouldn't stop IAST.
		a.logger.Warn("Static analysis failed for script", zap.String("filename", filename), zap.Error(err))
		return nil, err
	}

	// Store the findings regardless of whether vulnerabilities were found (for caching).
	a.findingsMutex.Lock()
	a.staticFindings[filename] = findings
	a.findingsMutex.Unlock()

	if len(findings) > 0 {
		a.logger.Info("SAST engine found potential vulnerabilities", zap.String("file", filename), zap.Int("count", len(findings)))
	}

	return findings, nil
}

// -- End Hybrid IAST: Static Analysis Execution --

// UpdateTaintFlowRuleForTesting provides a thread-safe mechanism to modify the
// taint flow validation rules during tests.
func (a *Analyzer) UpdateTaintFlowRuleForTesting(flow TaintFlowPath, isValid bool) {
	a.rulesMutex.Lock()
	defer a.rulesMutex.Unlock()
	a.validTaintFlows[flow] = isValid
}

// BuildTaintShim is an exported utility function that constructs the final
// JavaScript instrumentation shim.
func BuildTaintShim(templateContent string, configJSON string, sinkCallback, proofCallback, errorCallback string) (string, error) {
	// 1. Parse the template content passed as an argument.
	tmpl, err := template.New("shim").Parse(templateContent)
	if err != nil {
		return "", fmt.Errorf("failed to parse provided shim template: %w", err)
	}

	// 2. Define the data structure for template execution.
	data := struct {
		SinksJSON         string
		SinkCallbackName  string
		ProofCallbackName string
		ErrorCallbackName string
	}{
		SinksJSON:         configJSON,
		SinkCallbackName:  sinkCallback,
		ProofCallbackName: proofCallback,
		ErrorCallbackName: errorCallback,
	}

	// 3. Execute the template into a buffer.
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute shim template: %w", err)
	}

	return buf.String(), nil
}

// applyConfigDefaults ensures that critical configuration parameters have sane defaults.
func applyConfigDefaults(cfg Config) Config {
	if cfg.EventChannelBuffer == 0 {
		cfg.EventChannelBuffer = 1000
	}
	if cfg.FinalizationGracePeriod == 0 {
		cfg.FinalizationGracePeriod = 10 * time.Second
	}
	if cfg.ProbeExpirationDuration == 0 {
		cfg.ProbeExpirationDuration = 10 * time.Minute
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 1 * time.Minute
	}
	if cfg.OASTPollingInterval == 0 {
		cfg.OASTPollingInterval = 20 * time.Second
	}
	if cfg.CorrelationWorkers == 0 {
		cfg.CorrelationWorkers = 5
	}
	return cfg
}

// Analyze is the main entry point for the Hybrid IAST analysis.
func (a *Analyzer) Analyze(ctx context.Context, session SessionContext) error {
	a.logger.Info("Starting Hybrid IAST analysis (IAST+SAST)",
		zap.String("target", a.config.Target.String()),
		zap.Int("correlation_workers", a.config.CorrelationWorkers),
	)

	analysisCtx, cancel := context.WithTimeout(ctx, a.config.AnalysisTimeout)
	defer cancel()

	a.backgroundCtx, a.backgroundCancel = context.WithCancel(context.Background())

	// -- Humanoid Integration: Retrieve Controller --
	var h *humanoid.Humanoid
	if provider, ok := session.(HumanoidProvider); ok {
		h = provider.GetHumanoid()
	}

	// We rely on the session implementation (browser controller) to intercept scripts
	// and notify the analyzer (e.g., by calling HandleScriptLoaded).

	if err := a.instrument(analysisCtx, session); err != nil {
		return fmt.Errorf("failed to instrument browser: %w", err)
	}

	// Launch the concurrent machinery.
	a.startBackgroundWorkers()

	// Execute the attack vectors and user interactions.
	if err := a.executeProbes(analysisCtx, session, h); err != nil {
		// Only log as error if the failure wasn't simply due to the analysis context timeout/cancellation.
		if analysisCtx.Err() == nil {
			a.logger.Error("Error encountered during probing phase", zap.Error(err))
		}
	}

	a.logger.Debug("Probing finished. Waiting for asynchronous events.", zap.Duration("grace_period", a.config.FinalizationGracePeriod))

	select {
	case <-time.After(a.config.FinalizationGracePeriod):
		a.logger.Debug("Grace period concluded.")
	case <-analysisCtx.Done():
		a.logger.Warn("Analysis timeout reached during finalization grace period.")
	}

	// Initiate a graceful shutdown of all background processes.
	a.shutdown()

	a.logger.Info("Hybrid IAST analysis completed")
	return nil
}

// shutdown handles the ordered, graceful shutdown of all goroutines.
func (a *Analyzer) shutdown() {
	a.logger.Debug("Initiating graceful shutdown.")
	// 1. Signal background producers (OAST, Cleanup) to stop their work.
	a.backgroundCancel()
	// 2. Wait for producers to finish their final cycles (e.g., one last OAST poll).
	a.producersWG.Wait()
	a.logger.Debug("All event producers have stopped.")

	// 3. Close the event channel. This is the signal for the correlation workers to drain the channel and terminate.
	close(a.eventsChan)
	// 4. Wait for all correlation workers to complete processing any remaining events in the buffer.
	a.wg.Wait()
	a.logger.Debug("All correlation workers have finished.")
}

// startBackgroundWorkers launches the correlation worker pool and other background tasks.
func (a *Analyzer) startBackgroundWorkers() {
	a.logger.Debug("Starting background workers.", zap.Int("correlation_workers", a.config.CorrelationWorkers))
	// -- Consumers --
	// Launch the Correlation Worker Pool to process events concurrently.
	for i := 0; i < a.config.CorrelationWorkers; i++ {
		a.wg.Add(1)
		go a.correlateWorker(i)
	}

	// -- Producers --
	// Launch the background task to clean up expired probes.
	a.producersWG.Add(1)
	go a.cleanupExpiredProbes()

	// Launch the OAST poller if a provider is configured.
	if a.oastProvider != nil {
		a.producersWG.Add(1)
		go a.pollOASTInteractions()
	}
}

// instrument hooks into the client side by exposing Go functions to JavaScript
// and injecting the instrumentation shim.
func (a *Analyzer) instrument(ctx context.Context, session SessionContext) error {
	// VULN-FIX: Use the randomized, session-specific names when exposing functions.
	if err := session.ExposeFunction(ctx, a.jsCallbackSinkEventName, a.handleSinkEvent); err != nil {
		return fmt.Errorf("failed to expose sink event callback: %w", err)
	}
	if err := session.ExposeFunction(ctx, a.jsCallbackExecutionProofName, a.handleExecutionProof); err != nil {
		return fmt.Errorf("failed to expose execution proof callback: %w", err)
	}
	if err := session.ExposeFunction(ctx, a.jsCallbackShimErrorName, a.handleShimError); err != nil {
		return fmt.Errorf("failed to expose shim error callback: %w", err)
	}

	shim, err := a.generateShim()
	if err != nil {
		return fmt.Errorf("failed to generate instrumentation shim: %w", err)
	}

	if err := session.InjectScriptPersistently(ctx, shim); err != nil {
		return fmt.Errorf("failed to inject instrumentation shim: %w", err)
	}

	return nil
}

// generateShim creates the javascript instrumentation code from the embedded template.
func (a *Analyzer) generateShim() (string, error) {
	// 1. Marshal the sinks config specific to this analyzer instance.
	sinksJSON, err := json.Marshal(a.config.Sinks)
	if err != nil {
		return "", fmt.Errorf("failed to marshal sinks configuration: %w", err)
	}

	// 2. Call the exported BuildTaintShim function with the pre-loaded template string.
	// VULN-FIX: Pass the session-specific randomized callback names.
	return BuildTaintShim(a.shimTemplate, string(sinksJSON), a.jsCallbackSinkEventName, a.jsCallbackExecutionProofName, a.jsCallbackShimErrorName)
}

// enqueueEvent provides a safe, non blocking mechanism for sending an event to the correlation engine.
func (a *Analyzer) enqueueEvent(event Event, eventType string) {
	// First, check if a shutdown has been initiated. If so, don't accept new events.
	select {
	case <-a.backgroundCtx.Done():
		a.logger.Debug("Dropping event during shutdown.", zap.String("type", eventType))
		return
	default:
		// The context is still active, proceed to send the event.
	}

	// Attempt to send the event, but drop it if the channel is full to prevent blocking the producer.
	select {
	case a.eventsChan <- event:
		// The event was successfully enqueued.
	default:
		// This case handles backpressure, which is critical for system stability.
		a.logger.Warn("Event channel full, dropping event. Consider increasing CorrelationWorkers or EventChannelBuffer.", zap.String("type", eventType))
	}
}

// handleSinkEvent is the callback from the JS shim for a detected taint flow.
func (a *Analyzer) handleSinkEvent(event SinkEvent) {
	a.logger.Debug("Sink event received", zap.String("sink", string(event.Type)), zap.String("detail", event.Detail))
	a.enqueueEvent(event, "SinkEvent")
}

// handleExecutionProof is the callback when an XSS payload executes successfully.
func (a *Analyzer) handleExecutionProof(event ExecutionProofEvent) {
	a.logger.Info("Execution proof received!", zap.String("canary", event.Canary))
	a.enqueueEvent(event, "ExecutionProofEvent")
}

// handleShimError is the callback for internal errors within the JavaScript instrumentation.
func (a *Analyzer) handleShimError(event ShimErrorEvent) {
	a.logger.Error("JavaScript Instrumentation Shim Error reported.",
		zap.String("error_message", event.Error),
		zap.String("location", event.Location),
		zap.String("stack_trace", event.StackTrace),
	)
}

// executePause attempts to execute a Humanoid cognitive pause using the provided context.
func (a *Analyzer) executePause(ctx context.Context, h *humanoid.Humanoid, meanMs, stdDevMs float64) error {
	// Check if the operation context (ctx) is done.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if h == nil {
		return nil
	}

	// The CognitivePause function takes the operation context.
	if err := h.CognitivePause(ctx, meanMs, stdDevMs); err != nil {
		// Log error if it wasn't just the context being cancelled.
		if ctx.Err() == nil {
			a.logger.Debug("Error during Humanoid pause execution.", zap.Error(err))
		}
		return err
	}
	return nil
}

// executeProbes orchestrates the various probing strategies against the target.
func (a *Analyzer) executeProbes(ctx context.Context, session SessionContext, h *humanoid.Humanoid) error {

	// REFACTOR: Pause before initial navigation.
	if err := a.executePause(ctx, h, 500, 200); err != nil {
		return err // Return if context cancelled during pause
	}

	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		// We continue even if navigation fails.
		a.logger.Warn("Initial navigation failed, attempting to continue probes.", zap.Error(err))
	}

	// NOTE: We assume that the underlying browser infrastructure intercepts script loads
	// during navigation and calls a.HandleScriptLoaded() concurrently.

	// REFACTOR: Pause after initial navigation.
	if err := a.executePause(ctx, h, 800, 300); err != nil {
		return err
	}

	// Pass Humanoid and context down.
	if err := a.probePersistentSources(ctx, session, h); err != nil {
		// Check if the context was cancelled before logging the error.
		if ctx.Err() == nil {
			a.logger.Error("Error during persistent source probing", zap.Error(err))
		}
	}

	// Pause between probing phases.
	if err := a.executePause(ctx, h, 400, 150); err != nil {
		return err
	}

	// Pass Humanoid and context down.
	if err := a.probeURLSources(ctx, session, h); err != nil {
		// Check if the context was cancelled before logging the error.
		if ctx.Err() == nil {
			a.logger.Error("Error during URL source probing", zap.Error(err))
		}
	}

	// --- Hybrid IAST: Static-Assisted Probing (Step 2/3.2) ---
	// Generate and execute smart probes based on static findings gathered during previous navigations.
	a.generateAndExecuteSmartProbes(ctx, session, h)
	// ----------------------------------------------------------

	a.logger.Info("Starting interactive probing phase.")

	// REFACTOR: Pause before starting interaction phase.
	if err := a.executePause(ctx, h, 600, 250); err != nil {
		return err
	}

	// The Interact method itself likely uses Humanoid if the session implementation supports it.
	if err := session.Interact(ctx, a.config.Interaction); err != nil {
		// Check if the context was cancelled before logging the error.
		if ctx.Err() == nil {
			a.logger.Warn("Interactive probing phase encountered errors", zap.Error(err))
		}
	}

	// Pause after interaction phase concludes.
	if err := a.executePause(ctx, h, 1000, 400); err != nil {
		// We don't return error here as probing is done, we just log if the final pause failed.
		if ctx.Err() == nil {
			a.logger.Debug("Final post-interaction pause interrupted.", zap.Error(err))
		}
	}

	return nil
}

// --- Hybrid IAST: Smart Probing Implementation (Step 2/3.2) ---

// generateAndExecuteSmartProbes (New Method) identifies parameters from static findings and launches targeted probes.
func (a *Analyzer) generateAndExecuteSmartProbes(ctx context.Context, session SessionContext, h *humanoid.Humanoid) {
	a.logger.Info("Starting Smart Probing phase based on SAST results.")

	// Collect all findings gathered so far thread-safely
	a.findingsMutex.RLock()
	var allFindings []javascript.StaticFinding
	for _, findings := range a.staticFindings {
		allFindings = append(allFindings, findings...)
	}
	a.findingsMutex.RUnlock()

	if len(allFindings) == 0 {
		a.logger.Debug("No static findings available yet for smart probing.")
		return
	}

	// Identify target parameters (URL Query, Hash Fragment, Storage)
	targetQueryParams := make(map[string]bool)
	targetHashParams := make(map[string]bool)
	// Future: targetStorageKeys

	for _, finding := range allFindings {
		// Check if the static finding indicates a specific parameter usage.
		// This relies on the enhanced walker.go (Step 4) returning specific source formats.

		// Findings might have multiple sources joined by "|". We need to check all of them.
		sources := strings.Split(string(finding.Source), "|")
		for _, sourceStr := range sources {

			// Source format for URL Query Parameters: "param:query:PARAM_NAME"
			if strings.HasPrefix(sourceStr, "param:query:") {
				paramName := strings.TrimPrefix(sourceStr, "param:query:")
				if paramName != "" {
					targetQueryParams[paramName] = true
				}
			}

			// Source format for Hash Fragment Parameters: "param:hash:PARAM_NAME"
			if strings.HasPrefix(sourceStr, "param:hash:") {
				paramName := strings.TrimPrefix(sourceStr, "param:hash:")
				if paramName != "" {
					targetHashParams[paramName] = true
				}
			}
			// Future: Handle param:storage:KEY_NAME
		}
	}

	if len(targetQueryParams) == 0 && len(targetHashParams) == 0 {
		// This is common if SAST found vulnerabilities but they didn't originate from URL/Hash params.
		return
	}

	a.logger.Info("Targeting statically discovered parameters",
		zap.Int("query_params", len(targetQueryParams)),
		zap.Int("hash_params", len(targetHashParams)),
	)

	// Execute targeted probing for Query Parameters
	if len(targetQueryParams) > 0 {
		if err := a.probeSpecificURLParams(ctx, session, h, targetQueryParams, false); err != nil {
			if ctx.Err() == nil {
				a.logger.Error("Error during smart probing (URL Query params)", zap.Error(err))
			}
		}
	}

	// Execute targeted probing for Hash Parameters
	if len(targetHashParams) > 0 {
		if err := a.probeSpecificURLParams(ctx, session, h, targetHashParams, true); err != nil {
			if ctx.Err() == nil {
				a.logger.Error("Error during smart probing (Hash params)", zap.Error(err))
			}
		}
	}
}

// injects probes into specific URL query parameters or hash fragments.
// It iterates one parameter at a time for better isolation and detection.
func (a *Analyzer) probeSpecificURLParams(ctx context.Context, session SessionContext, h *humanoid.Humanoid, params map[string]bool, useHash bool) error {
	// Create a safe copy of the target URL to modify it.
	baseURL, err := url.Parse(a.config.Target.String())
	if err != nil {
		return fmt.Errorf("failed to parse base URL for smart probing: %w", err)
	}

	sourceType := schemas.SourceURLParam
	prefix := "SMART_Q"
	if useHash {
		sourceType = schemas.SourceHashFragment
		prefix = "SMART_H"
	}

	// Iterate over each identified parameter.
	for paramName := range params {
		targetURL, _ := url.Parse(baseURL.String()) // Copy for this iteration
		probesInjected := 0

		// Prepare the query or hash map for modification.
		var paramsMap url.Values
		if useHash {
			// Parsing hash fragment if it follows query string format.
			paramsMap, _ = url.ParseQuery(targetURL.Fragment)
			if paramsMap == nil {
				paramsMap = url.Values{}
			}
		} else {
			paramsMap = targetURL.Query()
		}

		// Inject all relevant probes into the target parameter.
		// Strategy: Iterate probes and inject one by one into the parameter for this navigation.
		for _, probeDef := range a.config.Probes {
			// Basic filter for relevance (e.g., avoid JSON PP in standard URL param unless QS_PARSE_MERGE)
			if probeDef.Type == schemas.ProbeTypePrototypePollution && probeDef.Context != "QS_PARSE_MERGE" {
				continue
			}

			canary := a.generateCanary(prefix, probeDef.Type)
			payload := a.preparePayload(probeDef, canary)
			if payload == "" {
				continue
			}

			// We use Add() to potentially test parameter pollution, or append if the map implementation allows it.
			// If the underlying implementation treats the hash like standard query params, this works.
			paramsMap.Add(paramName, payload)

			a.registerProbe(ActiveProbe{
				Type:      probeDef.Type,
				Key:       paramName,
				Value:     payload, // Register the specific payload for correlation
				Canary:    canary,
				Source:    sourceType, // Statically informed dynamic probe
				CreatedAt: time.Now(),
			})
			probesInjected++
		}

		if probesInjected > 0 {
			// Update the URL with the modified parameters.
			if useHash {
				targetURL.Fragment = paramsMap.Encode()
			} else {
				targetURL.RawQuery = paramsMap.Encode()
			}

			a.logger.Debug("Navigating with smart probes",
				zap.String("param", paramName),
				zap.Bool("use_hash", useHash),
				zap.Int("probe_count", probesInjected),
			)

			// Pause before navigation.
			if err := a.executePause(ctx, h, 400, 150); err != nil {
				return err
			}

			if err := session.Navigate(ctx, targetURL.String()); err != nil {
				a.logger.Warn("Navigation failed during smart probing", zap.String("param", paramName), zap.Error(err))
			}

			// Pause after navigation.
			if err := a.executePause(ctx, h, 700, 300); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- End Hybrid IAST: Smart Probing Implementation ---

// generateCanary creates a unique canary string for tracking a probe.
func (a *Analyzer) generateCanary(prefix string, probeType schemas.ProbeType) string {
	return fmt.Sprintf("SCALPEL_%s_%s_%s", prefix, probeType, uuid.New().String()[:8])
}

// preparePayload replaces placeholders in a probe definition.
func (a *Analyzer) preparePayload(probeDef ProbeDefinition, canary string) string {
	requiresOAST := strings.Contains(probeDef.Payload, "{{.OASTServer}}")
	if requiresOAST && !a.oastConfigured {
		return ""
	}

	replacements := []string{
		"{{.Canary}}", canary,
		"{{.ProofCallbackName}}", a.jsCallbackExecutionProofName,
	}

	if requiresOAST {
		oastURL := a.oastProvider.GetServerURL()
		replacements = append(replacements, "{{.OASTServer}}", oastURL)
	}

	replacer := strings.NewReplacer(replacements...)
	return replacer.Replace(probeDef.Payload)
}

// probePersistentSources injects probes into Cookies, LocalStorage, and SessionStorage.
func (a *Analyzer) probePersistentSources(ctx context.Context, session SessionContext, h *humanoid.Humanoid) error {
	a.logger.Debug("Starting persistent source probing (Storage/Cookies).")
	storageKeyPrefix := "sc_store_"
	cookieNamePrefix := "sc_cookie_"
	var injectionScriptBuilder strings.Builder

	secureFlag := ""
	if a.config.Target.Scheme == "https" {
		secureFlag = " Secure;"
	}

	for i, probeDef := range a.config.Probes {
		// LocalStorage
		lsCanary := a.generateCanary("P", probeDef.Type)
		lsPayload := a.preparePayload(probeDef, lsCanary)
		if lsPayload != "" {
			jsonPayload, _ := json.Marshal(lsPayload)
			lsKey := fmt.Sprintf("%s%d", storageKeyPrefix, i)
			fmt.Fprintf(&injectionScriptBuilder, "try { localStorage.setItem(%q, %s); } catch(e) {}\n", lsKey, string(jsonPayload))
			a.registerProbe(ActiveProbe{Type: probeDef.Type, Key: lsKey, Value: lsPayload, Canary: lsCanary, Source: schemas.SourceLocalStorage, CreatedAt: time.Now()})
		}

		// SessionStorage
		ssCanary := a.generateCanary("P", probeDef.Type)
		ssPayload := a.preparePayload(probeDef, ssCanary)
		if ssPayload != "" {
			jsonPayload, _ := json.Marshal(ssPayload)
			ssKey := fmt.Sprintf("%s%d_s", storageKeyPrefix, i)
			fmt.Fprintf(&injectionScriptBuilder, "try { sessionStorage.setItem(%q, %s); } catch(e) {}\n", ssKey, string(jsonPayload))
			a.registerProbe(ActiveProbe{Type: probeDef.Type, Key: ssKey, Value: ssPayload, Canary: ssCanary, Source: schemas.SourceSessionStorage, CreatedAt: time.Now()})
		}

		// Cookies
		cookieCanary := a.generateCanary("P", probeDef.Type)
		cookiePayload := a.preparePayload(probeDef, cookieCanary)
		if cookiePayload != "" {
			cookieName := fmt.Sprintf("%s%d", cookieNamePrefix, i)
			cookieCmd := fmt.Sprintf("try { document.cookie = `%s=%s; path=/; max-age=3600; samesite=Lax;%s`; } catch(e) {}\n", cookieName, url.QueryEscape(cookiePayload), secureFlag)
			injectionScriptBuilder.WriteString(cookieCmd)
			a.registerProbe(ActiveProbe{Type: probeDef.Type, Key: cookieName, Value: cookiePayload, Canary: cookieCanary, Source: schemas.SourceCookie, CreatedAt: time.Now()})
		}
	}

	injectionScript := injectionScriptBuilder.String()
	if injectionScript == "" {
		return nil
	}

	if err := a.executePause(ctx, h, 300, 100); err != nil {
		return err
	}
	if _, err := session.ExecuteScript(ctx, injectionScript, nil); err != nil {
		a.logger.Warn("Failed to execute persistent probe injection script", zap.Error(err))
	}

	a.logger.Debug("Persistent probes injected. Refreshing page.")
	if err := a.executePause(ctx, h, 200, 80); err != nil {
		return err
	}
	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Navigation (refresh) failed after persistent probe injection", zap.Error(err))
	}
	if err := a.executePause(ctx, h, 700, 300); err != nil {
		return err
	}
	return nil
}

// probeURLSources injects probes into URL query parameters and the hash fragment (Generic/Blind probing).
func (a *Analyzer) probeURLSources(ctx context.Context, session SessionContext, h *humanoid.Humanoid) error {
	baseURL, err := url.Parse(a.config.Target.String())
	if err != nil {
		a.logger.Error("Failed to parse base URL for probing", zap.Error(err))
		return fmt.Errorf("failed to parse base URL for probing: %w", err)
	}

	paramPrefix := "sc_test_"

	// -- Query Parameter Probing --
	targetURL, _ := url.Parse(baseURL.String())
	q := targetURL.Query()
	probesInjected := 0
	for i, probeDef := range a.config.Probes {
		canary := a.generateCanary("Q", probeDef.Type)
		payload := a.preparePayload(probeDef, canary)
		if payload == "" {
			continue
		}
		paramName := fmt.Sprintf("%s%d", paramPrefix, i)
		q.Set(paramName, payload)
		a.registerProbe(ActiveProbe{Type: probeDef.Type, Key: paramName, Value: payload, Canary: canary, Source: schemas.SourceURLParam, CreatedAt: time.Now()})
		probesInjected++
	}

	if probesInjected > 0 {
		targetURL.RawQuery = q.Encode()
		a.logger.Debug("Navigating with combined URL parameter probes", zap.Int("probe_count", probesInjected))
		if err := a.executePause(ctx, h, 400, 150); err != nil {
			return err
		}
		if err := session.Navigate(ctx, targetURL.String()); err != nil {
			a.logger.Warn("Navigation failed during combined URL probing", zap.Error(err))
		}
		if err := a.executePause(ctx, h, 700, 300); err != nil {
			return err
		}
	}

	// -- Hash Fragment Probing --
	targetURL, _ = url.Parse(baseURL.String())
	var hashFragments []string
	probesInjected = 0
	for i, probeDef := range a.config.Probes {
		canary := a.generateCanary("H", probeDef.Type)
		payload := a.preparePayload(probeDef, canary)
		if payload == "" {
			continue
		}
		paramName := fmt.Sprintf("%s%d", paramPrefix, i)
		hashFragments = append(hashFragments, fmt.Sprintf("%s=%s", paramName, url.QueryEscape(payload)))
		a.registerProbe(ActiveProbe{Type: probeDef.Type, Key: paramName, Value: payload, Canary: canary, Source: schemas.SourceHashFragment, CreatedAt: time.Now()})
		probesInjected++
	}

	if probesInjected > 0 {
		targetURL.Fragment = strings.Join(hashFragments, "&")
		a.logger.Debug("Navigating with combined Hash fragment probes", zap.Int("probe_count", probesInjected))
		if err := a.executePause(ctx, h, 400, 150); err != nil {
			return err
		}
		if err := session.Navigate(ctx, targetURL.String()); err != nil {
			a.logger.Warn("Navigation failed during combined Hash probing", zap.Error(err))
		}
		if err := a.executePause(ctx, h, 700, 300); err != nil {
			return err
		}
	}
	return nil
}

// registerProbe adds a probe to the tracking map in a thread safe manner.
func (a *Analyzer) registerProbe(probe ActiveProbe) {
	a.probesMutex.Lock()
	defer a.probesMutex.Unlock()
	a.activeProbes[probe.Canary] = probe
}

// correlateWorker is a single worker in the pool.
func (a *Analyzer) correlateWorker(id int) {
	defer a.wg.Done()
	a.logger.Debug("Correlation worker started.", zap.Int("worker_id", id))
	for event := range a.eventsChan {
		a.processEvent(event)
	}
	a.logger.Debug("Correlation worker finished.", zap.Int("worker_id", id))
}

// cleanupExpiredProbes is a background goroutine that periodically removes old probes.
func (a *Analyzer) cleanupExpiredProbes() {
	defer a.producersWG.Done()
	ticker := time.NewTicker(a.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.executeCleanup()
		case <-a.backgroundCtx.Done():
			return
		}
	}
}

// executeCleanup performs the actual work of finding and deleting expired probes.
func (a *Analyzer) executeCleanup() {
	a.probesMutex.Lock()
	defer a.probesMutex.Unlock()
	now := time.Now()
	for canary, probe := range a.activeProbes {
		if now.Sub(probe.CreatedAt) > a.config.ProbeExpirationDuration {
			delete(a.activeProbes, canary)
		}
	}
}

// pollOASTInteractions is a background goroutine that periodically checks the OAST provider.
func (a *Analyzer) pollOASTInteractions() {
	defer a.producersWG.Done()
	ticker := time.NewTicker(a.config.OASTPollingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			a.fetchAndEnqueueOAST()
		case <-a.backgroundCtx.Done():
			// One final check after shutdown is signaled
			a.fetchAndEnqueueOAST()
			return
		}
	}
}

// fetchAndEnqueueOAST retrieves OAST interactions and sends them to the correlation engine.
func (a *Analyzer) fetchAndEnqueueOAST() {
	a.probesMutex.RLock()
	var canaries []string
	for canary, probe := range a.activeProbes {
		if probe.Type == schemas.ProbeTypeOAST || strings.Contains(probe.Value, a.oastProvider.GetServerURL()) {
			canaries = append(canaries, canary)
		}
	}
	a.probesMutex.RUnlock()

	if len(canaries) == 0 {
		return
	}

	interactions, err := a.oastProvider.GetInteractions(a.backgroundCtx, canaries)
	if err != nil {
		a.logger.Error("Failed to fetch OAST interactions", zap.Error(err))
		return
	}

	for _, interaction := range interactions {
		// Corrected: Wrap the schema definition in the local event type.
		// This utilizes struct embedding to adapt the external type to the internal interface.
		localInteraction := OASTInteraction{
			OASTInteraction: interaction,
		}
		a.enqueueEvent(localInteraction, "OASTInteraction")
	}
}

// processEvent is the main dispatcher for incoming events.
func (a *Analyzer) processEvent(event Event) {
	switch e := event.(type) {
	case SinkEvent:
		if e.Type == schemas.SinkPrototypePollution {
			a.processPrototypePollutionConfirmation(e)
		} else {
			a.processSinkEvent(e)
		}
	case ExecutionProofEvent:
		a.processExecutionProof(e)
	case OASTInteraction:
		a.processOASTInteraction(e)
	default:
		a.logger.Warn("Unknown event type received in correlation engine", zap.Any("event", e))
	}
}

// isErrorPageContext implements heuristics to determine if the context corresponds to an error page.
func (a *Analyzer) isErrorPageContext(pageURL, pageTitle string) bool {
	// Check Title patterns
	lowerTitle := strings.ToLower(pageTitle)
	if strings.Contains(lowerTitle, "404 not found") ||
		strings.Contains(lowerTitle, "page not found") ||
		strings.Contains(lowerTitle, "server error") ||
		strings.Contains(lowerTitle, "internal server error") {
		return true
	}

	// Check URL patterns: Look for explicit error pages in the path.
	// We convert to lower case to catch /Error, /ERROR, etc.
	u := strings.ToLower(pageURL)
	// Check for standard error filenames or paths.
	if strings.Contains(u, "/error.") || strings.Contains(u, "/errors/") {
		return true
	}
	// Check for status codes in the path (often used by frameworks e.g. /404).
	// We ensure they are path segments to avoid matching "node404" or similar IDs.
	parsedURL, err := url.Parse(pageURL)
	if err != nil {
		// Fallback to basic string matching if URL parsing fails
		if strings.Contains(u, "/404/") || strings.HasSuffix(u, "/404") {
			return true
		}
		if strings.Contains(u, "/500/") || strings.HasSuffix(u, "/500") {
			return true
		}
		return false
	}
	path := parsedURL.Path
	// BUG-FIX: Check for contains /404/ or suffix /404 to be more flexible.
	if strings.Contains(path, "/404/") || strings.HasSuffix(path, "/404") || strings.Contains(path, "/404.") {
		return true
	}
	if strings.Contains(path, "/500/") || strings.HasSuffix(path, "/500") || strings.Contains(path, "/500.") {
		return true
	}

	return false
}

// processOASTInteraction handles confirmed out of band callbacks and reports a finding.
func (a *Analyzer) processOASTInteraction(interaction OASTInteraction) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[interaction.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		return
	}

	detail := fmt.Sprintf("Out-of-band interaction (%s) detected from %s.", interaction.Protocol, interaction.SourceIP)
	occurrenceURL := a.config.Target.String()

	finding := CorrelatedFinding{
		TaskID:            a.config.TaskID,
		TargetURL:         a.config.Target.String(),
		OccurrenceURL:     occurrenceURL,
		OccurrenceTitle:   "N/A (Out of Band)",
		Sink:              schemas.SinkOASTInteraction,
		Origin:            probe.Source,
		Value:             probe.Value,
		Canary:            interaction.Canary,
		Probe:             probe,
		Detail:            detail,
		IsConfirmed:       true,
		SanitizationLevel: SanitizationNone,
		StackTrace:        "N/A (Out of Band)",
		OASTDetails:       &interaction,
		ConfirmedDynamic:  true,
		ConfirmedStatic:   false,
	}
	a.reporter.Report(finding)
}

// processExecutionProof handles confirmed payload executions and reports a finding.
func (a *Analyzer) processExecutionProof(proof ExecutionProofEvent) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[proof.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		return
	}

	finding := CorrelatedFinding{
		TaskID:            a.config.TaskID,
		TargetURL:         a.config.Target.String(),
		OccurrenceURL:     proof.PageURL,
		OccurrenceTitle:   proof.PageTitle,
		Sink:              schemas.SinkExecution,
		Origin:            probe.Source,
		Value:             probe.Value,
		Canary:            proof.Canary,
		Probe:             probe,
		Detail:            "Payload execution confirmed via JS callback.",
		IsConfirmed:       true,
		SanitizationLevel: SanitizationNone,
		StackTrace:        proof.StackTrace,
		ConfirmedDynamic:  true,
		ConfirmedStatic:   false,
	}

	a.correlateWithStaticFindings(&finding)
	a.reporter.Report(finding)
}

// processSinkEvent checks a sink event for our canaries and, if found, reports a potential finding.
func (a *Analyzer) processSinkEvent(event SinkEvent) {
	matchedCanaries := canaryRegex.FindAllString(event.Value, -1)
	if len(matchedCanaries) == 0 {
		return
	}

	a.probesMutex.RLock()
	matchedProbes := make(map[string]ActiveProbe)
	for _, canary := range matchedCanaries {
		if probe, ok := a.activeProbes[canary]; ok {
			matchedProbes[canary] = probe
		}
	}
	a.probesMutex.RUnlock()

	for canary, probe := range matchedProbes {
		if a.isContextValid(event, probe) {
			if a.isErrorPageContext(event.PageURL, event.PageTitle) {
				continue
			}

			sanitizationLevel, detailSuffix := a.checkSanitization(event.Value, probe)
			finding := CorrelatedFinding{
				TaskID:            a.config.TaskID,
				TargetURL:         a.config.Target.String(),
				OccurrenceURL:     event.PageURL,
				OccurrenceTitle:   event.PageTitle,
				Sink:              event.Type,
				Origin:            probe.Source,
				Value:             event.Value,
				Canary:            canary,
				Probe:             probe,
				Detail:            event.Detail + detailSuffix,
				IsConfirmed:       false,
				SanitizationLevel: sanitizationLevel,
				StackTrace:        event.StackTrace,
				ConfirmedDynamic:  true,
				ConfirmedStatic:   false,
			}

			a.correlateWithStaticFindings(&finding)
			a.reporter.Report(finding)
		} else {
			a.logger.Debug("Context mismatch: Taint flow suppressed (False Positive).",
				zap.String("probe_type", string(probe.Type)),
				zap.String("sink_type", string(event.Type)),
				zap.String("canary", canary),
			)
		}
	}
}

// processPrototypePollutionConfirmation handles the specific confirmation event for Prototype Pollution.
func (a *Analyzer) processPrototypePollutionConfirmation(event SinkEvent) {
	canary := event.Value
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[canary]
	a.probesMutex.RUnlock()

	if !ok || probe.Type != schemas.ProbeTypePrototypePollution {
		return
	}

	finding := CorrelatedFinding{
		TaskID:            a.config.TaskID,
		TargetURL:         a.config.Target.String(),
		OccurrenceURL:     event.PageURL,
		OccurrenceTitle:   event.PageTitle,
		Sink:              schemas.SinkPrototypePollution,
		Origin:            probe.Source,
		Value:             probe.Value,
		Canary:            canary,
		Probe:             probe,
		Detail:            fmt.Sprintf("Successfully polluted Object.prototype property: %s", event.Detail),
		IsConfirmed:       true,
		SanitizationLevel: SanitizationNone,
		StackTrace:        event.StackTrace,
		ConfirmedDynamic:  true,
		ConfirmedStatic:   false,
	}

	a.correlateWithStaticFindings(&finding)
	a.reporter.Report(finding)
}

// Step 5 Implementation: Hybrid Correlation Helper
// correlateWithStaticFindings attempts to match a dynamic finding with existing static analysis results.
func (a *Analyzer) correlateWithStaticFindings(finding *CorrelatedFinding) {
	scriptFile, line, _ := parseStackTrace(finding.StackTrace)
	targetFile := scriptFile
	if targetFile == "" {
		targetFile = finding.OccurrenceURL
	}

	if targetFile == "" {
		return
	}

	a.findingsMutex.RLock()
	staticFindings, exists := a.staticFindings[targetFile]
	a.findingsMutex.RUnlock()

	if !exists {
		return
	}

	for i := range staticFindings {
		sf := &staticFindings[i]

		isSinkMatch := false
		if sf.CanonicalType == finding.Sink {
			isSinkMatch = true
		} else if finding.Sink == schemas.SinkExecution {
			if core.GetSinkType(sf.CanonicalType) == core.SinkTypeExecution {
				isSinkMatch = true
			}
		}

		if !isSinkMatch {
			continue
		}

		if !a.isSourceContextMatch(finding.Probe.Source, sf.Source) {
			continue
		}

		isLocationMatch := false
		if line != -1 {
			if abs(sf.Location.Line-line) <= 3 {
				isLocationMatch = true
			}
		} else {
			isLocationMatch = true
		}

		if isLocationMatch {
			finding.ConfirmedStatic = true
			if !finding.IsConfirmed {
				finding.IsConfirmed = true
				finding.Detail += " (Statically Verified)"
			}
			finding.StaticFinding = sf

			a.logger.Info("Hybrid Correlation Success: IAST finding verified by SAST",
				zap.String("canary", finding.Canary),
				zap.String("sink_type", string(sf.SinkType)),
				zap.String("sast_location", sf.Location.String()))
			return
		}
	}
}

// isSourceContextMatch maps dynamic injection points (schemas.TaintSource) to static source definitions (core.TaintSource).
func (a *Analyzer) isSourceContextMatch(dynamicSource schemas.TaintSource, staticSource core.TaintSource) bool {
	staticSources := strings.Split(string(staticSource), "|")

	for _, staticSrcStr := range staticSources {
		switch dynamicSource {
		case schemas.SourceURLParam:
			if staticSrcStr == string(core.SourceLocationSearch) ||
				staticSrcStr == string(core.SourceLocationHref) ||
				strings.HasPrefix(staticSrcStr, "param:query:") {
				return true
			}
		case schemas.SourceHashFragment:
			if staticSrcStr == string(core.SourceLocationHash) ||
				strings.HasPrefix(staticSrcStr, "param:hash:") {
				return true
			}
		case schemas.SourceLocalStorage:
			if staticSrcStr == string(core.SourceLocalStorage) ||
				strings.HasPrefix(staticSrcStr, "param:storage:") {
				return true
			}
		case schemas.SourceSessionStorage:
			if staticSrcStr == string(core.SourceSessionStorage) ||
				strings.HasPrefix(staticSrcStr, "param:storage:") {
				return true
			}
		case schemas.SourceCookie:
			if staticSrcStr == string(core.SourceDocumentCookie) {
				return true
			}
		}
	}
	return false
}

// Helper function to parse stack traces (browser-dependent format).
func parseStackTrace(stack string) (file string, line int, col int) {
	matches := stackTraceLocationRegex.FindStringSubmatch(stack)

	if len(matches) == 4 {
		file = matches[1]
		line, _ = strconv.Atoi(matches[2])
		col, _ = strconv.Atoi(matches[3])
		return file, line, col
	}
	return "", -1, -1
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// checkSanitization compares the value seen at the sink with the original probe payload.
func (a *Analyzer) checkSanitization(sinkValue string, probe ActiveProbe) (SanitizationLevel, string) {
	if strings.Contains(sinkValue, probe.Value) {
		return SanitizationNone, ""
	}

	var details []string
	if probe.Type == schemas.ProbeTypeXSS {
		if strings.Contains(probe.Value, "<") && !strings.Contains(sinkValue, "<") {
			details = append(details, "HTML tags modified or stripped")
		}
		// FIX: Enhanced detection for escaped quotes (backslash) vs removed/encoded quotes.
		if strings.Contains(probe.Value, `"`) {
			// Create versions of the probe with quotes escaped and removed.
			probeWithEscapedQuotes := strings.ReplaceAll(probe.Value, `"`, `\"`)
			probeWithoutQuotes := strings.ReplaceAll(probe.Value, `"`, "")

			// Prioritize checking for escaped quotes first. This is a more specific transformation.
			if strings.Contains(sinkValue, probeWithEscapedQuotes) {
				details = append(details, "Quotes escaped")
			} else if strings.Contains(sinkValue, probeWithoutQuotes) {
				// If not escaped, check if the quotes were simply removed.
				details = append(details, "Quotes removed or encoded")
			}
		}
	}

	if len(details) > 0 {
		return SanitizationPartial, " (Potential Sanitization: " + strings.Join(details, ", ") + ")"
	}

	return SanitizationFull, " (Payload fully sanitized)"
}

// isContextValid implements the rules engine for reducing false positives.
func (a *Analyzer) isContextValid(event SinkEvent, probe ActiveProbe) bool {
	a.rulesMutex.RLock()
	defer a.rulesMutex.RUnlock()

	flow := TaintFlowPath{ProbeType: probe.Type, SinkType: event.Type}
	isValid, defined := a.validTaintFlows[flow]
	if !defined || !isValid {
		return false
	}

	if event.Type == schemas.SinkNavigation && !strings.HasPrefix(event.Value, "javascript:") {
		return false
	}

	return true
}
