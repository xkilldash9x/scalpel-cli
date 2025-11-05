// File: internal/analysis/active/taint/analyzer.go
package taint

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors" // <-- Added
	"fmt"
	"net/url"
	"regexp"
	"runtime/debug" // <-- Added
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
)

//go:embed taint_shim.js
var taintShimFS embed.FS

const taintShimFilename = "taint_shim.js"

// Canary format: SCALPEL_{Prefix}_{Type}_{UUID_Short}
// Robust regex allowing underscores in both the Prefix and Type segments.
var canaryRegex = regexp.MustCompile(`SCALPEL_[A-Z0-9_]+_[A-Z_]+_[a-f0-9]{8}`) // <-- Updated Regex

// HumanoidProvider defines an interface for optional integration with the Humanoid controller.
type HumanoidProvider interface {
	GetHumanoid() *humanoid.Humanoid
}

// Analyzer is the central component of the IAST system. It orchestrates probe
// injection, event collection, correlation, and reporting.
type Analyzer struct {
	config       Config
	reporter     ResultsReporter
	oastProvider OASTProvider
	logger       *zap.Logger
	shimTemplate string

	// -- State Management --
	activeProbes map[string]ActiveProbe
	// probesMutex protects concurrent access to activeProbes.
	probesMutex sync.RWMutex

	// rulesMutex protects the local copy of validTaintFlows.
	rulesMutex      sync.RWMutex
	validTaintFlows map[TaintFlowPath]bool

	// -- Concurrency Control --
	// eventsChan is the central channel from producers to consumers.
	eventsChan chan Event

	// wg tracks the lifecycle of the correlation worker pool.
	wg sync.WaitGroup
	// producersWG tracks the background producer goroutines (cleanup, OAST polling).
	producersWG sync.WaitGroup

	// backgroundCtx and backgroundCancel manage the lifecycle of background routines.
	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc
}

// NewAnalyzer initializes the analyzer, applies configuration defaults,
// loads the shim template, and prepares the rules engine.
func NewAnalyzer(config Config, reporter ResultsReporter, oastProvider OASTProvider, logger *zap.Logger) (*Analyzer, error) {
	taskLogger := logger.Named("taint_analyzer").With(zap.String("task_id", config.TaskID))

	// 1. Load the embedded JavaScript shim template.
	templateContent, err := loadShimTemplate()
	if err != nil {
		taskLogger.Error("Failed to load embedded taint shim.", zap.Error(err))
		return nil, err
	}

	// 2. Apply robust defaults for tuning parameters.
	config = applyConfigDefaults(config)

	// 3. Initialize the rules engine with a local copy for thread safety.
	localValidTaintFlows := make(map[TaintFlowPath]bool, len(ValidTaintFlows))
	for k, v := range ValidTaintFlows {
		localValidTaintFlows[k] = v
	}

	return &Analyzer{
		config:          config,
		reporter:        reporter,
		oastProvider:    oastProvider,
		logger:          taskLogger,
		activeProbes:    make(map[string]ActiveProbe),
		eventsChan:      make(chan Event, config.Tuning.EventChannelBuffer), // <-- Updated path
		shimTemplate:    templateContent,
		validTaintFlows: localValidTaintFlows,
	}, nil
}

// loadShimTemplate reads the embedded JS template file.
func loadShimTemplate() (string, error) {
	templateBytes, err := taintShimFS.ReadFile(taintShimFilename)
	if err != nil {
		return "", fmt.Errorf("failed to read embedded shim file %s: %w", taintShimFilename, err)
	}
	return string(templateBytes), nil
}

// UpdateTaintFlowRuleForTesting provides a thread-safe way to modify a rule for a specific test.
func (a *Analyzer) UpdateTaintFlowRuleForTesting(flow TaintFlowPath, isValid bool) {
	a.rulesMutex.Lock()
	defer a.rulesMutex.Unlock()
	a.validTaintFlows[flow] = isValid
}

// BuildTaintShim constructs the final JavaScript shim from a template string and config.
// This function is exported to be used by the session manager during initialization.
func BuildTaintShim(templateContent string, configJSON string) (string, error) {
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
		SinkCallbackName:  JSCallbackSinkEvent,
		ProofCallbackName: JSCallbackExecutionProof,
		ErrorCallbackName: JSCallbackShimError,
	}

	// 3. Execute the template into a buffer.
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute shim template: %w", err)
	}

	return buf.String(), nil
}

// applyConfigDefaults ensures that critical configuration parameters have sensible default values.
func applyConfigDefaults(cfg Config) Config {
	// Define defaults within the TuningConfig struct.
	if cfg.Tuning.EventChannelBuffer <= 0 {
		cfg.Tuning.EventChannelBuffer = 1000
	}
	if cfg.Tuning.FinalizationGracePeriod <= 0 {
		cfg.Tuning.FinalizationGracePeriod = 10 * time.Second
	}
	if cfg.Tuning.ProbeExpirationDuration <= 0 {
		cfg.Tuning.ProbeExpirationDuration = 15 * time.Minute
	}
	if cfg.Tuning.CleanupInterval <= 0 {
		cfg.Tuning.CleanupInterval = 2 * time.Minute
	}
	if cfg.Tuning.OASTPollingInterval <= 0 {
		cfg.Tuning.OASTPollingInterval = 30 * time.Second
	}
	if cfg.Tuning.CorrelationWorkers <= 0 {
		cfg.Tuning.CorrelationWorkers = 5
	}
	if cfg.AnalysisTimeout <= 0 {
		cfg.AnalysisTimeout = 10 * time.Minute
	}
	return cfg
}

// Analyze executes the comprehensive IAST analysis workflow.
func (a *Analyzer) Analyze(ctx context.Context, session SessionContext) error {
	a.logger.Info("Starting IAST analysis",
		zap.String("target", a.config.Target.String()),
		zap.Int("correlation_workers", a.config.Tuning.CorrelationWorkers),
	)

	// Create a derived context with the analysis timeout.
	analysisCtx, cancelAnalysis := context.WithTimeout(ctx, a.config.AnalysisTimeout)
	defer cancelAnalysis()

	// Initialize the background context used for graceful shutdown of workers.
	// Derived from context.Background() to allow workers to finish processing even if analysisCtx times out.
	a.backgroundCtx, a.backgroundCancel = context.WithCancel(context.Background())
	// Ensure shutdown is always called when Analyze returns.
	defer a.shutdown()

	var h *humanoid.Humanoid
	if provider, ok := session.(HumanoidProvider); ok {
		h = provider.GetHumanoid()
	}

	// Instrument the browser session.
	if err := a.instrument(analysisCtx, session); err != nil {
		return fmt.Errorf("failed to instrument browser session: %w", err)
	}

	// Launch the concurrent machinery.
	a.startBackgroundWorkers()

	// Execute the attack vectors and interactions.
	if err := a.executeProbes(analysisCtx, session, h); err != nil {
		// Log errors unless the error was simply the analysis context timing out.
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			a.logger.Error("Error encountered during probing phase", zap.Error(err))
		}
	}

	// Wait for asynchronous events.
	a.waitForFinalization(analysisCtx)

	a.logger.Info("IAST analysis completed")
	return nil
}

// waitForFinalization blocks until the grace period is over or the analysis context is done.
func (a *Analyzer) waitForFinalization(analysisCtx context.Context) {
	a.logger.Debug("Probing finished. Waiting for asynchronous events.", zap.Duration("grace_period", a.config.Tuning.FinalizationGracePeriod))

	select {
	case <-time.After(a.config.Tuning.FinalizationGracePeriod):
		a.logger.Debug("Grace period concluded.")
	case <-analysisCtx.Done():
		a.logger.Warn("Analysis timeout reached during finalization grace period.")
	}
}

// shutdown handles the ordered, graceful shutdown of all goroutines, ensuring all events are processed.
func (a *Analyzer) shutdown() {
	if a.backgroundCancel == nil {
		return
	}

	a.logger.Debug("Initiating graceful shutdown.")

	// 1. Signal background producers (OAST, Cleanup) to stop.
	a.backgroundCancel()

	// 2. Wait for producers to complete their final cycles.
	a.producersWG.Wait()
	a.logger.Debug("All event producers have stopped.")

	// 3. Close the event channel. This signals the correlation workers to drain the channel and terminate.
	func() {
		defer func() {
			if r := recover(); r != nil {
				a.logger.Debug("Events channel already closed during shutdown.")
			}
		}()
		close(a.eventsChan)
	}()

	// 4. Wait for all correlation workers to finish processing the remaining events.
	a.wg.Wait()
	a.logger.Debug("All correlation workers have finished. Shutdown complete.")
}

// startBackgroundWorkers launches the correlation worker pool and other background tasks.
func (a *Analyzer) startBackgroundWorkers() {
	a.logger.Debug("Starting background workers.", zap.Int("correlation_workers", a.config.Tuning.CorrelationWorkers))
	// -- Consumers --
	// Launch the Correlation Worker Pool to process events concurrently.
	for i := 0; i < a.config.Tuning.CorrelationWorkers; i++ {
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
	if err := session.ExposeFunction(ctx, JSCallbackSinkEvent, a.handleSinkEvent); err != nil {
		return fmt.Errorf("failed to expose sink event callback: %w", err)
	}
	if err := session.ExposeFunction(ctx, JSCallbackExecutionProof, a.handleExecutionProof); err != nil {
		return fmt.Errorf("failed to expose execution proof callback: %w", err)
	}
	if err := session.ExposeFunction(ctx, JSCallbackShimError, a.handleShimError); err != nil {
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
	return BuildTaintShim(a.shimTemplate, string(sinksJSON))
}

// enqueueEvent provides a safe, non-blocking mechanism for sending events. Handles shutdown and backpressure.
func (a *Analyzer) enqueueEvent(event Event, eventType string) {
	// 1. Check for shutdown signal.
	select {
	case <-a.backgroundCtx.Done():
		a.logger.Debug("Dropping event during shutdown.", zap.String("type", eventType))
		return
	default:
	}

	// 2. Attempt to send, handle backpressure if the channel is full.
	select {
	case a.eventsChan <- event:
	default:
		a.logger.Warn("Event channel full (backpressure), dropping event. System may be overloaded.",
			zap.String("type", eventType),
			zap.Int("buffer_size", a.config.Tuning.EventChannelBuffer))
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
// If Humanoid is nil, it skips the pause silently.
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

	if err := a.executePause(ctx, h, 500, 200); err != nil {
		return err // Return if context cancelled during pause
	}

	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Initial navigation failed, attempting to continue probes.", zap.Error(err))
	}

	if err := a.executePause(ctx, h, 800, 300); err != nil {
		return err
	}

	if err := a.probePersistentSources(ctx, session, h); err != nil {
		// Check if the context was cancelled before logging the error.
		if ctx.Err() == nil {
			a.logger.Error("Error during persistent source probing", zap.Error(err))
		}
	}

	if err := a.executePause(ctx, h, 400, 150); err != nil {
		return err
	}

	if err := a.probeURLSources(ctx, session, h); err != nil {
		// Check if the context was cancelled before logging the error.
		if ctx.Err() == nil {
			a.logger.Error("Error during URL source probing", zap.Error(err))
		}
	}

	a.logger.Info("Starting interactive probing phase.")

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

	if err := a.executePause(ctx, h, 1000, 400); err != nil {
		// We don't return error here as probing is done, we just log if the final pause failed.
		if ctx.Err() == nil {
			a.logger.Debug("Final post-interaction pause interrupted.", zap.Error(err))
		}
	}

	return nil
}

// generateCanary creates a unique canary string for tracking a probe.
func (a *Analyzer) generateCanary(prefix string, probeType schemas.ProbeType) string {
	return fmt.Sprintf("SCALPEL_%s_%s_%s", prefix, probeType, uuid.New().String()[:8])
}

// preparePayload replaces placeholders in a probe definition with a canary and OAST server URL.
func (a *Analyzer) preparePayload(probeDef ProbeDefinition, canary string) string {
	requiresOAST := strings.Contains(probeDef.Payload, "{{.OASTServer}}")
	if requiresOAST && a.oastProvider == nil {
		a.logger.Warn("OAST probe defined but no OAST provider configured. Skipping probe.", zap.String("canary", canary))
		return ""
	}

	replacements := []string{"{{.Canary}}", canary}
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
		// -- LocalStorage --
		lsCanary := a.generateCanary("P", probeDef.Type)
		lsPayload := a.preparePayload(probeDef, lsCanary)
		if lsPayload != "" {
			jsonPayload, err := json.Marshal(lsPayload)
			if err != nil {
				a.logger.Error("Failed to JSON encode LocalStorage payload", zap.Error(err))
			} else {
				jsPayload := string(jsonPayload)
				lsKey := fmt.Sprintf("%s%d", storageKeyPrefix, i)
				fmt.Fprintf(&injectionScriptBuilder, "localStorage.setItem(%q, %s);\n", lsKey, jsPayload)
				a.registerProbe(ActiveProbe{
					Type:      probeDef.Type,
					Key:       lsKey,
					Value:     lsPayload,
					Canary:    lsCanary,
					Source:    schemas.SourceLocalStorage,
					CreatedAt: time.Now(),
				})
			}
		}

		// -- SessionStorage --
		ssCanary := a.generateCanary("P", probeDef.Type)
		ssPayload := a.preparePayload(probeDef, ssCanary)
		if ssPayload != "" {
			jsonPayload, err := json.Marshal(ssPayload)
			if err != nil {
				a.logger.Error("Failed to JSON encode SessionStorage payload", zap.Error(err))
			} else {
				jsPayload := string(jsonPayload)
				ssKey := fmt.Sprintf("%s%d_s", storageKeyPrefix, i)
				fmt.Fprintf(&injectionScriptBuilder, "sessionStorage.setItem(%q, %s);\n", ssKey, jsPayload)
				a.registerProbe(ActiveProbe{
					Type:      probeDef.Type,
					Key:       ssKey,
					Value:     ssPayload,
					Canary:    ssCanary,
					Source:    schemas.SourceSessionStorage,
					CreatedAt: time.Now(),
				})
			}
		}

		// -- Cookies --
		cookieCanary := a.generateCanary("P", probeDef.Type)
		cookiePayload := a.preparePayload(probeDef, cookieCanary)
		if cookiePayload != "" {
			jsonPayload, err := json.Marshal(cookiePayload)
			if err != nil {
				a.logger.Error("Failed to JSON encode Cookie payload", zap.Error(err))
			} else {
				jsPayload := string(jsonPayload)
				cookieName := fmt.Sprintf("%s%d", cookieNamePrefix, i)
				cookieCommand := fmt.Sprintf("document.cookie = `${%q}=${encodeURIComponent(%s)}; path=/; max-age=3600; samesite=Lax;%s`;\n", cookieName, jsPayload, secureFlag)
				injectionScriptBuilder.WriteString(cookieCommand)
				a.registerProbe(ActiveProbe{
					Type:      probeDef.Type,
					Key:       cookieName,
					Value:     cookiePayload,
					Canary:    cookieCanary,
					Source:    schemas.SourceCookie,
					CreatedAt: time.Now(),
				})
			}
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
		a.logger.Warn("Failed to inject persistent probes via JavaScript", zap.Error(err))
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

// probeURLSources injects probes into URL query parameters and the hash fragment.
func (a *Analyzer) probeURLSources(ctx context.Context, session SessionContext, h *humanoid.Humanoid) error {
	baseURL := *a.config.Target
	paramPrefix := "sc_test_"

	// -- Query Parameter Probing --
	targetURL := baseURL
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
		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       paramName,
			Value:     payload,
			Canary:    canary,
			Source:    schemas.SourceURLParam,
			CreatedAt: time.Now(),
		})
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
	targetURL = baseURL // reset for the next probe type
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
		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       paramName,
			Value:     payload,
			Canary:    canary,
			Source:    schemas.SourceHashFragment,
			CreatedAt: time.Now(),
		})
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

// correlateWorker is a single worker responsible for processing events from the channel.
func (a *Analyzer) correlateWorker(id int) {
	defer a.wg.Done()
	a.logger.Debug("Correlation worker started.", zap.Int("worker_id", id))

	// The loop iterates over the channel. It terminates when the channel is closed during shutdown.
	// We use the backgroundCtx for reporting findings, ensuring reports can complete during shutdown.
	for event := range a.eventsChan {
		// Wrap processing in a panic recovery block for production robustness.
		func() {
			defer func() {
				if r := recover(); r != nil {
					a.logger.Error("Panic recovered in correlation worker",
						zap.Any("panic_value", r),
						zap.Int("worker_id", id),
						zap.ByteString("stack", debug.Stack()), // Capture stack trace
					)
				}
			}()
			a.processEvent(a.backgroundCtx, event)
		}()
	}
	a.logger.Debug("Correlation worker finished (channel closed).", zap.Int("worker_id", id))
}

// cleanupExpiredProbes is a background goroutine that periodically removes old probes
// from the activeProbes map to prevent unbounded memory growth.
func (a *Analyzer) cleanupExpiredProbes() {
	defer a.producersWG.Done()
	ticker := time.NewTicker(a.config.Tuning.CleanupInterval)
	defer ticker.Stop()
	a.logger.Debug("Probe expiration cleanup routine started.", zap.Duration("interval", a.config.Tuning.CleanupInterval), zap.Duration("expiration", a.config.Tuning.ProbeExpirationDuration))

	for {
		select {
		case <-a.backgroundCtx.Done():
			a.logger.Debug("Cleanup routine shutting down.")
			return
		case <-ticker.C:
			a.executeCleanup()
		}
	}
}

// executeCleanup performs the actual work of finding and deleting expired probes.
func (a *Analyzer) executeCleanup() {
	expirationTime := time.Now().Add(-a.config.Tuning.ProbeExpirationDuration)
	var expiredCanaries []string

	// Use a read lock to identify expired probes without blocking writers for long.
	a.probesMutex.RLock()
	for canary, probe := range a.activeProbes {
		if probe.CreatedAt.Before(expirationTime) {
			expiredCanaries = append(expiredCanaries, canary)
		}
	}
	a.probesMutex.RUnlock()

	if len(expiredCanaries) == 0 {
		return
	}

	// Now, acquire a write lock to delete the expired probes.
	a.probesMutex.Lock()
	for _, canary := range expiredCanaries {
		delete(a.activeProbes, canary)
	}
	a.probesMutex.Unlock()
	a.logger.Debug("Cleaned up expired probes.", zap.Int("count", len(expiredCanaries)))
}

// pollOASTInteractions is a background goroutine that periodically checks the
// OAST provider for out of band callbacks.
func (a *Analyzer) pollOASTInteractions() {
	defer a.producersWG.Done()
	ticker := time.NewTicker(a.config.Tuning.OASTPollingInterval)
	defer ticker.Stop()
	a.logger.Debug("OAST polling routine started.", zap.Duration("interval", a.config.Tuning.OASTPollingInterval))

	for {
		select {
		case <-a.backgroundCtx.Done():
			a.logger.Debug("OAST polling routine shutting down. Performing final check.")
			a.fetchAndEnqueueOAST()
			return
		case <-ticker.C:
			a.fetchAndEnqueueOAST()
		}
	}
}

// fetchAndEnqueueOAST retrieves OAST interactions and sends them to the correlation engine.
func (a *Analyzer) fetchAndEnqueueOAST() {
	a.probesMutex.RLock()
	var relevantCanaries []string

	if a.oastProvider == nil {
		a.probesMutex.RUnlock()
		return
	}

	oastServerURL := a.oastProvider.GetServerURL()
	for canary, probe := range a.activeProbes {
		if probe.Type == schemas.ProbeTypeOAST || strings.Contains(probe.Value, oastServerURL) {
			relevantCanaries = append(relevantCanaries, canary)
		}
	}
	a.probesMutex.RUnlock()

	if len(relevantCanaries) == 0 {
		return
	}

	fetchCtx, cancel := context.WithTimeout(context.Background(), a.config.Tuning.OASTPollingInterval)
	defer cancel()

	interactions, err := a.oastProvider.GetInteractions(fetchCtx, relevantCanaries)
	if err != nil {
		a.logger.Error("Failed to fetch OAST interactions.", zap.Error(err))
		return
	}

	if len(interactions) > 0 {
		a.logger.Info("OAST Interactions detected!", zap.Int("count", len(interactions)))
	}

	for _, interaction := range interactions {
		// Convert from the canonical schema type to the local event type.
		localInteraction := OASTInteraction{
			Canary:          interaction.Canary,
			Protocol:        interaction.Protocol,
			SourceIP:        interaction.SourceIP,
			InteractionTime: interaction.InteractionTime,
			RawRequest:      interaction.RawRequest,
		}
		a.enqueueEvent(localInteraction, "OASTInteraction")
	}
}

// processEvent is the main dispatcher for incoming events.
func (a *Analyzer) processEvent(ctx context.Context, event Event) {
	switch e := event.(type) {
	case SinkEvent:
		a.processSinkEvent(ctx, e)
	case ExecutionProofEvent:
		a.processExecutionProof(ctx, e)
	case OASTInteraction:
		a.processOASTInteraction(ctx, e)
	default:
		a.logger.Warn("Received unknown event type in correlation engine", zap.Any("event", event))
	}
}

// processOASTInteraction handles confirmed out-of-band callbacks and reports a finding.
func (a *Analyzer) processOASTInteraction(ctx context.Context, interaction OASTInteraction) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[interaction.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		a.logger.Debug("OAST interaction received for unknown or expired canary.", zap.String("canary", interaction.Canary))
		return
	}

	a.logger.Warn("Vulnerability Confirmed via OAST Interaction!",
		zap.String("source", string(probe.Source)),
		zap.String("type", string(probe.Type)),
		zap.String("canary", interaction.Canary),
	)

	detail := fmt.Sprintf("Out of Band interaction confirmed via %s protocol.", interaction.Protocol)
	switch probe.Type {
	case schemas.ProbeTypeXSS, schemas.ProbeTypeSSTI:
		detail = "Blind XSS/SSTI confirmed via OAST callback."
	case schemas.ProbeTypeOAST:
		detail = "Blind vulnerability (e.g., SSRF, RCE) confirmed via OAST callback."
	}

	finding := CorrelatedFinding{
		TaskID:            a.config.TaskID,
		TargetURL:         a.config.Target.String(),
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
	}
	a.reporter.Report(ctx, finding) // <-- Pass context
}

// processExecutionProof handles confirmed payload executions and reports a finding.
func (a *Analyzer) processExecutionProof(ctx context.Context, proof ExecutionProofEvent) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[proof.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		a.logger.Debug("Execution proof received for unknown or expired canary.", zap.String("canary", proof.Canary))
		return
	}

	// This is just a sanity check.
	switch probe.Type {
	case schemas.ProbeTypeXSS, schemas.ProbeTypeSSTI, schemas.ProbeTypeSQLi, schemas.ProbeTypeCmdInjection, schemas.ProbeTypeDOMClobbering:
		// This is an expected probe type for an execution proof.
	default:
		a.logger.Debug("Execution proof received for unexpected probe type.", zap.String("canary", proof.Canary), zap.String("type", string(probe.Type)))
		return
	}

	a.logger.Warn("Vulnerability Confirmed via Execution Proof!",
		zap.String("source", string(probe.Source)),
		zap.String("type", string(probe.Type)),
		zap.String("canary", proof.Canary),
	)

	finding := CorrelatedFinding{
		TaskID:            a.config.TaskID,
		TargetURL:         a.config.Target.String(),
		Sink:              schemas.SinkExecution,
		Origin:            probe.Source,
		Value:             probe.Value,
		Canary:            proof.Canary,
		Probe:             probe,
		Detail:            "Payload execution confirmed via JS callback.",
		IsConfirmed:       true,
		SanitizationLevel: SanitizationNone,
		StackTrace:        proof.StackTrace,
	}
	a.reporter.Report(ctx, finding) // <-- Pass context
}

// processSinkEvent analyzes a sink event, validates context, checks sanitization, and reports findings.
func (a *Analyzer) processSinkEvent(ctx context.Context, event SinkEvent) {
	if event.Type == schemas.SinkPrototypePollution {
		a.processPrototypePollutionConfirmation(ctx, event) // <-- Pass context
		return
	}

	potentialCanaries := canaryRegex.FindAllString(event.Value, -1)
	if len(potentialCanaries) == 0 {
		return
	}

	a.probesMutex.RLock()
	matchedProbes := make(map[string]ActiveProbe)
	for _, canary := range potentialCanaries {
		if probe, ok := a.activeProbes[canary]; ok {
			matchedProbes[canary] = probe
		}
	}
	a.probesMutex.RUnlock()

	for canary, probe := range matchedProbes {
		a.logger.Info("Taint flow detected!",
			zap.String("source", string(probe.Source)),
			zap.String("sink", string(event.Type)),
			zap.String("canary", canary),
		)

		if a.isContextValid(event, probe) {
			sanitizationLevel, detailSuffix := a.checkSanitization(event.Value, probe)
			finding := CorrelatedFinding{
				TaskID:            a.config.TaskID,
				TargetURL:         a.config.Target.String(),
				Sink:              event.Type,
				Origin:            probe.Source,
				Value:             event.Value,
				Canary:            canary,
				Probe:             probe,
				Detail:            event.Detail + detailSuffix,
				IsConfirmed:       false,
				SanitizationLevel: sanitizationLevel,
				StackTrace:        event.StackTrace,
			}
			a.reporter.Report(ctx, finding) // <-- Pass context
		} else {
			a.logger.Debug("Context mismatch: Taint flow suppressed (False Positive).",
				zap.String("canary", canary),
				zap.String("probe_type", string(probe.Type)),
				zap.String("sink_type", string(event.Type)),
			)
		}
	}
}

// processPrototypePollutionConfirmation handles the specific confirmation event for Prototype Pollution.
func (a *Analyzer) processPrototypePollutionConfirmation(ctx context.Context, event SinkEvent) {
	a.probesMutex.RLock()
	defer a.probesMutex.RUnlock()

	canary := event.Value
	probe, ok := a.activeProbes[canary]
	if !ok {
		a.logger.Debug("Prototype Pollution confirmation for unknown canary.", zap.String("canary", canary))
		return
	}
	if probe.Type != schemas.ProbeTypePrototypePollution {
		a.logger.Warn("Prototype Pollution confirmation for non-pollution probe.", zap.String("canary", canary), zap.String("type", string(probe.Type)))
		return
	}

	a.logger.Warn("Vulnerability Confirmed: JavaScript Prototype Pollution!",
		zap.String("source", string(probe.Source)),
		zap.String("canary", canary),
		zap.String("polluted_property", event.Detail),
	)

	finding := CorrelatedFinding{
		TaskID:            a.config.TaskID,
		TargetURL:         a.config.Target.String(),
		Sink:              schemas.SinkPrototypePollution,
		Origin:            probe.Source,
		Value:             probe.Value,
		Canary:            canary,
		Probe:             probe,
		Detail:            fmt.Sprintf("Successfully polluted Object.prototype property: %s", event.Detail),
		IsConfirmed:       true,
		SanitizationLevel: SanitizationNone,
		StackTrace:        event.StackTrace,
	}
	a.reporter.Report(ctx, finding) // <-- Pass context
}

// checkSanitization compares the value seen at the sink with the original probe payload
// to infer if any sanitization or encoding was applied.
func (a *Analyzer) checkSanitization(sinkValue string, probe ActiveProbe) (SanitizationLevel, string) {
	if strings.Contains(sinkValue, probe.Value) {
		return SanitizationNone, ""
	}

	if probe.Type == schemas.ProbeTypeXSS || probe.Type == schemas.ProbeTypeSSTI {
		hasOriginalTags := strings.Contains(probe.Value, "<") || strings.Contains(probe.Value, ">")
		hasSinkTags := strings.Contains(sinkValue, "<") || strings.Contains(sinkValue, ">")
		if hasOriginalTags && !hasSinkTags {
			return SanitizationPartial, " (Potential Sanitization: HTML tags modified or stripped)"
		}

		hasOriginalQuotes := strings.Contains(probe.Value, "\"")
		hasEscapedQuotes := strings.Contains(sinkValue, "\\\"") || strings.Contains(sinkValue, "&#34;")
		if hasOriginalQuotes && hasEscapedQuotes {
			return SanitizationPartial, " (Potential Sanitization: Quotes escaped)"
		}
	}

	return SanitizationPartial, " (Potential Sanitization: Payload modified)"
}

// isContextValid implements the rules engine (ValidTaintFlows) to verify if the flow context is valid.
func (a *Analyzer) isContextValid(event SinkEvent, probe ActiveProbe) bool {
	flow := TaintFlowPath{ProbeType: probe.Type, SinkType: event.Type}

	// Use the analyzer's local, mutex-protected copy of the rules.
	a.rulesMutex.RLock()
	defer a.rulesMutex.RUnlock()

	// 1. Normalize probe types for broader rule matching.
	// SQLi and CmdInjection probes detected via reflection follow XSS rules.
	normalizedProbeType := probe.Type
	probeTypeString := string(probe.Type)

	if strings.Contains(probeTypeString, "SQLi") || strings.Contains(probeTypeString, "CmdInjection") {
		normalizedProbeType = schemas.ProbeTypeXSS
	}

	// Check against the normalized flow path first.
	normalizedFlow := TaintFlowPath{ProbeType: normalizedProbeType, SinkType: event.Type}
	isValid := a.validTaintFlows[normalizedFlow]

	// If the normalized flow is invalid, check the original flow as a fallback (for specific overrides).
	if !isValid && normalizedProbeType != probe.Type {
		isValid = a.validTaintFlows[flow]
	}

	if !isValid {
		return false
	}

	// 2. Apply dynamic logic for ambiguous sinks.

	// Rule: Navigation Sink Protocol Validation
	if (normalizedProbeType == schemas.ProbeTypeXSS || probe.Type == schemas.ProbeTypeDOMClobbering) && event.Type == schemas.SinkNavigation {
		normalizedValue := strings.ToLower(strings.TrimSpace(event.Value))
		// Only consider `javascript:` or `data:` protocols as valid XSS vectors in navigation sinks.
		if strings.HasPrefix(normalizedValue, "javascript:") || strings.HasPrefix(normalizedValue, "data:text/html") {
			return true
		}
		// Suppress if it's a standard URL navigation triggered by the payload.
		return false
	}

	return true
}
