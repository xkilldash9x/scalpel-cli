// internal/analysis/active/taint/analyzer.go
package taint

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

//go:embed taint_shim.js
var taintShimFS embed.FS

const taintShimFilename = "taint_shim.js"

// Canary format: SCALPEL_{Prefix}_{Type}_{UUID_Short}
var canaryRegex = regexp.MustCompile(`SCALPEL_[A-Z]+_[A-Z_]+_[a-f0-9]{8}`)

// Analyzer is the brains of the whole IAST operation.
type Analyzer struct {
	config       Config
	browser      BrowserInteractor
	reporter     ResultsReporter
	// OAST Integration
	oastProvider OASTProvider
	logger       *zap.Logger

	// Maps Canary string -> ActiveProbe
	activeProbes map[string]ActiveProbe
	probesMutex  sync.RWMutex

	// Channel for SinkEvents, ExecutionProofEvents, ShimErrorEvents, and OASTInteractions.
	eventsChan chan Event

	// wg tracks the correlation engine (consumer).
	wg sync.WaitGroup
	// producersWG tracks background tasks that produce events (OAST, Cleanup).
	producersWG sync.WaitGroup

	// Context and cancel function for background tasks.
	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc

	shimTemplate *template.Template
}

// NewAnalyzer initializes a new analyzer.
// MODULARITY: Accepts configuration directly. OASTProvider is optional.
func NewAnalyzer(config Config, browser BrowserInteractor, reporter ResultsReporter, oastProvider OASTProvider, logger *zap.Logger) (*Analyzer, error) {
	// Add TaskID to the logger context for structured logging.
	taskLogger := logger.Named("taint_analyzer").With(zap.String("task_id", config.TaskID))

	// Initialize the template from the embedded file system
	tmpl, err := template.ParseFS(taintShimFS, taintShimFilename)
	if err != nil {
		taskLogger.Error("Failed to parse embedded taint shim template.", zap.Error(err))
		return nil, fmt.Errorf("failed to parse embedded shim: %w", err)
	}

	// Set defaults for robustness/performance settings if not provided.
	if config.EventChannelBuffer == 0 {
		config.EventChannelBuffer = 500 // Increased buffer for high traffic sites.
	}
	if config.FinalizationGracePeriod == 0 {
		config.FinalizationGracePeriod = 10 * time.Second
	}
	if config.ProbeExpirationDuration == 0 {
		config.ProbeExpirationDuration = 10 * time.Minute // Default expiration for SPA environments.
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Minute
	}
	if config.OASTPollingInterval == 0 {
		config.OASTPollingInterval = 20 * time.Second
	}

	return &Analyzer{
		config:       config,
		browser:      browser,
		reporter:     reporter,
		oastProvider: oastProvider,
		logger:       taskLogger,
		activeProbes: make(map[string]ActiveProbe),
		eventsChan:   make(chan Event, config.EventChannelBuffer),
		shimTemplate: tmpl,
	}, nil
}

// Analyze kicks off the analysis for a given target.
func (a *Analyzer) Analyze(ctx context.Context) error {
	a.logger.Info("Starting IAST analysis", zap.String("target", a.config.Target.String()))

	analysisCtx, cancel := context.WithTimeout(ctx, a.config.AnalysisTimeout)
	defer cancel()

	// Initialize context for background tasks (correlation, cleanup, OAST).
	// We use context.Background() as the parent so background tasks can continue finalizing even if analysisCtx times out.
	a.backgroundCtx, a.backgroundCancel = context.WithCancel(context.Background())

	// 1. Initialize browser session.
	session, err := a.browser.InitializeSession(analysisCtx)
	if err != nil {
		return fmt.Errorf("failed to initialize browser session: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			a.logger.Error("Failed to close browser session cleanly", zap.Error(closeErr))
		}
	}()

	// 2. Instrument the browser.
	if err := a.instrument(analysisCtx, session); err != nil {
		return fmt.Errorf("failed to instrument browser: %w", err)
	}

	// 3. Start background workers.
	a.startBackgroundWorkers()

	// 4. Execute probes.
	if err := a.executeProbes(analysisCtx, session); err != nil {
		// Log the error but continue to finalize the analysis.
		a.logger.Error("Error encountered during probing phase", zap.Error(err))
	}

	// 5. Finalization and Shutdown Synchronization.
	a.logger.Debug("Probing finished. Waiting for asynchronous events.", zap.Duration("grace_period", a.config.FinalizationGracePeriod))

	// Wait for the grace period, or until the analysis context times out (if timeout is shorter than grace period).
	select {
	case <-time.After(a.config.FinalizationGracePeriod):
		a.logger.Debug("Grace period concluded.")
	case <-analysisCtx.Done():
		a.logger.Warn("Analysis timeout reached during finalization grace period.")
	}

	// Signal background workers (producers) to stop their main loops.
	a.backgroundCancel()

	// Wait for background producers to finish their final cycles (e.g., final OAST poll).
	a.producersWG.Wait()

	// Now that all producers are done, safely close the events channel.
	close(a.eventsChan)

	// Wait for the correlation engine (consumer) to finish processing the channel.
	a.wg.Wait()

	a.logger.Info("IAST analysis completed")
	return nil
}


// startBackgroundWorkers launches the necessary background goroutines.
func (a *Analyzer) startBackgroundWorkers() {
	// Correlation Engine (Consumer)
	a.wg.Add(1)
	go a.correlate()

	// Probe Expiration Cleaner (Producer)
	a.producersWG.Add(1)
	go a.cleanupExpiredProbes()

	// OAST Poller (Producer)
	if a.oastProvider != nil {
		a.producersWG.Add(1)
		go a.pollOASTInteractions()
	}
}


// instrument hooks into the client side.
func (a *Analyzer) instrument(ctx context.Context, session SessionContext) error {
	// 1. Expose Go functions to the browser's JS world.

	// Taint flow callback
	if err := session.ExposeFunction(ctx, JSCallbackSinkEvent, a.handleSinkEvent); err != nil {
		return fmt.Errorf("failed to expose sink event callback: %w", err)
	}

	// Execution proof callback
	if err := session.ExposeFunction(ctx, JSCallbackExecutionProof, a.handleExecutionProof); err != nil {
		return fmt.Errorf("failed to expose execution proof callback: %w", err)
	}

	// ROBUSTNESS: Shim error callback
	if err := session.ExposeFunction(ctx, JSCallbackShimError, a.handleShimError); err != nil {
		return fmt.Errorf("failed to expose shim error callback: %w", err)
	}

	// 2. Generate JS shim.
	shim, err := a.generateShim()
	if err != nil {
		return fmt.Errorf("failed to generate instrumentation shim: %w", err)
	}

	// 3. Inject shim persistently. This should also apply to Workers and Shadow DOM if the driver supports it.
	if err := session.InjectScriptPersistently(ctx, shim); err != nil {
		return fmt.Errorf("failed to inject instrumentation shim: %w", err)
	}

	return nil
}

// generateShim creates the javascript instrumentation code.
func (a *Analyzer) generateShim() (string, error) {
	sinksJSON, err := json.Marshal(a.config.Sinks)
	if err != nil {
		return "", fmt.Errorf("failed to marshal sinks configuration: %w", err)
	}

	// Data structure for the template execution.
	data := struct {
		SinksJSON         string
		SinkCallbackName  string
		ProofCallbackName string
		ErrorCallbackName string
	}{
		SinksJSON:         string(sinksJSON),
		SinkCallbackName:  JSCallbackSinkEvent,
		ProofCallbackName: JSCallbackExecutionProof,
		ErrorCallbackName: JSCallbackShimError,
	}

	var buf bytes.Buffer
	if err := a.shimTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute shim template: %w", err)
	}

	return buf.String(), nil
}

// -- Callbacks Handlers (Browser -> Go) --

// handleSinkEvent is the callback from the JS shim.
func (a *Analyzer) handleSinkEvent(event SinkEvent) {
	// Check if analysis is finalizing before attempting to send.
	select {
	case <-a.backgroundCtx.Done():
		// Context is cancelled, system is shutting down. Drop event.
		a.logger.Debug("Dropping sink event during shutdown.", zap.String("sink", string(event.Type)))
		return
	default:
		// Proceed as normal.
	}

	select {
	case a.eventsChan <- event:
		a.logger.Debug("Sink event received", zap.String("sink", string(event.Type)), zap.String("detail", event.Detail))
	default:
		// Non blocking send; drop if the buffer is full to prioritize performance.
		a.logger.Warn("Event channel full, dropping sink event.", zap.String("sink", string(event.Type)))
	}
}

// handleExecutionProof is the callback when an XSS payload executes.
func (a *Analyzer) handleExecutionProof(event ExecutionProofEvent) {
	// Check if analysis is finalizing before attempting to send.
	select {
	case <-a.backgroundCtx.Done():
		a.logger.Debug("Dropping execution proof during shutdown.", zap.String("canary", event.Canary))
		return
	default:
	}

	select {
	case a.eventsChan <- event:
		a.logger.Info("Execution proof received!", zap.String("canary", event.Canary))
	default:
		a.logger.Warn("Event channel full, dropping execution proof.")
	}
}


// handleShimError is the callback for internal errors within the JavaScript instrumentation.
func (a *Analyzer) handleShimError(event ShimErrorEvent) {
	// These errors are important for debugging the IAST tool itself or identifying compatibility issues.
	a.logger.Error("JavaScript Instrumentation Shim Error reported.",
		zap.String("error_message", event.Error),
		zap.String("location", event.Location),
		zap.String("stack_trace", event.StackTrace),
	)
	// We do not send this to the correlation engine.
}

// -- Probing Strategies --

// executeProbes orchestrates the probing strategies.
func (a *Analyzer) executeProbes(ctx context.Context, session SessionContext) error {

	// Ensure we are at the target origin for storage/cookie injection.
	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Initial navigation failed, attempting to continue probes.", zap.Error(err))
	}

	// Strategy 1: Persistent sources (Cookies, Storage).
	if err := a.probePersistentSources(ctx, session); err != nil {
		a.logger.Error("Error during persistent source probing", zap.Error(err))
	}

	// Strategy 2: URL sources (Params, Hash).
	if err := a.probeURLSources(ctx, session); err != nil {
		a.logger.Error("Error during URL source probing", zap.Error(err))
	}

	// Strategy 3: Interactive probing (Crawling and Form Filling).
	a.logger.Info("Starting interactive probing phase.")
	if err := session.Interact(ctx, a.config.Interaction); err != nil {
		// Interaction errors (e.g., navigation timeouts during crawling) are common and non fatal.
		a.logger.Warn("Interactive probing phase encountered errors", zap.Error(err))
	}

	return nil
}

// generateCanary creates a unique canary string.
func (a *Analyzer) generateCanary(prefix string, probeType ProbeType) string {
	// Format: SCALPEL_{Prefix}_{Type}_{UUID_Short}
	return fmt.Sprintf("SCALPEL_%s_%s_%s", prefix, probeType, uuid.New().String()[:8])
}

// preparePayload replaces placeholders (Canary, OASTServer) in the probe definition.
func (a *Analyzer) preparePayload(probeDef ProbeDefinition, canary string) string {
	// Check if OAST replacement is needed and valid before starting replacements.
	requiresOAST := strings.Contains(probeDef.Payload, "{{.OASTServer}}")
	if requiresOAST && a.oastProvider == nil {
		a.logger.Warn("OAST probe defined but no OAST provider configured. Skipping probe.", zap.String("canary", canary))
		return ""
	}

	// Efficiently replace placeholders using strings.NewReplacer
	replacements := []string{"{{.Canary}}", canary}

	if requiresOAST {
		oastURL := a.oastProvider.GetServerURL()
		replacements = append(replacements, "{{.OASTServer}}", oastURL)
	}

	replacer := strings.NewReplacer(replacements...)
	return replacer.Replace(probeDef.Payload)
}


// probePersistentSources injects probes into Cookies, LocalStorage, and SessionStorage.
func (a *Analyzer) probePersistentSources(ctx context.Context, session SessionContext) error {
	a.logger.Debug("Starting persistent source probing (Storage/Cookies).")

	storageKeyPrefix := "sc_store_"
	cookieNamePrefix := "sc_cookie_"

	var injectionScriptBuilder strings.Builder

	// Determine if 'Secure' flag should be used for cookies.
	secureFlag := ""
	if a.config.Target.Scheme == "https" {
		secureFlag = " Secure;"
	}

	for i, probeDef := range a.config.Probes {
		canary := a.generateCanary("P", probeDef.Type)
		payload := a.preparePayload(probeDef, canary)

		// If payload is empty, it means an OAST probe was skipped.
		if payload == "" {
			continue
		}

		// JSON encode the payload for safe injection via JavaScript execution context
		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			a.logger.Error("Failed to JSON encode payload", zap.Error(err))
			continue
		}
		jsPayload := string(jsonPayload)

		// 1. LocalStorage
		lsKey := fmt.Sprintf("%s%d", storageKeyPrefix, i)
		fmt.Fprintf(&injectionScriptBuilder, "localStorage.setItem(%q, %s);\n", lsKey, jsPayload)
		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       lsKey,
			Value:     payload,
			Canary:    canary,
			Source:    SourceLocalStorage,
			CreatedAt: time.Now(),
		})

		// 2. SessionStorage
		ssKey := fmt.Sprintf("%s%d_s", storageKeyPrefix, i)
		fmt.Fprintf(&injectionScriptBuilder, "sessionStorage.setItem(%q, %s);\n", ssKey, jsPayload)
		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       ssKey,
			Value:     payload,
			Canary:    canary,
			Source:    SourceSessionStorage,
			CreatedAt: time.Now(),
		})

		// 3. Cookies
		cookieName := fmt.Sprintf("%s%d", cookieNamePrefix, i)
		// Set cookie via JS. Ensure SameSite=Lax.
		cookieCommand := fmt.Sprintf("document.cookie = `${%q}=${encodeURIComponent(%s)}; path=/; max-age=3600; samesite=Lax;%s`;\n", cookieName, jsPayload, secureFlag)
		injectionScriptBuilder.WriteString(cookieCommand)

		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       cookieName,
			Value:     payload,
			Canary:    canary,
			Source:    SourceCookie,
			CreatedAt: time.Now(),
		})
	}

	injectionScript := injectionScriptBuilder.String()
	if injectionScript == "" {
		return nil
	}

	// Execute the injection script
	if err := session.ExecuteScript(ctx, injectionScript); err != nil {
		a.logger.Warn("Failed to inject persistent probes via JavaScript", zap.Error(err))
	}

	a.logger.Debug("Persistent probes injected. Refreshing page.")

	// Refresh the page for the application to process the injected data.
	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Navigation (refresh) failed after persistent probe injection", zap.Error(err))
		return err
	}

	return nil
}


// probeURLSources throws probes into URL query params and the hash.
func (a *Analyzer) probeURLSources(ctx context.Context, session SessionContext) error {
	// Clone the base URL to avoid modifying the original config.
	baseURL := *a.config.Target
	paramPrefix := "sc_test_"

	// -- Injection Point 1: Combined Query Parameter Probing --
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

		q.Set(paramName, payload) // Query parameters are automatically encoded

		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       paramName,
			Value:     payload,
			Canary:    canary,
			Source:    SourceURLParam,
			CreatedAt: time.Now(),
		})
		probesInjected++
	}

	if probesInjected > 0 {
		targetURL.RawQuery = q.Encode()

		a.logger.Debug("Navigating with combined URL parameter probes", zap.Int("probe_count", probesInjected))
		if err := session.Navigate(ctx, targetURL.String()); err != nil {
			a.logger.Warn("Navigation failed during combined URL probing", zap.Error(err))
		}
	}

	// -- Injection Point 2: Combined Hash Fragment Probing --
	targetURL = baseURL // reset
	var hashFragments []string
	probesInjected = 0

	for i, probeDef := range a.config.Probes {
		// generate NEW canaries for the hash injection
		canary := a.generateCanary("H", probeDef.Type)
		payload := a.preparePayload(probeDef, canary)

		if payload == "" {
			continue
		}

		paramName := fmt.Sprintf("%s%d", paramPrefix, i)

		// CRITICAL: Payloads MUST be URL encoded when placed in the fragment.
		hashFragments = append(hashFragments, fmt.Sprintf("%s=%s", paramName, url.QueryEscape(payload)))

		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       paramName,
			Value:     payload,
			Canary:    canary,
			Source:    SourceHashFragment,
			CreatedAt: time.Now(),
		})
		probesInjected++
	}

	if probesInjected > 0 {
		// Combine fragments (SPAs often use '&' as a delimiter)
		targetURL.Fragment = strings.Join(hashFragments, "&")

		a.logger.Debug("Navigating with combined Hash fragment probes", zap.Int("probe_count", probesInjected))
		if err := session.Navigate(ctx, targetURL.String()); err != nil {
			a.logger.Warn("Navigation failed during combined Hash probing", zap.Error(err))
		}
	}

	return nil
}

// registerProbe adds a probe to our tracking map.
func (a *Analyzer) registerProbe(probe ActiveProbe) {
	a.probesMutex.Lock()
	defer a.probesMutex.Unlock()
	a.activeProbes[probe.Canary] = probe
}

// -- Background Workers --

// correlate is the background goroutine where we connect the dots.
func (a *Analyzer) correlate() {
	// Signal the WaitGroup when this function finishes.
	defer a.wg.Done()

	// Range over the channel. This loop will terminate automatically when eventsChan is closed by Analyze().
	for event := range a.eventsChan {
		a.processEvent(event)
	}

	a.logger.Debug("Correlation engine finished processing events.")
}

// cleanupExpiredProbes periodically removes old probes to manage state in SPAs.
func (a *Analyzer) cleanupExpiredProbes() {
	defer a.producersWG.Done()
	ticker := time.NewTicker(a.config.CleanupInterval)
	defer ticker.Stop()

	a.logger.Debug("Probe expiration cleanup routine started.", zap.Duration("interval", a.config.CleanupInterval), zap.Duration("expiration", a.config.ProbeExpirationDuration))

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

func (a *Analyzer) executeCleanup() {
	// 1. Identify expired probes under a Read Lock.
	expirationTime := time.Now().Add(-a.config.ProbeExpirationDuration)
	var expiredCanaries []string

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

	// 2. Acquire Write Lock and delete the identified probes.
	a.probesMutex.Lock()
	for _, canary := range expiredCanaries {
		// Re-check existence in case state changed, although less critical for cleanup.
		if _, exists := a.activeProbes[canary]; exists {
			delete(a.activeProbes, canary)
		}
	}
	a.probesMutex.Unlock()

	a.logger.Debug("Cleaned up expired probes.", zap.Int("count", len(expiredCanaries)))
}


// pollOASTInteractions periodically checks the OAST provider for callbacks.
func (a *Analyzer) pollOASTInteractions() {
	defer a.producersWG.Done()
	ticker := time.NewTicker(a.config.OASTPollingInterval)
	defer ticker.Stop()

	a.logger.Debug("OAST polling routine started.", zap.Duration("interval", a.config.OASTPollingInterval))

	for {
		select {
		case <-a.backgroundCtx.Done():
			a.logger.Debug("OAST polling routine shutting down. Performing final check.")
			// Perform one last check before exiting to catch late interactions.
			a.fetchAndEnqueueOAST()
			return
		case <-ticker.C:
			a.fetchAndEnqueueOAST()
		}
	}
}

// fetchAndEnqueueOAST retrieves OAST interactions and sends them to the correlation engine.
func (a *Analyzer) fetchAndEnqueueOAST() {
	// 1. Get the list of active canaries relevant to OAST.
	a.probesMutex.RLock()
	var relevantCanaries []string
	oastServerURL := a.oastProvider.GetServerURL()

	for canary, probe := range a.activeProbes {
		// We are interested if the probe type is OAST, or if it's an XSS/SSTI/etc probe that included an OAST payload.
		if probe.Type == ProbeTypeOAST || strings.Contains(probe.Value, oastServerURL) {
			relevantCanaries = append(relevantCanaries, canary)
		}
	}
	a.probesMutex.RUnlock()

	if len(relevantCanaries) == 0 {
		return
	}

	// 2. Fetch interactions from the provider.
	// Use a separate context with a timeout for the API call.
	fetchCtx, cancel := context.WithTimeout(context.Background(), a.config.OASTPollingInterval)
	defer cancel()

	interactions, err := a.oastProvider.GetInteractions(fetchCtx, relevantCanaries)
	if err != nil {
		a.logger.Error("Failed to fetch OAST interactions.", zap.Error(err))
		return
	}

	if len(interactions) > 0 {
		a.logger.Info("OAST Interactions detected!", zap.Int("count", len(interactions)))
	}

	// 3. Enqueue interactions for correlation.
	for _, interaction := range interactions {
		// Check context before sending to avoid panics on closed channels.
		select {
		case <-a.backgroundCtx.Done():
			a.logger.Debug("Dropping OAST interaction during shutdown.", zap.String("canary", interaction.Canary))
			return // Stop trying to send if shutdown has started.
		default:
		}

		select {
		case a.eventsChan <- interaction:
		default:
			a.logger.Warn("Event channel full, dropping OAST interaction.")
		}
	}
}

// -- Event Processing --

// processEvent handles incoming events from the channel.
func (a *Analyzer) processEvent(event Event) {
	switch e := event.(type) {
	case SinkEvent:
		a.processSinkEvent(e)
	case ExecutionProofEvent:
		a.processExecutionProof(e)
	case OASTInteraction:
		a.processOASTInteraction(e)
	// ShimErrorEvent is handled in the callback directly, not here.
	default:
		a.logger.Warn("Received unknown event type in correlation engine", zap.Any("event", event))
	}
}


// processOASTInteraction handles confirmed out of band callbacks. This is high confidence.
func (a *Analyzer) processOASTInteraction(interaction OASTInteraction) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[interaction.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		// This might happen if the probe just expired but the OAST interaction was delayed.
		a.logger.Debug("OAST interaction received for unknown or expired canary.", zap.String("canary", interaction.Canary))
		return
	}

	a.logger.Warn("Vulnerability Confirmed via OAST Interaction!",
		zap.String("source", string(probe.Source)),
		zap.String("type", string(probe.Type)),
		zap.String("canary", interaction.Canary),
		zap.String("protocol", interaction.Protocol),
		zap.String("source_ip", interaction.SourceIP),
	)

	// Determine the detail message based on the probe type.
	detail := fmt.Sprintf("Out of Band interaction confirmed via %s protocol.", interaction.Protocol)
	if probe.Type == ProbeTypeXSS || probe.Type == ProbeTypeSSTI {
		detail = "Blind XSS/SSTI confirmed via OAST callback."
	} else if probe.Type == ProbeTypeOAST {
		detail = "Blind vulnerability (e.g., SSRF, RCE) confirmed via OAST callback."
	}

	// Report the finding immediately.
	finding := CorrelatedFinding{
		TaskID:            a.config.TaskID,
		TargetURL:         a.config.Target.String(),
		Sink:              SinkOASTInteraction,
		Origin:            probe.Source,
		Value:             probe.Value, // The original payload value.
		Canary:            interaction.Canary,
		Probe:             probe,
		Detail:            detail,
		IsConfirmed:       true,
		SanitizationLevel: SanitizationNone, // OAST confirms execution/network access.
		StackTrace:        "N/A (Out of Band)",
		OASTDetails:       &interaction,
	}
	a.reporter.Report(finding)
}

// processExecutionProof handles confirmed executions (e.g., alert/callback). This is high confidence.
func (a *Analyzer) processExecutionProof(proof ExecutionProofEvent) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[proof.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		a.logger.Debug("Execution proof received for unknown or expired canary.", zap.String("canary", proof.Canary))
		return
	}

	// Ensure the probe type is one that expects execution.
	switch probe.Type {
	case ProbeTypeXSS, ProbeTypeSSTI, ProbeTypeSQLi, ProbeTypeCmdInjection, ProbeTypeDOMClobbering:
		// Valid execution types.
	default:
		a.logger.Debug("Execution proof received for unexpected probe type.", zap.String("canary", proof.Canary), zap.String("type", string(probe.Type)))
		return
	}

	a.logger.Warn("Vulnerability Confirmed via Execution Proof!",
		zap.String("source", string(probe.Source)),
		zap.String("type", string(probe.Type)),
		zap.String("canary", proof.Canary),
	)

	// Report the finding immediately.
	finding := CorrelatedFinding{
		TaskID:            a.config.TaskID,
		TargetURL:         a.config.Target.String(),
		Sink:              SinkExecution,
		Origin:            probe.Source,
		Value:             probe.Value, // The original payload value.
		Canary:            proof.Canary,
		Probe:             probe,
		Detail:            "Payload execution confirmed via JS callback.",
		IsConfirmed:       true,
		SanitizationLevel: SanitizationNone, // Execution implies no effective sanitization.
		StackTrace:        proof.StackTrace,
	}
	a.reporter.Report(finding)
}

// processSinkEvent checks a sink event to see if it matches one of our canaries.
func (a *Analyzer) processSinkEvent(event SinkEvent) {
	// Handle Prototype Pollution Confirmation separately as it's a unique sink type.
	if event.Type == SinkPrototypePollution {
		a.processPrototypePollutionConfirmation(event)
		return
	}

	// Optimization: Use regex to find specific canaries before locking.
	potentialCanaries := canaryRegex.FindAllString(event.Value, -1)
	if len(potentialCanaries) == 0 {
		return
	}

	// Acquire lock only to check the map and collect matches.
	a.probesMutex.RLock()
	matchedProbes := make(map[string]ActiveProbe)
	for _, canary := range potentialCanaries {
		if probe, ok := a.activeProbes[canary]; ok {
			matchedProbes[canary] = probe
		}
	}
	a.probesMutex.RUnlock() // Release lock before processing.

	// Process the findings outside the lock.
	for canary, probe := range matchedProbes {
		a.logger.Info("Taint flow detected!",
			zap.String("source", string(probe.Source)),
			zap.String("sink", string(event.Type)),
			zap.String("canary", canary),
			zap.String("detail", event.Detail))

		if a.isContextValid(event, probe) {
			// SANITIZATION AWARENESS: Check if the payload was modified.
			sanitizationLevel, detailSuffix := a.checkSanitization(event.Value, probe)

			// Determine confirmation status. Sink events are suspicious but not definitive proof.
			isConfirmed := false

			finding := CorrelatedFinding{
				TaskID:            a.config.TaskID,
				TargetURL:         a.config.Target.String(),
				Sink:              event.Type,
				Origin:            probe.Source,
				Value:             event.Value,
				Canary:            canary,
				Probe:             probe,
				Detail:            event.Detail + detailSuffix,
				IsConfirmed:       isConfirmed,
				SanitizationLevel: sanitizationLevel,
				StackTrace:        event.StackTrace,
			}
			a.reporter.Report(finding)
		} else {
			a.logger.Debug("Context mismatch: Taint flow suppressed (False Positive).",
				zap.String("canary", canary),
				zap.String("probe_type", string(probe.Type)),
				zap.String("sink_type", string(event.Type)),
			)
		}
	}
}


// processPrototypePollutionConfirmation handles the specific event when the JS shim confirms Object.prototype was polluted.
func (a *Analyzer) processPrototypePollutionConfirmation(event SinkEvent) {
	a.probesMutex.RLock()
	defer a.probesMutex.RUnlock()

	// The 'Value' field in this specific event contains the Canary that successfully polluted the prototype.
	canary := event.Value

	probe, ok := a.activeProbes[canary]
	if !ok {
		a.logger.Debug("Prototype Pollution confirmation received for unknown or expired canary.", zap.String("canary", canary))
		return
	}

	if probe.Type != ProbeTypePrototypePollution {
		a.logger.Warn("Prototype Pollution confirmation received for non pollution probe type.", zap.String("canary", canary), zap.String("type", string(probe.Type)))
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
		Sink:              SinkPrototypePollution,
		Origin:            probe.Source,
		Value:             probe.Value, // The payload used for pollution.
		Canary:            canary,
		Probe:             probe,
		Detail:            fmt.Sprintf("Successfully polluted Object.prototype property: %s", event.Detail),
		IsConfirmed:       true,
		SanitizationLevel: SanitizationNone,
		StackTrace:        event.StackTrace,
	}
	a.reporter.Report(finding)
}

// -- Validation and False Positive Reduction --
// Define a key representing a specific taint flow path.
type TaintFlowPath struct {
	ProbeType ProbeType
	SinkType  TaintSink
}

// ValidTaintFlows defines the set of acceptable source-to-sink paths.
var ValidTaintFlows = map[TaintFlowPath]bool{
	// Rule 1: XSS (Examples)
	{ProbeTypeXSS, SinkEval}:              true,
	{ProbeTypeXSS, SinkInnerHTML}:         true,
	{ProbeTypeXSS, SinkOuterHTML}:         true,
	{ProbeTypeXSS, SinkDocumentWrite}:     true,
	{ProbeTypeXSS, SinkIframeSrcDoc}:      true,
	{ProbeTypeXSS, SinkFunctionConstructor}: true,
	{ProbeTypeXSS, SinkScriptSrc}:         true,
	{ProbeTypeXSS, SinkIframeSrc}:         true,
	{ProbeTypeXSS, SinkNavigation}:        true, // Requires exceptional handling
	{ProbeTypeXSS, SinkPostMessage}:       true,
	{ProbeTypeXSS, SinkWorkerPostMessage}: true,

	// DOM Clobbering can lead to XSS sinks
	{ProbeTypeDOMClobbering, SinkEval}:              true,
	{ProbeTypeDOMClobbering, SinkInnerHTML}:         true,
	{ProbeTypeDOMClobbering, SinkNavigation}:        true,

	// SSTI leading to client-side execution
	{ProbeTypeSSTI, SinkEval}:              true,
	{ProbeTypeSSTI, SinkInnerHTML}:         true,
	{ProbeTypeSSTI, SinkOuterHTML}:         true,
	{ProbeTypeSSTI, SinkDocumentWrite}:     true,
	{ProbeTypeSSTI, SinkIframeSrcDoc}:      true,
	{ProbeTypeSSTI, SinkFunctionConstructor}: true,

	// Backend injections reflecting as XSS
	{ProbeTypeSQLi, SinkInnerHTML}:         true,
	{ProbeTypeCmdInjection, SinkInnerHTML}: true,

	// Rule 3: Generic/OAST Probes for Data Leakage
	{ProbeTypeGeneric, SinkWebSocketSend}:      true,
	{ProbeTypeGeneric, SinkXMLHTTPRequest}:     true,
	{ProbeTypeGeneric, SinkXMLHTTPRequest_URL}: true,
	{ProbeTypeGeneric, SinkFetch}:              true,
	{ProbeTypeGeneric, SinkFetch_URL}:          true,
	{ProbeTypeGeneric, SinkNavigation}:         true,
	{ProbeTypeGeneric, SinkSendBeacon}:         true,
	{ProbeTypeGeneric, SinkWorkerSrc}:          true,

	{ProbeTypeOAST, SinkWebSocketSend}:      true,
	{ProbeTypeOAST, SinkXMLHTTPRequest}:     true,
	{ProbeTypeOAST, SinkXMLHTTPRequest_URL}: true,
	{ProbeTypeOAST, SinkFetch}:              true,
	{ProbeTypeOAST, SinkFetch_URL}:          true,
	{ProbeTypeOAST, SinkNavigation}:         true,
	{ProbeTypeOAST, SinkSendBeacon}:         true,
	{ProbeTypeOAST, SinkWorkerSrc}:          true,
}


// checkSanitization compares the value that reached the sink with the original probe payload.
// It detects if critical parts of the payload were stripped or encoded.
func (a *Analyzer) checkSanitization(sinkValue string, probe ActiveProbe) (SanitizationLevel, string) {
	// If the original payload is found exactly within the sink value, there was no effective sanitization.
	if strings.Contains(sinkValue, probe.Value) {
		return SanitizationNone, ""
	}

	// If we are here, the canary was found (checked in processSinkEvent), but the full payload was not.
	// This indicates partial sanitization.

	// Example advanced check for XSS probes:
	if probe.Type == ProbeTypeXSS || probe.Type == ProbeTypeSSTI {
		// Check if HTML tags seem to be encoded or stripped.
		if !strings.Contains(sinkValue, "<") && !strings.Contains(sinkValue, ">") && (strings.Contains(probe.Value, "<") || strings.Contains(probe.Value, ">")) {
			return SanitizationPartial, " (Potential Sanitization: HTML tags modified or stripped)"
		}
		// Check if quotes seem to be escaped (basic heuristic).
		if (strings.Contains(sinkValue, "\\\"") || strings.Contains(sinkValue, "&#34;")) && !strings.Contains(probe.Value, "\\\"") && !strings.Contains(probe.Value, "&#34;") {
			return SanitizationPartial, " (Potential Sanitization: Quotes escaped)"
		}
	}

	return SanitizationPartial, " (Potential Sanitization: Payload modified)"
}

// isContextValid implements the rules engine for reducing false positives.
func (a *Analyzer) isContextValid(event SinkEvent, probe ActiveProbe) bool {
	flow := TaintFlowPath{ProbeType: probe.Type, SinkType: event.Type}

	// Handle probes that can manifest as XSS (e.g., Reflected SQLi)
	probeTypeString := string(probe.Type)
	if strings.Contains(probeTypeString, "XSS") || strings.Contains(probeTypeString, "SQLi") || strings.Contains(probeTypeString, "CmdInjection") {
		flow.ProbeType = ProbeTypeXSS // Treat as XSS for validation purposes
	}

	// Check the declarative rules map.
	if !ValidTaintFlows[flow] {
		return false
	}

	// Handle specific condition-based exceptions that cannot be declared statically.

	// Exception 1: Navigation sinks require specific protocols for XSS/Clobbering.
	if (flow.ProbeType == ProbeTypeXSS || flow.ProbeType == ProbeTypeDOMClobbering) && event.Type == SinkNavigation {
		normalizedValue := strings.ToLower(strings.TrimSpace(event.Value))
		if strings.HasPrefix(normalizedValue, "javascript:") || strings.HasPrefix(normalizedValue, "data:text/html") {
			return true
		}
		return false
	}

	// If no exceptions apply, the flow is valid.
	return true
}
