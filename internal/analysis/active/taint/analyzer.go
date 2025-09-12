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
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

//go:embed taint_shim.js
var taintShimFS embed.FS

const taintShimFilename = "taint_shim.js"

// Canary format: SCALPEL_{Prefix}_{Type}_{UUID_Short}
var canaryRegex = regexp.MustCompile(`SCALPEL_[A-Z_]+_[A-Z_]+_[a-f0-9]{8}`)

// Define JS callback names as constants for consistency.
const (
	JSCallbackSinkEvent      = "scalpel_sink_event"
	JSCallbackExecutionProof = "scalpel_execution_proof"
	JSCallbackShimError      = "scalpel_shim_error"
)

// -- Interfaces (Decoupling from concrete implementations) --

// BrowserInteractor defines the interface for managing browser sessions.
type BrowserInteractor interface {
	InitializeSession(ctx context.Context) (SessionContext, error)
}

// SessionContext defines the interface for interacting with a specific browser tab/page.
type SessionContext interface {
	Navigate(ctx context.Context, url string) error
	Interact(ctx context.Context, config schemas.InteractionConfig) error
	ExposeFunction(ctx context.Context, name string, function interface{}) error
	InjectScriptPersistently(ctx context.Context, script string) error
	ExecuteScript(ctx context.Context, script string) error
	Close() error
}

// ResultsReporter defines the interface for reporting findings.
type ResultsReporter interface {
	Report(finding CorrelatedFinding)
}

// OASTProvider defines the interface for Out-of-Band Application Security Testing services.
type OASTProvider interface {
	GetServerURL() string
	GetInteractions(ctx context.Context, canaries []string) ([]OASTInteraction, error)
}

// Analyzer is the brains of the whole IAST operation.
type Analyzer struct {
	config         Config
	browser        BrowserInteractor
	reporter       ResultsReporter
	oastProvider   OASTProvider // OAST Integration
	logger         *zap.Logger

	activeProbes map[string]ActiveProbe // Maps Canary string -> ActiveProbe
	probesMutex  sync.RWMutex

	eventsChan chan Event // Channel for all event types.

	wg          sync.WaitGroup // wg tracks the correlation engine (consumer).
	producersWG sync.WaitGroup // producersWG tracks background tasks that produce events (OAST, Cleanup).

	backgroundCtx    context.Context    // Context and cancel function for background tasks.
	backgroundCancel context.CancelFunc

	shimTemplate *template.Template
}

// NewAnalyzer initializes a new analyzer.
func NewAnalyzer(config Config, browser BrowserInteractor, reporter ResultsReporter, oastProvider OASTProvider, logger *zap.Logger) (*Analyzer, error) {
	// Add TaskID to the logger context for structured logging.
	taskLogger := logger.Named("taint_analyzer").With(zap.String("task_id", config.TaskID))

	// Initialize the template from the embedded file system.
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
		a.backgroundCancel() // Ensure background context is cancelled if session init fails.
		return fmt.Errorf("failed to initialize browser session: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			a.logger.Error("Failed to close browser session cleanly", zap.Error(closeErr))
		}
	}()

	// 2. Instrument the browser.
	if err := a.instrument(analysisCtx, session); err != nil {
		a.backgroundCancel()
		return fmt.Errorf("failed to instrument browser: %w", err)
	}

	// 3. Start background workers.
	a.startBackgroundWorkers()

	// 4. Execute probes.
	if err := a.executeProbes(analysisCtx, session); err != nil {
		// Log the error but continue to finalize the analysis.
		// Check if the context was cancelled, which is expected during shutdown or timeout.
		if analysisCtx.Err() == nil {
			a.logger.Error("Error encountered during probing phase", zap.Error(err))
		}
	}

	// 5. Finalization and Shutdown Synchronization.
	a.logger.Debug("Probing finished. Waiting for asynchronous events.", zap.Duration("grace_period", a.config.FinalizationGracePeriod))

	// Wait for the grace period, or until the analysis context times out.
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

// instrument hooks into the client side by exposing Go functions and injecting the JS shim.
func (a *Analyzer) instrument(ctx context.Context, session SessionContext) error {
	// 1. Expose Go functions to the browser's JS world.
	if err := session.ExposeFunction(ctx, JSCallbackSinkEvent, a.handleSinkEvent); err != nil {
		return fmt.Errorf("failed to expose sink event callback: %w", err)
	}
	if err := session.ExposeFunction(ctx, JSCallbackExecutionProof, a.handleExecutionProof); err != nil {
		return fmt.Errorf("failed to expose execution proof callback: %w", err)
	}
	if err := session.ExposeFunction(ctx, JSCallbackShimError, a.handleShimError); err != nil {
		return fmt.Errorf("failed to expose shim error callback: %w", err)
	}

	// 2. Generate JS shim from the template.
	shim, err := a.generateShim()
	if err != nil {
		return fmt.Errorf("failed to generate instrumentation shim: %w", err)
	}

	// 3. Inject shim persistently.
	if err := session.InjectScriptPersistently(ctx, shim); err != nil {
		return fmt.Errorf("failed to inject instrumentation shim: %w", err)
	}

	return nil
}

// generateShim creates the javascript instrumentation code from the embedded template.
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

// handleSinkEvent is the callback from the JS shim for a detected taint flow.
func (a *Analyzer) handleSinkEvent(event SinkEvent) {
	// Non-blocking send to the events channel.
	select {
	case <-a.backgroundCtx.Done():
		a.logger.Debug("Dropping sink event during shutdown.", zap.String("sink", string(event.Type)))
		return
	case a.eventsChan <- event:
		a.logger.Debug("Sink event received", zap.String("sink", string(event.Type)), zap.String("detail", event.Detail))
	default:
		a.logger.Warn("Event channel full, dropping sink event.", zap.String("sink", string(event.Type)))
	}
}

// handleExecutionProof is the callback when an XSS payload successfully executes.
func (a *Analyzer) handleExecutionProof(event ExecutionProofEvent) {
	// Non-blocking send to the events channel.
	select {
	case <-a.backgroundCtx.Done():
		a.logger.Debug("Dropping execution proof during shutdown.", zap.String("canary", event.Canary))
		return
	case a.eventsChan <- event:
		a.logger.Info("Execution proof received!", zap.String("canary", event.Canary))
	default:
		a.logger.Warn("Event channel full, dropping execution proof.")
	}
}

// handleShimError is the callback for internal errors within the JavaScript instrumentation.
func (a *Analyzer) handleShimError(event ShimErrorEvent) {
	// These errors are for debugging the IAST tool itself.
	a.logger.Error("JavaScript Instrumentation Shim Error reported.",
		zap.String("error_message", event.Error),
		zap.String("location", event.Location),
		zap.String("stack_trace", event.StackTrace),
	)
}

// -- Probing Strategies --

// executeProbes orchestrates the different probing strategies.
func (a *Analyzer) executeProbes(ctx context.Context, session SessionContext) error {
	// Ensure we are at the target origin for storage/cookie injection.
	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Initial navigation failed, attempting to continue probes.", zap.Error(err))
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	// Strategy 1: Persistent sources (Cookies, Storage).
	if err := a.probePersistentSources(ctx, session); err != nil {
		a.logger.Error("Error during persistent source probing", zap.Error(err))
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	// Strategy 2: URL sources (Params, Hash). This involves a navigation.
	if err := a.probeURLSources(ctx, session); err != nil {
		a.logger.Error("Error during URL source probing", zap.Error(err))
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	// Strategy 3: Interactive probing (Crawling and Form Filling).
	a.logger.Info("Starting interactive probing phase.")
	if err := session.Interact(ctx, a.config.Interaction); err != nil {
		if ctx.Err() == nil {
			a.logger.Warn("Interactive probing phase encountered errors", zap.Error(err))
		}
	}

	return nil
}

// generateCanary creates a unique canary string with a specific prefix and type.
func (a *Analyzer) generateCanary(prefix string, probeType schemas.ProbeType) string {
	// Format: SCALPEL_{Prefix}_{Type}_{UUID_Short}
	return fmt.Sprintf("SCALPEL_%s_%s_%s", prefix, probeType, uuid.New().String()[:8])
}

// preparePayload replaces placeholders (Canary, OASTServer) in a probe definition.
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

	return strings.NewReplacer(replacements...).Replace(probeDef.Payload)
}

// probePersistentSources injects probes into Cookies, LocalStorage, and SessionStorage.
func (a *Analyzer) probePersistentSources(ctx context.Context, session SessionContext) error {
	a.logger.Debug("Starting persistent source probing (Storage/Cookies).")

	var injectionScriptBuilder strings.Builder
	secureFlag := ""
	if a.config.Target.Scheme == "https" {
		secureFlag = " Secure;"
	}

	for i, probeDef := range a.config.Probes {
		// 1. LocalStorage
		lsCanary := a.generateCanary("P_LS", probeDef.Type)
		lsPayload := a.preparePayload(probeDef, lsCanary)
		if lsPayload != "" {
			lsKey := fmt.Sprintf("sc_store_%d", i)
			fmt.Fprintf(&injectionScriptBuilder, "try{localStorage.setItem(%q,%q);}catch(e){}\n", lsKey, lsPayload)
			a.registerProbe(ActiveProbe{
				Type:      probeDef.Type,
				Key:       lsKey,
				Value:     lsPayload,
				Canary:    lsCanary,
				Source:    schemas.SourceLocalStorage,
				CreatedAt: time.Now(),
			})
		}

		// 2. SessionStorage
		ssCanary := a.generateCanary("P_SS", probeDef.Type)
		ssPayload := a.preparePayload(probeDef, ssCanary)
		if ssPayload != "" {
			ssKey := fmt.Sprintf("sc_store_%d_s", i)
			fmt.Fprintf(&injectionScriptBuilder, "try{sessionStorage.setItem(%q,%q);}catch(e){}\n", ssKey, ssPayload)
			a.registerProbe(ActiveProbe{
				Type:      probeDef.Type,
				Key:       ssKey,
				Value:     ssPayload,
				Canary:    ssCanary,
				Source:    schemas.SourceSessionStorage,
				CreatedAt: time.Now(),
			})
		}

		// 3. Cookies
		cCanary := a.generateCanary("P_C", probeDef.Type)
		cPayload := a.preparePayload(probeDef, cCanary)
		if cPayload != "" {
			cKey := fmt.Sprintf("sc_cookie_%d", i)
			cookieCmd := fmt.Sprintf("document.cookie=`${%q}=${encodeURIComponent(%q)};path=/;max-age=3600;samesite=Lax;%s`", cKey, cPayload, secureFlag)
			fmt.Fprintf(&injectionScriptBuilder, "try{%s}catch(e){}\n", cookieCmd)
			a.registerProbe(ActiveProbe{
				Type:      probeDef.Type,
				Key:       cKey,
				Value:     cPayload,
				Canary:    cCanary,
				Source:    schemas.SourceCookie,
				CreatedAt: time.Now(),
			})
		}
	}

	// Execute the combined injection script.
	if injectionScript := injectionScriptBuilder.String(); injectionScript != "" {
		if err := session.ExecuteScript(ctx, injectionScript); err != nil {
			a.logger.Warn("Failed to inject persistent probes via JavaScript", zap.Error(err))
		}

		// Refresh the page for the application to process the injected data.
		a.logger.Debug("Persistent probes injected. Refreshing page.")
		if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
			a.logger.Warn("Navigation (refresh) failed after persistent probe injection", zap.Error(err))
			return err
		}
	}

	return nil
}

// probeURLSources injects probes into URL parameters and the hash, then navigates once.
func (a *Analyzer) probeURLSources(ctx context.Context, session SessionContext) error {
	a.logger.Debug("Starting URL source probing (Params/Hash).")
	targetURL := *a.config.Target // Create a mutable copy.

	// 1. Prepare URL Parameters
	queryParams := targetURL.Query()
	for i, probeDef := range a.config.Probes {
		canary := a.generateCanary("U_P", probeDef.Type)
		payload := a.preparePayload(probeDef, canary)
		if payload != "" {
			paramKey := fmt.Sprintf("sc_param_%d", i)
			queryParams.Add(paramKey, payload)
			a.registerProbe(ActiveProbe{
				Type:      probeDef.Type,
				Key:       paramKey,
				Value:     payload,
				Canary:    canary,
				Source:    schemas.SourceURLParam,
				CreatedAt: time.Now(),
			})
		}
	}
	targetURL.RawQuery = queryParams.Encode()

	// 2. Prepare URL Hash (Fragment)
	var hashBuilder strings.Builder
	for i, probeDef := range a.config.Probes {
		canary := a.generateCanary("U_H", probeDef.Type)
		payload := a.preparePayload(probeDef, canary)
		if payload != "" {
			hashKey := fmt.Sprintf("sc_hash_%d", i)
			fmt.Fprintf(&hashBuilder, "%s=%s&", hashKey, url.QueryEscape(payload))
			a.registerProbe(ActiveProbe{
				Type:      probeDef.Type,
				Key:       hashKey,
				Value:     payload,
				Canary:    canary,
				Source:    schemas.SourceHashFragment,
				CreatedAt: time.Now(),
			})
		}
	}
	if hashStr := strings.TrimSuffix(hashBuilder.String(), "&"); hashStr != "" {
		targetURL.Fragment = hashStr
	}

	// 3. Navigate to the single, combined URL.
	a.logger.Debug("Navigating with combined URL probes.", zap.String("url", targetURL.String()))
	if err := session.Navigate(ctx, targetURL.String()); err != nil {
		a.logger.Warn("Navigation failed during combined URL probing.", zap.Error(err))
		return err
	}

	return nil
}

// registerProbe adds a probe to the active tracking map with logging.
func (a *Analyzer) registerProbe(probe ActiveProbe) {
	a.probesMutex.Lock()
	defer a.probesMutex.Unlock()
	a.activeProbes[probe.Canary] = probe
	a.logger.Debug("Registered active probe", zap.String("canary", probe.Canary), zap.String("source", string(probe.Source)))
}

// -- Background Workers --

// correlate is the background goroutine where we connect the dots.
func (a *Analyzer) correlate() {
	defer a.wg.Done()
	a.logger.Debug("Correlation engine started.")
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

	a.logger.Debug("Probe expiration cleanup routine started.", zap.Duration("interval", a.config.CleanupInterval))
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
	expirationTime := time.Now().Add(-a.config.ProbeExpirationDuration)
	var expiredCanaries []string

	a.probesMutex.RLock()
	for canary, probe := range a.activeProbes {
		if probe.CreatedAt.Before(expirationTime) {
			expiredCanaries = append(expiredCanaries, canary)
		}
	}
	a.probesMutex.RUnlock()

	if len(expiredCanaries) > 0 {
		a.probesMutex.Lock()
		for _, canary := range expiredCanaries {
			delete(a.activeProbes, canary)
		}
		a.probesMutex.Unlock()
		a.logger.Debug("Cleaned up expired probes.", zap.Int("count", len(expiredCanaries)))
	}
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

	fetchCtx, cancel := context.WithTimeout(context.Background(), a.config.OASTPollingInterval)
	defer cancel()

	interactions, err := a.oastProvider.GetInteractions(fetchCtx, relevantCanaries)
	if err != nil {
		a.logger.Error("Failed to fetch OAST interactions.", zap.Error(err))
		return
	}

	if len(interactions) > 0 {
		a.logger.Info("OAST Interactions detected!", zap.Int("count", len(interactions)))
		for _, interaction := range interactions {
			select {
			case <-a.backgroundCtx.Done():
				a.logger.Debug("Dropping OAST interaction during shutdown.", zap.String("canary", interaction.Canary))
				return
			case a.eventsChan <- interaction:
			default:
				a.logger.Warn("Event channel full, dropping OAST interaction.")
			}
		}
	}
}

// -- Event Processing --

// processEvent handles incoming events from the channel by type.
func (a *Analyzer) processEvent(event Event) {
	switch e := event.(type) {
	case SinkEvent:
		a.processSinkEvent(e)
	case ExecutionProofEvent:
		a.processExecutionProof(e)
	case OASTInteraction:
		a.processOASTInteraction(e)
	default:
		a.logger.Warn("Received unknown event type in correlation engine", zap.Any("event", event))
	}
}

// processOASTInteraction handles confirmed out-of-band callbacks. This is high confidence.
func (a *Analyzer) processOASTInteraction(interaction OASTInteraction) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[interaction.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		a.logger.Debug("OAST interaction for unknown/expired canary.", zap.String("canary", interaction.Canary))
		return
	}

	a.logger.Warn("Vulnerability Confirmed via OAST Interaction!",
		zap.String("source", string(probe.Source)),
		zap.String("type", string(probe.Type)),
		zap.String("canary", interaction.Canary),
	)

	detail := fmt.Sprintf("Out-of-band interaction confirmed via %s protocol.", interaction.Protocol)
	if probe.Type == schemas.ProbeTypeXSS || probe.Type == schemas.ProbeTypeSSTI {
		detail = "Blind XSS/SSTI confirmed via OAST callback."
	} else if probe.Type == schemas.ProbeTypeOAST {
		detail = "Blind vulnerability (e.g., SSRF, RCE) confirmed via OAST callback."
	}

	a.reporter.Report(CorrelatedFinding{
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
	})
}

// processExecutionProof handles confirmed executions (e.g., alert/callback). This is high confidence.
func (a *Analyzer) processExecutionProof(proof ExecutionProofEvent) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[proof.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		a.logger.Debug("Execution proof for unknown/expired canary.", zap.String("canary", proof.Canary))
		return
	}

	switch probe.Type {
	case schemas.ProbeTypeXSS, schemas.ProbeTypeSSTI, schemas.ProbeTypeDOMClobbering: // Only applicable types
	default:
		a.logger.Debug("Execution proof for unexpected probe type.", zap.String("canary", proof.Canary), zap.String("type", string(probe.Type)))
		return
	}

	a.logger.Warn("Vulnerability Confirmed via Execution Proof!",
		zap.String("source", string(probe.Source)),
		zap.String("type", string(probe.Type)),
		zap.String("canary", proof.Canary),
	)

	a.reporter.Report(CorrelatedFinding{
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
	})
}

// processSinkEvent checks a sink event to see if it matches one of our canaries.
func (a *Analyzer) processSinkEvent(event SinkEvent) {
	if event.Type == schemas.SinkPrototypePollution {
		a.processPrototypePollutionConfirmation(event)
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
			a.reporter.Report(CorrelatedFinding{
				TaskID:            a.config.TaskID,
				TargetURL:         a.config.Target.String(),
				Sink:              event.Type,
				Origin:            probe.Source,
				Value:             event.Value,
				Canary:            canary,
				Probe:             probe,
				Detail:            event.Detail + detailSuffix,
				IsConfirmed:       false, // Sink events are suspicious, not confirmed.
				SanitizationLevel: sanitizationLevel,
				StackTrace:        event.StackTrace,
			})
		} else {
			a.logger.Debug("Context mismatch: Taint flow suppressed (False Positive).",
				zap.String("canary", canary),
				zap.String("probe_type", string(probe.Type)),
				zap.String("sink_type", string(event.Type)),
			)
		}
	}
}

// processPrototypePollutionConfirmation handles the specific event for confirmed prototype pollution.
func (a *Analyzer) processPrototypePollutionConfirmation(event SinkEvent) {
	canary := event.Value // The canary is in the 'Value' field for this event.

	a.probesMutex.RLock()
	probe, ok := a.activeProbes[canary]
	a.probesMutex.RUnlock()

	if !ok {
		a.logger.Debug("Prototype Pollution confirmation for unknown/expired canary.", zap.String("canary", canary))
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

	a.reporter.Report(CorrelatedFinding{
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
	})
}

// -- Validation and False Positive Reduction --

type TaintFlowPath struct {
	ProbeType schemas.ProbeType
	SinkType  schemas.TaintSink
}

var ValidTaintFlows = map[TaintFlowPath]bool{
	// XSS Probes
	{schemas.ProbeTypeXSS, schemas.SinkEval}:                true,
	{schemas.ProbeTypeXSS, schemas.SinkInnerHTML}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkOuterHTML}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkDocumentWrite}:       true,
	{schemas.ProbeTypeXSS, schemas.SinkIframeSrcDoc}:        true,
	{schemas.ProbeTypeXSS, schemas.SinkFunctionConstructor}: true,
	{schemas.ProbeTypeXSS, schemas.SinkScriptSrc}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkNavigation}:          true, // Requires special handling

	// DOM Clobbering Probes
	{schemas.ProbeTypeDOMClobbering, schemas.SinkEval}:      true,
	{schemas.ProbeTypeDOMClobbering, schemas.SinkInnerHTML}: true,
	{schemas.ProbeTypeDOMClobbering, schemas.SinkNavigation}:true,

	// SSTI Probes (can result in client-side execution)
	{schemas.ProbeTypeSSTI, schemas.SinkEval}:         true,
	{schemas.ProbeTypeSSTI, schemas.SinkInnerHTML}:    true,
	{schemas.ProbeTypeSSTI, schemas.SinkOuterHTML}:    true,
	{schemas.ProbeTypeSSTI, schemas.SinkDocumentWrite}:true,

	// Data Leakage Probes (Generic & OAST)
	{schemas.ProbeTypeGeneric, schemas.SinkWebSocketSend}:    true,
	{schemas.ProbeTypeGeneric, schemas.SinkXMLHTTPRequest}:   true,
	{schemas.ProbeTypeGeneric, schemas.SinkFetch_URL}:        true,
	{schemas.ProbeTypeGeneric, schemas.SinkNavigation}:       true,
	{schemas.ProbeTypeOAST, schemas.SinkWebSocketSend}:       true,
	{schemas.ProbeTypeOAST, schemas.SinkXMLHTTPRequest_URL}:  true,
	{schemas.ProbeTypeOAST, schemas.SinkFetch}:               true,
	{schemas.ProbeTypeOAST, schemas.SinkNavigation}:          true,
}

// checkSanitization compares the value that reached the sink with the original probe payload.
func (a *Analyzer) checkSanitization(sinkValue string, probe ActiveProbe) (SanitizationLevel, string) {
	// First, check for specific evidence of sanitization.
	if probe.Type == schemas.ProbeTypeXSS || probe.Type == schemas.ProbeTypeSSTI {
		hasOriginalQuotes := strings.Contains(probe.Value, `"`)
		hasEscapedQuotes := strings.Contains(sinkValue, `\"`) || strings.Contains(sinkValue, "&#34;")
		if hasEscapedQuotes && !hasOriginalQuotes {
			return SanitizationPartial, " (Potential Sanitization: Quotes escaped)"
		}

		hasOriginalTags := strings.ContainsAny(probe.Value, "<>")
		hasSinkTags := strings.ContainsAny(sinkValue, "<>")
		if hasOriginalTags && !hasSinkTags {
			return SanitizationPartial, " (Potential Sanitization: HTML tags modified or stripped)"
		}
	}

	// If no specific sanitization was detected, check if the original payload is still perfectly intact.
	if strings.Contains(sinkValue, probe.Value) {
		return SanitizationNone, ""
	}

	// Otherwise, the payload was modified in some other way.
	return SanitizationPartial, " (Potential Sanitization: Payload modified)"
}

// isContextValid implements the rules engine for reducing false positives.
func (a *Analyzer) isContextValid(event SinkEvent, probe ActiveProbe) bool {
	flow := TaintFlowPath{ProbeType: probe.Type, SinkType: event.Type}

	// Normalize probe types that can manifest as XSS for validation purposes.
	switch probe.Type {
	case schemas.ProbeTypeXSS, schemas.ProbeTypeSQLi, schemas.ProbeTypeCmdInjection, schemas.ProbeTypeSSTI:
		flow.ProbeType = schemas.ProbeTypeXSS
	}

	// Check the declarative rules map.
	if !ValidTaintFlows[flow] {
		return false
	}

	// Handle specific condition-based exceptions.
	// Exception: Navigation sinks are only dangerous for XSS with specific protocols.
	if (flow.ProbeType == schemas.ProbeTypeXSS || flow.ProbeType == schemas.ProbeTypeDOMClobbering) && event.Type == schemas.SinkNavigation {
		normalizedValue := strings.ToLower(strings.TrimSpace(event.Value))
		if strings.HasPrefix(normalizedValue, "javascript:") || strings.HasPrefix(normalizedValue, "data:text/html") {
			return true
		}
		return false
	}

	return true
}