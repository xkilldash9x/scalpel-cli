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

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid" // Added import
)

//go:embed taint_shim.js
var taintShimFS embed.FS

const taintShimFilename = "taint_shim.js"

// Canary format: SCALPEL_{Prefix}_{Type}_{UUID_Short}
var canaryRegex = regexp.MustCompile(`SCALPEL_[A-Z]+_[A-Z_]+_[a-f0-9]{8}`)

// HumanoidProvider defines an interface for duck-typing the SessionContext
// to check if it provides access to the Humanoid controller.
type HumanoidProvider interface {
	GetHumanoid() *humanoid.Humanoid
}

// REFACTOR: Removed BrowserContextProvider interface as GetContext() is deprecated and anti-pattern.

// Analyzer is the central nervous system of the IAST operation. It orchestrates probe
// injection, event collection, and vulnerability correlation.
type Analyzer struct {
	config       Config
	reporter     ResultsReporter
	oastProvider OASTProvider
	logger       *zap.Logger
	shimTemplate *template.Template

	// -- State Management --
	activeProbes map[string]ActiveProbe
	probesMutex  sync.RWMutex // Protects activeProbes. Optimized for many concurrent reads from correlation workers.

	// -- Concurrency Control --
	// The primary communication channel from producers (JS callbacks, OAST poller) to consumers (correlation workers).
	eventsChan chan Event

	// wg tracks the lifecycle of the correlation worker pool.
	wg sync.WaitGroup
	// producersWG tracks the background producer goroutines (probe cleanup, OAST polling).
	producersWG sync.WaitGroup

	// backgroundCtx and backgroundCancel are used to signal a graceful shutdown to the producer goroutines.
	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc
}

// NewAnalyzer initializes the analyzer, applies configuration defaults,
// and prepares the instrumentation shim template.
func NewAnalyzer(config Config, reporter ResultsReporter, oastProvider OASTProvider, logger *zap.Logger) (*Analyzer, error) {
	taskLogger := logger.Named("taint_analyzer").With(zap.String("task_id", config.TaskID))

	tmpl, err := template.ParseFS(taintShimFS, taintShimFilename)
	if err != nil {
		taskLogger.Error("Failed to parse embedded taint shim template.", zap.Error(err))
		return nil, fmt.Errorf("failed to parse embedded shim: %w", err)
	}

	// Apply robust defaults for performance and stability.
	config = applyConfigDefaults(config)

	return &Analyzer{
		config:       config,
		reporter:     reporter,
		oastProvider: oastProvider,
		logger:       taskLogger,
		activeProbes: make(map[string]ActiveProbe),
		eventsChan:   make(chan Event, config.EventChannelBuffer),
		shimTemplate: tmpl,
	}, nil
}

// applyConfigDefaults ensures that critical configuration parameters have sane default values.
func applyConfigDefaults(cfg Config) Config {
	if cfg.EventChannelBuffer == 0 {
		// A larger buffer is a good default for a worker pool model to absorb bursts.
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
		// Default to a small pool of concurrent workers for processing events.
		cfg.CorrelationWorkers = 5
	}
	return cfg
}

// Analyze executes the IAST analysis for a target URL using a provided browser session.
// It orchestrates instrumentation, probing, and the graceful shutdown of background workers.
func (a *Analyzer) Analyze(ctx context.Context, session SessionContext) error {
	a.logger.Info("Starting IAST analysis",
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

	// REFACTOR: We no longer attempt to retrieve BrowserContext via GetContext().
	// The operation context (analysisCtx) will be used for all actions including Humanoid pauses.
	// -----------------------------------------------------------

	if err := a.instrument(analysisCtx, session); err != nil {
		return fmt.Errorf("failed to instrument browser: %w", err)
	}

	// Launch the concurrent machinery: the correlation worker pool and background producers.
	a.startBackgroundWorkers()

	// Execute the attack vectors and user interactions.
	// REFACTOR: Pass Humanoid controller. Removed browser context argument.
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

	a.logger.Info("IAST analysis completed")
	return nil
}

// shutdown handles the ordered, graceful shutdown of all goroutines.
// This ensures that all events are processed and no data is lost.
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
	sinksJSON, err := json.Marshal(a.config.Sinks)
	if err != nil {
		return "", fmt.Errorf("failed to marshal sinks configuration: %w", err)
	}

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

// enqueueEvent provides a safe, non blocking mechanism for sending an event to the correlation engine.
// It handles shutdown signals and channel backpressure gracefully.
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
// If Humanoid is nil, it skips the pause silently.
// REFACTOR: Updated signature and implementation. Now relies only on the operation context (ctx).
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
// REFACTOR: Updated signature to remove BrowserContext. Integrated pauses using operation context.
func (a *Analyzer) executeProbes(ctx context.Context, session SessionContext, h *humanoid.Humanoid) error {

	// REFACTOR: Pause before initial navigation. Use operation context.
	if err := a.executePause(ctx, h, 500, 200); err != nil {
		return err // Return if context cancelled during pause
	}

	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Initial navigation failed, attempting to continue probes.", zap.Error(err))
	}

	// REFACTOR: Pause after initial navigation. Use operation context.
	if err := a.executePause(ctx, h, 800, 300); err != nil {
		return err
	}

	// REFACTOR: Pass Humanoid and context down.
	if err := a.probePersistentSources(ctx, session, h); err != nil {
		// Check if the context was cancelled before logging the error.
		if ctx.Err() == nil {
			a.logger.Error("Error during persistent source probing", zap.Error(err))
		}
	}

	// REFACTOR: Pause between probing phases. Use operation context.
	if err := a.executePause(ctx, h, 400, 150); err != nil {
		return err
	}

	// REFACTOR: Pass Humanoid and context down.
	if err := a.probeURLSources(ctx, session, h); err != nil {
		// Check if the context was cancelled before logging the error.
		if ctx.Err() == nil {
			a.logger.Error("Error during URL source probing", zap.Error(err))
		}
	}

	a.logger.Info("Starting interactive probing phase.")

	// REFACTOR: Pause before starting interaction phase. Use operation context.
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

	// REFACTOR: Pause after interaction phase concludes. Use operation context.
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
// REFACTOR: Updated signature to remove BrowserContext. Integrated pauses using operation context.
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
		// FIX: Generate a unique canary and payload for each storage type to prevent overwrites in the activeProbes map.

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

	// REFACTOR: Pause before executing the injection script. Use operation context.
	if err := a.executePause(ctx, h, 300, 100); err != nil {
		return err
	}

	// FIX: The ExecuteScript function now requires a third 'options' argument. Pass nil.
	if _, err := session.ExecuteScript(ctx, injectionScript, nil); err != nil {
		a.logger.Warn("Failed to inject persistent probes via JavaScript", zap.Error(err))
	}

	a.logger.Debug("Persistent probes injected. Refreshing page.")

	// REFACTOR: Pause before refreshing the page. Use operation context.
	if err := a.executePause(ctx, h, 200, 80); err != nil {
		return err
	}

	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Navigation (refresh) failed after persistent probe injection", zap.Error(err))
		// We don't return the error immediately, allowing the post-navigation pause to occur if possible.
	}

	// REFACTOR: Pause after refresh. Use operation context.
	if err := a.executePause(ctx, h, 700, 300); err != nil {
		return err
	}
	return nil
}

//  injects probes into URL query parameters and the hash fragment.
// REFACTOR: Updated signature to remove BrowserContext. Integrated pauses using operation context.
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

		// REFACTOR: Pause before navigating with query params. Use operation context.
		if err := a.executePause(ctx, h, 400, 150); err != nil {
			return err
		}

		if err := session.Navigate(ctx, targetURL.String()); err != nil {
			a.logger.Warn("Navigation failed during combined URL probing", zap.Error(err))
		}

		// REFACTOR: Pause after navigation. Use operation context.
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

		// REFACTOR: Pause before navigating with hash fragments. Use operation context.
		if err := a.executePause(ctx, h, 400, 150); err != nil {
			return err
		}

		if err := session.Navigate(ctx, targetURL.String()); err != nil {
			a.logger.Warn("Navigation failed during combined Hash probing", zap.Error(err))
		}

		// REFACTOR: Pause after navigation. Use operation context.
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

// correlateWorker is a single worker in the pool. It continuously processes events
// from the events channel until the channel is closed.
func (a *Analyzer) correlateWorker(id int) {
	defer a.wg.Done()
	a.logger.Debug("Correlation worker started.", zap.Int("worker_id", id))

	// This loop will naturally terminate when the `eventsChan` is closed by the shutdown() method.
	for event := range a.eventsChan {
		a.processEvent(event)
	}
	a.logger.Debug("Correlation worker finished.", zap.Int("worker_id", id))
}

// cleanupExpiredProbes is a background goroutine that periodically removes old probes
// from the activeProbes map to prevent unbounded memory growth.
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

// executeCleanup performs the actual work of finding and deleting expired probes.
func (a *Analyzer) executeCleanup() {
	expirationTime := time.Now().Add(-a.config.ProbeExpirationDuration)
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

	// MODIFICATION: Check if oastProvider is nil before accessing it.
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

//  main dispatcher for incoming events. It routes events
// to the appropriate handler based on their type.
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

//  handles confirmed out of band callbacks and reports a finding.
func (a *Analyzer) processOASTInteraction(interaction OASTInteraction) {
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
	if probe.Type == schemas.ProbeTypeXSS || probe.Type == schemas.ProbeTypeSSTI {
		detail = "Blind XSS/SSTI confirmed via OAST callback."
	} else if probe.Type == schemas.ProbeTypeOAST {
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
	a.reporter.Report(finding)
}

// processExecutionProof handles confirmed payload executions and reports a finding.
func (a *Analyzer) processExecutionProof(proof ExecutionProofEvent) {
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
	a.reporter.Report(finding)
}

// processSinkEvent checks a sink event for our canaries and, if found, reports a potential finding.
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

// processPrototypePollutionConfirmation handles the specific confirmation event for Prototype Pollution.
func (a *Analyzer) processPrototypePollutionConfirmation(event SinkEvent) {
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
	a.reporter.Report(finding)
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

// isContextValid implements the rules engine for reducing false positives by checking
// if a detected taint flow from a source to a sink is logical.
func (a *Analyzer) isContextValid(event SinkEvent, probe ActiveProbe) bool {
	flow := TaintFlowPath{ProbeType: probe.Type, SinkType: event.Type}

	// Normalize probe types for broader rule matching.
	probeTypeString := string(probe.Type)
	if strings.Contains(probeTypeString, "XSS") || strings.Contains(probeTypeString, "SQLi") || strings.Contains(probeTypeString, "CmdInjection") {
		flow.ProbeType = schemas.ProbeTypeXSS
	}

	if !ValidTaintFlows[flow] {
		return false
	}

	// Add specific logic for potentially noisy sinks like navigation.
	if (flow.ProbeType == schemas.ProbeTypeXSS || flow.ProbeType == schemas.ProbeTypeDOMClobbering) && event.Type == schemas.SinkNavigation {
		normalizedValue := strings.ToLower(strings.TrimSpace(event.Value))
		// Only consider `javascript:` or `data:` protocols as valid XSS vectors in a navigation sink.
		if strings.HasPrefix(normalizedValue, "javascript:") || strings.HasPrefix(normalizedValue, "data:text/html") {
			return true
		}
		return false
	}

	return true
}