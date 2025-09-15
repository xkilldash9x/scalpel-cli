// internal/analysis/active/taint/analyzer.go
package taint

import (
	// These imports were added to resolve compilation errors.
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

	// All shared data structures are now referenced from the canonical schemas package.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
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
	oastProvider OASTProvider
	logger       *zap.Logger
	activeProbes map[string]ActiveProbe
	probesMutex  sync.RWMex
	eventsChan   chan Event
	wg           sync.WaitGroup
	producersWG  sync.WaitGroup
	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc
	shimTemplate     *template.Template
}

// NewAnalyzer initializes a new analyzer.
func NewAnalyzer(config Config, browser BrowserInteractor, reporter ResultsReporter, oastProvider OASTProvider, logger *zap.Logger) (*Analyzer, error) {
	taskLogger := logger.Named("taint_analyzer").With(zap.String("task_id", config.TaskID))

	tmpl, err := template.ParseFS(taintShimFS, taintShimFilename)
	if err != nil {
		taskLogger.Error("Failed to parse embedded taint shim template.", zap.Error(err))
		return nil, fmt.Errorf("failed to parse embedded shim: %w", err)
	}

	if config.EventChannelBuffer == 0 {
		config.EventChannelBuffer = 500
	}
	if config.FinalizationGracePeriod == 0 {
		config.FinalizationGracePeriod = 10 * time.Second
	}
	if config.ProbeExpirationDuration == 0 {
		config.ProbeExpirationDuration = 10 * time.Minute
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

	a.backgroundCtx, a.backgroundCancel = context.WithCancel(context.Background())

	session, err := a.browser.InitializeSession(analysisCtx)
	if err != nil {
		return fmt.Errorf("failed to initialize browser session: %w", err)
	}
	defer func() {
		if closeErr := session.Close(); closeErr != nil {
			a.logger.Error("Failed to close browser session cleanly", zap.Error(closeErr))
		}
	}()

	if err := a.instrument(analysisCtx, session); err != nil {
		return fmt.Errorf("failed to instrument browser: %w", err)
	}

	a.startBackgroundWorkers()

	if err := a.executeProbes(analysisCtx, session); err != nil {
		a.logger.Error("Error encountered during probing phase", zap.Error(err))
	}

	a.logger.Debug("Probing finished. Waiting for asynchronous events.", zap.Duration("grace_period", a.config.FinalizationGracePeriod))

	select {
	case <-time.After(a.config.FinalizationGracePeriod):
		a.logger.Debug("Grace period concluded.")
	case <-analysisCtx.Done():
		a.logger.Warn("Analysis timeout reached during finalization grace period.")
	}

	a.backgroundCancel()
	a.producersWG.Wait()
	close(a.eventsChan)
	a.wg.Wait()

	a.logger.Info("IAST analysis completed")
	return nil
}

// startBackgroundWorkers launches the necessary background goroutines.
func (a *Analyzer) startBackgroundWorkers() {
	a.wg.Add(1)
	go a.correlate()

	a.producersWG.Add(1)
	go a.cleanupExpiredProbes()

	if a.oastProvider != nil {
		a.producersWG.Add(1)
		go a.pollOASTInteractions()
	}
}

// instrument hooks into the client side.
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

// generateShim creates the javascript instrumentation code.
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

// handleSinkEvent is the callback from the JS shim.
func (a *Analyzer) handleSinkEvent(event SinkEvent) {
	select {
	case <-a.backgroundCtx.Done():
		a.logger.Debug("Dropping sink event during shutdown.", zap.String("sink", string(event.Type)))
		return
	default:
	}

	select {
	case a.eventsChan <- event:
		a.logger.Debug("Sink event received", zap.String("sink", string(event.Type)), zap.String("detail", event.Detail))
	default:
		a.logger.Warn("Event channel full, dropping sink event.", zap.String("sink", string(event.Type)))
	}
}

// handleExecutionProof is the callback when an XSS payload executes.
func (a *Analyzer) handleExecutionProof(event ExecutionProofEvent) {
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
	a.logger.Error("JavaScript Instrumentation Shim Error reported.",
		zap.String("error_message", event.Error),
		zap.String("location", event.Location),
		zap.String("stack_trace", event.StackTrace),
	)
}

// executeProbes orchestrates the probing strategies.
func (a *Analyzer) executeProbes(ctx context.Context, session SessionContext) error {
	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Initial navigation failed, attempting to continue probes.", zap.Error(err))
	}

	if err := a.probePersistentSources(ctx, session); err != nil {
		a.logger.Error("Error during persistent source probing", zap.Error(err))
	}

	if err := a.probeURLSources(ctx, session); err != nil {
		a.logger.Error("Error during URL source probing", zap.Error(err))
	}

	a.logger.Info("Starting interactive probing phase.")
	if err := session.Interact(ctx, a.config.Interaction); err != nil {
		a.logger.Warn("Interactive probing phase encountered errors", zap.Error(err))
	}

	return nil
}

// generateCanary creates a unique canary string.
func (a *Analyzer) generateCanary(prefix string, probeType schemas.ProbeType) string {
	return fmt.Sprintf("SCALPEL_%s_%s_%s", prefix, probeType, uuid.New().String()[:8])
}

// preparePayload replaces placeholders (Canary, OASTServer) in the probe definition.
func (a *Analyzer) preparePayload(probeDef schemas.ProbeDefinition, canary string) string {
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
func (a *Analyzer) probePersistentSources(ctx context.Context, session SessionContext) error {
	a.logger.Debug("Starting persistent source probing (Storage/Cookies).")
	storageKeyPrefix := "sc_store_"
	cookieNamePrefix := "sc_cookie_"
	var injectionScriptBuilder strings.Builder

	secureFlag := ""
	if a.config.Target.Scheme == "https" {
		secureFlag = " Secure;"
	}

	for i, probeDef := range a.config.Probes {
		canary := a.generateCanary("P", probeDef.Type)
		payload := a.preparePayload(probeDef, canary)
		if payload == "" {
			continue
		}

		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			a.logger.Error("Failed to JSON encode payload", zap.Error(err))
			continue
		}
		jsPayload := string(jsonPayload)

		// LocalStorage
		lsKey := fmt.Sprintf("%s%d", storageKeyPrefix, i)
		fmt.Fprintf(&injectionScriptBuilder, "localStorage.setItem(%q, %s);\n", lsKey, jsPayload)
		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       lsKey,
			Value:     payload,
			Canary:    canary,
			Source:    schemas.SourceLocalStorage,
			CreatedAt: time.Now(),
		})

		// SessionStorage
		ssKey := fmt.Sprintf("%s%d_s", storageKeyPrefix, i)
		fmt.Fprintf(&injectionScriptBuilder, "sessionStorage.setItem(%q, %s);\n", ssKey, jsPayload)
		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       ssKey,
			Value:     payload,
			Canary:    canary,
			Source:    schemas.SourceSessionStorage,
			CreatedAt: time.Now(),
		})

		// Cookies
		cookieName := fmt.Sprintf("%s%d", cookieNamePrefix, i)
		cookieCommand := fmt.Sprintf("document.cookie = `${%q}=${encodeURIComponent(%s)}; path=/; max-age=3600; samesite=Lax;%s`;\n", cookieName, jsPayload, secureFlag)
		injectionScriptBuilder.WriteString(cookieCommand)
		a.registerProbe(ActiveProbe{
			Type:      probeDef.Type,
			Key:       cookieName,
			Value:     payload,
			Canary:    canary,
			Source:    schemas.SourceCookie,
			CreatedAt: time.Now(),
		})
	}

	injectionScript := injectionScriptBuilder.String()
	if injectionScript == "" {
		return nil
	}

	if err := session.ExecuteScript(ctx, injectionScript); err != nil {
		a.logger.Warn("Failed to inject persistent probes via JavaScript", zap.Error(err))
	}

	a.logger.Debug("Persistent probes injected. Refreshing page.")
	if err := session.Navigate(ctx, a.config.Target.String()); err != nil {
		a.logger.Warn("Navigation (refresh) failed after persistent probe injection", zap.Error(err))
		return err
	}
	return nil
}

// probeURLSources throws probes into URL query params and the hash.
func (a *Analyzer) probeURLSources(ctx context.Context, session SessionContext) error {
	baseURL := *a.config.Target
	paramPrefix := "sc_test_"

	// Query Parameter Probing
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
		if err := session.Navigate(ctx, targetURL.String()); err != nil {
			a.logger.Warn("Navigation failed during combined URL probing", zap.Error(err))
		}
	}

	// Hash Fragment Probing
	targetURL = baseURL // reset
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

// correlate is the background goroutine where we connect the dots.
func (a *Analyzer) correlate() {
	defer a.wg.Done()
	for event := range a.eventsChan {
		a.processEvent(event)
	}
	a.logger.Debug("Correlation engine finished processing events.")
}

// cleanupExpiredProbes periodically removes old probes.
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

	a.probesMutex.Lock()
	for _, canary := range expiredCanaries {
		delete(a.activeProbes, canary)
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
	}

	for _, interaction := range interactions {
		select {
		case <-a.backgroundCtx.Done():
			a.logger.Debug("Dropping OAST interaction during shutdown.", zap.String("canary", interaction.Canary))
			return
		default:
		}
		select {
		case a.eventsChan <- interaction:
		default:
			a.logger.Warn("Event channel full, dropping OAST interaction.")
		}
	}
}

// processEvent handles incoming events from the channel.
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

// processOASTInteraction handles confirmed out of band callbacks.
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
		SanitizationLevel: schemas.SanitizationNone,
		StackTrace:        "N/A (Out of Band)",
		OASTDetails:       &interaction,
	}
	a.reporter.Report(finding)
}

// processExecutionProof handles confirmed executions.
func (a *Analyzer) processExecutionProof(proof ExecutionProofEvent) {
	a.probesMutex.RLock()
	probe, ok := a.activeProbes[proof.Canary]
	a.probesMutex.RUnlock()

	if !ok {
		a.logger.Debug("Execution proof received for unknown or expired canary.", zap.String("canary", proof.Canary))
		return
	}

	switch probe.Type {
	case schemas.ProbeTypeXSS, schemas.ProbeTypeSSTI, schemas.ProbeTypeSQLi, schemas.ProbeTypeCmdInjection, schemas.ProbeTypeDOMClobbering:
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
		SanitizationLevel: schemas.SanitizationNone,
		StackTrace:        proof.StackTrace,
	}
	a.reporter.Report(finding)
}

// processSinkEvent checks a sink event for our canaries.
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

// processPrototypePollutionConfirmation handles the specific confirmation event.
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
		SanitizationLevel: schemas.SanitizationNone,
		StackTrace:        event.StackTrace,
	}
	a.reporter.Report(finding)
}

// TaintFlowPath defines a specific taint flow path.
type TaintFlowPath struct {
	ProbeType schemas.ProbeType
	SinkType  schemas.TaintSink
}

// ValidTaintFlows defines the set of acceptable source-to-sink paths.
var ValidTaintFlows = map[TaintFlowPath]bool{
	{schemas.ProbeTypeXSS, schemas.SinkEval}:                true,
	{schemas.ProbeTypeXSS, schemas.SinkInnerHTML}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkOuterHTML}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkDocumentWrite}:       true,
	{schemas.ProbeTypeXSS, schemas.SinkIframeSrcDoc}:        true,
	{schemas.ProbeTypeXSS, schemas.SinkFunctionConstructor}: true,
	{schemas.ProbeTypeXSS, schemas.SinkScriptSrc}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkIframeSrc}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkNavigation}:          true,
	{schemas.ProbeTypeXSS, schemas.SinkPostMessage}:         true,
	{schemas.ProbeTypeXSS, schemas.SinkWorkerPostMessage}:   true,

	{schemas.ProbeTypeDOMClobbering, schemas.SinkEval}:      true,
	{schemas.ProbeTypeDOMClobbering, schemas.SinkInnerHTML}: true,
	{schemas.ProbeTypeDOMClobbering, schemas.SinkNavigation}:true,

	{schemas.ProbeTypeSSTI, schemas.SinkEval}:                true,
	{schemas.ProbeTypeSSTI, schemas.SinkInnerHTML}:           true,
	{schemas.ProbeTypeSSTI, schemas.SinkOuterHTML}:           true,
	{schemas.ProbeTypeSSTI, schemas.SinkDocumentWrite}:       true,
	{schemas.ProbeTypeSSTI, schemas.SinkIframeSrcDoc}:        true,
	{schemas.ProbeTypeSSTI, schemas.SinkFunctionConstructor}: true,

	{schemas.ProbeTypeSQLi, schemas.SinkInnerHTML}:         true,
	{schemas.ProbeTypeCmdInjection, schemas.SinkInnerHTML}: true,

	{schemas.ProbeTypeGeneric, schemas.SinkWebSocketSend}:      true,
	{schemas.ProbeTypeGeneric, schemas.SinkXMLHTTPRequest}:     true,
	{schemas.ProbeTypeGeneric, schemas.SinkXMLHTTPRequest_URL}: true,
	{schemas.ProbeTypeGeneric, schemas.SinkFetch}:              true,
	{schemas.ProbeTypeGeneric, schemas.SinkFetch_URL}:          true,
	{schemas.ProbeTypeGeneric, schemas.SinkNavigation}:         true,
	{schemas.ProbeTypeGeneric, schemas.SinkSendBeacon}:         true,
	{schemas.ProbeTypeGeneric, schemas.SinkWorkerSrc}:          true,

	{schemas.ProbeTypeOAST, schemas.SinkWebSocketSend}:      true,
	{schemas.ProbeTypeOAST, schemas.SinkXMLHTTPRequest}:     true,
	{schemas.ProbeTypeOAST, schemas.SinkXMLHTTPRequest_URL}: true,
	{schemas.ProbeTypeOAST, schemas.SinkFetch}:              true,
	{schemas.ProbeTypeOAST, schemas.SinkFetch_URL}:          true,
	{schemas.ProbeTypeOAST, schemas.SinkNavigation}:         true,
	{schemas.ProbeTypeOAST, schemas.SinkSendBeacon}:         true,
	{schemas.ProbeTypeOAST, schemas.SinkWorkerSrc}:          true,
}

// checkSanitization compares the sink value with the original probe payload.
func (a *Analyzer) checkSanitization(sinkValue string, probe ActiveProbe) (schemas.SanitizationLevel, string) {
	if strings.Contains(sinkValue, probe.Value) {
		return schemas.SanitizationNone, ""
	}

	if probe.Type == schemas.ProbeTypeXSS || probe.Type == schemas.ProbeTypeSSTI {
		if !strings.Contains(sinkValue, "<") && !strings.Contains(sinkValue, ">") && (strings.Contains(probe.Value, "<") || strings.Contains(probe.Value, ">")) {
			return schemas.SanitizationPartial, " (Potential Sanitization: HTML tags modified or stripped)"
		}
		if (strings.Contains(sinkValue, "\\\"") || strings.Contains(sinkValue, "&#34;")) && !strings.Contains(probe.Value, "\\\"") && !strings.Contains(probe.Value, "&#34;") {
			return schemas.SanitizationPartial, " (Potential Sanitization: Quotes escaped)"
		}
	}

	return schemas.SanitizationPartial, " (Potential Sanitization: Payload modified)"
}

// isContextValid implements the rules engine for reducing false positives.
func (a *Analyzer) isContextValid(event SinkEvent, probe ActiveProbe) bool {
	flow := TaintFlowPath{ProbeType: probe.Type, SinkType: event.Type}

	probeTypeString := string(probe.Type)
	if strings.Contains(probeTypeString, "XSS") || strings.Contains(probeTypeString, "SQLi") || strings.Contains(probeTypeString, "CmdInjection") {
		flow.ProbeType = schemas.ProbeTypeXSS
	}

	if !ValidTaintFlows[flow] {
		return false
	}

	if (flow.ProbeType == schemas.ProbeTypeXSS || flow.ProbeType == schemas.ProbeTypeDOMClobbering) && event.Type == schemas.SinkNavigation {
		normalizedValue := strings.ToLower(strings.TrimSpace(event.Value))
		if strings.HasPrefix(normalizedValue, "javascript:") || strings.HasPrefix(normalizedValue, "data:text/html") {
			return true
		}
		return false
	}

	return true
}
