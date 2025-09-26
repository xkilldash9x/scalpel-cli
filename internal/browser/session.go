package browser

import (
	"context"
	"encoding/json"
	"errors" // Import added
	"fmt"
	"math/rand"
	"reflect"
	"runtime/debug"
	"strings" // FIX: Added strings import for error message checks
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/playwright-community/playwright-go"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// Session represents a single, isolated browser context and its primary page.
// It implements both schemas.SessionContext and humanoid.Controller.
type Session struct {
	id      string
	ctx     context.Context    // Context derived from the request/task, controls session lifecycle.
	cancel  context.CancelFunc // Cancels the session context.
	logger  *zap.Logger
	cfg     *config.Config
	persona schemas.Persona

	// Playwright specific components
	pwContext playwright.BrowserContext
	page      playwright.Page

	harvester  *Harvester
	interactor *Interactor

	// Humanoid components
	humanoidCtrl humanoid.Controller // The high level humanoid controller.
	humanoidCfg  *humanoid.Config    // Configuration for human like behavior.

	findingsChan chan<- schemas.Finding

	onClose func()
	closeOnce sync.Once
}

// Ensure Session implements the required interfaces.
var _ schemas.SessionContext = (*Session)(nil)
var _ humanoid.Controller = (*Session)(nil)

// NewSession creates the structure for a new browser session. Initialization happens in Initialize().
func NewSession(
	parentCtx context.Context,
	cfg *config.Config,
	persona schemas.Persona,
	logger *zap.Logger,
	findingsChan chan<- schemas.Finding,
) (*Session, error) {
	sessionID := uuid.New().String()
	log := logger.With(zap.String("session_id", sessionID))

	// Create a context specific to this session, linked to the parent context.
	ctx, cancel := context.WithCancel(parentCtx)

	s := &Session{
		id:           sessionID,
		ctx:          ctx,
		cancel:       cancel,
		logger:       log,
		cfg:          cfg,
		persona:      persona,
		findingsChan: findingsChan,
	}

	// Configure humanoid behavior if enabled.
	var hCfg *humanoid.Config
	if cfg.Browser.Humanoid.Enabled {
		// Create a copy of the config for this session persona initialization.
		cfgCopy := cfg.Browser.Humanoid
		hCfg = &cfgCopy
		s.humanoidCfg = hCfg
	}

	// Define the stabilization function used by the interactor.
	stabilizeFn := func(ctx context.Context) error {
		quietPeriod := 1500 * time.Millisecond // Default stabilization time.
		if s.cfg.Network.PostLoadWait > 0 {
			quietPeriod = s.cfg.Network.PostLoadWait
		}
		// Delegating to the session's internal stabilize function, which uses the Harvester.
		return s.stabilize(ctx, quietPeriod)
	}

	// Initialize the interactor. Page is set later.
	s.interactor = NewInteractor(log, hCfg, stabilizeFn)

	return s, nil
}

// Initialize creates the Playwright BrowserContext and Page, applies configurations, and starts monitoring.
func (s *Session) Initialize(ctx context.Context, browser playwright.Browser, taintTemplate, taintConfig string) error {
	s.logger.Debug("Initializing session.")

	// 1. Prepare BrowserContext options.
	options := s.prepareContextOptions()

	// 2. Create the isolated BrowserContext.
	// NewContext relies on implicit browser context and does not take a context.
	pwContext, err := browser.NewContext(options)
	if err != nil {
		return fmt.Errorf("failed to create new browser context: %w", err)
	}
	s.pwContext = pwContext

	// Set default timeouts.
	s.configureTimeouts()

	// 3. Apply advanced stealth evasions (JS injection).
	if err := stealth.ApplyEvasions(s.pwContext, s.persona, s.logger); err != nil {
		s.logger.Warn("Failed to apply advanced stealth evasions (non critical).", zap.Error(err))
	}
	// 4. Initialize IAST Shim if enabled.
	if s.cfg.IAST.Enabled {
		if err := s.initializeIAST(ctx, taintTemplate, taintConfig); err != nil {
			return fmt.Errorf("failed to initialize IAST shim: %w", err)
		}
	}

	// 5. Create the main Page within the context.
	// NewPage relies on context from pwContext and does not take a context.
	page, err := pwContext.NewPage()
	if err != nil {
		return fmt.Errorf("failed to create new page: %w", err)
	}
	s.page = page
	s.interactor.SetPage(page) // Link the page to the interactor.

	// 6. Initialize the Humanoid Controller if configured.
	if s.humanoidCfg != nil {
		// Create the adapter which implements the humanoid.Executor interface using this session.
		executorAdapter := NewPlaywrightExecutorAdapter(s)
		// Initialize the humanoid controller with the configuration and the adapter.
		s.humanoidCtrl = humanoid.New(*s.humanoidCfg, s.logger.Named("humanoid"), executorAdapter)
	}

	// 7. Initialize the Harvester.
	s.harvester = NewHarvester(s.ctx, s.logger, s.cfg.Network.CaptureResponseBodies)
	s.harvester.Start(page)

	return nil
}

// configureTimeouts sets Playwright specific timeouts based on the global config.
func (s *Session) configureTimeouts() {
	navTimeoutMs := float64(s.cfg.Network.NavigationTimeout.Milliseconds())
	if navTimeoutMs <= 0 {
		navTimeoutMs = 60000 // Default 60s if not specified
	}
	s.pwContext.SetDefaultNavigationTimeout(navTimeoutMs)
	// Crucial: Set default timeout for actions (clicks, evaluations) as they don't take context arguments.
	s.pwContext.SetDefaultTimeout(navTimeoutMs + 5000)
}

// prepareContextOptions sets up the Playwright options based on the configuration and persona.
func (s *Session) prepareContextOptions() playwright.BrowserNewContextOptions {
	options := playwright.BrowserNewContextOptions{
		UserAgent:         playwright.String(s.persona.UserAgent),
		IgnoreHttpsErrors: playwright.Bool(s.cfg.Browser.IgnoreTLSErrors || s.cfg.Network.IgnoreTLSErrors),
		JavaScriptDisabled: playwright.Bool(false),
		Locale:            playwright.String(s.persona.Locale),
		TimezoneId:        playwright.String(s.persona.Timezone),
	}

	if s.persona.Width > 0 && s.persona.Height > 0 {
		options.Viewport = &playwright.BrowserNewContextOptionsViewport{
			Width:  int(s.persona.Width),
			Height: int(s.persona.Height),
		}
	}

	// TODO: Implement proxy configuration based on cfg.Network.Proxy

	return options
}

// initializeIAST sets up the client side taint analysis instrumentation by exposing a Go callback
// and injecting the IAST shim script.
func (s *Session) initializeIAST(ctx context.Context, taintTemplate, taintConfig string) error {
	// 1. Expose the Go callback function.
	sinkEventHandler := func(eventData map[string]interface{}) {
		finding := schemas.Finding{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Target:    "Client Side",
			Module:    "IAST",
			Severity:  schemas.SeverityHigh,
		}

		// Extract details from the map provided by the shim.
		if t, ok := eventData["type"].(string); ok {
			finding.Vulnerability.Name = fmt.Sprintf("Taint Flow to Sink: %s", t)
		}
		if d, ok := eventData["detail"].(string); ok {
			finding.Description = fmt.Sprintf("Tainted data reached a sensitive sink: %s", d)
		}
		if v, ok := eventData["value"].(string); ok {
			finding.Evidence = fmt.Sprintf("Payload: %s", v)
		}

		// Send the finding non blocking to avoid stalling the browser.
		select {
		case s.findingsChan <- finding:
		case <-s.ctx.Done():
			s.logger.Warn("Could not send IAST finding, session context is done.")
		default:
			s.logger.Warn("Findings channel full, dropping IAST finding.")
		}
	}

	// The context parameter here is used for the Go logic flow in ExposeFunction.
	if err := s.ExposeFunction(ctx, "__scalpel_sink_event", sinkEventHandler); err != nil {
		return fmt.Errorf("could not expose taint sink event handler: %w", err)
	}

	// 2. Inject the IAST shim script.
	scriptToInject := taintTemplate // Assumes caller builds the final script string.

	if scriptToInject != "" {
		// Pass the context to the updated method signature.
		if err := s.InjectScriptPersistently(ctx, scriptToInject); err != nil {
			return fmt.Errorf("could not inject IAST shim script: %w", err)
		}
	}

	return nil
}

// Close gracefully terminates the session and cleans up resources.
func (s *Session) Close(ctx context.Context) error {
	var finalErr error
	s.closeOnce.Do(func() {
		s.logger.Debug("Closing session.")

		// 1. Stop the Harvester.
		if s.harvester != nil {
			s.harvester.Stop()
		}

		// 2. Close the Playwright BrowserContext.
		if s.pwContext != nil {
			// Provide a 'Reason' for closure.
			// Close relies on implicit timeouts and does not take a context.
			closeOptions := playwright.BrowserContextCloseOptions{
				Reason: playwright.String(fmt.Sprintf("Session %s finalized.", s.id)),
			}
			if err := s.pwContext.Close(closeOptions); err != nil {
				// FIX: playwright.IsTargetClosedError is undefined. Fallback to string matching.
				if err != nil && 
					!strings.Contains(err.Error(), "Target closed") && 
					!strings.Contains(err.Error(), "Context closed") {
					s.logger.Warn("Error while closing browser context.", zap.Error(err))
					if finalErr == nil {
						finalErr = err
					}
				}
			}
		}

		// 3. Cancel the session's internal context.
		s.cancel()

		// 4. Call the manager's cleanup callback.
		if s.onClose != nil {
			s.onClose()
		}

		s.logger.Info("Session closed.")
	})
	return finalErr
}

// ID returns the unique identifier for the session.
func (s *Session) ID() string {
	return s.id
}

// GetContext returns the session's primary context.
func (s *Session) GetContext() context.Context {
	return s.ctx
}

// stabilize waits for the network to be idle using the Harvester.
func (s *Session) stabilize(ctx context.Context, quietPeriod time.Duration) error {
	if s.harvester == nil || s.page == nil || s.page.IsClosed() {
		s.logger.Debug("Harvester or Page not available for stabilization.")
		return nil // Cannot stabilize if components are missing or closed.
	}

	// Use the custom Harvester implementation for robust idle detection.
	// Use a combined context to respect both the specific operation context and the session lifecycle.
	stabCtx, stabCancel := CombineContext(s.ctx, ctx)
	defer stabCancel()

	return s.harvester.WaitNetworkIdle(stabCtx, quietPeriod)
}

// CollectArtifacts gathers data like HAR, DOM, logs, and storage from the session.
func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	s.logger.Debug("Collecting artifacts.")

	if s.page == nil || s.page.IsClosed() {
		s.logger.Warn("Session page is closed or unavailable for artifact collection.")
		// Return partial artifacts if harvester is available.
		if s.harvester != nil {
			return &schemas.Artifacts{
				HAR:         s.harvester.GenerateHAR(),
				ConsoleLogs: s.harvester.GetConsoleLogs(),
			}, nil
		}
		return nil, fmt.Errorf("session unavailable for artifact collection")
	}

	artifacts := &schemas.Artifacts{
		Storage: schemas.StorageState{},
	}

	// Combine context for collection operations (used for Go logic flow control).
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	// 1. Collect DOM Snapshot.
	// Content relies on implicit timeouts and does not take a context.
	dom, err := s.page.Content()
	if err != nil && opCtx.Err() == nil {
		s.logger.Warn("Failed to collect DOM content.", zap.Error(err))
	}
	artifacts.DOM = dom

	// 2. Collect Storage.
	// Cookies relies on implicit timeouts and does not take a context.
	cookies, err := s.pwContext.Cookies()
	if err != nil && opCtx.Err() == nil {
		s.logger.Warn("Failed to collect cookies.", zap.Error(err))
	}
	artifacts.Storage.Cookies = convertPwCooiesToSchema(cookies)

	// Local and Session Storage via JS execution.
	var storageData map[string]map[string]string
	script := `
				() => {
					const data = { localStorage: {}, sessionStorage: {} };
					for (let i = 0; i < localStorage.length; i++) {
						const key = localStorage.key(i);
						data.localStorage[key] = localStorage.getItem(key);
					}
					for (let i = 0; i < sessionStorage.length; i++) {
						const key = sessionStorage.key(i);
						data.sessionStorage[key] = sessionStorage.getItem(key);
					}
					return data;
				}
			`
	// Using s.ExecuteScript, which handles unmarshaling the result.
	if err := s.ExecuteScript(opCtx, script, &storageData); err != nil && opCtx.Err() == nil {
		s.logger.Warn("Failed to collect local/session storage.", zap.Error(err))
	} else if storageData != nil {
		artifacts.Storage.LocalStorage = storageData["localStorage"]
		artifacts.Storage.SessionStorage = storageData["sessionStorage"]
	}

	// 3. Collect Console Logs and HAR (from Harvester).
	if s.harvester != nil {
		// Stop the harvester before generating the final HAR if it hasn't been stopped yet.
		s.harvester.Stop()
		artifacts.ConsoleLogs = s.harvester.GetConsoleLogs()
		artifacts.HAR = s.harvester.GenerateHAR()
	}

	return artifacts, nil
}

// AddFinding implements schemas.SessionContext. It sends a finding to the results channel.
func (s *Session) AddFinding(finding schemas.Finding) error {
	// Ensure the finding has essential metadata if not already set.
	if finding.ID == "" {
		finding.ID = uuid.New().String()
	}
	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now()
	}

	// Send the finding non-blocking.
	select {
	case s.findingsChan <- finding:
		return nil
	case <-s.ctx.Done():
		s.logger.Warn("Could not add finding, session context is done.")
		return s.ctx.Err()
	default:
		// Log if the channel is full.
		s.logger.Warn("Findings channel full, dropping finding.", zap.String("vuln_name", finding.Vulnerability.Name))
		return fmt.Errorf("findings channel full")
	}
}

// -- Interaction Methods (schemas.SessionContext and humanoid.Controller implementations) --

// Navigate loads the specified URL and waits for the page to stabilize.
func (s *Session) Navigate(ctx context.Context, url string) error {
	s.logger.Debug("Navigating to URL", zap.String("url", url))

	if s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("session page not initialized or closed")
	}

	// Combine the operation context (ctx) with the session lifecycle context (s.ctx).
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	// Goto relies on implicit timeouts and does not take a context.
	_, err := s.page.Goto(url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilLoad,
	})

	if err != nil {
		// Check if the Go context was cancelled during the navigation.
		if opCtx.Err() != nil {
			return fmt.Errorf("navigation canceled or timed out: %w", opCtx.Err())
		}
		
		// FIX: playwright.TimeoutError is undefined. Fallback to checking the error message for "Timeout"
		if strings.Contains(err.Error(), "Timeout") {
			return fmt.Errorf("navigation timed out (%s): %w", s.cfg.Network.NavigationTimeout, err)
		}
		return fmt.Errorf("navigation failed: %w", err)
	}

	// Post navigation stabilization.
	quietPeriod := 1500 * time.Millisecond
	if s.cfg.Network.PostLoadWait > 0 {
		quietPeriod = s.cfg.Network.PostLoadWait
	}

	if err := s.stabilize(opCtx, quietPeriod); err != nil {
		// Stabilization errors are generally non critical unless the context was canceled.
		if opCtx.Err() == nil {
			s.logger.Debug("Page stabilization incomplete after navigation.", zap.Error(err))
		} else {
			return opCtx.Err()
		}
	}

	// Simulate cognitive pause if configured.
	if s.humanoidCfg != nil && s.humanoidCtrl != nil {
		// Use the humanoid controller for a realistic pause.
		if err := s.humanoidCtrl.CognitivePause(opCtx, 300, 150); err != nil {
			return err
		}
	} else if s.humanoidCfg != nil {
		// Fallback to simple sleep if controller failed to initialize but config exists.
		pauseDuration := time.Duration(300+rand.Intn(150)) * time.Millisecond
		select {
		case <-time.After(pauseDuration):
		case <-opCtx.Done():
			return opCtx.Err()
		}
	}

	return nil
}

// Click implementation for schemas.SessionContext.
// If humanoid is enabled, it delegates to the humanoid controller. Otherwise, uses standard Playwright click.
func (s *Session) Click(ctx context.Context, selector string) error {
	// Combine the operation context (ctx) with the session lifecycle context (s.ctx).
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	if s.humanoidCtrl != nil {
		s.logger.Debug("Delegating click to Humanoid Controller", zap.String("selector", selector))
		return s.humanoidCtrl.IntelligentClick(opCtx, selector, nil)
	}

	s.logger.Debug("Attempting standard click element", zap.String("selector", selector))
	if s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("page not initialized")
	}

	// Check context before proceeding.
	if opCtx.Err() != nil {
		return opCtx.Err()
	}

	options := playwright.PageClickOptions{
		Timeout: playwright.Float(30000), // Note: Playwright uses implicit timeout here, but we guard with Go context.
	}

	// Click relies on implicit timeouts and does not take a context.
	err := s.page.Click(selector, options)
	if err != nil {
		// Check if the Go context was cancelled during the action.
		if opCtx.Err() != nil {
			return opCtx.Err()
		}
		return err
	}
	return nil
}

// Type implementation for schemas.SessionContext.
// If humanoid is enabled, it delegates to the humanoid controller. Otherwise, uses standard Playwright type/fill.
func (s *Session) Type(ctx context.Context, selector string, text string) error {
	// Combine the operation context (ctx) with the session lifecycle context (s.ctx).
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	if s.humanoidCtrl != nil {
		s.logger.Debug("Delegating type to Humanoid Controller", zap.String("selector", selector))
		return s.humanoidCtrl.Type(opCtx, selector, text)
	}

	s.logger.Debug("Attempting standard type into element", zap.String("selector", selector))
	if s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("page not initialized")
	}

	// Check context before proceeding.
	if opCtx.Err() != nil {
		return opCtx.Err()
	}

	// Use Fill for standard, fast input when humanoid is disabled.
	// Fill relies on implicit timeouts and does not take a context.
	err := s.page.Fill(selector, text, playwright.PageFillOptions{Timeout: playwright.Float(30000)})
	if err != nil {
		// Check if the Go context was cancelled during the action.
		if opCtx.Err() != nil {
			return opCtx.Err()
		}
		return err
	}
	return nil
}

// Implementations for the humanoid.Controller interface.

// MoveTo implements humanoid.Controller.
func (s *Session) MoveTo(ctx context.Context, selector string, field *humanoid.PotentialField) error {
	if s.humanoidCtrl != nil {
		return s.humanoidCtrl.MoveTo(ctx, selector, field)
	}
	// If humanoid is disabled, perform a standard move (less realistic).
	if s.page == nil {
		return fmt.Errorf("page not initialized")
	}
	// Hover relies on implicit timeouts and does not take a context.
	return s.page.Hover(selector)
}

// IntelligentClick implements humanoid.Controller.
func (s *Session) IntelligentClick(ctx context.Context, selector string, field *humanoid.PotentialField) error {
	if s.humanoidCtrl != nil {
		return s.humanoidCtrl.IntelligentClick(ctx, selector, field)
	}
	// Fallback to standard click if humanoid is disabled. Pass the context.
	return s.Click(ctx, selector)
}

// DragAndDrop implements humanoid.Controller.
func (s *Session) DragAndDrop(ctx context.Context, startSelector, endSelector string) error {
	if s.humanoidCtrl != nil {
		return s.humanoidCtrl.DragAndDrop(ctx, startSelector, endSelector)
	}
	// Fallback if humanoid is disabled.
	if s.page == nil {
		return fmt.Errorf("page not initialized")
	}
	// DragAndDrop relies on implicit timeouts and does not take a context.
	return s.page.DragAndDrop(startSelector, endSelector)
}

// CognitivePause implements humanoid.Controller.
func (s *Session) CognitivePause(ctx context.Context, meanMs, stdDevMs float64) error {
	if s.humanoidCtrl != nil {
		return s.humanoidCtrl.CognitivePause(ctx, meanMs, stdDevMs)
	}
	// Fallback: Simple context aware sleep if humanoid is disabled.
	duration := time.Duration(meanMs) * time.Millisecond
	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Submit attempts to submit the form associated with the selector.
func (s *Session) Submit(ctx context.Context, selector string) error {
	s.logger.Debug("Attempting to submit form", zap.String("selector", selector))
	if s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("page not initialized")
	}

	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	if opCtx.Err() != nil {
		return opCtx.Err()
	}

	// Execute JavaScript to submit the form reliably.
	script := `(element) => {
				if (!element) throw new Error("Element not found");
				if (element.form) {
					element.form.submit();
				} else if (element.tagName === 'FORM') {
					element.submit();
				} else {
					throw new Error("Element is not a form or part of a form.");
				}
			}`

	// EvalOnSelector relies on implicit timeouts and does not take a context.
	_, err := s.page.EvalOnSelector(selector, script, nil)
	if err != nil {
		if opCtx.Err() != nil {
			return opCtx.Err()
		}
		return err
	}
	return nil
}

// ScrollPage simulates scrolling the page.
func (s *Session) ScrollPage(ctx context.Context, direction string) error {
	s.logger.Debug("Scrolling page", zap.String("direction", direction))
	if s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("page not initialized")
	}

	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	if opCtx.Err() != nil {
		return opCtx.Err()
	}

	var script string
	switch direction {
	case "down":
		script = `window.scrollBy(0, window.innerHeight * 0.8);`
	case "up":
		script = `window.scrollBy(0, -window.innerHeight * 0.8);`
	case "bottom":
		script = `window.scrollTo(0, document.body.scrollHeight);`
	case "top":
		script = `window.scrollTo(0, 0);`
	default:
		return fmt.Errorf("invalid scroll direction: %s", direction)
	}

	// Evaluate relies on implicit timeouts and does not take a context.
	_, err := s.page.Evaluate(script)
	if err != nil {
		if opCtx.Err() != nil {
			return opCtx.Err()
		}
		return err
	}
	return nil
}

// WaitForAsync pauses execution for a specified duration.
func (s *Session) WaitForAsync(ctx context.Context, milliseconds int) error {
	s.logger.Debug("Waiting for async operations", zap.Int("duration_ms", milliseconds))

	// Use Go context-aware sleep for better responsiveness to cancellation.
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	select {
	case <-time.After(time.Duration(milliseconds) * time.Millisecond):
		return nil
	case <-opCtx.Done():
		return opCtx.Err()
	}
}

// Interact triggers the automated recursive interaction logic.
func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	if s.interactor == nil || s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("interactor or page not initialized or closed")
	}
	s.logger.Info("Starting automated interaction sequence.")

	// Combine operation context with session context.
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	return s.interactor.RecursiveInteract(opCtx, config)
}

// -- Management Methods --

// ExposeFunction allows Go functions to be called from the browser's JavaScript context.
func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	if s.pwContext == nil {
		return fmt.Errorf("browser context not initialized")
	}

	fnVal := reflect.ValueOf(function)
	if fnVal.Kind() != reflect.Func {
		return fmt.Errorf("provided implementation for '%s' is not a function", name)
	}

	// Wrapper function with robust argument handling and panic recovery.
	wrappedFunc := func(args ...interface{}) (interface{}, error) {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("Panic during exposed function call.",
					zap.String("name", name),
					zap.Any("panic_reason", r),
					zap.String("stack", string(debug.Stack())))
			}
		}()

		fnType := fnVal.Type()

		// Handle the specific case used by IAST: a single map argument.
		if fnType.NumIn() == 1 && fnType.In(0).Kind() == reflect.Map {
			if len(args) != 1 {
				return nil, fmt.Errorf("expected 1 argument (map), got %d", len(args))
			}
			// Robustly convert the JS object (interface{}) to the target map type using JSON intermediary.
			targetType := fnType.In(0)
			paramPtr := reflect.New(targetType)

			data, err := json.Marshal(args[0])
			if err != nil {
				return nil, fmt.Errorf("failed to marshal argument: %w", err)
			}
			if err := json.Unmarshal(data, paramPtr.Interface()); err != nil {
				return nil, fmt.Errorf("failed to unmarshal argument to %s: %w", targetType.String(), err)
			}

			in := []reflect.Value{paramPtr.Elem()}
			results := fnVal.Call(in)
			return processResults(results)
		}

		// Standard positional arguments handling.
		if len(args) != fnType.NumIn() {
			return nil, fmt.Errorf("invalid argument count: expected %d, got %d", fnType.NumIn(), len(args))
		}

		in := make([]reflect.Value, len(args))
		for i, arg := range args {
			targetType := fnType.In(i)
			argVal := reflect.ValueOf(arg)

			if argVal.IsValid() && argVal.Type().ConvertibleTo(targetType) {
				in[i] = argVal.Convert(targetType)
			} else {
				// Fallback using JSON intermediary for complex conversions.
				data, err := json.Marshal(arg)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal argument %d: %w", i, err)
				}
				paramPtr := reflect.New(targetType)
				if err := json.Unmarshal(data, paramPtr.Interface()); err != nil {
					return nil, fmt.Errorf("failed to unmarshal argument %d to %s: %w", i, targetType.String(), err)
				}
				in[i] = paramPtr.Elem()
			}
		}

		results := fnVal.Call(in)
		return processResults(results)
	}

	// Expose the function on the context.
	// ExposeFunction relies on implicit timeouts and does not take a context.
	return s.pwContext.ExposeFunction(name, wrappedFunc)
}

// Helper to process reflection results into (interface{}, error) expected by Playwright.
func processResults(results []reflect.Value) (interface{}, error) {
	if len(results) == 0 {
		return nil, nil
	}

	var resultVal interface{}
	var errVal error

	for _, res := range results {
		// Check for error return value
		if res.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) {
			if !res.IsNil() {
				errVal = res.Interface().(error)
			}
		} else if res.IsValid() && (res.Kind() != reflect.Ptr || !res.IsNil()) {
			// This is a non-error return value (e.g., string, map, struct)
			resultVal = res.Interface()
		}
	}
	return resultVal, errVal
}

// InjectScriptPersistently adds a script that will be executed on all new documents.
func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	if s.pwContext == nil {
		return fmt.Errorf("browser context not initialized")
	}

	// Check context before proceeding.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// AddInitScript does not take context.
	err := s.pwContext.AddInitScript(playwright.Script{
		Content: playwright.String(script),
	})
	if err != nil {
		// Check if the Go context was cancelled during the operation.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("could not inject persistent script: %w", err)
	}
	s.logger.Debug("Injected persistent script.")
	return nil
}

// ExecuteScript runs a snippet of JavaScript in the current document's main frame.
// This implements the schemas.SessionContext interface.
func (s *Session) ExecuteScript(ctx context.Context, script string, res interface{}) error {
	if s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("page not initialized or closed")
	}

	// Combine context for Go logic flow control.
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	// Evaluate relies on implicit timeouts and does not take a context.
	result, err := s.page.Evaluate(script)
	if err != nil {
		// Check if the Go context was cancelled during evaluation.
		if opCtx.Err() != nil {
			return opCtx.Err()
		}
		return fmt.Errorf("failed to execute script: %w", err)
	}

	// If a result pointer is provided, unmarshal the result into it.
	if res != nil && result != nil {
		// Use JSON marshaling as an intermediary for robust type conversion.
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal script result: %w", err)
		}
		if err := json.Unmarshal(data, res); err != nil {
			return fmt.Errorf("failed to unmarshal script result into target: %w", err)
		}
	}

	return nil
}

// Helper to convert Playwright cookies to the schema format.
func convertPwCooiesToSchema(pwCookies []playwright.Cookie) []*schemas.Cookie {
	schemaCookies := make([]*schemas.Cookie, len(pwCookies))
	for i, c := range pwCookies {
		// playwright.Cookie.Expires is a float64 representing a Unix timestamp.
		// A value of -1 or 0 often indicates a session cookie.
		isSession := c.Expires == -1 || c.Expires == 0

		schemaCookies[i] = &schemas.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  c.Expires, // Directly assign the float64
			Size:     int64(len(c.Name) + len(c.Value)),
			HTTPOnly: c.HttpOnly,
			Secure:   c.Secure,
			Session:  isSession,
			SameSite: schemas.CookieSameSite(c.SameSite),
		}
	}
	return schemaCookies
}

