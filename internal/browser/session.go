// internal/browser/session.go
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"runtime/debug"
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

	harvester    *Harvester
	interactor   *Interactor
	humanoidCfg  *humanoid.Config // Configuration for human-like behavior.
	findingsChan chan<- schemas.Finding

	onClose   func()
	closeOnce sync.Once
}

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
	if cfg.Browser.Humanoid.Enabled {
		s.humanoidCfg = &cfg.Browser.Humanoid
	}

	// Define the stabilization function used by the interactor.
	stabilizeFn := func(ctx context.Context) error {
		quietPeriod := 1500 * time.Millisecond // Default stabilization time.
		if s.cfg.Network.PostLoadWait > 0 {
			quietPeriod = s.cfg.Network.PostLoadWait
		}
		return s.stabilize(ctx, quietPeriod)
	}

	// Initialize the interactor. Page is set later.
	s.interactor = NewInteractor(log, s.humanoidCfg, stabilizeFn)

	return s, nil
}

// Initialize creates the Playwright BrowserContext and Page, applies configurations, and starts monitoring.
func (s *Session) Initialize(ctx context.Context, browser playwright.Browser, taintTemplate, taintConfig string) error {
	s.logger.Debug("Initializing session.")

	// 1. Prepare BrowserContext options.
	options := s.prepareContextOptions()

	// 2. Create the isolated BrowserContext.
	// We pass the session context (s.ctx) so operations on the context respect the session lifecycle.
	pwContext, err := browser.NewContext(s.ctx, options)
	if err != nil {
		return fmt.Errorf("failed to create new browser context: %w", err)
	}
	s.pwContext = pwContext

	// Set default timeouts.
	s.configureTimeouts()

	// 3. Apply advanced stealth evasions (JS injection).
	if err := stealth.ApplyEvasions(s.pwContext, s.persona, s.logger); err != nil {
		s.logger.Warn("Failed to apply advanced stealth evasions (non-critical).", zap.Error(err))
	}
	// 4. Initialize IAST Shim if enabled.
	if s.cfg.IAST.Enabled {
		if err := s.initializeIAST(ctx, taintTemplate, taintConfig); err != nil {
			return fmt.Errorf("failed to initialize IAST shim: %w", err)
		}
	}

	// 5. Create the main Page within the context.
	page, err := pwContext.NewPage(s.ctx)
	if err != nil {
		return fmt.Errorf("failed to create new page: %w", err)
	}
	s.page = page
	s.interactor.SetPage(page) // Link the page to the interactor.

	// 6. Initialize the Harvester.
	s.harvester = NewHarvester(s.ctx, s.logger, s.cfg.Network.CaptureResponseBodies)
	s.harvester.Start(page)

	return nil
}

func (s *Session) configureTimeouts() {
	navTimeoutMs := float64(s.cfg.Network.NavigationTimeout.Milliseconds())
	if navTimeoutMs <= 0 {
		navTimeoutMs = 60000 // Default 60s if not specified
	}
	s.pwContext.SetDefaultNavigationTimeout(navTimeoutMs)
	// Set a slightly longer default timeout for actions.
	s.pwContext.SetDefaultTimeout(navTimeoutMs + 5000)
}

// prepareContextOptions sets up the Playwright options based on the configuration and persona.
func (s *Session) prepareContextOptions() playwright.BrowserNewContextOptions {
	options := playwright.BrowserNewContextOptions{
		UserAgent:          playwright.String(s.persona.UserAgent),
		IgnoreHttpsErrors:  playwright.Bool(s.cfg.Browser.IgnoreTLSErrors || s.cfg.Network.IgnoreTLSErrors),
		JavaScriptDisabled: playwright.Bool(false),
		Locale:             playwright.String(s.persona.Locale),
		TimezoneId:         playwright.String(s.persona.Timezone),
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

// initializeIAST sets up the client-side taint analysis instrumentation.
func (s *Session) initializeIAST(ctx context.Context, taintTemplate, taintConfig string) error {
	// 1. Expose the Go callback function.
	sinkEventHandler := func(eventData map[string]interface{}) {
		finding := schemas.Finding{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Target:    "Client-Side",
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

		// Send the finding non-blocking.
		select {
		case s.findingsChan <- finding:
		case <-s.ctx.Done():
			s.logger.Warn("Could not send IAST finding, session context is done.")
		default:
			s.logger.Warn("Findings channel full, dropping IAST finding.")
		}
	}

	if err := s.ExposeFunction(ctx, "__scalpel_sink_event", sinkEventHandler); err != nil {
		return fmt.Errorf("could not expose taint sink event handler: %w", err)
	}

	// 2. Inject the IAST shim script. (Assumes caller builds the final script string).
	scriptToInject := taintTemplate // Simplified: Should use shim builder in production.

	if scriptToInject != "" {
		if err := s.InjectScriptPersistently(scriptToInject); err != nil {
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
			// Use the provided context for the close operation to allow timeouts.
			if err := s.pwContext.Close(ctx); err != nil {
				// Check if the error is just because the target was already closed.
				if !playwright.IsTargetClosedError(err) {
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

	// Combine context for collection operations.
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	// 1. Collect DOM Snapshot.
	dom, err := s.page.Content(opCtx)
	if err != nil && opCtx.Err() == nil {
		s.logger.Warn("Failed to collect DOM content.", zap.Error(err))
	}
	artifacts.DOM = dom

	// 2. Collect Storage.
	cookies, err := s.pwContext.Cookies(opCtx)
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
	if err := s.ExecuteScript(opCtx, script, &storageData); err != nil && opCtx.Err() == nil {
		s.logger.Warn("Failed to collect local/session storage.", zap.Error(err))
	} else {
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

// --- Interaction Methods ---

// Navigate loads the specified URL and waits for the page to stabilize.
func (s *Session) Navigate(ctx context.Context, url string) error {
	s.logger.Debug("Navigating to URL", zap.String("url", url))

	if s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("session page not initialized or closed")
	}

	// Combine the operation context (ctx) with the session lifecycle context (s.ctx).
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	// Playwright's Goto uses the default navigation timeout configured on the context.
	// We wait until 'load' by default, but stabilization handles 'networkidle'.
	_, err := s.page.Goto(opCtx, url, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilLoad,
	})

	if err != nil {
		if opCtx.Err() != nil {
			return fmt.Errorf("navigation canceled or timed out: %w", opCtx.Err())
		}
		if playwright.IsTimeoutError(err) {
			return fmt.Errorf("navigation timed out (%s): %w", s.cfg.Network.NavigationTimeout, err)
		}
		return fmt.Errorf("navigation failed: %w", err)
	}

	// Post-navigation stabilization.
	quietPeriod := 1500 * time.Millisecond
	if s.cfg.Network.PostLoadWait > 0 {
		quietPeriod = s.cfg.Network.PostLoadWait
	}

	if err := s.stabilize(opCtx, quietPeriod); err != nil {
		// Stabilization errors are generally non-critical unless the context was canceled.
		if opCtx.Err() == nil {
			s.logger.Debug("Page stabilization incomplete after navigation.", zap.Error(err))
		} else {
			return opCtx.Err()
		}
	}

	// Simulate cognitive pause if configured.
	if s.humanoidCfg != nil {
		pauseDuration := time.Duration(300+rand.Intn(150)) * time.Millisecond
		select {
		case <-time.After(pauseDuration):
		case <-opCtx.Done():
			return opCtx.Err()
		}
	}

	return nil
}

// Click interacts with the element matching the selector.
func (s *Session) Click(selector string) error {
	s.logger.Debug("Attempting to click element", zap.String("selector", selector))
	if s.page == nil {
		return fmt.Errorf("page not initialized")
	}

	// Use a specific timeout for the click action, respecting the session context.
	clickCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	options := playwright.PageClickOptions{
		Timeout: playwright.Float(30000),
	}

	// Apply humanoid configuration if available.
	if s.humanoidCfg != nil {
		// Calculate random delay based on configuration.
		minMs := int(s.humanoidCfg.ClickHoldMinMs)
		maxMs := int(s.humanoidCfg.ClickHoldMaxMs)
		if maxMs > minMs {
			delay := float64(minMs + rand.Intn(maxMs-minMs))
			options.Delay = playwright.Float(delay)
		}
	}

	return s.page.Click(clickCtx, selector, options)
}

// Type inputs text into the element matching the selector.
func (s *Session) Type(selector string, text string) error {
	s.logger.Debug("Attempting to type into element", zap.String("selector", selector))
	if s.page == nil {
		return fmt.Errorf("page not initialized")
	}

	typeCtx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	// Use Type for humanoid behavior (key-by-key delay), otherwise use Fill.
	if s.humanoidCfg != nil && s.humanoidCfg.KeyHoldMeanMs > 0 {
		// Clear the field first using Fill for reliability.
		if err := s.page.Fill(typeCtx, selector, "", playwright.PageFillOptions{Timeout: playwright.Float(5000)}); err != nil {
			return fmt.Errorf("failed to clear input field before typing: %w", err)
		}

		// Use Type with a delay to simulate keyboard events.
		delay := float64(s.humanoidCfg.KeyHoldMeanMs * (1.0 + rand.Float64()*0.5)) // Add some variance
		typeOptions := playwright.PageTypeOptions{
			Timeout: playwright.Float(30000),
			Delay:   playwright.Float(delay),
		}
		return s.page.Type(typeCtx, selector, text, typeOptions)
	}

	// Use Fill for standard, fast input.
	return s.page.Fill(typeCtx, selector, text, playwright.PageFillOptions{Timeout: playwright.Float(30000)})
}

// Submit attempts to submit the form associated with the selector.
func (s *Session) Submit(selector string) error {
	s.logger.Debug("Attempting to submit form", zap.String("selector", selector))
	if s.page == nil {
		return fmt.Errorf("page not initialized")
	}

	submitCtx, cancel := context.WithTimeout(s.ctx, 15*time.Second)
	defer cancel()

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

	// Evaluate on the specific element matching the selector.
	_, err := s.page.EvaluateOnSelector(submitCtx, selector, script, nil)
	return err
}

// ScrollPage simulates scrolling the page.
func (s *Session) ScrollPage(direction string) error {
	s.logger.Debug("Scrolling page", zap.String("direction", direction))
	if s.page == nil {
		return fmt.Errorf("page not initialized")
	}

	scrollCtx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

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

	_, err := s.page.Evaluate(scrollCtx, script)
	return err
}

// WaitForAsync pauses execution for a specified duration.
func (s *Session) WaitForAsync(milliseconds int) error {
	s.logger.Debug("Waiting for async operations", zap.Int("duration_ms", milliseconds))
	// Use the session context for the wait operation.
	return s.page.WaitForTimeout(s.ctx, float64(milliseconds))
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

// --- Management Methods ---

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
	return s.pwContext.ExposeFunction(ctx, name, wrappedFunc)
}

// Helper to process reflection results into (interface{}, error) expected by Playwright.
func processResults(results []reflect.Value) (interface{}, error) {
	if len(results) == 0 {
		return nil, nil
	}

	var resultVal interface{}
	var errVal error

	for _, res := range results {
		if err, ok := res.Interface().(error); ok && !res.IsNil() {
			errVal = err
		} else if res.IsValid() && (res.Kind() != reflect.Ptr || !res.IsNil()) {
			resultVal = res.Interface()
		}
	}
	return resultVal, errVal
}

// InjectScriptPersistently adds a script that will be executed on all new documents.
func (s *Session) InjectScriptPersistently(script string) error {
	if s.pwContext == nil {
		return fmt.Errorf("browser context not initialized")
	}

	err := s.pwContext.AddInitScript(playwright.Script{
		Content: playwright.String(script),
	})
	if err != nil {
		return fmt.Errorf("could not inject persistent script: %w", err)
	}
	s.logger.Debug("Injected persistent script.")
	return nil
}

// ExecuteScript runs a snippet of JavaScript in the current document's main frame.
func (s *Session) ExecuteScript(ctx context.Context, script string, res interface{}) error {
	if s.page == nil || s.page.IsClosed() {
		return fmt.Errorf("page not initialized or closed")
	}

	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	result, err := s.page.Evaluate(opCtx, script)
	if err != nil {
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

