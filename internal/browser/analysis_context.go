package browser

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// AnalysisContext implements the schemas.SessionContext interface.
// It provides a high level API for interacting with a browser tab,
// handling stabilization, and collecting artifacts for analysis.
type AnalysisContext struct {
	// Core session components
	ctx        context.Context
	cancelFunc context.CancelFunc
	sessionID  string
	logger     *zap.Logger
	cfg        *config.Config
	persona    schemas.Persona

	// Specialized components
	harvester  *Harvester
	interactor *Interactor
	humanoid   *humanoid.Humanoid

	// Lifecycle management
	observer SessionLifecycleObserver
	isClosed bool
	mu       sync.Mutex
}

// Ensure AnalysisContext implements the interface.
var _ schemas.SessionContext = (*AnalysisContext)(nil)

// NewAnalysisContext creates a new, initialized AnalysisContext. It sets up all necessary
// subcomponents like the harvester and interactor and kicks off data collection.
func NewAnalysisContext(
	ctx context.Context,
	cancel context.CancelFunc,
	logger *zap.Logger,
	cfg *config.Config,
	persona schemas.Persona,
	observer SessionLifecycleObserver,
	sessionID string,
) *AnalysisContext {

	sessionLogger := logger.Named("session").With(zap.String("session_id", sessionID))

	ac := &AnalysisContext{
		ctx:        ctx,
		cancelFunc: cancel,
		sessionID:  sessionID,
		logger:     sessionLogger,
		cfg:        cfg,
		persona:    persona,
		observer:   observer,
	}

	// Set up the harvester to start grabbing network and console events.
	ac.harvester = NewHarvester(ctx, sessionLogger, cfg.Network.CaptureResponseBodies)

	// Initialize the humanoid for more realistic user interactions.
	if cfg.Browser.Humanoid.Enabled {
		browserContextID := chromedp.FromContext(ctx).Browser.BrowserContextID
		ac.humanoid = humanoid.New(cfg.Browser.Humanoid, sessionLogger, browserContextID)
	}

	// The interactor needs a way to know when the page is 'settled' before acting.
	stabilizeFn := func(stabCtx context.Context) error {
		// A short quiet period is usually enough for interaction stability.
		return ac.stabilize(stabCtx, 500*time.Millisecond)
	}
	ac.interactor = NewInteractor(sessionLogger, ac.humanoid, stabilizeFn)

	// Start the harvester immediately to make sure we don't miss a thing.
	if err := ac.harvester.Start(); err != nil {
		ac.logger.Error("Failed to start harvester, data collection may be incomplete", zap.Error(err))
	}

	return ac
}

// stabilize waits for the application state to settle down. This is a crucial step
// before interacting with elements to avoid race conditions. It waits for the DOM
// to be ready and for network activity to go quiet for a specified period.
func (ac *AnalysisContext) stabilize(ctx context.Context, quietPeriod time.Duration) error {
	// Don't wait forever, enforce a max stabilization time.
	stabCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// First, wait for the basic document structure to be ready.
	if err := chromedp.Run(stabCtx, chromedp.WaitReady("body", chromedp.ByQuery)); err != nil {
		ac.logger.Debug("Stabilization timed out waiting for DOM readiness.")
		// We only bubble up an error if the parent context was cancelled.
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	// Next, wait for the network to chill out.
	err := ac.harvester.WaitNetworkIdle(stabCtx, quietPeriod)
	if err != nil {
		if stabCtx.Err() != nil {
			ac.logger.Debug("Stabilization timed out waiting for network idle.")
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

// Navigate tells the browser to go to a new URL and waits for the page
// to become stable before returning.
func (ac *AnalysisContext) Navigate(ctx context.Context, url string) error {
	ac.logger.Info("Navigating", zap.String("url", url))

	// A navigation shouldn't take forever.
	navCtx, cancel := context.WithTimeout(ctx, ac.cfg.Network.NavigationTimeout)
	defer cancel()

	// This is a robust way to handle timeouts with chromedp. We run the action
	// on the main session context but watch for our navigation timeout.
	err := chromedp.Run(ac.ctx, chromedp.ActionFunc(func(actionCtx context.Context) error {
		// This derived context will cancel if either the chromedp action context
		// or our navigation timeout context is done.
		runCtx, cancelRun := context.WithCancel(actionCtx)
		defer cancelRun()

		go func() {
			select {
			case <-navCtx.Done():
				cancelRun()
			case <-runCtx.Done():
			}
		}()

		// Fire off the navigation. This waits for the 'load' event by default.
		_, _, _, _, err := page.Navigate(url).Do(runCtx)
		return err
	}))

	if err != nil {
		if navCtx.Err() != nil {
			return fmt.Errorf("navigation timed out after %s: %w", ac.cfg.Network.NavigationTimeout, err)
		}
		return fmt.Errorf("navigation failed: %w", err)
	}

	// After the page loads, give it a moment to run startup scripts and fetch initial data.
	if err := ac.stabilize(navCtx, 1500*time.Millisecond); err != nil {
		// This isn't a fatal error, just log it.
		ac.logger.Debug("Post navigation stabilization was incomplete.", zap.Error(err))
	}

	return nil
}

// Interact kicks off the automated recursive interaction logic, attempting to
// explore the web application like a user would.
func (ac *AnalysisContext) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	ac.logger.Info("Starting automated interaction sequence.")

	interactCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// If the calling context doesn't have a deadline, set a reasonable default.
	if _, ok := ctx.Deadline(); !ok {
		var cancelWithTimeout context.CancelFunc
		interactCtx, cancelWithTimeout = context.WithTimeout(ctx, 5*time.Minute)
		defer cancelWithTimeout()
	}

	if err := ac.interactor.RecursiveInteract(interactCtx, config); err != nil {
		if interactCtx.Err() != nil {
			// This is an expected outcome if the interaction times out.
			ac.logger.Warn("Interaction sequence aborted (context done).", zap.Error(err))
			return nil
		}
		return fmt.Errorf("interaction sequence failed: %w", err)
	}

	ac.logger.Info("Automated interaction sequence completed.")
	return nil
}

// CollectArtifacts gathers all data collected during the session into a single structure.
// This is typically called at the end of an analysis flow.
func (ac *AnalysisContext) CollectArtifacts() (*schemas.Artifacts, error) {
	// Use a background context with its own timeout to ensure collection can finish
	// even if the original request context has been cancelled.
	collectCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// This is a critical synchronization point. Stopping the harvester finalizes
	// all pending network requests and returns the complete HAR and console logs.
	har, consoleLogs := ac.harvester.Stop(collectCtx)

	var domContent string
	storageState := schemas.StorageState{}

	// Now grab a final snapshot of the DOM and storage state.
	err := chromedp.Run(ac.ctx, chromedp.ActionFunc(func(actionCtx context.Context) error {
		runCtx, cancelRun := context.WithCancel(actionCtx)
		defer cancelRun()

		go func() {
			select {
			case <-collectCtx.Done():
				cancelRun()
			case <-runCtx.Done():
			}
		}()

		// Capture the full outer HTML of the document.
		if err := chromedp.OuterHTML("html", &domContent, chromedp.ByQuery).Do(runCtx); err != nil {
			ac.logger.Warn("Failed to capture DOM.", zap.Error(err))
		}

		// Capture cookies, local storage, and session storage.
		if err := ac.captureStorage(runCtx, &storageState); err != nil {
			ac.logger.Warn("Failed to capture storage.", zap.Error(err))
		}
		return nil
	}))

	// If the main browser context is dead, we might not get everything.
	if err != nil && ac.ctx.Err() != nil {
		ac.logger.Warn("Browser context was unavailable during artifact collection.", zap.Error(err))
	}

	return &schemas.Artifacts{
		HAR:         har,
		DOM:         domContent,
		ConsoleLogs: consoleLogs,
		Storage:     storageState,
	}, nil
}

// captureStorage is a helper to extract various storage data using efficient CDP commands.
func (ac *AnalysisContext) captureStorage(ctx context.Context, state *schemas.StorageState) error {
	// Get all cookies for all domains, including HttpOnly ones.
	var err error
	state.Cookies, err = storage.GetCookies().Do(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cookies: %w", err)
	}

	// This JS snippet is a robust way to dump key/value storage.
	jsGetStorage := func(storageType string) string {
		return fmt.Sprintf(`(() => {
                let items = {};
                try {
                    const storage = window.%s;
                    if (!storage) return items;
                    for (let i = 0; i < storage.length; i++) {
                        const key = storage.key(i);
                        if (key !== null) {
                            items[key] = storage.getItem(key);
                        }
                    }
                } catch (e) {
                    // Access can be denied by browser security policies.
                }
                return items;
            })()`, storageType)
	}

	if err := chromedp.Evaluate(jsGetStorage("localStorage"), &state.LocalStorage).Do(ctx); err != nil {
		ac.logger.Debug("Could not access LocalStorage.", zap.Error(err))
	}

	if err := chromedp.Evaluate(jsGetStorage("sessionStorage"), &state.SessionStorage).Do(ctx); err != nil {
		ac.logger.Debug("Could not access SessionStorage.", zap.Error(err))
	}

	return nil
}

// Close gracefully terminates the browser session, ensuring all resources are cleaned up.
func (ac *AnalysisContext) Close(ctx context.Context) error {
	ac.mu.Lock()
	if ac.isClosed {
		ac.mu.Unlock()
		return nil // Already closed.
	}
	ac.isClosed = true
	ac.mu.Unlock()

	ac.logger.Debug("Closing session.")

	// Give the harvester a chance to stop gracefully.
	ac.harvester.Stop(ctx)

	// Explicitly close the browser target (the tab).
	err := chromedp.Run(ac.ctx, chromedp.ActionFunc(func(c context.Context) error {
		if cdptarget := chromedp.FromContext(c).Target; cdptarget != nil {
			return target.CloseTarget(cdptarget.TargetID).Do(c)
		}
		return nil
	}))

	if err != nil {
		ac.logger.Debug("Failed to explicitly close target, will rely on context cancellation.", zap.Error(err))
	}

	// Cancel the underlying ChromeDP context as the final cleanup step.
	if ac.cancelFunc != nil {
		ac.cancelFunc()
	}

	// Notify the manager that this session is going away.
	if ac.observer != nil {
		ac.observer.unregisterSession(ac)
	}

	return nil
}

// InitializeTaint is a placeholder for IAST/Taint analysis initialization logic.
func (ac *AnalysisContext) InitializeTaint(template, config string) error {
	ac.logger.Info("Taint instrumentation would be initialized here.")
	// Actual implementation would involve ac.ExposeFunction and ac.InjectScriptPersistently.
	return nil
}

// ID returns the unique session identifier.
func (ac *AnalysisContext) ID() string {
	return ac.sessionID
}

// -- Low-Level Interface Implementations --

// GetContext returns the underlying ChromeDP context for this session.
func (ac *AnalysisContext) GetContext() context.Context {
	return ac.ctx
}

// Click finds an element by selector and clicks it, using humanoid logic if available.
func (ac *AnalysisContext) Click(selector string) error {
	ac.logger.Debug("Clicking", zap.String("selector", selector))
	if ac.humanoid != nil {
		return chromedp.Run(ac.ctx, ac.humanoid.IntelligentClick(selector, nil))
	}
	return chromedp.Run(ac.ctx, chromedp.Click(selector, chromedp.NodeVisible))
}

// Type finds an element by selector and types text into it.
func (ac *AnalysisContext) Type(selector string, text string) error {
	ac.logger.Debug("Typing", zap.String("selector", selector), zap.Int("length", len(text)))
	if ac.humanoid != nil {
		return chromedp.Run(ac.ctx, ac.humanoid.Type(selector, text))
	}
	return chromedp.Run(ac.ctx, chromedp.SendKeys(selector, text, chromedp.NodeVisible))
}

// Submit finds a form element and triggers its submission.
func (ac *AnalysisContext) Submit(selector string) error {
	ac.logger.Debug("Submitting form", zap.String("selector", selector))
	return chromedp.Run(ac.ctx, chromedp.Submit(selector, chromedp.NodeVisible))
}

// ScrollPage scrolls the page up or down by a fraction of the viewport height.
func (ac *AnalysisContext) ScrollPage(direction string) error {
	ac.logger.Debug("Scrolling", zap.String("direction", direction))
	script := `window.scrollBy(0, window.innerHeight * 0.8);`
	if strings.ToLower(direction) == "up" {
		script = `window.scrollBy(0, -window.innerHeight * 0.8);`
	}
	return chromedp.Run(ac.ctx, chromedp.Evaluate(script, nil))
}

// WaitForAsync pauses execution for a specified duration.
func (ac *AnalysisContext) WaitForAsync(milliseconds int) error {
	ac.logger.Debug("Waiting for async operations", zap.Int("ms", milliseconds))
	return chromedp.Run(ac.ctx, chromedp.Sleep(time.Duration(milliseconds)*time.Millisecond))
}

// ExposeFunction makes a Go function available to be called from JavaScript in the page.
func (ac *AnalysisContext) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	ac.logger.Debug("Exposing function", zap.String("name", name))
	// This only creates the binding; a listener is needed to handle calls.
	return chromedp.Run(ac.ctx, runtime.AddBinding(name))
}

// InjectScriptPersistently adds a script that will be executed on all subsequent
// page loads and navigations within this context.
func (ac *AnalysisContext) InjectScriptPersistently(ctx context.Context, script string) error {
	ac.logger.Debug("Injecting persistent script", zap.Int("length", len(script)))
	return chromedp.Run(ac.ctx, chromedp.ActionFunc(func(actionCtx context.Context) error {
		runCtx, cancelRun := context.WithCancel(actionCtx)
		defer cancelRun()
		go func() {
			select {
			case <-ctx.Done():
				cancelRun()
			case <-runCtx.Done():
			}
		}()
		_, err := page.AddScriptToEvaluateOnNewDocument(script).Do(runCtx)
		return err
	}))
}

// ExecuteScript runs a snippet of JavaScript in the current page context.
func (ac *AnalysisContext) ExecuteScript(ctx context.Context, script string) error {
	ac.logger.Debug("Executing script", zap.Int("length", len(script)))
	return chromedp.Run(ac.ctx, chromedp.ActionFunc(func(actionCtx context.Context) error {
		runCtx, cancelRun := context.WithCancel(actionCtx)
		defer cancelRun()
		go func() {
			select {
			case <-ctx.Done():
				cancelRun()
			case <-runCtx.Done():
			}
		}()
		_, _, err := runtime.Evaluate(script).Do(runCtx)
		return err
	}))
}