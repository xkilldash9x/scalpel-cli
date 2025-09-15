package browser

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/shim"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.package browser

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/shim"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

const (
	// Timeouts (Principle 3)
	defaultNavigationTimeout  = 60 * time.Second
	artifactCollectionTimeout = 30 * time.Second
	contextDisposeTimeout     = 10 * time.Second
	finalSessionCloseWait     = 5 * time.Second

	// Stabilization (Principle 2)
	networkIdleQuietPeriod = 500 * time.Millisecond
	networkIdleMaxWait     = 15 * time.Second
)

// AnalysisContext represents a single, isolated browser session (equivalent to an incognito profile/tab).
type AnalysisContext struct {
	id           string
	globalConfig *config.Config
	logger       *zap.Logger
	persona      stealth.Persona

	// parentCtx is the context from the allocator, used as the parent for the session context.
	parentCtx context.Context
	// controllerCtx is the context of the main browser CDP session, used for creating/disposing BrowserContexts.
	controllerCtx context.Context
	// contextCreationLock is shared by the manager to synchronize context/target creation.
	contextCreationLock *sync.Mutex

	// sessionContext is the chromedp context specific to this session's target.
	sessionContext context.Context
	// sessionCancel cancels the sessionContext.
	sessionCancel context.CancelFunc
	// browserContextID is the ID of the isolated CDP BrowserContext.
	browserContextID cdp.BrowserContextID

	humanoid   *humanoid.Humanoid
	harvester  *Harvester
	interactor *Interactor

	taintShimTemplate string
	taintConfigJSON   string

	findings []schemas.Finding
	// capturedScreenshot stores the last screenshot taken (Principle 5).
	capturedScreenshot []byte

	// State synchronization
	isClosed      bool
	isInitialized bool
	mu            sync.Mutex

	// observer is the entity to notify when the session closes (the Manager).
	observer SessionLifecycleObserver
}

// NewAnalysisContext creates the structure for a new session but does not initialize the browser resources.
func NewAnalysisContext(
	parentCtx context.Context,
	controllerCtx context.Context,
	cfg *config.Config,
	logger *zap.Logger,
	persona stealth.Persona,
	taintTemplate string,
	taintConfig string,
	contextCreationLock *sync.Mutex,
	observer SessionLifecycleObserver,
) *AnalysisContext {
	id := uuid.New().String()
	l := logger.With(zap.String("session_id", id))
	return &AnalysisContext{
		id:                  id,
		parentCtx:           parentCtx,
		controllerCtx:       controllerCtx,
		contextCreationLock: contextCreationLock,
		globalConfig:        cfg,
		logger:              l,
		persona:             persona,
		taintShimTemplate:   taintTemplate,
		taintConfigJSON:     taintConfig,
		findings:            make([]schemas.Finding, 0),
		observer:            observer,
	}
}

// Initialize sets up the isolated browser context (incognito profile) and the target (tab).
func (ac *AnalysisContext) Initialize(ctx context.Context) error {
	ac.logger.Debug("Initialize: START", zap.Error(ctx.Err()))
	ac.mu.Lock()
	if ac.isInitialized {
		ac.mu.Unlock()
		return fmt.Errorf("session already initialized")
	}
	ac.mu.Unlock()

	// Ensure cleanup if initialization fails at any point.
	success := false
	defer func() {
		if !success {
			ac.logger.Debug("Initialize: Defer triggered due to failure.")
			cleanupCtx, cancel := context.WithTimeout(context.Background(), contextDisposeTimeout)
			defer cancel()
			ac.internalClose(cleanupCtx)
		}
	}()

	// 1. Create the Isolated Browser Context and Target (Synchronized)
	ac.contextCreationLock.Lock()
	ac.logger.Debug("Initialize: Context creation lock acquired.")
	defer func() {
		ac.logger.Debug("Initialize: Context creation lock released.")
		ac.contextCreationLock.Unlock()
	}()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before creating browser context: %w", err)
	}

	initCmdCtx, cancelInitCmd := context.WithDeadline(ac.controllerCtx, getContextDeadline(ctx))
	defer cancelInitCmd()
	ac.logger.Debug("Initialize: Checking controller context state before creating target.", zap.Error(initCmdCtx.Err()))

	browserContextID, targetID, err := ac.createIsolatedTarget(initCmdCtx)
	if err != nil {
		return err
	}
	ac.logger.Debug("Initialize: Isolated target created.", zap.String("targetID", string(targetID)))

	// 2. Create the Chromedp Context for the new Target
	sessionCtx, cancelSession := chromedp.NewContext(ac.parentCtx, chromedp.WithTargetID(targetID))
	ac.logger.Debug("Initialize: New chromedp session context created.", zap.Error(sessionCtx.Err()))

	// 3. Initialize Components
	ac.humanoid = humanoid.New(ac.globalConfig.Browser.Humanoid, ac.logger, browserContextID)
	ac.harvester = NewHarvester(sessionCtx, ac.logger, ac.globalConfig.Network.CaptureResponseBodies)
	stabilizeFn := func(c context.Context) error {
		idleCtx, cancelIdle := context.WithTimeout(c, networkIdleMaxWait)
		defer cancelIdle()
		return ac.harvester.WaitNetworkIdle(idleCtx, networkIdleQuietPeriod)
	}
	ac.interactor = NewInteractor(ac.logger, ac.humanoid, stabilizeFn)

	chromedp.ListenTarget(sessionCtx, ac.eventListener)

	// 4. Apply Configuration and Start Harvester
	if err := ac.setupSession(sessionCtx); err != nil {
		return fmt.Errorf("failed to setup session: %w", err)
	}

	// 5. Finalize Initialization State
	ac.mu.Lock()
	ac.sessionContext = sessionCtx
	ac.sessionCancel = cancelSession
	ac.browserContextID = browserContextID
	ac.isInitialized = true
	ac.mu.Unlock()

	success = true
	ac.logger.Info("Browser session initialized, instrumented, and ready.")
	ac.logger.Debug("Initialize: END")
	return nil
}

// createIsolatedTarget handles the CDP commands to create an incognito context and a blank tab within it.
func (ac *AnalysisContext) createIsolatedTarget(ctx context.Context) (cdp.BrowserContextID, target.ID, error) {
	// Create an isolated BrowserContext (incognito profile).
	browserContextID, err := target.CreateBrowserContext().Do(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to create browser context: %w", err)
	}

	// Create a new target (tab) within that isolated context.
	targetID, err := target.CreateTarget("about:blank").
		WithBrowserContextID(browserContextID).
		Do(ctx)
	if err != nil {
		// Clean up the orphaned browser context if target creation failed.
		ac.bestEffortCleanupBrowserContext(browserContextID)
		return "", "", fmt.Errorf("failed to create target: %w", err)
	}

	return browserContextID, targetID, nil
}

// setupSession applies initial configuration, instrumentation, and starts the harvester.
func (ac *AnalysisContext) setupSession(ctx context.Context) error {
	tasks := chromedp.Tasks{
		// Apply stealth evasions and persona settings.
		stealth.Apply(ac.persona, ac.logger),

		// Apply IAST instrumentation if available.
		chromedp.ActionFunc(func(c context.Context) error {
			if err := ac.applyInstrumentation(c); err != nil {
				// Non-critical error.
				ac.logger.Error("Failed to apply IAST instrumentation. Proceeding without runtime analysis.", zap.Error(err))
			}
			return nil
		}),

		// Start the Harvester (enables Network/Log/Runtime domains).
		chromedp.ActionFunc(func(c context.Context) error {
			if ac.harvester != nil {
				return ac.harvester.Start(c)
			}
			return nil
		}),
	}
	return tasks.Do(ctx)
}

// Navigate directs the browser session to a specific URL and waits for stabilization.
func (ac *AnalysisContext) Navigate(url string) error {
	ac.logger.Debug("Navigating to URL.", zap.String("url", url))
	ctx := ac.GetContext()
	if ctx.Err() != nil {
		return fmt.Errorf("session context is invalid before navigation: %w", ctx.Err())
	}

	// Principle 3: Apply specific timeout for navigation.
	// Accessing the newly added NavigationTimeout field.
	navTimeout := ac.globalConfig.Network.NavigationTimeout
	if navTimeout <= 0 {
		navTimeout = defaultNavigationTimeout
	}
	navCtx, cancelNav := context.WithTimeout(ctx, navTimeout)
	defer cancelNav()

	tasks := chromedp.Tasks{
		// Pre-navigation actions
		chromedp.ActionFunc(func(c context.Context) error {
			if ac.globalConfig.Browser.DisableCache {
				if err := network.SetCacheDisabled(true).Do(c); err != nil {
					ac.logger.Warn("Failed to disable browser cache", zap.Error(err))
				}
			}
			return ac.humanoid.CognitivePause(500, 200).Do(c)
		}),

		// Main navigation action
		chromedp.Navigate(url),

		// Principle 2: Wait Dynamically for the DOM to be ready.
		chromedp.WaitReady("body", chromedp.ByQuery),

		// Principle 2: Wait Dynamically for the network to stabilize.
		chromedp.ActionFunc(func(c context.Context) error {
			ac.logger.Debug("Waiting for post-load network stabilization.")
			// Use a specific timeout context for the stabilization wait (Principle 3).
			idleCtx, cancelIdle := context.WithTimeout(c, networkIdleMaxWait)
			defer cancelIdle()
			return ac.harvester.WaitNetworkIdle(idleCtx, networkIdleQuietPeriod)
		}),
	}

	if err := chromedp.Run(navCtx, tasks); err != nil {
		// Principle 5: Capture screenshot on failure.
		ac.logger.Error("Navigation failed. Capturing screenshot.", zap.Error(err), zap.String("url", url))
		// Use the original session context for the screenshot, not the potentially cancelled navCtx.
		ac.captureScreenshot(ctx)
		return fmt.Errorf("navigation failed: %w", err)
	}

	return nil
}

// Interact starts the automated interaction phase.
func (ac *AnalysisContext) Interact(config schemas.InteractionConfig) error {
	ac.logger.Debug("Starting automated humanoid interaction phase.")
	ctx := ac.GetContext()
	if ctx.Err() != nil {
		return fmt.Errorf("session context is invalid before interaction: %w", ctx.Err())
	}

	// Note: The RecursiveInteract implementation relies on the provided ctx having a timeout (Principle 3).
	// If the overall analysis task has a time limit, it should be enforced on the context passed here.
	err := ac.interactor.RecursiveInteract(ctx, config)
	if err != nil {
		// Principle 5: Capture screenshot if interaction fails.
		ac.captureScreenshot(ctx)
		return err
	}
	return nil
}

// CollectArtifacts gathers data collected during the session (HAR, DOM, Storage, Logs).
func (ac *AnalysisContext) CollectArtifacts() (*schemas.Artifacts, error) {
	ac.mu.Lock()
	if !ac.isInitialized {
		ac.mu.Unlock()
		return nil, fmt.Errorf("session is not initialized")
	}
	// Check if the session is still active for live artifact collection.
	isSessionActive := !ac.isClosed && ac.sessionContext != nil && ac.sessionContext.Err() == nil
	ac.mu.Unlock()

	ac.logger.Debug("Starting artifact collection.")
	artifacts := &schemas.Artifacts{}

	// 1. Collect Harvested Artifacts (HAR, Console Logs)
	// Use a background context with a timeout for harvester processing (Principle 3).
	harvesterCtx, cancelHarvester := context.WithTimeout(context.Background(), artifactCollectionTimeout)
	defer cancelHarvester()

	if ac.harvester != nil {
		artifacts.HAR, artifacts.ConsoleLogs = ac.harvester.Stop(harvesterCtx)
	}

	// 2. Collect Live Artifacts (DOM, Storage) - Only if the session is still active.
	if !isSessionActive {
		ac.logger.Debug("Session context closed, skipping live artifact collection (DOM, Storage).")
		return artifacts, nil
	}

	// Principle 3: Enforce a strict timeout for live collection using the active session context.
	liveCollectCtx, cancelLive := context.WithTimeout(ac.GetContext(), artifactCollectionTimeout)
	defer cancelLive()

	// Collect DOM and Storage concurrently.
	var domCaptureErr, storageErr error
	var wg sync.WaitGroup
	wg.Add(2)

	// DOM Collection
	go func() {
		defer wg.Done()
		var domContent string
		if err := chromedp.Run(liveCollectCtx, chromedp.OuterHTML("html", &domContent, chromedp.ByQuery)); err != nil {
			// Log error only if it wasn't caused by the context closing (e.g., timeout).
			if liveCollectCtx.Err() == nil {
				ac.logger.Error("Failed to collect final DOM snapshot.", zap.Error(err))
				domCaptureErr = err
			}
		} else {
			artifacts.DOM = domContent
		}
	}()

	// Storage Collection
	go func() {
		defer wg.Done()
		if err := ac.collectStorageState(liveCollectCtx, artifacts); err != nil {
			if liveCollectCtx.Err() == nil {
				ac.logger.Error("Failed to collect storage state.", zap.Error(err))
				storageErr = err
			}
		}
	}()

	wg.Wait()

	if domCaptureErr != nil || storageErr != nil {
		return artifacts, fmt.Errorf("artifact collection partially failed (DOM: %v, Storage: %v)", domCaptureErr, storageErr)
	}

	ac.logger.Debug("Artifact collection complete.")
	return artifacts, nil
}

// Close terminates the session, cleans up resources, and notifies the manager.
func (ac *AnalysisContext) Close(ctx context.Context) {
	ac.mu.Lock()
	if ac.isClosed {
		ac.mu.Unlock()
		return
	}
	// Mark as closed immediately to prevent new operations.
	ac.isClosed = true

	// Determine if unregistration is needed.
	shouldUnregister := ac.isInitialized && ac.observer != nil
	ac.mu.Unlock()

	// Unregister from the manager (Principle 4).
	if shouldUnregister {
		// We do this outside the lock.
		ac.observer.unregisterSession(ac)
	}

	// Perform the actual resource cleanup.
	ac.internalClose(ctx)
}

// internalClose handles the actual cleanup of browser resources (CDP context, target).
func (ac *AnalysisContext) internalClose(ctx context.Context) {
	ac.logger.Debug("internalClose: START", zap.String("session_id", ac.id))

	// Safely retrieve required fields.
	ac.mu.Lock()
	sessionCancel := ac.sessionCancel
	browserCtxID := ac.browserContextID
	controllerCtx := ac.controllerCtx
	harvester := ac.harvester
	ac.mu.Unlock()

	// 1. Stop the Harvester (if running)
	if harvester != nil {
		stopCtx, cancelStop := context.WithTimeout(context.Background(), artifactCollectionTimeout)
		defer cancelStop()
		harvester.Stop(stopCtx)
	}

	// 2. Cancel the session context (signals tasks in the tab to stop).
	if sessionCancel != nil {
		ac.logger.Debug("internalClose: Cancelling session context.")
		sessionCancel()
	}

	// 3. Dispose of the isolated BrowserContext (Principle 4).
	if browserCtxID != "" && controllerCtx != nil && controllerCtx.Err() == nil {
		disposeCtx, cancelDispose := context.WithTimeout(controllerCtx, contextDisposeTimeout)
		defer cancelDispose()

		ac.logger.Debug("internalClose: Disposing browser context...", zap.String("browserContextID", string(browserCtxID)))
		if err := target.DisposeBrowserContext(browserCtxID).Do(disposeCtx); err != nil {
			if controllerCtx.Err() == nil {
				ac.logger.Warn("Failed to dispose of browser context.", zap.Error(err))
			}
		} else {
			ac.logger.Debug("internalClose: Disposed browser context successfully.")
		}
	} else {
		ac.logger.Debug("internalClose: Skipping browser context disposal.",
			zap.Bool("hasID", browserCtxID != ""),
			zap.Bool("controllerValid", controllerCtx != nil && controllerCtx.Err() == nil),
		)
	}
	ac.logger.Debug("internalClose: END")
}

// -- Helper Functions, Storage, Instrumentation, etc. --

// GetContext provides safe access to the session context.
func (ac *AnalysisContext) GetContext() context.Context {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if !ac.isInitialized || ac.isClosed || ac.sessionContext == nil {
		// Return a cancelled context if the session is invalid.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return ac.sessionContext
}

func (ac *AnalysisContext) ID() string {
	return ac.id
}

// GetScreenshot returns the last captured screenshot, if any (Principle 5).
func (ac *AnalysisContext) GetScreenshot() []byte {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return ac.capturedScreenshot
}

// AddFinding is a helper method to append a finding to the context.
// This resolves the build error in the ATO analyzer.
func (ac *AnalysisContext) AddFinding(finding schemas.Finding) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.findings = append(ac.findings, finding)
}

// captureScreenshot attempts to take a full-page screenshot (Principle 5).
func (ac *AnalysisContext) captureScreenshot(ctx context.Context) {
	// Enforce a strict timeout for taking the screenshot (Principle 3).
	captureCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var screenshotData []byte
	if err := chromedp.Run(captureCtx, chromedp.FullScreenshot(&screenshotData, 80)); err != nil {
		// Log only if the error wasn't due to context cancellation.
		if captureCtx.Err() == nil && ctx.Err() == nil {
			ac.logger.Warn("Failed to capture screenshot.", zap.Error(err))
		}
		return
	}

	ac.mu.Lock()
	ac.capturedScreenshot = screenshotData
	ac.mu.Unlock()
	ac.logger.Info("Screenshot captured successfully.", zap.Int("size_bytes", len(screenshotData)))
}

// bestEffortCleanupBrowserContext is used during failed initialization.
func (ac *AnalysisContext) bestEffortCleanupBrowserContext(id cdp.BrowserContextID) {
	if ac.controllerCtx == nil || ac.controllerCtx.Err() != nil {
		return
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(ac.controllerCtx, 5*time.Second)
	defer cleanupCancel()
	if err := target.DisposeBrowserContext(id).Do(cleanupCtx); err != nil {
		ac.logger.Debug("Failed best-effort cleanup of orphaned browser context.", zap.String("browserContextID", string(id)), zap.Error(err))
	}
}

// getContextDeadline helper to safely retrieve a context deadline.
func getContextDeadline(ctx context.Context) time.Time {
	deadline, ok := ctx.Deadline()
	if !ok {
		// If no deadline is set, return a time far in the future.
		return time.Now().Add(24 * time.Hour)
	}
	return deadline
}

// applyInstrumentation injects the IAST shim.
func (ac *AnalysisContext) applyInstrumentation(ctx context.Context) error {
	if ac.taintShimTemplate == "" {
		return nil
	}
	script, err := shim.BuildTaintShim(ac.taintShimTemplate, ac.taintConfigJSON)
	if err != nil {
		return fmt.Errorf("failed to build taint shim script: %w", err)
	}
	const callbackName = "scalpel_sink_event"
	// Expose the callback function to JavaScript.
	if err := runtime.AddBinding(callbackName).Do(ctx); err != nil {
		return fmt.Errorf("failed to expose taint callback (%s): %w", callbackName, err)
	}
	// Inject the script to run on every new document load.
	if _, err = page.AddScriptToEvaluateOnNewDocument(script).Do(ctx); err != nil {
		return fmt.Errorf("failed to inject taint shim persistently: %w", err)
	}
	ac.logger.Debug("IAST instrumentation applied successfully.")
	return nil
}

// eventListener handles various CDP events for the session.
func (ac *AnalysisContext) eventListener(ev interface{}) {
	// Handle instrumentation bindings.
	if binding, ok := ev.(*runtime.EventBindingCalled); ok {
		if binding.Name == "scalpel_sink_event" {
			ac.handleTaintEvent(binding.Payload)
		}
		return
	}

	// Handle JavaScript dialogs (alerts, prompts, confirms) to prevent hanging the browser.
	if msg, ok := ev.(*page.EventJavascriptDialogOpening); ok {
		ac.logger.Info("JavaScript dialog opened. Automatically handling.", zap.String("type", string(msg.Type)), zap.String("message", msg.Message))
		go ac.handleJSDialog(msg)
	}
}

// handleJSDialog automatically accepts JS dialogs.
func (ac *AnalysisContext) handleJSDialog(ev *page.EventJavascriptDialogOpening) {
	ctx := ac.GetContext()
	if ctx.Err() != nil {
		return
	}
	// Principle 3: Timeout for handling the dialog.
	dialogCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Accept the dialog.
	err := page.HandleJavaScriptDialog(true).Do(dialogCtx)
	if err != nil && dialogCtx.Err() == nil {
		ac.logger.Warn("Failed to handle JavaScript dialog.", zap.Error(err))
	}
}

func (ac *AnalysisContext) handleTaintEvent(payload string) {
	// Placeholder: In a real implementation, this would parse the payload and generate a Finding.
	ac.logger.Info("Taint Sink Triggered (IAST Event)", zap.String("payload", payload))
}

// collectStorageState gathers cookies, localStorage, and sessionStorage.
func (ac *AnalysisContext) collectStorageState(ctx context.Context, artifacts *schemas.Artifacts) error {
	storageResult := schemas.StorageState{
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
	}

	// 1. Collect Cookies using the Storage domain (includes HttpOnly).
	// This requires the BrowserContextID.
	var cookies []*network.Cookie
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) (err error) {
		cookies, err = storage.GetCookies().WithBrowserContextID(ac.browserContextID).Do(c)
		return err
	}))

	storageResult.Cookies = cookies
	artifacts.Storage = storageResult

	if err != nil {
		ac.logger.Warn("Could not retrieve cookies via CDP. Proceeding with JS fallback for other storage.", zap.Error(err))
	}

	// 2. Collect LocalStorage and SessionStorage using JavaScript evaluation.
	return ac.collectStorageStateJSFallback(ctx, &storageResult)
}

// collectStorageStateJSFallback uses JavaScript evaluation to extract storage.
func (ac *AnalysisContext) collectStorageStateJSFallback(ctx context.Context, storageResult *schemas.StorageState) error {
	var jsStorage struct {
		LocalStorage   map[string]string `json:"localStorage"`
		SessionStorage map[string]string `json:"sessionStorage"`
	}

	// JavaScript snippet to safely collect storage data, handling potential SecurityErrors (e.g., cross-origin iframes).
	jsScript := `(function() {
        const result = { localStorage: {}, sessionStorage: {} };
        try {
            if (window.localStorage) {
                Object.assign(result.localStorage, localStorage);
            }
        } catch (e) {
            result.localStorage = { 'error': 'Access Denied: ' + e.message };
        }
        try {
            if (window.sessionStorage) {
                Object.assign(result.sessionStorage, sessionStorage);
            }
        } catch (e) {
            result.sessionStorage = { 'error': 'Access Denied: ' + e.message };
        }
        return result;
    })()`

	err := chromedp.Run(ctx,
		chromedp.Evaluate(jsScript, &jsStorage),
	)

	if err != nil {
		return fmt.Errorf("JS evaluation for storage retrieval failed: %w", err)
	}

	storageResult.LocalStorage = jsStorage.LocalStorage
	storageResult.SessionStorage = jsStorage.SessionStorage
	return nil
}
com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

const (
	// Timeouts (Principle 3)
	defaultNavigationTimeout  = 60 * time.Second
	artifactCollectionTimeout = 30 * time.Second
	contextDisposeTimeout     = 10 * time.Second
	finalSessionCloseWait     = 5 * time.Second

	// Stabilization (Principle 2)
	networkIdleQuietPeriod = 500 * time.Millisecond
	networkIdleMaxWait     = 15 * time.Second
)

// AnalysisContext represents a single, isolated browser session (equivalent to an incognito profile/tab).
type AnalysisContext struct {
	id           string
	globalConfig *config.Config
	logger       *zap.Logger
	persona      stealth.Persona

	// parentCtx is the context from the allocator, used as the parent for the session context.
	parentCtx context.Context
	// controllerCtx is the context of the main browser CDP session, used for creating/disposing BrowserContexts.
	controllerCtx context.Context
	// contextCreationLock is shared by the manager to synchronize context/target creation.
	contextCreationLock *sync.Mutex

	// sessionContext is the chromedp context specific to this session's target.
	sessionContext context.Context
	// sessionCancel cancels the sessionContext.
	sessionCancel context.CancelFunc
	// browserContextID is the ID of the isolated CDP BrowserContext.
	browserContextID cdp.BrowserContextID

	humanoid   *humanoid.Humanoid
	harvester  *Harvester
	interactor *Interactor

	taintShimTemplate string
	taintConfigJSON   string

	findings []schemas.Finding
	// capturedScreenshot stores the last screenshot taken (Principle 5).
	capturedScreenshot []byte

	// State synchronization
	isClosed      bool
	isInitialized bool
	mu            sync.Mutex

	// observer is the entity to notify when the session closes (the Manager).
	observer SessionLifecycleObserver
}

// NewAnalysisContext creates the structure for a new session but does not initialize the browser resources.
func NewAnalysisContext(
	parentCtx context.Context,
	controllerCtx context.Context,
	cfg *config.Config,
	logger *zap.Logger,
	persona stealth.Persona,
	taintTemplate string,
	taintConfig string,
	contextCreationLock *sync.Mutex,
	observer SessionLifecycleObserver,
) *AnalysisContext {
	id := uuid.New().String()
	l := logger.With(zap.String("session_id", id))
	return &AnalysisContext{
		id:                  id,
		parentCtx:           parentCtx,
		controllerCtx:       controllerCtx,
		contextCreationLock: contextCreationLock,
		globalConfig:        cfg,
		logger:              l,
		persona:             persona,
		taintShimTemplate:   taintTemplate,
		taintConfigJSON:     taintConfig,
		findings:            make([]schemas.Finding, 0),
		observer:            observer,
	}
}

// Initialize sets up the isolated browser context (incognito profile) and the target (tab).
func (ac *AnalysisContext) Initialize(ctx context.Context) error {
	ac.mu.Lock()
	if ac.isInitialized {
		ac.mu.Unlock()
		return fmt.Errorf("session already initialized")
	}
	ac.mu.Unlock()

	// Ensure cleanup if initialization fails at any point.
	success := false
	defer func() {
		if !success {
			// Use a background context for cleanup if the initialization context is already cancelled.
			cleanupCtx, cancel := context.WithTimeout(context.Background(), contextDisposeTimeout)
			defer cancel()
			ac.internalClose(cleanupCtx)
		}
	}()

	// 1. Create the Isolated Browser Context and Target (Synchronized)
	// Principle 1 implementation: Manually creating isolated context.
	ac.contextCreationLock.Lock()

	if err := ctx.Err(); err != nil {
		ac.contextCreationLock.Unlock()
		return fmt.Errorf("context cancelled before creating browser context: %w", err)
	}

	// We use the controllerCtx for these commands, but respect the deadline of the initialization ctx.
	initCmdCtx, cancelInitCmd := context.WithDeadline(ac.controllerCtx, getContextDeadline(ctx))
	defer cancelInitCmd()

	browserContextID, targetID, err := ac.createIsolatedTarget(initCmdCtx)
	if err != nil {
		ac.contextCreationLock.Unlock()
		return err
	}

	// 2. Create the Chromedp Context for the new Target
	// We derive from the parentCtx (allocator context).
	sessionCtx, cancelSession := chromedp.NewContext(ac.parentCtx, chromedp.WithTargetID(targetID))

	// We can release the lock now that the target is created and attached.
	ac.contextCreationLock.Unlock()

	// 3. Initialize Components
	ac.humanoid = humanoid.New(ac.globalConfig.Browser.Humanoid, ac.logger, browserContextID)
	// Principle 6: Initialize Harvester
	ac.harvester = NewHarvester(sessionCtx, ac.logger, ac.globalConfig.Network.CaptureResponseBodies)

	// Principle 2: Define the dynamic stabilization function for the Interactor.
	stabilizeFn := func(c context.Context) error {
		ac.logger.Debug("Interactor waiting for stabilization (network idle).")
		// Apply specific timeout for stabilization wait (Principle 3).
		idleCtx, cancelIdle := context.WithTimeout(c, networkIdleMaxWait)
		defer cancelIdle()
		return ac.harvester.WaitNetworkIdle(idleCtx, networkIdleQuietPeriod)
	}
	ac.interactor = NewInteractor(ac.logger, ac.humanoid, stabilizeFn)

	// Listen for custom events (e.g., IAST instrumentation callbacks).
	chromedp.ListenTarget(sessionCtx, ac.eventListener)

	// 4. Apply Configuration and Start Harvester
	if err := ac.setupSession(sessionCtx); err != nil {
		return fmt.Errorf("failed to setup session: %w", err)
	}

	// 5. Finalize Initialization State
	ac.mu.Lock()
	ac.sessionContext = sessionCtx
	ac.sessionCancel = cancelSession
	ac.browserContextID = browserContextID
	ac.isInitialized = true
	ac.mu.Unlock()

	success = true
	ac.logger.Info("Browser session initialized, instrumented, and ready.")
	return nil
}

// createIsolatedTarget handles the CDP commands to create an incognito context and a blank tab within it.
func (ac *AnalysisContext) createIsolatedTarget(ctx context.Context) (cdp.BrowserContextID, target.ID, error) {
	// Create an isolated BrowserContext (incognito profile).
	browserContextID, err := target.CreateBrowserContext().Do(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to create browser context: %w", err)
	}

	// Create a new target (tab) within that isolated context.
	targetID, err := target.CreateTarget("about:blank").
		WithBrowserContextID(browserContextID).
		Do(ctx)
	if err != nil {
		// Clean up the orphaned browser context if target creation failed.
		ac.bestEffortCleanupBrowserContext(browserContextID)
		return "", "", fmt.Errorf("failed to create target: %w", err)
	}

	return browserContextID, targetID, nil
}

// setupSession applies initial configuration, instrumentation, and starts the harvester.
func (ac *AnalysisContext) setupSession(ctx context.Context) error {
	tasks := chromedp.Tasks{
		// Apply stealth evasions and persona settings.
		stealth.Apply(ac.persona, ac.logger),

		// Apply IAST instrumentation if available.
		chromedp.ActionFunc(func(c context.Context) error {
			if err := ac.applyInstrumentation(c); err != nil {
				// Non-critical error.
				ac.logger.Error("Failed to apply IAST instrumentation. Proceeding without runtime analysis.", zap.Error(err))
			}
			return nil
		}),

		// Start the Harvester (enables Network/Log/Runtime domains).
		chromedp.ActionFunc(func(c context.Context) error {
			if ac.harvester != nil {
				return ac.harvester.Start(c)
			}
			return nil
		}),
	}
	return tasks.Do(ctx)
}

// Navigate directs the browser session to a specific URL and waits for stabilization.
func (ac *AnalysisContext) Navigate(url string) error {
	ac.logger.Debug("Navigating to URL.", zap.String("url", url))
	ctx := ac.GetContext()
	if ctx.Err() != nil {
		return fmt.Errorf("session context is invalid before navigation: %w", ctx.Err())
	}

	// Principle 3: Apply specific timeout for navigation.
	// Accessing the newly added NavigationTimeout field.
	navTimeout := ac.globalConfig.Network.NavigationTimeout
	if navTimeout <= 0 {
		navTimeout = defaultNavigationTimeout
	}
	navCtx, cancelNav := context.WithTimeout(ctx, navTimeout)
	defer cancelNav()

	tasks := chromedp.Tasks{
		// Pre-navigation actions
		chromedp.ActionFunc(func(c context.Context) error {
			if ac.globalConfig.Browser.DisableCache {
				if err := network.SetCacheDisabled(true).Do(c); err != nil {
					ac.logger.Warn("Failed to disable browser cache", zap.Error(err))
				}
			}
			return ac.humanoid.CognitivePause(500, 200).Do(c)
		}),

		// Main navigation action
		chromedp.Navigate(url),

		// Principle 2: Wait Dynamically for the DOM to be ready.
		chromedp.WaitReady("body", chromedp.ByQuery),

		// Principle 2: Wait Dynamically for the network to stabilize.
		chromedp.ActionFunc(func(c context.Context) error {
			ac.logger.Debug("Waiting for post-load network stabilization.")
			// Use a specific timeout context for the stabilization wait (Principle 3).
			idleCtx, cancelIdle := context.WithTimeout(c, networkIdleMaxWait)
			defer cancelIdle()
			return ac.harvester.WaitNetworkIdle(idleCtx, networkIdleQuietPeriod)
		}),
	}

	if err := chromedp.Run(navCtx, tasks); err != nil {
		// Principle 5: Capture screenshot on failure.
		ac.logger.Error("Navigation failed. Capturing screenshot.", zap.Error(err), zap.String("url", url))
		// Use the original session context for the screenshot, not the potentially cancelled navCtx.
		ac.captureScreenshot(ctx)
		return fmt.Errorf("navigation failed: %w", err)
	}

	return nil
}

// Interact starts the automated interaction phase.
func (ac *AnalysisContext) Interact(config schemas.InteractionConfig) error {
	ac.logger.Debug("Starting automated humanoid interaction phase.")
	ctx := ac.GetContext()
	if ctx.Err() != nil {
		return fmt.Errorf("session context is invalid before interaction: %w", ctx.Err())
	}

	// Note: The RecursiveInteract implementation relies on the provided ctx having a timeout (Principle 3).
	// If the overall analysis task has a time limit, it should be enforced on the context passed here.
	err := ac.interactor.RecursiveInteract(ctx, config)
	if err != nil {
		// Principle 5: Capture screenshot if interaction fails.
		ac.captureScreenshot(ctx)
		return err
	}
	return nil
}

// CollectArtifacts gathers data collected during the session (HAR, DOM, Storage, Logs).
func (ac *AnalysisContext) CollectArtifacts() (*schemas.Artifacts, error) {
	ac.mu.Lock()
	if !ac.isInitialized {
		ac.mu.Unlock()
		return nil, fmt.Errorf("session is not initialized")
	}
	// Check if the session is still active for live artifact collection.
	isSessionActive := !ac.isClosed && ac.sessionContext != nil && ac.sessionContext.Err() == nil
	ac.mu.Unlock()

	ac.logger.Debug("Starting artifact collection.")
	artifacts := &schemas.Artifacts{}

	// 1. Collect Harvested Artifacts (HAR, Console Logs)
	// Use a background context with a timeout for harvester processing (Principle 3).
	harvesterCtx, cancelHarvester := context.WithTimeout(context.Background(), artifactCollectionTimeout)
	defer cancelHarvester()

	if ac.harvester != nil {
		artifacts.HAR, artifacts.ConsoleLogs = ac.harvester.Stop(harvesterCtx)
	}

	// 2. Collect Live Artifacts (DOM, Storage) - Only if the session is still active.
	if !isSessionActive {
		ac.logger.Debug("Session context closed, skipping live artifact collection (DOM, Storage).")
		return artifacts, nil
	}

	// Principle 3: Enforce a strict timeout for live collection using the active session context.
	liveCollectCtx, cancelLive := context.WithTimeout(ac.GetContext(), artifactCollectionTimeout)
	defer cancelLive()

	// Collect DOM and Storage concurrently.
	var domCaptureErr, storageErr error
	var wg sync.WaitGroup
	wg.Add(2)

	// DOM Collection
	go func() {
		defer wg.Done()
		var domContent string
		if err := chromedp.Run(liveCollectCtx, chromedp.OuterHTML("html", &domContent, chromedp.ByQuery)); err != nil {
			// Log error only if it wasn't caused by the context closing (e.g., timeout).
			if liveCollectCtx.Err() == nil {
				ac.logger.Error("Failed to collect final DOM snapshot.", zap.Error(err))
				domCaptureErr = err
			}
		} else {
			artifacts.DOM = domContent
		}
	}()

	// Storage Collection
	go func() {
		defer wg.Done()
		if err := ac.collectStorageState(liveCollectCtx, artifacts); err != nil {
			if liveCollectCtx.Err() == nil {
				ac.logger.Error("Failed to collect storage state.", zap.Error(err))
				storageErr = err
			}
		}
	}()

	wg.Wait()

	if domCaptureErr != nil || storageErr != nil {
		return artifacts, fmt.Errorf("artifact collection partially failed (DOM: %v, Storage: %v)", domCaptureErr, storageErr)
	}

	ac.logger.Debug("Artifact collection complete.")
	return artifacts, nil
}

// Close terminates the session, cleans up resources, and notifies the manager.
func (ac *AnalysisContext) Close(ctx context.Context) {
	ac.mu.Lock()
	if ac.isClosed {
		ac.mu.Unlock()
		return
	}
	// Mark as closed immediately to prevent new operations.
	ac.isClosed = true

	// Determine if unregistration is needed.
	shouldUnregister := ac.isInitialized && ac.observer != nil
	ac.mu.Unlock()

	// Unregister from the manager (Principle 4).
	if shouldUnregister {
		// We do this outside the lock.
		ac.observer.unregisterSession(ac)
	}

	// Perform the actual resource cleanup.
	ac.internalClose(ctx)
}

// internalClose handles the actual cleanup of browser resources (CDP context, target).
func (ac *AnalysisContext) internalClose(ctx context.Context) {
	ac.logger.Debug("Closing analysis context.")

	// Safely retrieve required fields.
	ac.mu.Lock()
	sessionCtx := ac.sessionContext
	sessionCancel := ac.sessionCancel
	browserCtxID := ac.browserContextID
	controllerCtx := ac.controllerCtx
	harvester := ac.harvester
	ac.mu.Unlock()

	// 1. Stop the Harvester (if running)
	if harvester != nil {
		// Use a background context with timeout for cleanup (Principle 3).
		stopCtx, cancelStop := context.WithTimeout(context.Background(), artifactCollectionTimeout)
		defer cancelStop()
		harvester.Stop(stopCtx)
	}

	// 2. Cancel the session context (signals tasks in the tab to stop).
	if sessionCancel != nil {
		sessionCancel()
	}

	// 3. Dispose of the isolated BrowserContext (Principle 4).
	// This is crucial when manually managing contexts. Check if controllerCtx is valid.
	if browserCtxID != "" && controllerCtx != nil && controllerCtx.Err() == nil {
		// Enforce a strict timeout for the disposal command.
		disposeCtx, cancelDispose := context.WithTimeout(controllerCtx, contextDisposeTimeout)
		defer cancelDispose()

		if err := target.DisposeBrowserContext(browserCtxID).Do(disposeCtx); err != nil {
			// Log if the failure wasn't due to the controller shutting down.
			if controllerCtx.Err() == nil {
				ac.logger.Warn("Failed to dispose of browser context. It may be orphaned.",
					zap.String("browserContextID", string(browserCtxID)),
					zap.Error(err),
				)
			}
		} else {
			ac.logger.Debug("Disposed browser context.", zap.String("browserContextID", string(browserCtxID)))
		}
	}

	// 4. Wait for the session context to be fully closed.
	if sessionCtx != nil {
		select {
		case <-sessionCtx.Done():
			ac.logger.Debug("Browser session context closed.")
		case <-ctx.Done():
			// The external closing context timed out.
			ac.logger.Warn("Context cancelled while waiting for session close.", zap.Error(ctx.Err()))
		case <-time.After(finalSessionCloseWait):
			// Hard timeout waiting for the tab to close.
			ac.logger.Warn("Timeout waiting for browser session context to close.")
		}
	}
}

// -- Helper Functions, Storage, Instrumentation, etc. --

// GetContext provides safe access to the session context.
func (ac *AnalysisContext) GetContext() context.Context {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if !ac.isInitialized || ac.isClosed || ac.sessionContext == nil {
		// Return a cancelled context if the session is invalid.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return ac.sessionContext
}

func (ac *AnalysisContext) ID() string {
	return ac.id
}

// GetScreenshot returns the last captured screenshot, if any (Principle 5).
func (ac *AnalysisContext) GetScreenshot() []byte {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return ac.capturedScreenshot
}

// AddFinding is a helper method to append a finding to the context.
// This resolves the build error in the ATO analyzer.
func (ac *AnalysisContext) AddFinding(finding schemas.Finding) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.findings = append(ac.findings, finding)
}

// captureScreenshot attempts to take a full-page screenshot (Principle 5).
func (ac *AnalysisContext) captureScreenshot(ctx context.Context) {
	// Enforce a strict timeout for taking the screenshot (Principle 3).
	captureCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var screenshotData []byte
	if err := chromedp.Run(captureCtx, chromedp.FullScreenshot(&screenshotData, 80)); err != nil {
		// Log only if the error wasn't due to context cancellation.
		if captureCtx.Err() == nil && ctx.Err() == nil {
			ac.logger.Warn("Failed to capture screenshot.", zap.Error(err))
		}
		return
	}

	ac.mu.Lock()
	ac.capturedScreenshot = screenshotData
	ac.mu.Unlock()
	ac.logger.Info("Screenshot captured successfully.", zap.Int("size_bytes", len(screenshotData)))
}

// bestEffortCleanupBrowserContext is used during failed initialization.
func (ac *AnalysisContext) bestEffortCleanupBrowserContext(id cdp.BrowserContextID) {
	if ac.controllerCtx == nil || ac.controllerCtx.Err() != nil {
		return
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(ac.controllerCtx, 5*time.Second)
	defer cleanupCancel()
	if err := target.DisposeBrowserContext(id).Do(cleanupCtx); err != nil {
		ac.logger.Debug("Failed best-effort cleanup of orphaned browser context.", zap.String("browserContextID", string(id)), zap.Error(err))
	}
}

// getContextDeadline helper to safely retrieve a context deadline.
func getContextDeadline(ctx context.Context) time.Time {
	deadline, ok := ctx.Deadline()
	if !ok {
		// If no deadline is set, return a time far in the future.
		return time.Now().Add(24 * time.Hour)
	}
	return deadline
}

// applyInstrumentation injects the IAST shim.
func (ac *AnalysisContext) applyInstrumentation(ctx context.Context) error {
	if ac.taintShimTemplate == "" {
		return nil
	}
	script, err := shim.BuildTaintShim(ac.taintShimTemplate, ac.taintConfigJSON)
	if err != nil {
		return fmt.Errorf("failed to build taint shim script: %w", err)
	}
	const callbackName = "scalpel_sink_event"
	// Expose the callback function to JavaScript.
	if err := runtime.AddBinding(callbackName).Do(ctx); err != nil {
		return fmt.Errorf("failed to expose taint callback (%s): %w", callbackName, err)
	}
	// Inject the script to run on every new document load.
	if _, err = page.AddScriptToEvaluateOnNewDocument(script).Do(ctx); err != nil {
		return fmt.Errorf("failed to inject taint shim persistently: %w", err)
	}
	ac.logger.Debug("IAST instrumentation applied successfully.")
	return nil
}

// eventListener handles various CDP events for the session.
func (ac *AnalysisContext) eventListener(ev interface{}) {
	// Handle instrumentation bindings.
	if binding, ok := ev.(*runtime.EventBindingCalled); ok {
		if binding.Name == "scalpel_sink_event" {
			ac.handleTaintEvent(binding.Payload)
		}
		return
	}

	// Handle JavaScript dialogs (alerts, prompts, confirms) to prevent hanging the browser.
	if msg, ok := ev.(*page.EventJavascriptDialogOpening); ok {
		ac.logger.Info("JavaScript dialog opened. Automatically handling.", zap.String("type", string(msg.Type)), zap.String("message", msg.Message))
		go ac.handleJSDialog(msg)
	}
}

// handleJSDialog automatically accepts JS dialogs.
func (ac *AnalysisContext) handleJSDialog(ev *page.EventJavascriptDialogOpening) {
	ctx := ac.GetContext()
	if ctx.Err() != nil {
		return
	}
	// Principle 3: Timeout for handling the dialog.
	dialogCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Accept the dialog.
	err := page.HandleJavaScriptDialog(true).Do(dialogCtx)
	if err != nil && dialogCtx.Err() == nil {
		ac.logger.Warn("Failed to handle JavaScript dialog.", zap.Error(err))
	}
}

func (ac *AnalysisContext) handleTaintEvent(payload string) {
	// Placeholder: In a real implementation, this would parse the payload and generate a Finding.
	ac.logger.Info("Taint Sink Triggered (IAST Event)", zap.String("payload", payload))
}

// collectStorageState gathers cookies, localStorage, and sessionStorage.
func (ac *AnalysisContext) collectStorageState(ctx context.Context, artifacts *schemas.Artifacts) error {
	storageResult := schemas.StorageState{
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
	}

	// 1. Collect Cookies using the Storage domain (includes HttpOnly).
	// This requires the BrowserContextID.
	var cookies []*network.Cookie
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) (err error) {
		cookies, err = storage.GetCookies().WithBrowserContextID(ac.browserContextID).Do(c)
		return err
	}))

	storageResult.Cookies = cookies
	artifacts.Storage = storageResult

	if err != nil {
		ac.logger.Warn("Could not retrieve cookies via CDP. Proceeding with JS fallback for other storage.", zap.Error(err))
	}

	// 2. Collect LocalStorage and SessionStorage using JavaScript evaluation.
	return ac.collectStorageStateJSFallback(ctx, &storageResult)
}

// collectStorageStateJSFallback uses JavaScript evaluation to extract storage.
func (ac *AnalysisContext) collectStorageStateJSFallback(ctx context.Context, storageResult *schemas.StorageState) error {
	var jsStorage struct {
		LocalStorage   map[string]string `json:"localStorage"`
		SessionStorage map[string]string `json:"sessionStorage"`
	}

	// JavaScript snippet to safely collect storage data, handling potential SecurityErrors (e.g., cross-origin iframes).
	jsScript := `(function() {
        const result = { localStorage: {}, sessionStorage: {} };
        try {
            if (window.localStorage) {
                Object.assign(result.localStorage, localStorage);
            }
        } catch (e) {
            result.localStorage = { 'error': 'Access Denied: ' + e.message };
        }
        try {
            if (window.sessionStorage) {
                Object.assign(result.sessionStorage, sessionStorage);
            }
        } catch (e) {
            result.sessionStorage = { 'error': 'Access Denied: ' + e.message };
        }
        return result;
    })()`

	err := chromedp.Run(ctx,
		chromedp.Evaluate(jsScript, &jsStorage),
	)

	if err != nil {
		return fmt.Errorf("JS evaluation for storage retrieval failed: %w", err)
	}

	storageResult.LocalStorage = jsStorage.LocalStorage
	storageResult.SessionStorage = jsStorage.SessionStorage
	return nil
}
