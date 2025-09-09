// internal/browser/analysis_context.go
package browser

import (
	"context"
	"fmt"
	"sync"
	"time"

	// Required for low-level CDP access to network, page, storage, and context management.
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/storage"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	// Project specific imports
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/shim"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
)

// Define constants for timeouts.
const (
	// artifactCollectionTimeout is the maximum time allowed for collecting final artifacts.
	artifactCollectionTimeout = 30 * time.Second
	// closeTimeout is the maximum time to wait for the browser tab to close gracefully.
	closeTimeout = 15 * time.Second
	// initializationTimeout is the maximum time allowed for initializing the session (tab creation, instrumentation).
	initializationTimeout = 45 * time.Second
)

// Ensure AnalysisContext implements the required interface.
var _ interfaces.SessionContext = (*AnalysisContext)(nil)

// AnalysisContext manages a single, isolated browser tab (session) using CDP.
type AnalysisContext struct {
	id               string
	globalConfig     *config.Config
	logger           *zap.Logger
	persona          stealth.Persona
	allocatorContext context.Context // Context of the main browser process.

	// Session specific resources.
	sessionContext   context.Context      // Context for the specific tab (Target).
	sessionCancel    context.CancelFunc
	browserContextID cdp.BrowserContextID // Required for precise Humanoid targeting.
	humanoid         *humanoid.Humanoid
	harvester        *Harvester
	interactor       *Interactor

	// Instrumentation configuration 
	taintShimTemplate string
	taintConfigJSON   string

	// State management.
	isClosed      bool
	isInitialized bool
	mu            sync.Mutex // Protects the state variables and session resources.
}

// NewAnalysisContext creates a new context structure. Initialize() must be called next.
func NewAnalysisContext(
	allocCtx context.Context,
	cfg *config.Config,
	logger *zap.Logger,
	persona stealth.Persona,
	taintTemplate string,
	taintConfig string,
) *AnalysisContext {
	id := uuid.New().String()
	// Create a logger instance specific to this session.
	l := logger.With(zap.String("session_id", id))

	return &AnalysisContext{
		id:                id,
		allocatorContext:  allocCtx,
		globalConfig:      cfg,
		logger:            l,
		persona:           persona,
		taintShimTemplate: taintTemplate,
		taintConfigJSON:   taintConfig,
	}
}

// Initialize creates the browser tab (context) and applies all necessary instrumentation and stealth measures.
func (ac *AnalysisContext) Initialize(ctx context.Context) error {
	ac.mu.Lock()
	// Check state but release lock before long-running browser operations.
	if ac.isInitialized {
		ac.mu.Unlock()
		return fmt.Errorf("session already initialized")
	}
	ac.mu.Unlock()

	// Create a new tab context derived from the main browser allocator.
	// We must capture the BrowserContextID during creation for the Humanoid instance.
	var browserContextID cdp.BrowserContextID
	sessionCtx, cancel := chromedp.NewContext(ac.allocatorContext, chromedp.WithBrowserOption(
		// This option ensures an isolated context is created and its ID is captured.
		chromedp.WithBrowserContextID(&browserContextID),
	))

	// Ensure the context (Target connection) is fully initialized by chromedp.
	if err := chromedp.Run(sessionCtx); err != nil {
		cancel() // Clean up the context if the initial run fails.
		return fmt.Errorf("failed to initialize session target connection: %w", err)
	}

	ac.mu.Lock()
	ac.sessionContext = sessionCtx
	ac.sessionCancel = cancel
	ac.browserContextID = browserContextID
	ac.mu.Unlock()

	// Ensure robust cleanup if initialization fails partway through.
	success := false
	defer func() {
		if !success {
			ac.logger.Warn("Initialization failed, cleaning up session resources.")
			// Use a background context for cleanup as the provided ctx might already be cancelled.
			ac.Close(context.Background())
		}
	}()

	// Initialize helpers/components.
	// Initialize Humanoid now that we have the definitive BrowserContextID.
	ac.humanoid = humanoid.New(ac.globalConfig.Humanoid, ac.logger, ac.browserContextID)

	// Initialize the Harvester.
	captureBodies := ac.globalConfig.Network.CaptureResponseBodies
	ac.harvester = NewHarvester(ac.sessionContext, ac.logger, captureBodies)
	ac.interactor = NewInteractor(ac.logger, ac.humanoid)

	// Apply instrumentation and stealth within a defined timeout.
	initCtx, cancelInit := context.WithTimeout(ctx, initializationTimeout)
	defer cancelInit()

	// Create a derived context that bridges the session context (for execution target)
	// and the initialization context (for timeout enforcement).
	runCtx, runCancel := chromedp.NewContext(ac.sessionContext, chromedp.WithParentContext(initCtx))
	defer runCancel()

	// Apply configurations and instrumentation. Order is crucial.
	if err := ac.setupSession(runCtx); err != nil {
		return fmt.Errorf("failed to setup session: %w", err)
	}

	// Start the harvester to begin capturing events immediately.
	ac.harvester.Start()

	// Initialize the humanoid cursor position realistically within the viewport.
	if err := ac.humanoid.InitializePosition(runCtx); err != nil {
		// Non-fatal error, but should be logged.
		ac.logger.Warn("Failed to initialize humanoid cursor position.", zap.Error(err))
	}

	ac.mu.Lock()
	ac.isInitialized = true
	ac.mu.Unlock()

	success = true
	ac.logger.Info("Browser session initialized, instrumented, and ready.")
	return nil
}

// setupSession applies stealth measures and IAST instrumentation.
func (ac *AnalysisContext) setupSession(ctx context.Context) error {
	// Use chromedp.Tasks to define the setup sequence.
	tasks := chromedp.Tasks{
		// 1. Apply Stealth measures first.
		chromedp.ActionFunc(func(c context.Context) error {
			if err := ac.applyStealth(c); err != nil {
				return fmt.Errorf("failed to apply stealth: %w", err)
			}
			return nil
		}),

		// 2. Apply IAST instrumentation (Pinnacle Runtime).
		chromedp.ActionFunc(func(c context.Context) error {
			if err := ac.applyInstrumentation(c); err != nil {
				// Non-fatal: allow the session to continue without IAST if injection fails.
				ac.logger.Error("Failed to apply IAST instrumentation. Proceeding without runtime analysis.", zap.Error(err))
			}
			return nil
		}),
	}

	return tasks.Do(ctx)
}

func (ac *AnalysisContext) applyStealth(ctx context.Context) error {
	// The stealth package returns a chromedp.Action (Tasks). We execute it immediately.
	if err := stealth.Apply(ac.persona, ac.logger).Do(ctx); err != nil {
		return fmt.Errorf("failed to apply stealth persona: %w", err)
	}
	return nil
}

func (ac *AnalysisContext) applyInstrumentation(ctx context.Context) error {
	if ac.taintShimTemplate == "" {
		return nil
	}

	// 1. Build the Taint Shim script.
	script, err := shim.BuildTaintShim(ac.taintShimTemplate, ac.taintConfigJSON)
	if err != nil {
		return fmt.Errorf("failed to build taint shim script: %w", err)
	}

	// 2. Expose the Go callback function to the JavaScript environment.
	const callbackName = "scalpel_sink_event"
	if err = chromedp.Expose(callbackName, ac.handleTaintEvent).Do(ctx); err != nil {
		return fmt.Errorf("failed to expose taint callback (%s): %w", callbackName, err)
	}

	// 3. Inject the script persistently.
	if _, err = page.AddScriptToEvaluateOnNewDocument(script).Do(ctx); err != nil {
		return fmt.Errorf("failed to inject taint shim persistently: %w", err)
	}

	ac.logger.Debug("IAST instrumentation applied successfully.")
	return nil
}

// handleTaintEvent is the callback invoked by the JavaScript shim when a monitored sink is triggered.
func (ac *AnalysisContext) handleTaintEvent(event map[string]interface{}) {
	// This function executes outside the main event loop; logging is thread-safe.
	ac.logger.Info("Taint Sink Triggered (IAST Event)",
		zap.String("type", fmt.Sprintf("%v", event["type"])),
		zap.String("detail", fmt.Sprintf("%v", event["detail"])),
	)
}

// --- SessionContext Interface Implementation ---

// ID returns the unique identifier for this session.
func (ac *AnalysisContext) ID() string {
	return ac.id
}

// GetContext returns the underlying session context. It ensures the context is valid before returning.
func (ac *AnalysisContext) GetContext() context.Context {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	// Provide a safe, cancelled context if the session is not ready or already closed.
	if !ac.isInitialized || ac.isClosed {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return ac.sessionContext
}

// InjectScriptPersistently ensures a script is executed on every new document load.
func (ac *AnalysisContext) InjectScriptPersistently(script string) error {
	action := chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(script).Do(ctx)
		return err
	})
	// Execute using GetContext() to ensure a valid target context.
	return chromedp.Run(ac.GetContext(), action)
}

// Navigate loads a URL and waits for the page to be ready and settled, integrating humanoid behavior.
func (ac *AnalysisContext) Navigate(url string) error {
	ac.logger.Debug("Navigating to URL.", zap.String("url", url))

	ctx := ac.GetContext()
	if ctx.Err() != nil {
		return fmt.Errorf("session context is invalid before navigation: %w", ctx.Err())
	}

	tasks := chromedp.Tasks{
		// 1. Pre-navigation configuration and initial pause.
		chromedp.ActionFunc(func(c context.Context) error {
			if ac.globalConfig.Browser.DisableCache {
				if err := network.SetCacheDisabled(true).Do(c); err != nil {
					return fmt.Errorf("failed to disable cache: %w", err)
				}
			}
			// Cognitive pause before initiating navigation.
			return ac.humanoid.CognitivePause(500, 200).Do(c)
		}),

		// 2. Navigation.
		chromedp.Navigate(url),

		// 3. Wait for initial load readiness.
		chromedp.WaitReady("body", chromedp.ByQuery),

		// 4. Post-load stabilization (Wait for async operations).
		chromedp.ActionFunc(func(c context.Context) error {
			postLoadWait := ac.globalConfig.Network.PostLoadWait
			if postLoadWait > 0 {
				ac.logger.Debug("Waiting for post-load stabilization (Hesitation).", zap.Duration("duration", postLoadWait))
				// Use humanoid.Hesitate to simulate idling.
				if err := ac.humanoid.Hesitate(postLoadWait).Do(c); err != nil {
					return err // Context cancelled during wait.
				}
			}
			return nil
		}),
	}

	if err := chromedp.Run(ctx, tasks); err != nil {
		return fmt.Errorf("navigation failed: %w", err)
	}

	return nil
}

// Interact uses the Interactor helper to automatically explore the page state space using the humanoid engine.
func (ac *AnalysisContext) Interact(config schemas.InteractionConfig) error {
	ac.logger.Debug("Starting automated humanoid interaction phase.")
	return ac.interactor.RecursiveInteract(ac.GetContext(), config)
}

// CollectArtifacts gathers all data from the session (HAR, DOM, Storage, Logs) before closing.
func (ac *AnalysisContext) CollectArtifacts() (*schemas.Artifacts, error) {
	ac.mu.Lock()
	if ac.isClosed || !ac.isInitialized {
		ac.mu.Unlock()
		return nil, fmt.Errorf("session is closed or not initialized")
	}
	sessionCtx := ac.sessionContext
	ac.mu.Unlock()

	ac.logger.Debug("Starting artifact collection.")

	collectCtx, cancel := context.WithTimeout(sessionCtx, artifactCollectionTimeout)
	defer cancel()

	artifacts := &schemas.Artifacts{}
	var domCaptureErr error

	// 1. Capture final state (DOM Snapshot).
	var domContent string
	if err := chromedp.Run(collectCtx, chromedp.OuterHTML("html", &domContent, chromedp.ByQuery)); err != nil {
		ac.logger.Error("Failed to collect final DOM snapshot.", zap.Error(err))
		domCaptureErr = err
	} else {
		artifacts.DOM = domContent
	}

	// 2. Stop the harvester and retrieve active data (HAR and Console Logs).
	if ac.harvester != nil {
		artifacts.HAR, artifacts.ConsoleLogs = ac.harvester.Stop(collectCtx)
	}

	// 3. Capture Storage State (Cookies, Local/Session).
	if err := ac.collectStorageState(collectCtx, artifacts); err != nil {
		ac.logger.Error("Failed to collect storage state.", zap.Error(err))
		if artifacts.DOM == "" {
			return artifacts, fmt.Errorf("failed to retrieve DOM and storage state")
		}
	}
	
	if artifacts.DOM == "" && domCaptureErr != nil {
		return artifacts, fmt.Errorf("failed to retrieve DOM: %w", domCaptureErr)
	}

	ac.logger.Debug("Artifact collection complete.")
	return artifacts, nil
}

// collectStorageState implements a robust strategy for retrieving storage data using CDP with a JS fallback.
func (ac *AnalysisContext) collectStorageState(ctx context.Context, artifacts *schemas.Artifacts) error {
	storageResult := schemas.StorageState{
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
	}
	var cookies []*network.Cookie
	var frameTree *page.FrameTree

	// 1. Retrieve Cookies and FrameTree via CDP.
	err := chromedp.Run(ctx, chromedp.Tasks{
		chromedp.ActionFunc(func(c context.Context) (err error) {
			frameTree, err = page.GetFrameTree().Do(c)
			return err
		}),
		chromedp.ActionFunc(func(c context.Context) (err error) {
			cookies, err = network.GetAllCookies().Do(c)
			return err
		}),
	})

	storageResult.Cookies = cookies
	artifacts.Storage = storageResult

	if err != nil || frameTree == nil || frameTree.Frame == nil || frameTree.Frame.SecurityOrigin == "" {
		ac.logger.Debug("Could not determine security origin via CDP. Using JS fallback for storage.", zap.Error(err))
		return ac.collectStorageStateJSFallback(ctx, &storageResult)
	}

	// 2. Retrieve Local/Session Storage via CDP Storage Domain.
	securityOrigin := frameTree.Frame.SecurityOrigin
	storageID := &storage.StorageID{SecurityOrigin: securityOrigin}

	err = chromedp.Run(ctx, chromedp.Tasks{
		chromedp.ActionFunc(func(c context.Context) error {
			items, err := storage.GetLocalStorageItems(storageID).Do(c)
			if err != nil { return fmt.Errorf("CDP failed to get local storage: %w", err) }
			for _, item := range items {
				if len(item) == 2 { storageResult.LocalStorage[item[0]] = item[1] }
			}
			return nil
		}),
		chromedp.ActionFunc(func(c context.Context) error {
			items, err := storage.GetSessionStorageItems(storageID).Do(c)
			if err != nil { return fmt.Errorf("CDP failed to get session storage: %w", err) }
			for _, item := range items {
				if len(item) == 2 { storageResult.SessionStorage[item[0]] = item[1] }
			}
			return nil
		}),
	})

	if err == nil {
		return nil // Success using CDP
	}

	ac.logger.Debug("Failed to retrieve storage via CDP Storage Domain. Attempting JS fallback.", zap.Error(err))
	
	// 3. Fallback to JS Evaluation if CDP fails.
	return ac.collectStorageStateJSFallback(ctx, &storageResult)
}

// collectStorageStateJSFallback uses JavaScript evaluation to extract storage maps.
func (ac *AnalysisContext) collectStorageStateJSFallback(ctx context.Context, storageResult *schemas.StorageState) error {
	var jsStorage struct {
		LocalStorage   map[string]string `json:"localStorage"`
		SessionStorage map[string]string `json:"sessionStorage"`
	}

	// Evaluate JavaScript to retrieve storage objects safely.
	err := chromedp.Run(ctx,
		chromedp.Evaluate(
			`(function() {
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
			})()`, &jsStorage),
	)

	if err != nil {
		return fmt.Errorf("JS fallback storage retrieval failed: %w", err)
	}

	storageResult.LocalStorage = jsStorage.LocalStorage
	storageResult.SessionStorage = jsStorage.SessionStorage
	return nil
}

// Close safely terminates the browser tab and its associated resources.
func (ac *AnalysisContext) Close(ctx context.Context) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	return ac.internalClose(ctx)
}

// internalClose handles the closing logic. Must be called with the mutex held.
func (ac *AnalysisContext) internalClose(ctx context.Context) error {
	if ac.isClosed {
		return nil
	}

	if ac.sessionContext == nil {
		ac.isClosed = true
		return nil
	}

	ac.logger.Debug("Closing analysis context.")
	
	// Stop harvester, releasing lock temporarily for long operation.
	if ac.harvester != nil && ac.isInitialized {
		ac.mu.Unlock()
		ac.harvester.Stop(ctx)
		ac.mu.Lock()
	}

	if ac.sessionCancel != nil {
		ac.sessionCancel()
	}

	timeout := time.NewTimer(closeTimeout)
	defer timeout.Stop()
	
	// Release lock while waiting for context to close.
	ac.mu.Unlock()
	select {
	case <-ac.sessionContext.Done():
		ac.logger.Debug("Browser session closed gracefully.")
	case <-timeout.C:
		ac.logger.Warn("Timeout waiting for browser session to close. Resources might leak.")
	case <-ctx.Done():
		ac.logger.Warn("Context cancelled while waiting for session close.", zap.Error(ctx.Err()))
	}
	ac.mu.Lock() // Re-acquire lock to update state.

	ac.isClosed = true
	return nil
}