// internal/browser/analysis_context.go
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

// Define constants for timeouts.
const (
	artifactCollectionTimeout = 30 * time.Second
	closeTimeout              = 15 * time.Second
	initializationTimeout     = 45 * time.Second
)

// AnalysisContext manages a single, isolated browser tab (session) using CDP.
type AnalysisContext struct {
	id               string
	globalConfig     *config.Config
	logger           *zap.Logger
	persona          stealth.Persona
	parentBrowserCtx context.Context // Context of the main browser process.

	// Session specific resources.
	sessionContext   context.Context
	sessionCancel    context.CancelFunc
	browserContextID cdp.BrowserContextID
	humanoid         *humanoid.Humanoid
	harvester        *Harvester
	interactor       *Interactor

	taintShimTemplate string
	taintConfigJSON   string
	findings          []schemas.Finding

	isClosed      bool
	isInitialized bool
	mu            sync.Mutex
}

// NewAnalysisContext creates a new context structure. Initialize() must be called next.
func NewAnalysisContext(
	parentBrowserCtx context.Context,
	cfg *config.Config,
	logger *zap.Logger,
	persona stealth.Persona,
	taintTemplate string,
	taintConfig string,
) *AnalysisContext {
	id := uuid.New().String()
	l := logger.With(zap.String("session_id", id))

	return &AnalysisContext{
		id:                id,
		parentBrowserCtx:  parentBrowserCtx,
		globalConfig:      cfg,
		logger:            l,
		persona:           persona,
		taintShimTemplate: taintTemplate,
		taintConfigJSON:   taintConfig,
		findings:          make([]schemas.Finding, 0),
	}
}

// Initialize creates the browser tab (context) and applies all necessary instrumentation.
func (ac *AnalysisContext) Initialize(ctx context.Context) error {
	ac.mu.Lock()
	if ac.isInitialized {
		ac.mu.Unlock()
		return fmt.Errorf("session already initialized")
	}
	ac.mu.Unlock()

	// 1. Create a new, isolated browser context (like an incognito window).
	browserContextID, err := target.CreateBrowserContext().Do(ac.parentBrowserCtx)
	if err != nil {
		return fmt.Errorf("failed to create new browser context: %w", err)
	}
	ac.browserContextID = browserContextID

	// 2. Create a new tab (target) within that isolated context.
	targetID, err := target.CreateTarget("about:blank").WithBrowserContextID(browserContextID).Do(ac.parentBrowserCtx)
	if err != nil {
		// Cleanup the created browser context if target creation fails.
		_ = target.DisposeBrowserContext(browserContextID).Do(ac.parentBrowserCtx)
		return fmt.Errorf("failed to create new target: %w", err)
	}

	// 3. Create the final session context that connects to the new tab's target ID.
	sessionCtx, cancelSession := chromedp.NewContext(ac.parentBrowserCtx, chromedp.WithTargetID(targetID))

	ac.mu.Lock()
	ac.sessionContext = sessionCtx
	ac.sessionCancel = cancelSession
	ac.mu.Unlock()

	success := false
	defer func() {
		if !success {
			ac.logger.Warn("Initialization failed, cleaning up session resources.")
			ac.Close(context.Background())
		}
	}()

	ac.humanoid = humanoid.New(ac.globalConfig.Browser.Humanoid, ac.logger, ac.browserContextID)
	captureBodies := ac.globalConfig.Network.CaptureResponseBodies
	ac.harvester = NewHarvester(ac.sessionContext, ac.logger, captureBodies)
	ac.interactor = NewInteractor(ac.logger, ac.humanoid)

	chromedp.ListenTarget(ac.sessionContext, ac.bindingListener)

	initCtx, cancelInit := context.WithTimeout(ctx, initializationTimeout)
	defer cancelInit()

	if err := ac.setupSession(initCtx); err != nil {
		return fmt.Errorf("failed to setup session: %w", err)
	}

	ac.harvester.Start()

	ac.mu.Lock()
	ac.isInitialized = true
	ac.mu.Unlock()

	success = true
	ac.logger.Info("Browser session initialized, instrumented, and ready.")
	return nil
}

// setupSession applies stealth measures and IAST instrumentation.
func (ac *AnalysisContext) setupSession(ctx context.Context) error {
	tasks := chromedp.Tasks{
		stealth.Apply(ac.persona, ac.logger),
		chromedp.ActionFunc(func(c context.Context) error {
			if err := ac.applyInstrumentation(c); err != nil {
				ac.logger.Error("Failed to apply IAST instrumentation. Proceeding without runtime analysis.", zap.Error(err))
			}
			return nil
		}),
	}
	return tasks.Do(ctx)
}

func (ac *AnalysisContext) applyInstrumentation(ctx context.Context) error {
	if ac.taintShimTemplate == "" {
		return nil
	}

	script, err := shim.BuildTaintShim(ac.taintShimTemplate, ac.taintConfigJSON)
	if err != nil {
		return fmt.Errorf("failed to build taint shim script: %w", err)
	}

	const callbackName = "scalpel_sink_event"
	if err := runtime.AddBinding(callbackName).Do(ctx); err != nil {
		return fmt.Errorf("failed to expose taint callback (%s): %w", callbackName, err)
	}

	if _, err = page.AddScriptToEvaluateOnNewDocument(script).Do(ctx); err != nil {
		return fmt.Errorf("failed to inject taint shim persistently: %w", err)
	}

	ac.logger.Debug("IAST instrumentation applied successfully.")
	return nil
}

func (ac *AnalysisContext) bindingListener(ev interface{}) {
	if binding, ok := ev.(*runtime.EventBindingCalled); ok {
		if binding.Name == "scalpel_sink_event" {
			ac.handleTaintEvent(binding.Payload)
		}
	}
}

func (ac *AnalysisContext) handleTaintEvent(payload string) {
	ac.logger.Info("Taint Sink Triggered (IAST Event)", zap.String("payload", payload))
}

func (ac *AnalysisContext) AddFinding(finding schemas.Finding) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now().UTC()
	}
	ac.findings = append(ac.findings, finding)
	ac.logger.Info("New finding reported.",
		zap.String("module", finding.Module),
		zap.String("severity", string(finding.Severity)),
		zap.String("id", finding.ID),
	)
}

func (ac *AnalysisContext) ID() string {
	return ac.id
}

func (ac *AnalysisContext) GetContext() context.Context {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if !ac.isInitialized || ac.isClosed {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}
	return ac.sessionContext
}

func (ac *AnalysisContext) Navigate(url string) error {
	ac.logger.Debug("Navigating to URL.", zap.String("url", url))
	ctx := ac.GetContext()
	if ctx.Err() != nil {
		return fmt.Errorf("session context is invalid before navigation: %w", ctx.Err())
	}
	tasks := chromedp.Tasks{
		chromedp.ActionFunc(func(c context.Context) error {
			if ac.globalConfig.Browser.DisableCache {
				if err := network.SetCacheDisabled(true).Do(c); err != nil {
					ac.logger.Warn("Failed to disable browser cache", zap.Error(err))
				}
			}
			return ac.humanoid.CognitivePause(500, 200).Do(c)
		}),
		chromedp.Navigate(url),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.ActionFunc(func(c context.Context) error {
			postLoadWait := ac.globalConfig.Network.PostLoadWait
			if postLoadWait > 0 {
				ac.logger.Debug("Waiting for post-load stabilization.", zap.Duration("duration", postLoadWait))
				if err := ac.humanoid.Hesitate(postLoadWait).Do(c); err != nil {
					return err
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

func (ac *AnalysisContext) Interact(config schemas.InteractionConfig) error {
	ac.logger.Debug("Starting automated humanoid interaction phase.")
	return ac.interactor.RecursiveInteract(ac.GetContext(), config)
}

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
	var domCaptureErr, storageErr error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		var domContent string
		if err := chromedp.Run(collectCtx, chromedp.OuterHTML("html", &domContent, chromedp.ByQuery)); err != nil {
			ac.logger.Error("Failed to collect final DOM snapshot.", zap.Error(err))
			domCaptureErr = err
		} else {
			artifacts.DOM = domContent
		}
	}()

	go func() {
		defer wg.Done()
		if err := ac.collectStorageState(collectCtx, artifacts); err != nil {
			ac.logger.Error("Failed to collect storage state.", zap.Error(err))
			storageErr = err
		}
	}()

	if ac.harvester != nil {
		artifacts.HAR, artifacts.ConsoleLogs = ac.harvester.Stop(collectCtx)
	}

	wg.Wait()

	if domCaptureErr != nil || storageErr != nil {
		return artifacts, fmt.Errorf("artifact collection failed (DOM: %v, Storage: %v)", domCaptureErr, storageErr)
	}

	ac.logger.Debug("Artifact collection complete.")
	return artifacts, nil
}

func (ac *AnalysisContext) collectStorageState(ctx context.Context, artifacts *schemas.Artifacts) error {
	storageResult := schemas.StorageState{
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
	}
	var cookies []*network.Cookie
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) (err error) {
		cookies, err = network.GetCookies().Do(c)
		return err
	}))
	storageResult.Cookies = cookies
	artifacts.Storage = storageResult
	if err != nil {
		ac.logger.Warn("Could not retrieve cookies, proceeding with JS fallback for other storage.", zap.Error(err))
	}
	return ac.collectStorageStateJSFallback(ctx, &storageResult)
}

func (ac *AnalysisContext) collectStorageStateJSFallback(ctx context.Context, storageResult *schemas.StorageState) error {
	var jsStorage struct {
		LocalStorage   map[string]string `json:"localStorage"`
		SessionStorage map[string]string `json:"sessionStorage"`
	}
	err := chromedp.Run(ctx,
		chromedp.Evaluate(
			`(function() { const result = { localStorage: {}, sessionStorage: {} }; try { if (window.localStorage) { Object.assign(result.localStorage, localStorage); } } catch (e) { result.localStorage = { 'error': 'Access Denied: ' + e.message }; } try { if (window.sessionStorage) { Object.assign(result.sessionStorage, sessionStorage); } } catch (e) { result.sessionStorage = { 'error': 'Access Denied: ' + e.message }; } return result; })()`, &jsStorage),
	)
	if err != nil {
		return fmt.Errorf("JS fallback for storage retrieval failed: %w", err)
	}
	storageResult.LocalStorage = jsStorage.LocalStorage
	storageResult.SessionStorage = jsStorage.SessionStorage
	return nil
}

func (ac *AnalysisContext) Close(ctx context.Context) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.internalClose(ctx)
}

func (ac *AnalysisContext) internalClose(ctx context.Context) {
	if ac.isClosed {
		return
	}
	if ac.sessionContext == nil {
		ac.isClosed = true
		return
	}
	ac.logger.Debug("Closing analysis context.")
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
	ac.mu.Unlock()
	select {
	case <-ac.sessionContext.Done():
		ac.logger.Debug("Browser session closed gracefully.")
	case <-timeout.C:
		ac.logger.Warn("Timeout waiting for browser session to close. Resources might leak.")
	case <-ctx.Done():
		ac.logger.Warn("Context cancelled while waiting for session close.", zap.Error(ctx.Err()))
	}
	ac.mu.Lock()
	ac.isClosed = true
}