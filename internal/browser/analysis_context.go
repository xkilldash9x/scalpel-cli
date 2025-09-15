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
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

const (
	artifactCollectionTimeout = 30 * time.Second
	closeTimeout              = 15 * time.Second
)

type AnalysisContext struct {
	id                   string
	globalConfig         *config.Config
	logger               *zap.Logger
	persona              stealth.Persona
	parentBrowserCtx     context.Context
	browserControllerCtx context.Context
	contextCreationLock  *sync.Mutex
	sessionContext       context.Context
	sessionCancel        context.CancelFunc
	browserContextID     cdp.BrowserContextID
	humanoid             *humanoid.Humanoid
	harvester            *Harvester
	interactor           *Interactor
	taintShimTemplate    string
	taintConfigJSON      string
	findings             []schemas.Finding
	isClosed             bool
	isInitialized        bool
	mu                   sync.Mutex
	observer             SessionLifecycleObserver
}

func NewAnalysisContext(
	parentBrowserCtx context.Context,
	browserControllerCtx context.Context,
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
		id:                   id,
		parentBrowserCtx:     parentBrowserCtx,
		browserControllerCtx: browserControllerCtx,
		contextCreationLock:  contextCreationLock,
		globalConfig:         cfg,
		logger:               l,
		persona:              persona,
		taintShimTemplate:    taintTemplate,
		taintConfigJSON:      taintConfig,
		findings:             make([]schemas.Finding, 0),
		observer:             observer,
	}
}

// Initialize sets up the isolated browser context and target.
func (ac *AnalysisContext) Initialize(ctx context.Context) error {
	ac.mu.Lock()
	if ac.isInitialized {
		ac.mu.Unlock()
		return fmt.Errorf("session already initialized")
	}
	ac.mu.Unlock()

	var browserContextID cdp.BrowserContextID
	var targetID target.ID

	ac.contextCreationLock.Lock()
	defer ac.contextCreationLock.Unlock()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before creating browser context: %w", err)
	}

	var err error
	browserContextID, err = target.CreateBrowserContext().Do(ac.browserControllerCtx)
	if err != nil {
		return fmt.Errorf("failed to create browser context: %w", err)
	}

	targetID, err = target.CreateTarget("about:blank").
		WithBrowserContextID(browserContextID).
		Do(ac.browserControllerCtx)
	if err != nil {
		ac.bestEffortCleanupBrowserContext(browserContextID)
		return fmt.Errorf("failed to create target: %w", err)
	}

	sessionCtx, cancelSession := chromedp.NewContext(ac.parentBrowserCtx, chromedp.WithTargetID(targetID))

	ac.mu.Lock()
	ac.sessionContext = sessionCtx
	ac.sessionCancel = cancelSession
	ac.browserContextID = browserContextID
	ac.mu.Unlock()

	success := false
	defer func() {
		if !success {
			ac.Close(context.Background())
		}
	}()

	ac.humanoid = humanoid.New(ac.globalConfig.Browser.Humanoid, ac.logger, ac.browserContextID)
	ac.harvester = NewHarvester(ac.sessionContext, ac.logger, ac.globalConfig.Network.CaptureResponseBodies)
	ac.interactor = NewInteractor(ac.logger, ac.humanoid)
	chromedp.ListenTarget(ac.sessionContext, ac.bindingListener)

	if err := ac.setupSession(sessionCtx); err != nil {
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

func (ac *AnalysisContext) bestEffortCleanupBrowserContext(id cdp.BrowserContextID) {
	if ac.browserControllerCtx.Err() != nil {
		return
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(ac.browserControllerCtx, 5*time.Second)
	defer cleanupCancel()
	if err := target.DisposeBrowserContext(id).Do(cleanupCtx); err != nil {
		ac.logger.Debug("Failed best-effort cleanup of orphaned browser context.", zap.String("browserContextID", string(id)), zap.Error(err))
	}
}

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
		ac.logger.Debug("Taint shim template is empty. Skipping IAST instrumentation.")
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
	if !ac.isInitialized || ac.isClosed || ac.sessionContext == nil {
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
	if !ac.isInitialized {
		ac.mu.Unlock()
		return nil, fmt.Errorf("session is not initialized")
	}
	sessionCtx := ac.sessionContext
	if ac.isClosed || sessionCtx == nil || sessionCtx.Err() != nil {
		sessionCtx = context.Background()
	}
	ac.mu.Unlock()

	ac.logger.Debug("Starting artifact collection.")
	collectCtx, cancel := context.WithTimeout(sessionCtx, artifactCollectionTimeout)
	defer cancel()

	artifacts := &schemas.Artifacts{}

	if ac.harvester != nil {
		artifacts.HAR, artifacts.ConsoleLogs = ac.harvester.Stop(collectCtx)
	}

	if ac.GetContext().Err() != nil {
		ac.logger.Debug("Session context closed, skipping DOM and Storage collection.")
		return artifacts, nil
	}

	var domCaptureErr, storageErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var domContent string
		captureCtx, captureCancel := context.WithTimeout(ac.GetContext(), artifactCollectionTimeout)
		defer captureCancel()

		if err := chromedp.Run(captureCtx, chromedp.OuterHTML("html", &domContent, chromedp.ByQuery)); err != nil {
			if captureCtx.Err() == nil {
				ac.logger.Error("Failed to collect final DOM snapshot.", zap.Error(err))
				domCaptureErr = err
			}
		} else {
			artifacts.DOM = domContent
		}
	}()
	go func() {
		defer wg.Done()
		captureCtx, captureCancel := context.WithTimeout(ac.GetContext(), artifactCollectionTimeout)
		defer captureCancel()

		if err := ac.collectStorageState(captureCtx, artifacts); err != nil {
			if captureCtx.Err() == nil {
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

func (ac *AnalysisContext) collectStorageState(ctx context.Context, artifacts *schemas.Artifacts) error {
	storageResult := schemas.StorageState{
		LocalStorage:   make(map[string]string),
		SessionStorage: make(map[string]string),
	}
	var cookies []*network.Cookie
	err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) (err error) {
		cookies, err = storage.GetCookies().WithBrowserContextID(ac.browserContextID).Do(c)
		return err
	}))
	storageResult.Cookies = cookies
	artifacts.Storage = storageResult

	if err != nil {
		ac.logger.Warn("Could not retrieve cookies via CDP, proceeding with JS fallback for other storage.", zap.Error(err))
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
	if ac.isClosed {
		ac.mu.Unlock()
		return
	}
	ac.isClosed = true

	// Unregister from the manager to release the semaphore and decrement the WaitGroup.
	// This is done inside the lock to ensure it happens exactly once.
	if ac.observer != nil && ac.isInitialized {
		ac.observer.unregisterSession(ac)
	}

	ac.mu.Unlock()
	ac.internalClose(ctx)
}

func (ac *AnalysisContext) internalClose(ctx context.Context) {
	ac.mu.Lock()
	sessionCtx := ac.sessionContext
	sessionCancel := ac.sessionCancel
	browserCtxID := ac.browserContextID
	browserControllerCtx := ac.browserControllerCtx
	isInitialized := ac.isInitialized
	ac.mu.Unlock()

	if sessionCtx == nil {
		return
	}

	ac.logger.Debug("Closing analysis context.")

	if ac.harvester != nil && isInitialized {
		stopCtx, cancel := context.WithTimeout(context.Background(), artifactCollectionTimeout)
		if ctx.Err() == nil {
			stopCtx, cancel = context.WithTimeout(ctx, artifactCollectionTimeout)
		}
		defer cancel()
		ac.harvester.Stop(stopCtx)
	}

	if sessionCancel != nil {
		sessionCancel()
	}

	if browserCtxID != "" && browserControllerCtx.Err() == nil {
		timeoutCtx, cancelTimeout := context.WithTimeout(browserControllerCtx, 10*time.Second)
		defer cancelTimeout()
		if err := chromedp.Run(timeoutCtx, target.DisposeBrowserContext(browserCtxID)); err != nil {
			if browserControllerCtx.Err() == nil {
				ac.logger.Warn("Failed to dispose of browser context. It may be orphaned.",
					zap.String("browserContextID", string(browserCtxID)),
					zap.Error(err),
				)
			}
		} else {
			ac.logger.Debug("Disposed browser context.", zap.String("browserContextID", string(browserCtxID)))
		}
	}

	select {
	case <-sessionCtx.Done():
		ac.logger.Debug("Browser session context closed.")
	case <-ctx.Done():
		ac.logger.Warn("Context cancelled while waiting for session close.", zap.Error(ctx.Err()))
	case <-time.After(closeTimeout):
		ac.logger.Warn("Timeout waiting for browser session to close.")
	}
}