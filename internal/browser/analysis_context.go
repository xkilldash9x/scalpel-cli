// internal/browser/analysis_context.go
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// AnalysisContext implements the schemas.SessionContext interface.
type AnalysisContext struct {
	ctx        context.Context
	cancelFunc context.CancelFunc
	sessionID  string
	logger     *zap.Logger
	cfg        *config.Config
	persona    schemas.Persona
	harvester  *Harvester
	interactor *Interactor
	humanoid   *humanoid.Humanoid
	observer   SessionLifecycleObserver
	isClosed   bool
	mu         sync.Mutex
	findings   []schemas.Finding
}

var _ schemas.SessionContext = (*AnalysisContext)(nil)

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
	ac.harvester = NewHarvester(ctx, sessionLogger, cfg.Network.CaptureResponseBodies)
	if cfg.Browser.Humanoid.Enabled {
		// Logic for finding the browser context ID required for humanoid features.
		var browserContextID cdp.BrowserContextID
		if target := chromedp.FromContext(ctx).Target; target != nil {
			targetID := target.TargetID
			// Use a short-lived context to fetch the target list.
			targetsCtx, targetsCancel := context.WithTimeout(ctx, 5*time.Second)
			defer targetsCancel()

			if infos, err := chromedp.Targets(targetsCtx); err != nil {
				// Log only if the session context is still active.
				if ctx.Err() == nil {
					ac.logger.Warn("Failed to retrieve browser targets to initialize humanoid.", zap.Error(err))
				}
			} else {
				for _, info := range infos {
					if info.TargetID == targetID {
						browserContextID = info.BrowserContextID
						break
					}
				}
			}
		}
		ac.humanoid = humanoid.New(cfg.Browser.Humanoid, sessionLogger, browserContextID)
	}
	stabilizeFn := func(stabCtx context.Context) error {
		return ac.stabilize(stabCtx, 500*time.Millisecond)
	}
	ac.interactor = NewInteractor(sessionLogger, ac.humanoid, stabilizeFn)
	if err := ac.harvester.Start(); err != nil {
		// Log only if the session context is still active.
		if ctx.Err() == nil {
			ac.logger.Error("Failed to start harvester", zap.Error(err))
		}
	}
	return ac
}

func (ac *AnalysisContext) stabilize(ctx context.Context, quietPeriod time.Duration) error {
	stabCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	if err := chromedp.Run(stabCtx, chromedp.WaitReady("body", chromedp.ByQuery)); err != nil {
		// If the context was canceled, failing to wait is an expected outcome, not an error.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ac.logger.Debug("WaitReady failed during stabilization.", zap.Error(err))
	}
	// It is safe to ignore the error here. If stabilization is incomplete due to
	// context cancellation, the subsequent operation will also fail gracefully.
	_ = ac.harvester.WaitNetworkIdle(stabCtx, quietPeriod)
	return nil
}

func (ac *AnalysisContext) AddFinding(finding schemas.Finding) {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ac.findings = append(ac.findings, finding)
}

func (ac *AnalysisContext) Findings() []schemas.Finding {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	findingsCopy := make([]schemas.Finding, len(ac.findings))
	copy(findingsCopy, ac.findings)
	return findingsCopy
}

func (ac *AnalysisContext) Navigate(ctx context.Context, url string) error {
	ac.logger.Info("Navigating", zap.String("url", url))
	opCtx, opCancel := CombineContext(ac.ctx, ctx)
	defer opCancel()

	navCtx, navCancel := context.WithTimeout(opCtx, ac.cfg.Network.NavigationTimeout)
	defer navCancel()

	if err := chromedp.Run(navCtx, chromedp.Navigate(url)); err != nil {
		// Distinguish between a timeout and other cancellation reasons.
		if navCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("navigation to %s timed out after %s: %w", url, ac.cfg.Network.NavigationTimeout, err)
		}
		// The error is likely `context.Canceled`, which is an expected signal, not an error to log.
		return fmt.Errorf("navigation failed or was canceled: %w", err)
	}

	// Attempt to wait for the page to settle after navigation.
	_ = ac.stabilize(navCtx, 1500*time.Millisecond)
	return nil
}

func (ac *AnalysisContext) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	ac.logger.Info("Starting automated interaction sequence.")
	interactCtx, cancel := CombineContext(ac.ctx, ctx)
	defer cancel()

	return ac.interactor.RecursiveInteract(interactCtx, config)
}

func (ac *AnalysisContext) CollectArtifacts() (*schemas.Artifacts, error) {
	// Use a detached context for artifact collection to ensure it can complete
	// even if the original operation was canceled or timed out.
	collectCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	har, consoleLogs := ac.harvester.Stop(collectCtx)

	var domContent string
	storageState := schemas.StorageState{}

	// We still need to use the session's context for chromedp actions, but we wrap
	// it with its own timeout for this specific collection task.
	captureCtx, captureCancel := context.WithTimeout(ac.ctx, 10*time.Second)
	defer captureCancel()

	err := chromedp.Run(captureCtx,
		chromedp.OuterHTML("html", &domContent, chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return ac.captureStorage(ctx, &storageState)
		}),
	)

	// This is a key pattern from the paper: only log an error if it wasn't
	// caused by a pre-existing context cancellation. This prevents noisy,
	// un-actionable logs during graceful shutdowns.
	if err != nil && ac.ctx.Err() == nil {
		ac.logger.Warn("Could not fully collect browser artifacts.", zap.Error(err))
	}

	return &schemas.Artifacts{
		HAR:         har,
		DOM:         domContent,
		ConsoleLogs: consoleLogs,
		Storage:     storageState,
	}, nil
}

func (ac *AnalysisContext) captureStorage(ctx context.Context, state *schemas.StorageState) error {
	cookies, err := network.GetCookies().Do(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cookies: %w", err)
	}
	state.Cookies = cookies

	jsGetStorage := func(storageType string) string {
		return fmt.Sprintf(`(() => { let items = {}; try { const s = window.%s; for (let i = 0; i < s.length; i++) { const k = s.key(i); items[k] = s.getItem(k); } } catch (e) {} return items; })()`, storageType)
	}
	if err := chromedp.Run(ctx,
		chromedp.Evaluate(jsGetStorage("localStorage"), &state.LocalStorage),
		chromedp.Evaluate(jsGetStorage("sessionStorage"), &state.SessionStorage),
	); err != nil {
		ac.logger.Warn("Could not fully capture storage.", zap.Error(err))
	}
	return nil
}

func (ac *AnalysisContext) Close(ctx context.Context) error {
	ac.mu.Lock()
	if ac.isClosed {
		ac.mu.Unlock()
		return nil
	}
	ac.isClosed = true
	ac.mu.Unlock()

	ac.logger.Debug("Closing session.")
	ac.harvester.Stop(ctx)
	if ac.cancelFunc != nil {
		ac.cancelFunc()
	}
	if ac.observer != nil {
		ac.observer.unregisterSession(ac)
	}
	return nil
}

func (ac *AnalysisContext) InitializeTaint(template, config string) error {
	ac.logger.Info("Taint instrumentation would be initialized here.")
	return nil
}

func (ac *AnalysisContext) ID() string {
	return ac.sessionID
}

func (ac *AnalysisContext) GetContext() context.Context {
	return ac.ctx
}

func (ac *AnalysisContext) Click(selector string) error {
	if ac.humanoid != nil {
		return chromedp.Run(ac.ctx, ac.humanoid.IntelligentClick(selector, nil))
	}
	return chromedp.Run(ac.ctx, chromedp.Click(selector, chromedp.NodeVisible))
}

func (ac *AnalysisContext) Type(selector string, text string) error {
	if ac.humanoid != nil {
		return chromedp.Run(ac.ctx, ac.humanoid.Type(selector, text))
	}
	return chromedp.Run(ac.ctx, chromedp.SendKeys(selector, text, chromedp.NodeVisible))
}

func (ac *AnalysisContext) Submit(selector string) error {
	return chromedp.Run(ac.ctx, chromedp.Submit(selector, chromedp.NodeVisible))
}

func (ac *AnalysisContext) ScrollPage(direction string) error {
	script := `window.scrollBy(0, window.innerHeight * 0.8);`
	if strings.ToLower(direction) == "up" {
		script = `window.scrollBy(0, -window.innerHeight * 0.8);`
	}
	return chromedp.Run(ac.ctx, chromedp.Evaluate(script, nil))
}

func (ac *AnalysisContext) WaitForAsync(milliseconds int) error {
	return chromedp.Run(ac.ctx, chromedp.Sleep(time.Duration(milliseconds)*time.Millisecond))
}

// ExposeFunction exposes a Go function to the browser's JavaScript environment.
// The binding remains active until the provided ctx is canceled or the session is closed.
func (ac *AnalysisContext) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	// REFACTORED: Fixed context lifecycle management for persistent bindings.
	// The previous implementation incorrectly used 'defer' to launch cleanup immediately.

	// Create a context that is cancelled if either the session (ac.ctx) or the caller (ctx) is done.
	bindCtx, bindCancel := CombineContext(ac.ctx, ctx)

	// Set up a goroutine to manage the cleanup when the context is done.
	go func() {
		// Wait until the binding context is done.
		<-bindCtx.Done()

		// Now that the binding is no longer needed, perform cleanup.
		// We launch this in a separate goroutine as cleanupBinding is synchronous and uses a detached context.
		go ac.cleanupBinding(name)
	}()

	// Use a short timeout for the setup action itself, derived from bindCtx.
	setupCtx, setupCancel := context.WithTimeout(bindCtx, 5*time.Second)
	defer setupCancel()

	if err := chromedp.Run(setupCtx, runtime.AddBinding(name)); err != nil {
		bindCancel() // Ensure cancellation if setup fails.
		return fmt.Errorf("failed to add runtime binding for %s: %w", name, err)
	}

	// Listen for the binding being called from the browser. (Using long-lived bindCtx)
	eventChan := make(chan *runtime.EventBindingCalled, 16)
	chromedp.ListenTarget(bindCtx, func(ev interface{}) {
		if e, ok := ev.(*runtime.EventBindingCalled); ok && e.Name == name {
			select {
			case eventChan <- e:
			case <-bindCtx.Done():
			// Stop sending if context is done.
			default:
				ac.logger.Warn("Exposed function event channel full.", zap.String("name", name))
			}
		}
	})

	// Start the event handler goroutine. (Using long-lived bindCtx)
	go ac.bindingEventHandler(bindCtx, eventChan, function)

	return nil
}

// bindingEventHandler is the long lived goroutine that processes events from the browser.
func (ac *AnalysisContext) bindingEventHandler(ctx context.Context, events <-chan *runtime.EventBindingCalled, function interface{}) {
	fnVal := reflect.ValueOf(function)
	fnType := fnVal.Type()
	numArgs := fnType.NumIn()

	for {
		select {
		case <-ctx.Done():
			return // The context was canceled, so we exit.
		case e := <-events:
			// Handle each call in its own goroutine to prevent blocking the event loop.
			go ac.handleBindingCall(e.Payload, fnVal, fnType, numArgs)
		}
	}
}

func (ac *AnalysisContext) cleanupBinding(name string) {
	// This cleanup task must run even if the parent context is canceled.
	// We create a new "detached" context by wrapping the session context
	// in a valueOnlyContext (inherits CDP target info) and adding a timeout.
	cleanupCtx, cancel := context.WithTimeout(valueOnlyContext{ac.ctx}, 2*time.Second)
	defer cancel()

	if err := chromedp.Run(cleanupCtx, runtime.RemoveBinding(name)); err != nil {
		// Only log if the cleanup context itself didn't time out and the session context is still somewhat active.
		if cleanupCtx.Err() == nil && ac.ctx.Err() == nil {
			ac.logger.Debug("Failed to remove runtime binding.", zap.String("name", name), zap.Error(err))
		}
	}
}

func (ac *AnalysisContext) handleBindingCall(payload string, fnVal reflect.Value, fnType reflect.Type, numArgs int) {
	defer func() {
		if r := recover(); r != nil {
			ac.logger.Error("Panic recovered in exposed function call", zap.Any("panic_value", r))
		}
	}()

	// The payload from CDP runtime.EventBindingCalled is expected to be a JSON string
	// representing an array of the arguments passed in JavaScript.

	var rawArgs []json.RawMessage
	if err := json.Unmarshal([]byte(payload), &rawArgs); err != nil {
		ac.logger.Error("Failed to unmarshal binding payload as JSON array", zap.Error(err), zap.String("payload", payload))
		return
	}

	// The original implementation had a flawed double-unmarshal logic (checking len(rawArgs) != 1 and unmarshalling rawArgs[0]) which is removed.

	if len(rawArgs) != numArgs {
		ac.logger.Error("Binding argument count mismatch", zap.Int("expected", numArgs), zap.Int("got", len(rawArgs)))
		return
	}

	args := make([]reflect.Value, numArgs)
	for i := 0; i < numArgs; i++ {
		argPtr := reflect.New(fnType.In(i))
		if err := json.Unmarshal(rawArgs[i], argPtr.Interface()); err != nil {
			ac.logger.Error("Failed to unmarshal binding argument", zap.Error(err), zap.Int("arg_index", i))
			return
		}
		args[i] = argPtr.Elem()
	}
	fnVal.Call(args)
}

func (ac *AnalysisContext) InjectScriptPersistently(ctx context.Context, script string) error {
	injectCtx, injectCancel := CombineContext(ac.ctx, ctx)
	defer injectCancel()

	return chromedp.Run(injectCtx, chromedp.ActionFunc(func(c context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(script).Do(c)
		return err
	}))
}

func (ac *AnalysisContext) ExecuteScript(ctx context.Context, script string) error {
	execCtx, execCancel := CombineContext(ac.ctx, ctx)
	defer execCancel()
	return chromedp.Run(execCtx, chromedp.Evaluate(script, nil))
}