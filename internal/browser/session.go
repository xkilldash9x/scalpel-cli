// internal/browser/session.go
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// Session represents a single, isolated browser tab and its associated state.
type Session struct {
	id           string
	ctx          context.Context
	cancel       context.CancelFunc
	logger       *zap.Logger
	cfg          *config.Config
	persona      schemas.Persona
	harvester    *Harvester
	humanoid     *humanoid.Humanoid
	interactor   *Interactor
	onClose      func()
	findingsChan chan<- schemas.Finding
	closeOnce    sync.Once
}

// NewSession creates a new browser session.
func NewSession(
	ctx context.Context,
	cancel context.CancelFunc,
	cfg *config.Config,
	persona schemas.Persona,
	logger *zap.Logger,
	onClose func(),
	findingsChan chan<- schemas.Finding,
) (*Session, error) {
	sessionID := uuid.New().String()
	log := logger.With(zap.String("session_id", sessionID))

	s := &Session{
		id:           sessionID,
		ctx:          ctx,
		cancel:       cancel,
		logger:       log,
		cfg:          cfg,
		persona:      persona,
		onClose:      onClose,
		findingsChan: findingsChan,
	}

	if cfg.Browser.Humanoid.Enabled {
		s.humanoid = humanoid.New(cfg.Browser.Humanoid, s.logger, cdp.BrowserContextID(""))
	}

	stabilizeFn := func(ctx context.Context) error {
		quietPeriod := 1500 * time.Millisecond
		if s.cfg.Network.PostLoadWait > 0 {
			quietPeriod = s.cfg.Network.PostLoadWait
		}
		return s.stabilize(ctx, quietPeriod)
	}
	s.interactor = NewInteractor(log, s.humanoid, stabilizeFn)
	return s, nil
}

// Initialize sets up the session, applies stealth settings, and starts the harvester.
func (s *Session) Initialize(ctx context.Context, taintTemplate, taintConfig string) error {
	s.logger.Debug("Initializing session.")
	s.harvester = NewHarvester(s.ctx, s.logger, s.cfg.Network.CaptureResponseBodies)

	sinkEventHandler := func(eventData map[string]interface{}) {
		finding := schemas.Finding{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			Target:    "N/A",
			Module:    "IAST",
			Severity:  schemas.SeverityHigh,
		}

		if t, ok := eventData["type"].(string); ok {
			finding.Vulnerability.Name = fmt.Sprintf("Taint Flow to Sink: %s", t)
		}
		if d, ok := eventData["detail"].(string); ok {
			finding.Description = fmt.Sprintf("Tainted data reached a sensitive sink: %s", d)
		}
		if v, ok := eventData["value"].(string); ok {
			finding.Evidence = fmt.Sprintf("Payload: %s", v)
		}

		select {
		case s.findingsChan <- finding:
		case <-s.ctx.Done():
			s.logger.Warn("Could not send finding, session context is done.")
		}
	}

	initTasks := chromedp.Tasks{
		network.Enable(),
		page.Enable(),
		runtime.Enable(),
	}

	if err := s.runActions(ctx, initTasks); err != nil {
		return fmt.Errorf("failed to enable CDP domains: %w", err)
	}

	s.harvester.Start(s.ctx)

	if s.cfg.IAST.Enabled {
		if err := s.ExposeFunction(s.ctx, "__scalpel_sink_event", sinkEventHandler); err != nil {
			return fmt.Errorf("could not expose taint sink event handler: %w", err)
		}
	}

	return nil
}

// Close gracefully terminates the session and its resources.
func (s *Session) Close(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		s.logger.Debug("Closing session.")
		s.cancel()

		if s.onClose != nil {
			s.onClose()
		}

		if e := chromedp.Cancel(s.ctx); e != nil {
			s.logger.Warn("Error while canceling browser context on close.", zap.Error(e))
			err = e
		}
		s.logger.Info("Session closed.")
	})
	return err
}

// ID returns the unique identifier for the session.
func (s *Session) ID() string {
	return s.id
}

// GetContext returns the session's primary context.
func (s *Session) GetContext() context.Context {
	return s.ctx
}

// runActions is a central helper to execute chromedp actions against the session's context.
func (s *Session) runActions(ctx context.Context, actions ...chromedp.Action) error {
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	err := chromedp.Run(opCtx, actions...)

	if opCtx.Err() != nil {
		return opCtx.Err()
	}
	return err
}

// stabilize waits for the network to be idle.
func (s *Session) stabilize(ctx context.Context, quietPeriod time.Duration) error {
	if s.harvester == nil {
		return fmt.Errorf("harvester not initialized, cannot wait for network idle")
	}
	return s.harvester.WaitNetworkIdle(ctx, quietPeriod)
}

// CollectArtifacts gathers data like HAR, DOM, logs, and storage from the session.
func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	s.logger.Debug("Collecting artifacts.")

	var dom string
	var cookies []*network.Cookie
	var localStorage, sessionStorage map[string]string

	har, consoleLogs := s.harvester.Stop(ctx)

	collectionTasks := chromedp.Tasks{
		chromedp.OuterHTML("html", &dom, chromedp.ByQuery),
		chromedp.ActionFunc(func(c context.Context) error {
			var err error
			cookies, err = network.GetCookies().Do(c)
			return err
		}),
		chromedp.Evaluate(`
            (() => {
                const items = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    items[key] = localStorage.getItem(key);
                }
                return items;
            })()
        `, &localStorage),
		chromedp.Evaluate(`
            (() => {
                const items = {};
                for (let i = 0; i < sessionStorage.length; i++) {
                    const key = sessionStorage.key(i);
                    items[key] = sessionStorage.getItem(key);
                }
                return items;
            })()
        `, &sessionStorage),
	}

	if err := s.runActions(ctx, collectionTasks); err != nil {
		s.logger.Warn("Failed to collect some browser artifacts.", zap.Error(err))
	}

	return &schemas.Artifacts{
		HAR:         har,
		DOM:         dom,
		ConsoleLogs: consoleLogs,
		Storage: schemas.StorageState{
			Cookies:        cookies,
			LocalStorage:   localStorage,
			SessionStorage: sessionStorage,
		},
	}, nil
}

// --- Interaction Methods ---

// Navigate loads the specified URL and waits for the page to stabilize.
func (s *Session) Navigate(ctx context.Context, url string) error {
	s.logger.Debug("Navigating to URL", zap.String("url", url))
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	navTimeout := s.cfg.Network.NavigationTimeout
	if navTimeout <= 0 {
		navTimeout = 90 * time.Second
	}
	navCtx, navCancel := context.WithTimeout(opCtx, navTimeout)
	defer navCancel()

	if err := chromedp.Run(navCtx, chromedp.Navigate(url)); err != nil {
		if navCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("navigation timed out after %s: %w", navTimeout, err)
		}
		return fmt.Errorf("navigation failed: %w", err)
	}

	quietPeriod := 1500 * time.Millisecond
	if s.cfg.Network.PostLoadWait > 0 {
		quietPeriod = s.cfg.Network.PostLoadWait
	}
	if err := s.stabilize(opCtx, quietPeriod); err != nil {
		if opCtx.Err() == nil {
			s.logger.Warn("Page stabilization failed after navigation (non-critical).", zap.Error(err))
		}
	}

	if s.humanoid != nil {
		if err := s.humanoid.CognitivePause(300, 150).Do(opCtx); err != nil {
			return err
		}
	}
	return nil
}

// Click interacts with the element matching the selector.
func (s *Session) Click(selector string) error {
	s.logger.Debug("Attempting to click element", zap.String("selector", selector))
	var action chromedp.Action
	if s.humanoid != nil {
		action = s.humanoid.IntelligentClick(selector, nil)
	} else {
		action = chromedp.Click(selector, chromedp.ByQuery)
	}
	clickCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.runActions(clickCtx, action)
}

// Type inputs text into the element matching the selector.
func (s *Session) Type(selector string, text string) error {
	s.logger.Debug("Attempting to type into element", zap.String("selector", selector))
	var action chromedp.Action
	if s.humanoid != nil {
		action = s.humanoid.Type(selector, text)
	} else {
		action = chromedp.SendKeys(selector, text, chromedp.ByQuery)
	}
	typeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.runActions(typeCtx, action)
}

// Submit attempts to submit the form associated with the selector.
func (s *Session) Submit(selector string) error {
	s.logger.Debug("Attempting to submit form", zap.String("selector", selector))
	submitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.runActions(submitCtx, chromedp.Submit(selector, chromedp.ByQuery))
}

// ScrollPage simulates scrolling the page.
func (s *Session) ScrollPage(direction string) error {
	s.logger.Debug("Scrolling page", zap.String("direction", direction))
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
	scrollCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.runActions(scrollCtx, chromedp.Evaluate(script, nil))
}

// WaitForAsync pauses execution for a specified duration.
func (s *Session) WaitForAsync(milliseconds int) error {
	duration := time.Duration(milliseconds) * time.Millisecond
	s.logger.Debug("Waiting for async operations", zap.Duration("duration", duration))
	waitCtx, cancel := context.WithTimeout(context.Background(), duration+time.Second)
	defer cancel()
	return s.runActions(waitCtx, chromedp.Sleep(duration))
}

// Interact triggers the automated recursive interaction logic.
func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	if s.interactor == nil {
		return fmt.Errorf("interactor not initialized")
	}
	s.logger.Info("Starting automated interaction sequence.")
	return s.interactor.RecursiveInteract(ctx, config)
}

// --- Management Methods ---

// ExposeFunction allows Go functions to be called from the browser's JavaScript context.
func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	if err := s.runActions(ctx, runtime.AddBinding(name)); err != nil {
		return fmt.Errorf("failed to add binding '%s': %w", name, err)
	}

	fnVal := reflect.ValueOf(function)
	fnType := fnVal.Type()

	if fnType.Kind() != reflect.Func {
		return fmt.Errorf("provided implementation for '%s' is not a function", name)
	}

	chromedp.ListenTarget(s.ctx, func(ev interface{}) {
		if ev, ok := ev.(*runtime.EventBindingCalled); ok && ev.Name == name {
			go func() {
				defer func() {
					if r := recover(); r != nil {
						s.logger.Error("Panic during exposed function call.",
							zap.String("name", name),
							zap.Any("panic_reason", r),
							zap.String("stack", string(debug.Stack())))
					}
				}()

				var rawArgs []json.RawMessage
				if err := json.Unmarshal([]byte(ev.Payload), &rawArgs); err != nil {
					s.logger.Error("Could not unmarshal raw payload for exposed function.", zap.String("name", name), zap.Error(err))
					return
				}

				if len(rawArgs) != fnType.NumIn() {
					s.logger.Error("Mismatch in argument count for exposed function.", zap.String("name", name), zap.Int("expected", fnType.NumIn()), zap.Int("got", len(rawArgs)))
					return
				}

				in := make([]reflect.Value, fnType.NumIn())
				for i := 0; i < fnType.NumIn(); i++ {
					rawArg := rawArgs[i]
					paramType := fnType.In(i)
					paramPtr := reflect.New(paramType)

					if err := json.Unmarshal(rawArg, paramPtr.Interface()); err != nil {
						s.logger.Error("Failed to unmarshal argument for exposed function.", zap.String("name", name), zap.Int("arg_index", i), zap.Error(err), zap.String("target_type", paramType.String()))
						return
					}
					in[i] = paramPtr.Elem()
				}
				fnVal.Call(in)
			}()
		}
	})
	return nil
}

// InjectScriptPersistently adds a script that will be executed on all new documents.
func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	var scriptID page.ScriptIdentifier
	err := s.runActions(ctx, chromedp.ActionFunc(func(c context.Context) error {
		var err error
		scriptID, err = page.AddScriptToEvaluateOnNewDocument(script).Do(c)
		return err
	}))
	if err != nil {
		return fmt.Errorf("could not inject persistent script: %w", err)
	}
	s.logger.Debug("Injected persistent script.", zap.String("scriptID", string(scriptID)))
	return nil
}

// ExecuteScript runs a snippet of JavaScript in the current document.
func (s *Session) ExecuteScript(ctx context.Context, script string, res interface{}) error {
	return s.runActions(ctx, chromedp.Evaluate(script, res))
}


