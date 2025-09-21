// internal/browser/session.go
package browser

import (
	"context"
	"fmt"
	"sync"
	"time"


	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/shim"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// Session represents an active browser session (a tab) and implements schemas.SessionContext.
type Session struct {
	id string
	ctx    context.Context
	cancel context.CancelFunc
	logger *zap.Logger
	cfg    *config.Config

	persona schemas.Persona

	// Integrated components
	humanoid   *humanoid.Humanoid
	harvester  *Harvester
	interactor *Interactor

	onClose func()

	mu       sync.Mutex
	isClosed bool
}

// Ensure Session implements the interface.
var _ schemas.SessionContext = (*Session)(nil)

// NewSession creates a new Session instance wrapper.
func NewSession(
	ctx context.Context,
	cancel context.CancelFunc,
	cfg *config.Config,
	persona schemas.Persona,
	logger *zap.Logger,
	onClose func(),
) (*Session, error) {

	sessionID := uuid.New().String()
	sessionLogger := logger.With(zap.String("session_id", sessionID))

	s := &Session{
		id:      sessionID,
		ctx:     ctx,
		cancel:  cancel,
		logger:  sessionLogger,
		cfg:     cfg,
		persona: persona,
		onClose: onClose,
	}

	return s, nil
}

// Initialize applies configurations and starts necessary components.
func (s *Session) Initialize(ctx context.Context, taintTemplate, taintConfig string) error {
	// 1. Ensure the target (tab) is created and CDP is connected.
	if err := chromedp.Run(ctx); err != nil {
		return fmt.Errorf("failed to initialize browser context/target connection: %w", err)
	}

	// 2. Initialize Harvester.
	s.harvester = NewHarvester(s.ctx, s.logger, s.cfg.Network.CaptureResponseBodies)
	// Start the harvester using the initialization context.
	if err := s.harvester.Start(ctx); err != nil {
		return fmt.Errorf("failed to start harvester: %w", err)
	}

	var tasks chromedp.Tasks

	// 3. Apply Stealth Evasions and Persona Spoofing.
	tasks = append(tasks, stealth.Apply(s.persona, s.logger)...)

	// 4. Initialize Humanoid and Interactor.
	s.initializeControllers()

	// 5. Inject Taint Analysis Shim (if configured and enabled).
	if s.cfg.IAST.Enabled && taintTemplate != "" {
		// Use the initialization context (ctx) for setup, but the binding persists for the session.
		if err := s.initializeTaintShim(ctx, taintTemplate, taintConfig); err != nil {
			// Non-critical failure.
			s.logger.Error("Failed to initialize IAST Taint Shim.", zap.Error(err))
		}
	}

	// 6. Apply custom headers.
	if len(s.cfg.Network.Headers) > 0 {
		headers := make(network.Headers)
		for k, v := range s.cfg.Network.Headers {
			headers[k] = v
		}
		tasks = append(tasks, network.SetExtraHTTPHeaders(headers))
	}

	// Execute all remaining initialization tasks.
	if err := chromedp.Run(ctx, tasks); err != nil {
		return fmt.Errorf("failed to run session initialization tasks: %w", err)
	}

	// 7. Initialize cursor position.
	if s.humanoid != nil {
		if err := s.initializeCursorPosition(ctx); err != nil {
			s.logger.Debug("Could not set initial cursor position.", zap.Error(err))
		}
	}

	return nil
}

// stabilize waits for the page state to settle (DOM ready and network idle).
func (s *Session) stabilize(ctx context.Context, quietPeriod time.Duration) error {
	stabCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := chromedp.Run(stabCtx, chromedp.WaitReady("body", chromedp.ByQuery)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.logger.Debug("WaitReady failed during stabilization.", zap.Error(err))
	}

	if s.harvester != nil {
		if err := s.harvester.WaitNetworkIdle(stabCtx, quietPeriod); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.logger.Debug("Network idle wait failed during stabilization.", zap.Error(err))
		}
	}
	return nil
}

// initializeControllers sets up the Humanoid and Interactor components.
func (s *Session) initializeControllers() {
	// Initialize Humanoid
	if s.cfg.Browser.Humanoid.Enabled {
		target := chromedp.FromContext(s.ctx)
		if target != nil {
            // Retrieve the BrowserContextID associated with this session's target.
			browserContextID := target.BrowserContextID
			s.humanoid = humanoid.New(s.cfg.Browser.Humanoid, s.logger.Named("humanoid"), browserContextID)
		} else {
			s.logger.Error("Could not retrieve target info for Humanoid initialization.")
		}
	}

	// Initialize Interactor
	stabilizeFn := func(stabCtx context.Context) error {
		return s.stabilize(stabCtx, 500*time.Millisecond)
	}
	s.interactor = NewInteractor(s.logger, s.humanoid, stabilizeFn)
}

func (s *Session) initializeCursorPosition(ctx context.Context) error {
	width, height := s.persona.Width, s.persona.Height
	if width > 0 && height > 0 && s.humanoid != nil {
		startX, startY := float64(width)/2.0, float64(height)/2.0
		startVec := humanoid.Vector2D{X: startX, Y: startY}
		return s.humanoid.MoveToVector(startVec, nil).Do(ctx)
	}
	return fmt.Errorf("viewport dimensions are zero or humanoid disabled")
}


func (s *Session) initializeTaintShim(ctx context.Context, template, configJSON string) error {
	script, err := shim.BuildTaintShim(template, configJSON)
	if err != nil {
		return fmt.Errorf("failed to build shim script: %w", err)
	}

	// Expose the reporting function. Uses the manual binding implementation in management.go.
	if err := s.ExposeFunction(ctx, "__scalpel_sink_event", s.handleTaintEvent); err != nil {
		return fmt.Errorf("failed to expose sink event handler: %w", err)
	}

	// Inject the script persistently.
	if err := s.InjectScriptPersistently(ctx, script); err != nil {
		return fmt.Errorf("failed to inject shim script: %w", err)
	}
	return nil
}

// handleTaintEvent is the callback exposed to the browser's JS environment.
// FIX: Updated signature to accept the expected concrete type (map) for manual binding reflection.
func (s *Session) handleTaintEvent(eventData map[string]interface{}) {
	if eventData == nil {
		return
	}
	eventType, _ := eventData["type"].(string)
	detail, _ := eventData["detail"].(string)

	s.logger.Info("IAST Sink Triggered", zap.String("type", eventType), zap.String("detail", detail))
	// TODO: Process this event and generate Findings.
}

// ID returns the unique identifier for the session.
func (s *Session) ID() string {
	return s.id
}

// GetContext returns the underlying context for the session.
func (s *Session) GetContext() context.Context {
	return s.ctx
}

// Close terminates the browser session gracefully.
func (s *Session) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}
	s.isClosed = true
	s.mu.Unlock()

	s.logger.Debug("Closing browser session.")

	// 1. Stop the Harvester.
	if s.harvester != nil {
		s.harvester.Stop(ctx)
	}

	// 2. Cancel the session context.
	if s.cancel != nil {
		s.cancel()
	}

	// 3. Execute the onClose callback.
	if s.onClose != nil {
		s.onClose()
	}

	return nil
}

// CollectArtifacts gathers the HAR, DOM, Console Logs, and Storage state.
func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	s.logger.Debug("Starting artifact collection.")

	// 1. Stop the harvester.
	har, consoleLogs := s.harvester.Stop(ctx)

	// 2. Capture DOM and Storage state.
	var domContent string
	storageState := schemas.StorageState{}

	captureCtx, cancel := CombineContext(s.ctx, ctx)
	defer cancel()

	err := chromedp.Run(captureCtx,
		chromedp.OuterHTML("html", &domContent, chromedp.ByQuery),
		chromedp.ActionFunc(func(c context.Context) error {
			return s.captureStorage(c, &storageState)
		}),
	)

	if err != nil {
		if captureCtx.Err() == nil {
			s.logger.Warn("Could not fully collect browser artifacts.", zap.Error(err))
		}
	}

	return &schemas.Artifacts{
		HAR:         har,
		DOM:         domContent,
		ConsoleLogs: consoleLogs,
		Storage:     storageState,
	}, nil
}


// captureStorage retrieves cookies and local/session storage.
func (s *Session) captureStorage(ctx context.Context, state *schemas.StorageState) error {
	// 1. Get Cookies via CDP.
	// FIX: Use network.GetCookies() for compatibility.
	cookies, err := network.GetCookies().Do(ctx)
	if err != nil {
		s.logger.Warn("Failed to get cookies via CDP.", zap.Error(err))
	}
	state.Cookies = cookies

	// 2. Get Local/Session Storage via JS Evaluation.
	jsGetStorage := func(storageType string) string {
		return fmt.Sprintf(`(function() {
            let items = {};
            try {
                const s = window.%s;
                if (s) {
                    for (let i = 0; i < s.length; i++) {
                        const k = s.key(i);
                        if (k) { items[k] = s.getItem(k); }
                    }
                }
            } catch (e) { /* SecurityError or storage disabled */ }
            return items;
        })()`, storageType)
	}

	if err := chromedp.Run(ctx,
		chromedp.Evaluate(jsGetStorage("localStorage"), &state.LocalStorage),
		chromedp.Evaluate(jsGetStorage("sessionStorage"), &state.SessionStorage),
	); err != nil {
		s.logger.Warn("Could not capture Local/Session storage via JS.", zap.Error(err))
	}
	return nil
}

// runActions executes chromedp.Actions, ensuring they respect both the session lifetime (s.ctx)
// and the incoming request context (ctx).
func (s *Session) runActions(ctx context.Context, actions ...chromedp.Action) error {
	runCtx, cancel := CombineContext(s.ctx, ctx)
	defer cancel()

	return chromedp.Run(runCtx, actions...)
}
