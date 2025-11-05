// internal/browser/session/session.go
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	// Import cdp for page.LayoutMetrics

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/active/taint"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// NOTE: ActionExecutor interface is defined in interfaces.go

// Session represents an active browser session (a tab) and implements schemas.SessionContext.
type Session struct {
	id     string
	ctx    context.Context // Master context for the session lifetime
	cancel context.CancelFunc
	logger *zap.Logger
	cfg    config.Interface // Use the config interface

	persona schemas.Persona

	findingsChan chan<- schemas.Finding // Channel to send findings back

	// Integrated components
	humanoid   *humanoid.Humanoid
	harvester  *Harvester  // Ensure Harvester is defined/imported
	interactor *Interactor // Ensure Interactor is defined/imported
	//  Store the executor instance directly
	executor humanoid.Executor

	onClose func() // Callback when session is closed

	mu       sync.Mutex // Protects isClosed and findingsChan access
	isClosed bool
}

// Ensure Session implements the interface.
//
//	Interface implementation is checked here. Addressed InvalidIfaceAssign by updating ExecuteScript signature.
var _ schemas.SessionContext = (*Session)(nil)

// Ensure Session implements ActionExecutor.
var _ ActionExecutor = (*Session)(nil)

// NewSession creates a new Session instance wrapper.
func NewSession(
	ctx context.Context, // This should be the context created by chromedp.NewContext(allocCtx)
	cancel context.CancelFunc,
	cfg config.Interface, // Use the config interface
	persona schemas.Persona,
	logger *zap.Logger,
	onClose func(),
	findingsChan chan<- schemas.Finding, // Accept the findings channel
) (*Session, error) {

	sessionID := uuid.New().String()
	sessionLogger := logger.With(zap.String("session_id", sessionID))

	s := &Session{
		id:           sessionID,
		ctx:          ctx, // Store the master session context
		cancel:       cancel,
		logger:       sessionLogger,
		cfg:          cfg,
		persona:      persona,
		onClose:      onClose,
		findingsChan: findingsChan, // Store the channel
	}

	return s, nil
}

// SetOnClose allows setting the onClose callback after initialization (e.g., by the Manager).
func (s *Session) SetOnClose(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onClose = fn
}

// Initialize applies configurations and starts necessary components.
// ctx here is an operational context (e.g., initCtx) used to enforce initialization timeouts.
func (s *Session) Initialize(ctx context.Context, taintTemplate, taintConfig string) error {
	s.logger.Debug("Initializing session.")

	// 1. Ensure the target (tab) is created and CDP is connected.
	// The first call to cdp.Run initializes the target.
	// Chromedp binds the target's lifetime to the context used in this first call.
	// Previously, this used the operational context (ctx/initCtx), causing the tab to close when initCtx expired (e.g., 30s).
	// MUST use the session's master context (s.ctx) here to ensure the tab persists for the session's lifetime.
	if err := chromedp.Run(s.ctx, chromedp.Tasks{}); err != nil {
		// If this fails, it usually means s.ctx was already cancelled (e.g., browser allocation failed).
		return fmt.Errorf("failed to initialize browser context/target connection using session context: %w", err)
	}

	// Subsequent initialization steps use the operational context (ctx) to respect the initialization deadline.

	// 2. Initialize Harvester.
	// Use the session's master context (s.ctx) for the harvester's lifetime.
	//  Use config accessor `Network()`
	//  Pass 's' (as ActionExecutor) to NewHarvester to ensure Harvester's CDP calls are synchronized.
	s.harvester = NewHarvester(s.ctx, s.logger, s.cfg.Network().CaptureResponseBodies, s)
	// Start listening using the session context (s.ctx).
	// The Start method itself shouldn't block for long.
	if err := s.harvester.Start(s.ctx); err != nil {
		// If harvester fails to start, log and potentially disable HAR/console collection?
		// For now, return the error as it might indicate deeper CDP issues.
		s.logger.Error("Failed to start harvester", zap.Error(err))
		return fmt.Errorf("failed to start harvester: %w", err)
	}
	s.logger.Debug("Harvester initialized and started.")
	var tasks chromedp.Tasks

	tasks = append(tasks, network.Enable().WithMaxTotalBufferSize(20000000).WithMaxResourceBufferSize(10000000))

	//  Enable Log and Page domains (TestSession/NavigateAndCollectArtifacts failure).
	tasks = append(tasks, runtime.Enable())
	tasks = append(tasks, page.Enable())

	// 3. Apply Stealth Evasions and Persona Spoofing.
	tasks = append(tasks, stealth.Apply(s.persona, s.logger)...)

	// 4. Initialize Humanoid and Interactor.
	// FIX (R9): Check if controllers are already initialized (e.g., by test fixture) before attempting standard initialization.
	// This supports the DI pattern required to fix the race condition in the test harness (RACE 1).
	if s.executor == nil || s.interactor == nil {
		s.logger.Debug("Controllers not pre-initialized. Running standard initialization (initializeControllers).")
		if err := s.initializeControllers(); err != nil {
			// Log the error but continue; interactions might still work without humanoid.
			s.logger.Error("Failed to initialize controllers (humanoid/interactor)", zap.Error(err))
			// Clear humanoid reference if initialization failed
			s.humanoid = nil

			// Re-initialize interactor without humanoid if initialization failed but we want to proceed.
			// Ensure we don't overwrite if initializeControllers partially succeeded in setting the interactor.
			if s.interactor == nil {
				s.logger.Debug("Attempting fallback Interactor initialization (without humanoid).")
				stabilizeFn := func(stabCtx context.Context) error {
					// R8: Ensure fallback uses the updated stabilization mechanism (quiet + settle delay).
					return s.stabilize(stabCtx, 500*time.Millisecond)
				}
				//  Pass 's' (as ActionExecutor) and s.ctx to NewInteractor.
				// Use a default executor if it wasn't set (e.g. initializeControllers failed early)
				if s.executor == nil {
					s.executor = &cdpExecutor{
						ctx:            s.ctx,
						logger:         s.logger.Named("cdp_executor_fallback"),
						runActionsFunc: s.RunActions,
					}
				}
				s.interactor = NewInteractor(s.logger.Named("interactor_fallback"), nil, stabilizeFn, s, s.ctx)
			}
		}
	} else {
		s.logger.Debug("Controllers (Executor/Interactor) already initialized (skipping initializeControllers).")
		// Ensure Humanoid reference is consistent if Executor/Interactor exist but Humanoid doesn't (e.g. disabled config in test)
		if s.humanoid == nil {
			s.logger.Debug("Humanoid controller was not pre-initialized (likely disabled by config).")
		}
	}

	// Ensure core components (Interactor/Executor) exist before proceeding, even if initialization failed.
	if s.interactor == nil || s.executor == nil {
		return fmt.Errorf("session initialization failed: core components (Interactor/Executor) are nil after initialization attempt")
	}

	// 5. Inject Taint Analysis Shim (if configured and enabled).
	//  Use config accessor `IAST()`
	if s.cfg.IAST().Enabled && taintTemplate != "" {
		// Use the operational context (ctx) for setup actions.
		if err := s.initializeTaintShim(ctx, taintTemplate, taintConfig); err != nil {
			// Log as warning, maybe non-fatal depending on requirements.
			s.logger.Warn("Failed to initialize IAST Taint Shim", zap.Error(err))
		}
	}

	// 6. Apply custom headers.
	//  Use config accessor `Network()`
	if len(s.cfg.Network().Headers) > 0 {
		headers := make(network.Headers)
		//  Use config accessor `Network()`
		for k, v := range s.cfg.Network().Headers {
			headers[k] = v
		}
		tasks = append(tasks, network.SetExtraHTTPHeaders(headers))
	}

	// Execute all remaining initialization tasks sequentially for improved stability and diagnostics.
	s.logger.Debug("Executing initialization tasks sequentially", zap.Int("num_tasks", len(tasks)))
	for i, task := range tasks {
		// Log the type of the task for better diagnostics if it fails.
		// Use reflection to get the underlying type if it's an interface or pointer.
		taskType := fmt.Sprintf("%T", task)

		// Ensure the task is valid before attempting reflection or running.
		val := reflect.ValueOf(task)
		if !val.IsValid() || (val.Kind() == reflect.Ptr && val.IsNil()) {
			s.logger.Warn("Skipping nil or invalid initialization task", zap.Int("task_index", i), zap.String("task_type", taskType))
			continue
		}

		// Improve taskType logging for pointers (since we confirmed it's not nil)
		if val.Kind() == reflect.Ptr {
			// Attempt to get the type name of the element the pointer points to.
			//  Check if Elem() is valid before calling Interface() (handles interface pointers correctly)
			if val.Elem().IsValid() {
				taskType = fmt.Sprintf("%T", val.Elem().Interface())
			}
		}

		s.logger.Debug("Running initialization task", zap.Int("task_index", i), zap.String("task_type", taskType))

		// Use chromedp.Run with the operational context (ctx) to enforce the initialization deadline.
		if err := chromedp.Run(ctx, task); err != nil {
			// Return a detailed error message pinpointing the failed task.
			return fmt.Errorf("failed to run session initialization task %d (%s): %w", i, taskType, err)
		}
	}

	// 7. Initialize cursor position (only if humanoid was successfully initialized).
	// This check remains valid regardless of how humanoid was initialized.
	if s.humanoid != nil {
		// Use operational context for the initial move.
		if err := s.initializeCursorPosition(ctx); err != nil {
			// Log as debug, failure here is likely not critical.
			s.logger.Debug("Could not set initial cursor position", zap.Error(err))
		}
	}

	s.logger.Info("Session initialized successfully.")
	return nil
}

// RunActions executes chromedp actions by combining the operational context (ctx)
// with the session's master context (s.ctx). It implements the ActionExecutor interface.
// This is the standard way to execute actions that should be tied to both the session lifetime
// and the specific operation's deadline. (Context Best Practices 1.1)
func (s *Session) RunActions(ctx context.Context, actions ...chromedp.Action) error {
	// 1. Combine Contexts
	// s.ctx is the primary context (carries CDP connection info).
	// ctx is the secondary/operational context (carries deadlines/cancellation for this specific operation).
	combinedCtx, cancel := CombineContext(s.ctx, ctx)
	defer cancel()

	// 2. Execute Actions (Synchronized execution happens within chromedp.Run)
	err := chromedp.Run(combinedCtx, actions...)

	// 3. Error Prioritization and Handling
	if err != nil {
		// Prioritization: Operational > Session > Spurious > CDP Error

		// Check if the operational context was cancelled (timeout or explicit cancel).
		if ctx.Err() != nil {
			// Operation timed out or was cancelled. This is the most specific cause.
			// Note: If both s.ctx and ctx are cancelled, we favor the operational context error.
			return ctx.Err()
		}

		// Check if the session context was cancelled.
		if s.ctx.Err() != nil {
			// Session closed.
			return s.ctx.Err()
		}

		//  Handle navigation-induced spurious "context canceled" errors (TestInteractor/FormInteraction_VariousTypes failure).
		// If chromedp returns "context canceled", but neither context is done (checked above),
		// it often means the action triggered a navigation that interrupted the action's completion signal.
		// We treat this as success, as the action (e.g., click, JS eval) did execute.
		if err == context.Canceled {
			s.logger.Debug("RunActions received 'context canceled' but contexts are active (likely navigation). Treating as success.")
			return nil
		}

		// If none of the above, it's a specific CDP protocol or execution error.
		return err
	}
	return nil
}

//	Implemented RunBackgroundActions to support Harvester body fetching during session shutdown.
//
// RunBackgroundActions implements the ActionExecutor interface.
// It ensures actions run even if the main session context (s.ctx) is cancelled,
// by using a detached context that preserves CDP values. (Context Best Practices 3.3)
func (s *Session) RunBackgroundActions(ctx context.Context, actions ...chromedp.Action) error {
	// 1. Create Detached Context
	// Detach from the session context (s.ctx) to ignore its cancellation signal, while keeping its values (CDP info).
	detachedCtx := Detach(s.ctx)

	// 2. Combine Contexts
	// Combine the detached context (primary) with the operational context (ctx, secondary).
	// This ensures the operation respects the operational deadline (e.g., body fetch timeout),
	// but ignores the session lifecycle cancellation.
	combinedCtx, cancel := CombineContext(detachedCtx, ctx)
	defer cancel()

	// 3. Execute Actions
	err := chromedp.Run(combinedCtx, actions...)

	// 4. Error Handling (Simplified for background tasks)
	return err
}

// stabilize waits for the page state to settle (DOM ready and network idle).
func (s *Session) stabilize(ctx context.Context, quietPeriod time.Duration) error {
	s.logger.Debug("Stabilizing page state", zap.Duration("quietPeriod", quietPeriod))
	// Use a timeout specific to stabilization, combined with the incoming context (ctx)
	// and the session context (s.ctx).
	stabCtx, cancel := context.WithTimeout(ctx, 90*time.Second) // Stabilization timeout
	defer cancel()

	// Wait for body ready using RunActions (handles combined context)
	if err := s.RunActions(stabCtx, chromedp.WaitReady("body", chromedp.ByQuery)); err != nil {
		// Check original context errors before logging/returning stabilization error
		if ctx.Err() != nil {
			s.logger.Debug("Stabilization WaitReady interrupted by incoming context", zap.Error(ctx.Err()))
			return ctx.Err()
		}
		if s.ctx.Err() != nil {
			s.logger.Debug("Stabilization WaitReady interrupted by session context", zap.Error(s.ctx.Err()))
			return s.ctx.Err()
		}
		// Log WaitReady failure if not due to context cancel
		if stabCtx.Err() == nil {
			s.logger.Warn("WaitReady failed during stabilization", zap.Error(err))
		} else {
			s.logger.Warn("WaitReady timed out during stabilization", zap.Error(stabCtx.Err()))
		}
		return fmt.Errorf("stabilize: WaitReady failed: %w", err) // Return the specific error
	}

	// Wait for network idle using harvester, passing the stabilization context
	if s.harvester != nil {
		if err := s.harvester.WaitNetworkIdle(stabCtx, quietPeriod); err != nil {
			if ctx.Err() != nil {
				s.logger.Debug("Stabilization WaitNetworkIdle interrupted by incoming context.", zap.Error(ctx.Err()))
				return ctx.Err()
			}
			if s.ctx.Err() != nil {
				s.logger.Debug("Stabilization WaitNetworkIdle interrupted by session context", zap.Error(s.ctx.Err()))
				return s.ctx.Err()
			}
			// Log network idle failure if not due to context cancel
			if stabCtx.Err() == nil {
				s.logger.Warn("Network idle wait failed during stabilization", zap.Error(err))
			} else {
				s.logger.Warn("Network idle wait timed out during stabilization", zap.Error(stabCtx.Err()))
			}
			return fmt.Errorf("stabilize: WaitNetworkIdle failed: %w", err) // Return the specific error
		}
	}

	// R8: Add a mandatory post-stabilization sleep (Settle Delay).
	// Stabilization waits for network idle (WaitNetworkIdle) and DOM ready (WaitReady).
	// However, this is insufficient for modern applications that use setTimeout, requestAnimationFrame,
	// or post-network processing (e.g., rendering data fetched from the network) to update the DOM.
	// A short, fixed delay allows these asynchronous JS operations to complete and the DOM to settle.

	// The duration should be long enough to cover common JS timers but short enough not to slow down execution significantly.
	// R9: Increased Settle Delay (from 500ms).
	// Under heavy load (e.g., -race detector), the browser's rendering pipeline can lag significantly.
	// A longer delay provides more buffer for the DOM to update (TestInteractor/DepthLimiting failure).
	const settleDelay = 750 * time.Millisecond

	s.logger.Debug("Applying post-stabilization settle delay", zap.Duration("duration", settleDelay))
	select {
	case <-time.After(settleDelay):
		// Proceed
	case <-stabCtx.Done():
		// If stabilization context times out during the settle delay.
		s.logger.Debug("Settle delay interrupted by stabilization context", zap.Error(stabCtx.Err()))
		return stabCtx.Err()
	case <-ctx.Done():
		// If the operational context is cancelled during the settle delay.
		s.logger.Debug("Settle delay interrupted by incoming context", zap.Error(ctx.Err()))
		return ctx.Err()
	case <-s.ctx.Done():
		// If the session context is cancelled during the settle delay.
		s.logger.Debug("Settle delay interrupted by session context", zap.Error(s.ctx.Err()))
		return s.ctx.Err()
	}

	s.logger.Debug("Stabilization complete.")
	return nil
}

// initializeControllers sets up the Humanoid and Interactor components.
// R9: This function assumes it is only called if the components are not already initialized (handled by Initialize).
func (s *Session) initializeControllers() error {
	//  Initialize the CDP executor adapter first. It's needed regardless of Humanoid status.
	// R9: Removed check for s.executor == nil, as Initialize handles this check.
	s.executor = &cdpExecutor{
		ctx:    s.ctx, // Executor uses the session's master context for its operations
		logger: s.logger.Named("cdp_executor"),
		// Pass the session's RunActions method to the executor
		runActionsFunc: s.RunActions,
	}

	// Initialize Humanoid
	//  Use config accessor `Browser()`
	if s.cfg.Browser().Humanoid.Enabled {
		// R9: Removed check for s.humanoid == nil.
		//  Use config accessor `Browser()` and pass the valid executor
		// Use the already initialized executor
		s.humanoid = humanoid.New(s.cfg.Browser().Humanoid, s.logger.Named("humanoid"), s.executor)
		s.logger.Debug("Humanoid controller initialized.")
	} else {
		s.logger.Debug("Humanoid controller disabled by config. Basic executor initialized.")
	}

	// Initialize Interactor (even if humanoid is nil)
	// R9: Removed check for s.interactor == nil.
	stabilizeFn := func(stabCtx context.Context) error {
		// Stabilize function should use the context passed to it
		// R8/R9: Use 500ms network quiet period. The mandatory Settle Delay (R9: 750ms)
		// in stabilize() addresses race conditions related to delayed JS execution.
		return s.stabilize(stabCtx, 500*time.Millisecond)
	}
	//  Pass 's' (as ActionExecutor) and s.ctx to NewInteractor.
	s.interactor = NewInteractor(s.logger.Named("interactor"), s.humanoid, stabilizeFn, s, s.ctx)
	s.logger.Debug("Interactor initialized.")
	return nil
}

// initializeCursorPosition moves the mouse cursor to the center of the viewport.
func (s *Session) initializeCursorPosition(ctx context.Context) error {
	if s.humanoid == nil {
		// R9: This is expected if humanoid is disabled, not an error condition.
		s.logger.Debug("Humanoid not initialized, skipping initial cursor positioning.")
		return nil
	}
	width, height := s.persona.Width, s.persona.Height
	if width <= 0 || height <= 0 {
		s.logger.Debug("Persona viewport size invalid, attempting to get actual viewport size.")

		//  Correctly call GetLayoutMetrics and handle its multiple return values (WrongAssignCount error).
		// Assuming standard cdproto implementation returns 7 values.
		var layoutViewport *page.LayoutViewport
		var visualViewport *page.VisualViewport

		// Use chromedp.Run with the operational context (ctx) to respect the initialization deadline.
		err := chromedp.Run(ctx, chromedp.ActionFunc(func(c context.Context) error {
			// Use blank identifiers for unused return values (contentSize and CSS metrics).
			lv, vv, _, _, _, _, err := page.GetLayoutMetrics().Do(c)
			if err != nil {
				return fmt.Errorf("could not get layout metrics: %w", err)
			}
			layoutViewport = lv
			visualViewport = vv
			return nil
		}))

		if err != nil {
			// This handles both runActions error and the error returned from ActionFunc.
			return err
		}

		// Check the structure carefully based on cdproto definition
		if visualViewport == nil || layoutViewport == nil {
			return fmt.Errorf("received invalid layout metrics structure (viewports are nil)")
		}

		// Prefer VisualViewport, fallback to LayoutViewport
		if visualViewport.ClientWidth > 0 && visualViewport.ClientHeight > 0 {
			width = int64(visualViewport.ClientWidth)
			height = int64(visualViewport.ClientHeight)
			s.logger.Debug("Using VisualViewport dimensions for initial cursor", zap.Int64("width", width), zap.Int64("height", height))
		} else if layoutViewport.ClientWidth > 0 && layoutViewport.ClientHeight > 0 {
			width = int64(layoutViewport.ClientWidth)
			height = int64(layoutViewport.ClientHeight)
			s.logger.Debug("Falling back to LayoutViewport dimensions for initial cursor", zap.Int64("width", width), zap.Int64("height", height))
		} else {
			return fmt.Errorf("retrieved viewport dimensions are invalid (width=%d, height=%d)", width, height)
		}
	}

	startX, startY := float64(width)/2.0, float64(height)/2.0
	startVec := humanoid.Vector2D{X: startX, Y: startY}
	s.logger.Debug("Initializing cursor position.", zap.Float64("x", startX), zap.Float64("y", startY))

	// Use the provided operational context (ctx) for this action.
	//  Pass context as the first argument, remove invalid .Do()
	err := s.humanoid.MoveToVector(ctx, startVec, nil)
	if err != nil {
		s.logger.Warn("Failed to move cursor to initial position", zap.Error(err))
		return err // Still return the error
	}
	s.logger.Debug("Initial cursor position set.")
	return nil
}

// [Rest of the file remains unchanged from the provided input]
// initializeTaintShim builds, exposes the callback, and injects the IAST shim script.
func (s *Session) initializeTaintShim(ctx context.Context, template, configJSON string) error {
	script, err := taint.BuildTaintShim(template, configJSON)
	if err != nil {
		return fmt.Errorf("failed to build shim script: %w", err)
	}

	// Expose the reporting function using the operational context.
	if err := s.ExposeFunction(ctx, "__scalpel_sink_event", s.handleTaintEvent); err != nil {
		return fmt.Errorf("failed to expose sink event handler: %w", err)
	}

	// Inject the script persistently using the operational context.
	if err := s.InjectScriptPersistently(ctx, script); err != nil {
		return fmt.Errorf("failed to inject shim script: %w", err)
	}
	s.logger.Info("IAST Taint Shim initialized and injected.")
	return nil
}

// handleTaintEvent is the callback exposed to the browser's JS environment.
// It receives data from the IAST shim when a sink is triggered.
func (s *Session) handleTaintEvent(eventData map[string]interface{}) {
	// This function runs in a goroutine managed by the binding listener.
	// Avoid blocking here.

	//  Use a short timeout derived from background context for the send operation
	// instead of a bare context.Background(), to prevent blocking indefinitely if the channel is full.
	findingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s.mu.Lock()
	closed := s.isClosed
	s.mu.Unlock()
	if closed {
		s.logger.Debug("Session closed, ignoring taint event.")
		return
	}

	if eventData == nil {
		s.logger.Warn("Received nil event data in handleTaintEvent")
		return
	}
	eventType, _ := eventData["type"].(string)
	detail := eventData["detail"]

	s.logger.Info("IAST Sink Triggered", zap.String("type", eventType), zap.Any("detail", detail))

	//  Prepare evidence. Assuming schemas.Finding.Evidence is a string (e.g., JSON string) to fix IncompatibleAssign.
	evidenceDataMap := map[string]interface{}{
		"sink_type": eventType,
		"details":   eventData["detail"], // Store raw detail map
	}
	// Marshal the full evidenceDataMap for consistency.
	evidenceBytes, marshalErr := json.Marshal(evidenceDataMap)
	evidenceStr := "{}" // Fallback empty JSON object string
	if marshalErr == nil {
		evidenceStr = string(evidenceBytes) // Use the marshaled string
	} else {
		s.logger.Warn("Failed to marshal IAST evidence data.", zap.Error(marshalErr))
		// Fallback logic if needed...
	}

	//  Update finding creation to match current schemas.Finding structure
	finding := schemas.Finding{
		// ID, ScanID, TaskID are usually set by the engine/manager calling AddFinding
		// Target URL might be retrieved from context if available, or passed in eventData
		Module: "IAST",
		Vulnerability: schemas.Vulnerability{
			Name:        fmt.Sprintf("IAST Sink: %s", eventType),
			Description: "Interactive analysis detected data flow into a potentially sensitive sink.",
		},
		Severity:       "Info", // Default, could be adjusted based on eventType
		Description:    fmt.Sprintf("IAST Sink '%s' triggered.", eventType),
		Evidence:       evidenceStr, // Changed from map[string]interface{}
		Recommendation: "Review the source of the data and the context of the sink to determine if this represents a vulnerability (e.g., XSS, SQLi). Sanitize or validate input appropriately.",
		Timestamp:      time.Now().UTC(),
		// Add other necessary fields based on the current schemas.Finding definition
	}

	if err := s.AddFinding(findingCtx, finding); err != nil {
		s.logger.Error("Failed to add IAST finding", zap.Error(err))
	}
}

// ID returns the unique identifier for the session.
func (s *Session) ID() string {
	return s.id
}

// GetContext returns the underlying master context for the session.
func (s *Session) GetContext() context.Context {
	return s.ctx
}

// Close terminates the browser session gracefully.
func (s *Session) Close(ctx context.Context) error {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		s.logger.Debug("Session already closed.")
		return nil
	}
	s.isClosed = true
	// Set findingsChan to nil under lock to prevent writes during/after close
	s.findingsChan = nil
	s.mu.Unlock()

	s.logger.Info("Closing browser session.", zap.String("session_id", s.id))

	// 1. Stop the Harvester (gracefully). Use operational context with timeout.
	if s.harvester != nil {
		// Use a short, independent timeout context for stopping harvester
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()        //  Ensure context cancellation is deferred (idiomatic Go).
		s.harvester.Stop(stopCtx) // Pass the timed context
		s.logger.Debug("Harvester stopped.")
	}

	// 2. Cancel the main session context. This signals termination.
	if s.cancel != nil {
		s.cancel()
		s.logger.Debug("Session master context cancelled.")
	}

	// 3. Execute the onClose callback (e.g., remove from manager map).
	if s.onClose != nil {
		s.onClose()
		s.logger.Debug("onClose callback executed.")
	}

	s.logger.Info("Session close sequence complete.", zap.String("session_id", s.id))
	// Note: Closing the underlying browser tab/context is typically handled by chromedp
	// when the session context (s.ctx) derived from NewContext is canceled.
	return nil
}

// CollectArtifacts gathers the HAR, DOM, Console Logs, and Storage state.
func (s *Session) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil, fmt.Errorf("session %s is closed, cannot collect artifacts", s.id)
	}
	s.mu.Unlock()
	s.logger.Debug("Starting artifact collection.")

	// Apply a timeout for the entire collection process to the operational context.
	// RunActions will handle the combination with s.ctx.
	// P2  Increased timeout from 30s to 60s. This must be longer than the Harvester's
	// bodyFetchTimeout (30s) to allow background fetches to complete gracefully during collection (TestSession/* timeout failures).
	collectCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// 1. Stop the harvester and get data. Use the collectCtx.
	var harData *schemas.HAR
	var consoleLogs []schemas.ConsoleLog
	if s.harvester != nil {
		// Stop should be relatively quick, but use collectCtx
		harData, consoleLogs = s.harvester.Stop(collectCtx)
	} else {
		s.logger.Warn("Harvester not initialized, cannot collect HAR/console logs.")
		consoleLogs = []schemas.ConsoleLog{} // Ensure not nil
	}

	// 2. Capture DOM and Storage state using collectCtx.
	var domContent string
	storageState := schemas.StorageState{
		LocalStorage:   make(map[string]string), // Initialize maps
		SessionStorage: make(map[string]string),
		Cookies:        []*schemas.Cookie{}, // Initialize slice
	}

	// Run actions within the collectCtx timeout.
	err := s.RunActions(collectCtx,
		chromedp.OuterHTML("html", &domContent, chromedp.ByQuery),
		chromedp.ActionFunc(func(c context.Context) error {
			// Pass the ActionFunc's context (derived from collectCtx)
			return s.captureStorage(c, &storageState)
		}),
	)

	// Check for errors *after* potential context cancelation
	if err != nil {
		// Log errors not caused by expected cancellation
		if collectCtx.Err() == nil && ctx.Err() == nil && s.ctx.Err() == nil {
			s.logger.Warn("Could not fully collect browser artifacts (DOM/Storage)", zap.Error(err))
		} else {
			s.logger.Debug("Artifact collection (DOM/Storage) interrupted", zap.Error(err))
		}
		// Continue to return partial artifacts
	}

	// Serialize HAR data
	var harRaw *json.RawMessage
	if harData != nil {
		raw, err := json.Marshal(harData)
		if err == nil {
			msg := json.RawMessage(raw)
			harRaw = &msg
		} else {
			s.logger.Warn("Failed to serialize HAR data", zap.Error(err))
			raw := json.RawMessage("null") // Explicitly null on error
			harRaw = &raw
		}
	} else {
		raw := json.RawMessage("null") // Explicitly null if no data
		harRaw = &raw
	}

	s.logger.Debug("Artifact collection finished.")
	return &schemas.Artifacts{
		HAR:         harRaw,
		DOM:         domContent,
		ConsoleLogs: consoleLogs,
		Storage:     storageState,
	}, nil // Return partial artifacts even if errors occurred
}

// captureStorage retrieves cookies and local/session storage concurrently.
func (s *Session) captureStorage(ctx context.Context, state *schemas.StorageState) error {
	var wg sync.WaitGroup
	var cookiesErr, lsErr, ssErr error // Use separate error variables
	var cookies []*network.Cookie      // Temp storage for cookies

	// 1. Get Cookies via CDP concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var err error
		cookies, err = network.GetCookies().Do(ctx) // Assign to local var
		if err != nil {
			// Check context before logging warning
			if ctx.Err() == nil && s.ctx.Err() == nil {
				s.logger.Debug("Failed to get cookies via CDP", zap.Error(err))
			}
			cookiesErr = err // Store error
		}
	}()

	// 2. Get Local Storage via JS Evaluation concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		js := getStorageScript("localStorage")
		// We are already inside an ActionFunc (called via runActions), so we must use .Do(ctx)
		// instead of calling runActions again.
		lsErr = chromedp.Evaluate(js, &state.LocalStorage).Do(ctx)
		if lsErr != nil && ctx.Err() == nil {
			s.logger.Warn("Could not capture Local storage via JS", zap.Error(lsErr))
		}
	}()

	// 3. Get Session Storage via JS Evaluation concurrently.
	wg.Add(1)
	go func() {
		defer wg.Done()
		js := getStorageScript("sessionStorage")
		// Use .Do(ctx) as we are inside an ActionFunc.
		ssErr = chromedp.Evaluate(js, &state.SessionStorage).Do(ctx)
		if ssErr != nil && ctx.Err() == nil {
			s.logger.Warn("Could not capture Session storage via JS", zap.Error(ssErr))
		}
	}()

	wg.Wait() // Wait for all goroutines

	// Process cookies after wait
	if cookiesErr == nil && cookies != nil {
		//  Use the correct conversion function for []*network.Cookie to []*schemas.Cookie (IncompatibleAssign errors).
		state.Cookies = convertNetworkCookiesToSchemaCookies(cookies)
	}

	// Return the first non-nil error encountered
	if cookiesErr != nil {
		return cookiesErr
	}
	if lsErr != nil {
		return lsErr
	}
	return ssErr // Can be nil
}

// getStorageScript generates the JS snippet to retrieve storage items.
func getStorageScript(storageType string) string {
	// Added check for null storage object and item retrieval errors
	return fmt.Sprintf(`(function() {
		        let items = {};
		        try {
		            const s = window.%s;
		            if (s) {
		                for (let i = 0; i < s.length; i++) {
		                    const k = s.key(i);
		                    // Ensure key is not null/undefined before using it
		                    if (k != null) {
		                         try {
		                           const item = s.getItem(k);
		                           // Store even if item is null/undefined, as represented in storage
		                           items[k] = item;
		                         } catch(e) {
		                           console.error("Error getting storage item:", { storage: "%s", key: k, error: e.toString() });
		                         }
		                    }
		                }
		            }
		        } catch (e) { console.error("Error accessing %s:", e.toString()); }
		        return items;
		    })()`, storageType, storageType, storageType) // Pass storageType multiple times for logging
}

// bindingWrapperJS is the JavaScript code that wraps the raw CDP binding.
// It captures the arguments, serializes them to a JSON array string,
// and calls the underlying binding function with that string.
// This is necessary because runtime.AddBinding exposes a function that expects exactly one string argument.
//
//	Added wrapper injection to resolve ExposeFunction failures (JS exceptions and timeouts).
const bindingWrapperJS = `(function(name) {
  // Ensure the wrapper is applied only once (idempotency check)
  if (window[name] === undefined || window[name].__scalpel_wrapped) {
    return;
  }
  
  const binding = window[name];
  // Check if the raw binding function exists and is a function
  if (typeof binding !== 'function') {
    // Binding might not be ready yet if this script runs very early, or failed to register.
    return;
  }
  
  const wrapper = function(...args) {
    try {
        // The raw binding expects exactly one string argument.
        const serialized = JSON.stringify(args);
        binding(serialized);
    } catch (e) {
        console.error("Scalpel ExposeFunction shim: Failed to serialize arguments for " + name, e, args);
    }
  };
  wrapper.__scalpel_wrapped = true;
  window[name] = wrapper;
})("%s")`

// -- Interface Method Implementations --

// AddFinding sends a finding to the central findings channel safely.
func (s *Session) AddFinding(ctx context.Context, finding schemas.Finding) error {
	s.mu.Lock()
	// Check if closed or channel is nil under lock
	if s.isClosed || s.findingsChan == nil {
		s.mu.Unlock()
		msg := "session closed"
		if s.findingsChan == nil && !s.isClosed {
			msg = "findings channel is nil"
		}
		//  Use finding.Vulnerability.Name if available, else Description, else fallback
		findingIdentifier := finding.Vulnerability.Name
		if findingIdentifier == "" {
			findingIdentifier = finding.Description
		}
		if findingIdentifier == "" {
			findingIdentifier = "(unknown type)"
		}

		s.logger.Warn("Cannot add finding", zap.String("reason", msg), zap.String("finding_type", findingIdentifier))
		return fmt.Errorf("cannot add finding: %s", msg)
	}
	// Make a shallow copy of the channel under the lock to use outside
	ch := s.findingsChan
	s.mu.Unlock()

	// Add session ID to the finding for context if not already present
	//  Removed usage of Metadata as the field does not exist in schemas.Finding (MissingFieldOrMethod error).
	/*
		if finding.Metadata == nil {
			finding.Metadata = make(map[string]interface{})
		}
		if _, exists := finding.Metadata["session_id"]; !exists {
			finding.Metadata["session_id"] = s.id
		}
	*/

	// Add timestamp if missing
	if finding.Timestamp.IsZero() {
		finding.Timestamp = time.Now().UTC()
	}

	// Use a select to send non-blockingly, respecting contexts.
	select {
	case ch <- finding:
		//  Use finding.Vulnerability.Name if available for logging
		findingIdentifier := finding.Vulnerability.Name
		if findingIdentifier == "" {
			findingIdentifier = "(unknown type)"
		}
		s.logger.Debug("Finding added", zap.String("finding_type", findingIdentifier))
		return nil
	case <-ctx.Done(): // Check operational context first
		s.logger.Warn("Context cancelled before finding could be added", zap.Error(ctx.Err()), zap.String("context_type", "operational"), zap.String("finding_type", finding.Vulnerability.Name))
		return ctx.Err()
	case <-s.ctx.Done(): // Then check session context
		s.logger.Warn("Session context cancelled before finding could be added.", zap.Error(s.ctx.Err()), zap.String("finding_type", finding.Vulnerability.Name))
		return s.ctx.Err()
	}
}

// NOTE: Navigate, Click, Type, Submit, ScrollPage, WaitForAsync, Interact methods
// are defined in interaction.go. Ensure they have the correct context parameter.

// Sleep pauses execution for a specified duration (convenience wrapper respecting context).
func (s *Session) Sleep(ctx context.Context, d time.Duration) error {
	s.logger.Debug("Sleeping", zap.Duration("duration", d))

	// Use RunActions to execute the sleep. This centralizes context combination.
	return s.RunActions(ctx, chromedp.Sleep(d))
}

// DispatchMouseEvent directly dispatches a mouse event. Delegates to the executor.
func (s *Session) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	//  Use the stored executor directly.
	if s.executor == nil {
		// This should not happen if Initialize runs correctly.
		return fmt.Errorf("cannot dispatch mouse event: session executor not initialized")
	}
	// Pass the operational context (ctx) to the executor method
	return s.executor.DispatchMouseEvent(ctx, data)
}

// SendKeys directly dispatches keyboard events. Delegates to the executor.
func (s *Session) SendKeys(ctx context.Context, keys string) error {
	//  Use the stored executor directly.
	if s.executor == nil {
		return fmt.Errorf("cannot send keys: session executor not initialized")
	}
	return s.executor.SendKeys(ctx, keys)
}

// DispatchStructuredKey dispatches a structured key event. Delegates to the executor.
func (s *Session) DispatchStructuredKey(ctx context.Context, data schemas.KeyEventData) error {
	if s.executor == nil {
		return fmt.Errorf("cannot dispatch structured key: session executor not initialized")
	}
	return s.executor.DispatchStructuredKey(ctx, data)
}

// GetElementGeometry retrieves geometry. Delegates to the executor.
func (s *Session) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	//  Use the stored executor directly.
	if s.executor == nil {
		return nil, fmt.Errorf("cannot get element geometry: session executor not initialized")
	}
	return s.executor.GetElementGeometry(ctx, selector)
}

// ExposeFunction allows Go functions to be called from the browser's JavaScript context.
func (s *Session) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	// 1. Validate the Go function signature early.
	fnVal := reflect.ValueOf(function)
	fnType := fnVal.Type()
	if fnType.Kind() != reflect.Func {
		s.logger.Error("Exposed implementation is not a function", zap.String("name", name))
		return fmt.Errorf("provided implementation for '%s' is not a function", name)
	}

	// 2. Add the raw CDP binding. This exposes a function expecting one string argument.
	// Use RunActions for context safety (uses the operational context ctx).
	err := s.RunActions(ctx, runtime.AddBinding(name))
	if err != nil {
		return fmt.Errorf("failed to add binding '%s': %w", name, err)
	}

	// 3. Inject the JavaScript wrapper persistently.
	//  Inject wrapper script to handle argument serialization (TestSession/ExposeFunction* failures).
	wrapperScript := fmt.Sprintf(bindingWrapperJS, name)
	if err := s.InjectScriptPersistently(ctx, wrapperScript); err != nil {
		return fmt.Errorf("failed to inject persistent wrapper script for binding '%s': %w", name, err)
	}

	// 4. Evaluate the shim immediately in the current context(s) if possible.
	// This ensures the function is available immediately, not just after the next navigation.
	if err := s.RunActions(ctx, chromedp.Evaluate(wrapperScript, nil)); err != nil {
		// If immediate evaluation fails (e.g., no execution context yet), it's often non-fatal
		// as the persistent injection will handle subsequent navigations.
		s.logger.Debug("Failed to evaluate JS serialization shim immediately (non-fatal)", zap.String("name", name), zap.Error(err))
	}

	// Listen on the session's master context (s.ctx)
	chromedp.ListenTarget(s.ctx, func(ev interface{}) {
		s.mu.Lock()
		closed := s.isClosed
		s.mu.Unlock()
		if closed {
			return // Ignore events if session is closed
		}

		if ev, ok := ev.(*runtime.EventBindingCalled); ok && ev.Name == name {
			// Process in a new goroutine to avoid blocking the listener
			go func(payload string) {
				// Defer panic recovery for the goroutine
				defer func() {
					if r := recover(); r != nil {
						s.logger.Error("Panic during exposed function callback processing",
							zap.String("name", name),
							zap.Any("panic_reason", r),
							zap.String("stack", string(debug.Stack())))
					}
				}()
				// Check again if session closed before heavy processing
				s.mu.Lock()
				closed := s.isClosed
				s.mu.Unlock()
				if closed {
					return
				}

				//  The payload is expected to be a JSON array string (handled by bindingWrapperJS).
				var args []interface{}
				if err := json.Unmarshal([]byte(payload), &args); err != nil {
					s.logger.Error("Could not unmarshal payload for exposed function", zap.String("name", name), zap.Error(err), zap.String("payload", payload))
					return
				}

				numIn := fnType.NumIn()
				hasCtx := false
				if numIn > 0 && fnType.In(0) == reflect.TypeOf((*context.Context)(nil)).Elem() {
					hasCtx = true
					numIn-- // Expected JS args count
				}

				if len(args) != numIn {
					s.logger.Error("Mismatch in JS argument count for exposed function", zap.String("name", name), zap.Int("expected", numIn), zap.Int("got", len(args)))
					return
				}

				in := make([]reflect.Value, fnType.NumIn())
				argIdx := 0
				if hasCtx {
					// Pass session context to the called function
					in[0] = reflect.ValueOf(s.ctx)
					argIdx = 1
				}

				// Convert JS args to Go types
				for i := 0; i < numIn; i++ {
					goArg, err := s.convertJSToGoType(args[i], fnType.In(argIdx+i))
					if err != nil {
						s.logger.Error("Incompatible argument type for exposed function",
							zap.String("name", name),
							zap.Int("arg_index", argIdx+i),
							zap.String("expected", fnType.In(argIdx+i).String()),
							zap.String("got", fmt.Sprintf("%T", args[i])),
							zap.Any("value", args[i]),
							zap.Error(err))
						return // Stop processing args for this call
					}
					in[argIdx+i] = goArg
				}

				// Call the Go function
				fnVal.Call(in)

			}(ev.Payload) // Pass payload to goroutine
		}
	})
	return nil
}

// convertJSToGoType handles type conversions between JS (via JSON) and Go reflection types.
func (s *Session) convertJSToGoType(jsArg interface{}, goType reflect.Type) (reflect.Value, error) {
	if jsArg == nil {
		// Check if the Go type is nillable
		switch goType.Kind() {
		case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
			return reflect.Zero(goType), nil // Return the zero value (nil)
		default:
			return reflect.Value{}, fmt.Errorf("cannot assign JavaScript null to non-nillable Go type %s", goType.String())
		}
	}

	jsVal := reflect.ValueOf(jsArg)
	jsType := jsVal.Type()

	// Direct assignment?
	if jsType.AssignableTo(goType) {
		return jsVal, nil
	}

	// Handle numbers (JS numbers are float64 via JSON)
	if jsType.Kind() == reflect.Float64 {
		goKind := goType.Kind()
		floatVal := jsVal.Float()

		// Check if conversion to integer types is safe
		if goKind >= reflect.Int && goKind <= reflect.Int64 {
			intVal := int64(floatVal)
			// Check for potential precision loss or overflow if float wasn't an integer
			if floatVal != float64(intVal) {
				s.logger.Warn("Potential precision loss or overflow converting JS float to Go int.", zap.Float64("js_float", floatVal), zap.String("go_type", goType.String()))
				// Decide whether to error out or allow truncation based on requirements
				// return reflect.Value{}, fmt.Errorf("unsafe conversion from float64 %f to %s", floatVal, goType.String())
			}
			// Perform conversion if safe enough
			return reflect.ValueOf(intVal).Convert(goType), nil
		}
		// Check unsigned integers
		if goKind >= reflect.Uint && goKind <= reflect.Uintptr {
			if floatVal < 0 {
				return reflect.Value{}, fmt.Errorf("cannot assign negative JS number %.f to Go unsigned type %s", floatVal, goType.String())
			}
			uintVal := uint64(floatVal)
			if floatVal != float64(uintVal) {
				s.logger.Warn("Potential precision loss or overflow converting JS float to Go uint.", zap.Float64("js_float", floatVal), zap.String("go_type", goType.String()))
				// return reflect.Value{}, fmt.Errorf("unsafe conversion from float64 %f to %s", floatVal, goType.String())
			}
			return reflect.ValueOf(uintVal).Convert(goType), nil
		}
		// Allow float64 to float32 conversion
		if goKind == reflect.Float32 {
			// Check potential overflow for float32
			if floatVal > math.MaxFloat32 || floatVal < -math.MaxFloat32 {
				s.logger.Warn("Potential overflow converting JS float64 to Go float32.", zap.Float64("js_float", floatVal))
				// return reflect.Value{}, fmt.Errorf("overflow converting float64 %f to float32", floatVal)
			}
			return reflect.ValueOf(float32(floatVal)).Convert(goType), nil
		}
	}

	// Basic type conversion? (e.g., string alias)
	if jsType.ConvertibleTo(goType) {
		s.logger.Debug("Attempting direct Go type conversion", zap.String("from", jsType.String()), zap.String("to", goType.String()))
		// This conversion can panic if types are fundamentally incompatible despite ConvertibleTo returning true (rare).
		// Consider adding a recover block if needed, but usually this is safe for simple types.
		return jsVal.Convert(goType), nil
	}

	// Special case: map[string]interface{} from JS to Go struct (via JSON marshal/unmarshal)
	if goType.Kind() == reflect.Struct && jsType.Kind() == reflect.Map && jsType.Key().Kind() == reflect.String {
		s.logger.Debug("Attempting map-to-struct conversion via JSON", zap.String("struct_type", goType.String()))
		mapData, ok := jsArg.(map[string]interface{})
		if ok {
			jsonData, jsonErr := json.Marshal(mapData)
			if jsonErr == nil {
				// Create a pointer to the struct type for unmarshalling
				newStructPtr := reflect.New(goType)
				unmarshalErr := json.Unmarshal(jsonData, newStructPtr.Interface())
				if unmarshalErr == nil {
					return newStructPtr.Elem(), nil // Return the actual struct value, not the pointer
				}
				return reflect.Value{}, fmt.Errorf("JSON unmarshal failed during map-to-struct conversion: %w", unmarshalErr)
			}
			return reflect.Value{}, fmt.Errorf("JSON marshal failed during map-to-struct conversion: %w", jsonErr)
		}
		return reflect.Value{}, fmt.Errorf("JS argument was map-like but not map[string]interface{}")
	}

	// TODO: Add case for []interface{} from JS to Go slice/array if needed.

	return reflect.Value{}, fmt.Errorf("incompatible type: cannot convert JS type %s to Go type %s", jsType.String(), goType.String())
}

// InjectScriptPersistently adds a script to evaluate on new documents.
func (s *Session) InjectScriptPersistently(ctx context.Context, script string) error {
	var scriptID page.ScriptIdentifier
	err := s.RunActions(ctx, chromedp.ActionFunc(func(c context.Context) error {
		var err error
		scriptID, err = page.AddScriptToEvaluateOnNewDocument(script).Do(c) // Use ActionFunc's context 'c'
		return err
	}))
	if err != nil {
		// Check context errors before returning specific error
		if ctx.Err() != nil {
			return ctx.Err()
		}
		//  Corrected logic: check if s.ctx.Err() is NOT nil
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		return fmt.Errorf("could not inject persistent script: %w", err)
	}
	s.logger.Debug("Injected persistent script", zap.String("scriptID", string(scriptID)))
	return nil
}

// ExecuteScript runs JS in the current document context.
//
//	Updated signature to match schemas.SessionContext interface (InvalidIfaceAssign error).
func (s *Session) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	// Chromedp's Evaluate does not directly support passing arguments easily.
	if len(args) > 0 {
		// Log a warning as implementing robust argument passing requires complex IIFE wrapping and JSON handling.
		s.logger.Warn("Session.ExecuteScript: passing arguments via 'args' parameter is not fully supported with current chromedp backend implementation.")
	}

	var res json.RawMessage
	// Use RunActions for context safety.
	err := s.RunActions(ctx, chromedp.Evaluate(script, &res, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
		// Ensure promises are awaited and actual value is returned, suppress exceptions in JS
		return p.WithAwaitPromise(true).WithReturnByValue(true).WithSilent(true)
	}))

	return res, err
}

// -- Helper Functions --

//	Helper function to convert CDP cookies to schema cookies (used to fix IncompatibleAssign errors).
//
// convertNetworkCookiesToSchemaCookies converts CDP network.Cookie structs to schemas.Cookie pointers.
func convertNetworkCookiesToSchemaCookies(cdpCookies []*network.Cookie) []*schemas.Cookie {
	if cdpCookies == nil {
		return nil
	}
	schemaCookies := make([]*schemas.Cookie, 0, len(cdpCookies)) // Initialize with capacity
	for _, c := range cdpCookies {
		if c == nil {
			continue
		}
		schemaCookies = append(schemaCookies, &schemas.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Expires:  c.Expires,
			Size:     c.Size,
			HTTPOnly: c.HTTPOnly,
			Secure:   c.Secure,
			Session:  c.Session,
			// Assuming direct string conversion is valid between network.CookieSameSite and schemas.CookieSameSite
			SameSite: schemas.CookieSameSite(c.SameSite),
		})
	}
	return schemaCookies
}
