// internal/agent/executors.go
package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// -- Executor Registry --

// ExecutorRegistry acts as a dispatcher for various types of agent actions. It
// holds a map of action types to their corresponding `ActionExecutor`
// implementations, ensuring that actions are routed to the correct handler.
// It also manages dynamic providers for browser sessions and humanoid controllers.
type ExecutorRegistry struct {
	logger           *zap.Logger
	executors        map[ActionType]ActionExecutor
	sessionProvider  SessionProvider
	humanoidProvider HumanoidProvider
	providerMu       sync.RWMutex
	kg               GraphStore
}

// Verify interface compliance.
var _ ActionExecutor = (*ExecutorRegistry)(nil)

// NewExecutorRegistry creates and initializes a new registry, populating it with
// all the specialized executors (Browser, Codebase, Analysis, Humanoid).
func NewExecutorRegistry(projectRoot string, globalCtx *core.GlobalContext, kg GraphStore) *ExecutorRegistry {
	logger := observability.GetLogger()
	r := &ExecutorRegistry{
		logger:          logger.Named("executor_registry"),
		executors:       make(map[ActionType]ActionExecutor),
		sessionProvider: nil,
		kg:              kg,
	}

	// This getter ensures that the latest session provider is used by executors at runtime.
	safeProviderGetter := r.GetSessionProvider()
	safeHumanoidGetter := r.GetHumanoidProvider()

	// Initialize the executors managed by this registry.
	browserExec := NewBrowserExecutor(safeProviderGetter)
	codebaseExec := NewCodebaseExecutor(projectRoot)
	analysisExec := NewAnalysisExecutor(globalCtx, safeProviderGetter)
	humanoidExec := NewHumanoidExecutor(safeHumanoidGetter)
	loginExec := NewLoginExecutor(safeHumanoidGetter, safeProviderGetter, kg)
	controlExec := NewControlExecutor(globalCtx)

	signUpExec, err := NewSignUpExecutor(safeHumanoidGetter, safeProviderGetter, globalCtx.Config, NewFileSystemSecListsLoader())
	if err != nil {
		// Log a warning if initialization fails for any reason (e.g., SecLists path invalid).
		// The feature will be unavailable.
		r.logger.Warn("Failed to initialize SignUpExecutor. Sign-up actions will be disabled.", zap.Error(err))
	} else if signUpExec != nil {
		// Only register if the executor is not nil (i.e., it's enabled and initialized successfully).
		r.register(signUpExec, ActionSignUp)
	}

	// Register browser actions.
	// FIX: Register complex actions that were missing.
	r.register(browserExec,
		ActionNavigate,
		ActionSubmitForm,
		ActionScroll,
		ActionWaitForAsync,
		ActionFuzzEndpoint, // Complex workflow stub
	)

	// Register specialized complex actions.
	r.register(loginExec, ActionExecuteLoginSequence)
	r.register(controlExec, ActionDecideNextStep)

	r.register(browserExec, ActionExploreApplication) // Still mapped to browser executor for now, though likely complex.

	// Register complex, interactive browser actions (Humanoid).
	r.register(humanoidExec, ActionClick, ActionInputText, ActionHumanoidDragAndDrop)

	// Register codebase actions.
	r.register(codebaseExec, ActionGatherCodebaseContext)

	// Register analysis actions (Updated to include all defined actions).
	r.register(analysisExec,
		ActionAnalyzeTaint,
		ActionAnalyzeHeaders,
		ActionAnalyzeJWT,
		ActionTestRaceCondition,
		ActionTestATO,
		ActionTestIDOR,
	)

	return r
}

// UpdateSessionProvider is a thread-safe method for the Agent to dynamically
// set the function that provides access to the active browser session.
func (r *ExecutorRegistry) UpdateSessionProvider(provider SessionProvider) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	r.sessionProvider = provider
}

// UpdateHumanoidProvider is a thread-safe method for the Agent to dynamically
// set the function that provides access to the active humanoid controller.
func (r *ExecutorRegistry) UpdateHumanoidProvider(provider HumanoidProvider) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	r.humanoidProvider = provider
}

// GetSessionProvider returns a thread-safe function that retrieves the current
// browser session. This allows executors to access the session without race conditions.
func (r *ExecutorRegistry) GetSessionProvider() SessionProvider {
	return func() schemas.SessionContext {
		r.providerMu.RLock()
		defer r.providerMu.RUnlock()
		if r.sessionProvider != nil {
			return r.sessionProvider()
		}
		return nil
	}
}

// GetHumanoidProvider returns a thread-safe function that retrieves the current
// humanoid controller.
func (r *ExecutorRegistry) GetHumanoidProvider() HumanoidProvider {
	return func() *humanoid.Humanoid {
		r.providerMu.RLock()
		defer r.providerMu.RUnlock()
		if r.humanoidProvider != nil {
			return r.humanoidProvider()
		}
		return nil
	}
}

// register is an internal helper to associate an executor with one or more action types.
func (r *ExecutorRegistry) register(exec ActionExecutor, types ...ActionType) {
	for _, t := range types {
		if _, exists := r.executors[t]; exists {
			r.logger.Warn("Overwriting existing executor registration for action type.", zap.String("type", string(t)))
		}
		r.executors[t] = exec
	}
}

// Execute finds the appropriate executor for a given action and delegates
// execution to it. It returns an error if no executor is registered for the
// action type or if the action is a cognitive one that should be handled by the
// agent's main loop.
func (r *ExecutorRegistry) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	executor, ok := r.executors[action.Type]
	if !ok {
		switch action.Type {
		// These are cognitive control actions handled by the main Agent loop.
		case ActionConclude, ActionEvolveCodebase:
			return nil, fmt.Errorf("CRITICAL: %s is a cognitive control action and should be handled by the Agent loop, not dispatched to ExecutorRegistry", action.Type)
		default:
			// The action type is genuinely unknown by the executors.
			return &ExecutionResult{
				Status:          "failed",
				ObservationType: ObservedSystemState,
				ErrorCode:       ErrCodeUnknownAction,
				ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("No executor registered for action type: %s", action.Type)},
			}, nil
		}
	}
	return executor.Execute(ctx, action)
}

// -- Browser Executor --

// ActionHandler is a function signature for a method that handles a specific
// type of browser action.
type ActionHandler func(ctx context.Context, session schemas.SessionContext, action Action) error

// BrowserExecutor is a specialized executor for handling simple, non-interactive
// browser actions like navigating, submitting forms, and scrolling.
type BrowserExecutor struct {
	logger          *zap.Logger
	sessionProvider SessionProvider
	handlers        map[ActionType]ActionHandler
}

var _ ActionExecutor = (*BrowserExecutor)(nil) // Verify interface compliance.

// NewBrowserExecutor creates and initializes a new BrowserExecutor, registering
// all of its action handlers.
func NewBrowserExecutor(provider SessionProvider) *BrowserExecutor {
	e := &BrowserExecutor{
		logger:          observability.GetLogger().Named("browser_executor"),
		sessionProvider: provider,
		handlers:        make(map[ActionType]ActionHandler),
	}
	e.registerHandlers()
	return e
}

// Execute finds the correct handler for the given browser action and executes it.
// It retrieves the current browser session and returns a structured result,
// parsing any errors into a format the agent's mind can understand.
func (e *BrowserExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	session := e.sessionProvider()
	if session == nil {
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("cannot execute browser action (%s): no active browser session", action.Type)},
		}, nil
	}

	handler, ok := e.handlers[action.Type]
	if !ok {
		// Defense-in-depth check.
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeUnknownAction,
			ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("BrowserExecutor handler not found for type: %s", action.Type)},
		}, nil
	}

	err := handler(ctx, session, action)

	result := &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedDOMChange,
	}

	if err != nil {
		result.Status = "failed"
		errorCode, errorDetails := ParseBrowserError(err, action)
		result.ErrorCode = errorCode
		result.ErrorDetails = errorDetails
		e.logger.Warn("Browser action execution failed",
			zap.String("action", string(action.Type)),
			zap.String("error_code", string(errorCode)),
			zap.Error(err))
	}

	return result, nil
}

// registerHandlers maps action types to their corresponding handler functions.
func (e *BrowserExecutor) registerHandlers() {
	e.handlers[ActionNavigate] = e.handleNavigate
	e.handlers[ActionSubmitForm] = e.handleSubmitForm
	e.handlers[ActionScroll] = e.handleScroll
	e.handlers[ActionWaitForAsync] = e.handleWaitForAsync
	e.handlers[ActionFuzzEndpoint] = e.handleFuzzEndpoint
}

// handleNavigate executes the navigation action.
func (e *BrowserExecutor) handleNavigate(ctx context.Context, session schemas.SessionContext, action Action) error {
	if action.Value == "" {
		return fmt.Errorf("ActionNavigate requires a 'value' (URL)")
	}
	return session.Navigate(ctx, action.Value)
}

// handleSubmitForm executes the form submission action.
func (e *BrowserExecutor) handleSubmitForm(ctx context.Context, session schemas.SessionContext, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionSubmitForm requires a 'selector'")
	}
	return session.Submit(ctx, action.Selector)
}

// handleScroll executes the page scroll action.
func (e *BrowserExecutor) handleScroll(ctx context.Context, session schemas.SessionContext, action Action) error {
	direction := "down"
	if strings.EqualFold(action.Value, "up") {
		direction = "up"
	}
	return session.ScrollPage(ctx, direction)
}

// handleWaitForAsync executes a wait/sleep action.
func (e *BrowserExecutor) handleWaitForAsync(ctx context.Context, session schemas.SessionContext, action Action) error {
	defaultDurationMs := 1000
	// FIX: Define a maximum reasonable duration to prevent excessively long waits or integer overflows on 32-bit systems.
	maxDurationMs := 60000 // 60 seconds
	durationMs := defaultDurationMs

	val, exists := action.Metadata["duration_ms"]
	if exists {
		// Handle various numeric types resulting from JSON unmarshaling.
		switch v := val.(type) {
		case float64:
			if v > float64(maxDurationMs) {
				durationMs = maxDurationMs
			} else {
				durationMs = int(v)
			}
		case float32:
			if v > float32(maxDurationMs) {
				durationMs = maxDurationMs
			} else {
				durationMs = int(v)
			}
		case int:
			// Although 'int' might be 64-bit, we still enforce the cap.
			if v > maxDurationMs {
				durationMs = maxDurationMs
			} else {
				durationMs = v
			}
		case int64:
			if v > int64(maxDurationMs) {
				durationMs = maxDurationMs
			} else {
				// Safe cast as it's now within 'int' range if maxDurationMs fits in 'int'.
				durationMs = int(v)
			}
		default:
			e.logger.Warn("Invalid type for 'duration_ms' metadata. Using default.", zap.Any("value", val))
			durationMs = defaultDurationMs
		}
	}

	// Check if duration is non-positive, but only reset if it wasn't capped (to handle if default was negative).
	if durationMs <= 0 && durationMs != maxDurationMs {
		durationMs = defaultDurationMs
	}

	return session.WaitForAsync(ctx, durationMs)
}

// handleFuzzEndpoint is a stub implementation for fuzzing endpoints.
func (e *BrowserExecutor) handleFuzzEndpoint(ctx context.Context, session schemas.SessionContext, action Action) error {
	e.logger.Info("ActionFuzzEndpoint is a stub. Implementation pending.")
	return nil
}

// -- Control Executor --

// ControlExecutor handles high-level control actions like deciding next steps,
// adjusting tactics, and modifying agent behavior.
type ControlExecutor struct {
	logger    *zap.Logger
	globalCtx *core.GlobalContext
}

var _ ActionExecutor = (*ControlExecutor)(nil)

func NewControlExecutor(globalCtx *core.GlobalContext) *ControlExecutor {
	return &ControlExecutor{
		logger:    observability.GetLogger().Named("control_executor"),
		globalCtx: globalCtx,
	}
}

func (e *ControlExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	if action.Type == ActionDecideNextStep {
		return e.handleDecideNextStep(ctx, action)
	}

	return &ExecutionResult{
		Status:          "failed",
		ObservationType: ObservedSystemState,
		ErrorCode:       ErrCodeUnknownAction,
		ErrorDetails:    map[string]interface{}{"message": "ControlExecutor received unknown action type"},
	}, nil
}

func (e *ControlExecutor) handleDecideNextStep(ctx context.Context, action Action) (*ExecutionResult, error) {
	// Logic to "tie the scan process into the agents ability to decide, plan, react, replan or reorganize"
	// This would parse metadata to adjust global configuration if possible, or trigger
	// complex internal state transitions.
	// For now, it logs the decision and potentially adjusts some runtime tunable parameters.

	e.logger.Info("Agent is deciding next step / replanning...", zap.String("rationale", action.Rationale))

	if tactics, ok := action.Metadata["tactics"].(map[string]interface{}); ok {
		if speed, ok := tactics["scan_speed"].(string); ok {
			e.logger.Info("Adjusting scan speed based on agent decision", zap.String("new_speed", speed))
			// Implementation would involve adjusting rate limiters or delays in global context/config if exposed.
		}
	}

	// Adjusting timing (e.g. sleep)
	if delay, ok := action.Metadata["delay_ms"].(float64); ok {
		e.logger.Info("Agent requested tactical delay", zap.Float64("ms", delay))
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	return &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedSystemState,
		Data: map[string]interface{}{
			"message": "Plan updated / Decision processed",
		},
	}, nil
}

// -- Shared Error Parsing --

// ParseBrowserError is a utility function that inspects an error returned from
// a browser operation (BrowserExecutor or HumanoidExecutor) and classifies it
// into a structured `ErrorCode`. This provides the agent's mind with granular
// information about the nature of the failure, enabling intelligent error handling.
func ParseBrowserError(err error, action Action) (ErrorCode, map[string]interface{}) {
	errStr := err.Error()
	details := map[string]interface{}{
		"message":     errStr,
		"action_type": action.Type,
	}

	// 1. Check for parameter validation errors explicitly.
	// This prevents validation errors from being misclassified by subsequent checks.
	if strings.Contains(errStr, "requires a 'selector'") ||
		strings.Contains(errStr, "requires a 'value'") ||
		strings.Contains(errStr, "requires 'metadata.target_selector'") ||
		strings.Contains(errStr, "'metadata.target_selector' must be a non-empty string") {
		return ErrCodeInvalidParameters, details
	}

	// 2. Check for common execution errors.
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "context deadline exceeded") {
		return ErrCodeTimeoutError, details
	}

	// 3. Check for navigation errors.
	if strings.Contains(errStr, "net::ERR") || strings.Contains(errStr, "navigation failed") {
		return ErrCodeNavigationError, details
	}

	// 4. Check for element lookup failures.
	if strings.Contains(errStr, "no element found") || strings.Contains(errStr, "geometry retrieval failed") {
		details["selector"] = action.Selector
		return ErrCodeElementNotFound, details
	}

	// 5. Check for visibility/obstruction issues (Crucial for Humanoid actions).
	if strings.Contains(errStr, "not visible") ||
		strings.Contains(errStr, "obscured") ||
		strings.Contains(errStr, "is being covered") ||
		strings.Contains(errStr, "outside the viewport") {
		details["selector"] = action.Selector
		return ErrCodeHumanoidTargetNotVisible, details
	}

	return ErrCodeExecutionFailure, details
}
