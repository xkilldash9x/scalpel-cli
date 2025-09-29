// internal/agent/executors.go
package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// -- UPGRADE NOTE: Defined Constants --
// Adding standardized error codes for consistent error reporting back to the Mind.
// These are now used by the exported ParseBrowserError function.
const (
	ErrCodeElementNotFound         = "ELEMENT_NOT_FOUND"
	ErrCodeHumanoidGeometryInvalid = "HUMANOID_GEOMETRY_INVALID"
	ErrCodeTimeoutError            = "TIMEOUT_ERROR"
	ErrCodeNavigationError         = "NAVIGATION_ERROR"
)

// SessionProvider is a function type that retrieves the currently active session.
type SessionProvider func() schemas.SessionContext

// -- Executor Registry --

// ExecutorRegistry manages different executors and dispatches actions.
// Its role is now focused on handling non-interactive or specialized actions,
// as complex user-like interactions are handled directly by the Agent's humanoid controller.
type ExecutorRegistry struct {
	logger    *zap.Logger
	executors map[ActionType]ActionExecutor

	sessionProvider SessionProvider
	providerMu      sync.RWMutex
}

// NewExecutorRegistry creates and initializes the registry with its reduced set of executors.
func NewExecutorRegistry(logger *zap.Logger, projectRoot string) *ExecutorRegistry {
	r := &ExecutorRegistry{
		logger:          logger.Named("executor_registry"),
		executors:       make(map[ActionType]ActionExecutor),
		sessionProvider: nil,
	}

	// This getter ensures that the latest session provider is used at execution time.
	safeProviderGetter := r.GetSessionProvider()

	// Initialize the executors that this registry still manages.
	browserExec := NewBrowserExecutor(logger, safeProviderGetter)
	codebaseExec := NewCodebaseExecutor(logger, projectRoot)

	// -- REFACTORING NOTE --
	// The registry for BrowserExecutor is now smaller. CLICK and INPUT_TEXT
	// have been removed because they are now orchestrated by the Agent via the Humanoid module.
	r.register(browserExec,
		ActionNavigate, ActionSubmitForm, ActionScroll, ActionWaitForAsync)

	// The CodebaseExecutor is still managed here as it's a non-interactive, specialized task.
	r.register(codebaseExec,
		ActionGatherCodebaseContext)

	return r
}

// UpdateSessionProvider allows the Agent to dynamically update the session provider function
// once a browser session has been established.
func (r *ExecutorRegistry) UpdateSessionProvider(provider SessionProvider) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	r.sessionProvider = provider
}

// GetSessionProvider returns a function that safely retrieves the current session,
// preventing race conditions.
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

// register associates an executor with one or more action types.
func (r *ExecutorRegistry) register(exec ActionExecutor, types ...ActionType) {
	for _, t := range types {
		r.executors[t] = exec
	}
}

// Execute finds the appropriate executor and runs the action.
func (r *ExecutorRegistry) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	executor, ok := r.executors[action.Type]
	if !ok {
		// This switch provides a more helpful error if an action that should be
		// handled by the Agent's main actionLoop accidentally gets dispatched here.
		switch action.Type {
		case ActionConclude, ActionPerformComplexTask, ActionClick, ActionInputText, ActionHumanoidDragAndDrop:
			return nil, fmt.Errorf("%s should be handled by the Agent, not dispatched to ExecutorRegistry", action.Type)
		default:
			return nil, fmt.Errorf("no executor registered for action type: %s", action.Type)
		}
	}

	return executor.Execute(ctx, action)
}

// -- Browser Executor --

// ActionHandler defines the function signature for a browser action.
// It now accepts a context.Context to allow for timeouts and cancellations.
type ActionHandler func(ctx context.Context, session schemas.SessionContext, action Action) error

// BrowserExecutor implements the agent.ActionExecutor interface for the remaining simple browser tasks.
type BrowserExecutor struct {
	logger          *zap.Logger
	sessionProvider SessionProvider
	handlers        map[ActionType]ActionHandler
}

// इंश्योर BrowserExecutor implements the agent.ActionExecutor interface.
var _ ActionExecutor = (*BrowserExecutor)(nil)

// NewBrowserExecutor creates a new BrowserExecutor.
func NewBrowserExecutor(logger *zap.Logger, provider SessionProvider) *BrowserExecutor {
	e := &BrowserExecutor{
		logger:          logger.Named("browser_executor"),
		sessionProvider: provider,
		handlers:        make(map[ActionType]ActionHandler),
	}
	e.registerHandlers()
	return e
}

// registerHandlers registers the subset of actions this executor still handles.
func (e *BrowserExecutor) registerHandlers() {
	e.handlers[ActionNavigate] = e.handleNavigate
	e.handlers[ActionSubmitForm] = e.handleSubmitForm
	e.handlers[ActionScroll] = e.handleScroll
	e.handlers[ActionWaitForAsync] = e.handleWaitForAsync
}

// -- REFACTORING NOTE --
// This function is now exported (ParseBrowserError) so it can be shared and used
// by the Agent's `executeHumanoidAction` method. This centralizes error parsing logic.
// It uses more specific error codes and checks for more nuanced failure conditions.
func ParseBrowserError(err error, action Action) (string, map[string]interface{}) {
	errStr := err.Error()
	details := map[string]interface{}{
		"message": errStr,
		"action":  action.Type,
	}

	// Heuristic based error classification.
	if strings.Contains(errStr, "selector") || strings.Contains(errStr, "no element found") || strings.Contains(errStr, "geometry retrieval failed") {
		details["selector"] = action.Selector
		return ErrCodeElementNotFound, details
	}
	// This check is particularly useful for the Humanoid module, which might find an
	// element that is visually obstructed or has a size of zero.
	if strings.Contains(errStr, "not interactable") || strings.Contains(errStr, "zero size") {
		details["selector"] = action.Selector
		return ErrCodeHumanoidGeometryInvalid, details
	}
	if strings.Contains(errStr, "timeout") {
		return ErrCodeTimeoutError, details
	}
	if strings.Contains(errStr, "net::ERR") {
		return ErrCodeNavigationError, details
	}

	return ErrCodeExecutionFailure, details
}

// Execute looks up and runs the appropriate handler for a given browser action.
func (e *BrowserExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	session := e.sessionProvider()
	if session == nil {
		return nil, fmt.Errorf("cannot execute browser action (%s): no active browser session", action.Type)
	}

	handler, ok := e.handlers[action.Type]
	if !ok {
		return nil, fmt.Errorf("BrowserExecutor internal error: handler not found for type: %s (it may be handled by Humanoid now)", action.Type)
	}

	// The context from the agent's main loop is passed down to the handler.
	err := handler(ctx, session, action)

	result := &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedDOMChange,
	}
	if err != nil {
		// If the handler fails, create a structured error response for the Mind.
		result.Status = "failed"
		errorCode, errorDetails := ParseBrowserError(err, action)
		result.ErrorCode = errorCode
		result.ErrorDetails = errorDetails
		e.logger.Warn("Browser action execution failed", zap.String("action", string(action.Type)), zap.String("error_code", errorCode), zap.Error(err))
	}

	return result, nil
}

// -- Action Handlers --

func (e *BrowserExecutor) handleNavigate(ctx context.Context, session schemas.SessionContext, action Action) error {
	if action.Value == "" {
		return fmt.Errorf("ActionNavigate requires a 'value' (URL)")
	}
	return session.Navigate(ctx, action.Value)
}

func (e *BrowserExecutor) handleSubmitForm(ctx context.Context, session schemas.SessionContext, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionSubmitForm requires a 'selector'")
	}
	return session.Submit(ctx, action.Selector)
}

func (e *BrowserExecutor) handleScroll(ctx context.Context, session schemas.SessionContext, action Action) error {
	direction := "down"
	if strings.EqualFold(action.Value, "up") {
		direction = "up"
	}
	return session.ScrollPage(ctx, direction)
}

func (e *BrowserExecutor) handleWaitForAsync(ctx context.Context, session schemas.SessionContext, action Action) error {
	durationMs := 1000 // Default wait time
	val, exists := action.Metadata["duration_ms"]
	if exists {
		// Robustly handle different numeric types that can come from JSON unmarshaling.
		switch v := val.(type) {
		case float64:
			durationMs = int(v)
		case int:
			durationMs = v
		case int64:
			durationMs = int(v)
		case float32:
			durationMs = int(v)
		default:
			e.logger.Warn("Invalid type for duration_ms, using default.", zap.String("type", fmt.Sprintf("%T", v)))
		}
	}
	return session.WaitForAsync(ctx, durationMs)
}
