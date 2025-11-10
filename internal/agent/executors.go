// File: internal/agent/executors.go
package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
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
}

// NewExecutorRegistry creates and initializes a new registry, populating it with
// all the specialized executors (Browser, Codebase, Analysis, Humanoid).
func NewExecutorRegistry(logger *zap.Logger, projectRoot string, globalCtx *core.GlobalContext) *ExecutorRegistry {
	r := &ExecutorRegistry{
		logger:          logger.Named("executor_registry"),
		executors:       make(map[ActionType]ActionExecutor),
		sessionProvider: nil,
	}

	// This getter ensures that the latest session provider is used by executors at runtime.
	safeProviderGetter := r.GetSessionProvider()
	safeHumanoidGetter := r.GetHumanoidProvider()

	// Initialize the executors managed by this registry.
	browserExec := NewBrowserExecutor(logger, safeProviderGetter)
	codebaseExec := NewCodebaseExecutor(logger, projectRoot)
	analysisExec := NewAnalysisExecutor(logger, globalCtx, safeProviderGetter)
	humanoidExec := NewHumanoidExecutor(logger, safeHumanoidGetter)

	// Register browser actions. Note that CLICK and INPUT_TEXT are absent,
	// as they are now orchestrated by the Agent via the Humanoid module.
	r.register(browserExec, ActionNavigate, ActionSubmitForm, ActionScroll, ActionWaitForAsync)

	// Register complex, interactive browser actions.
	// These are handled by the HumanoidExecutor, which orchestrates human-like interactions.
	r.register(humanoidExec, ActionClick, ActionInputText, ActionHumanoidDragAndDrop)

	// Register codebase actions, which are non-interactive by nature.
	r.register(codebaseExec, ActionGatherCodebaseContext)

	// Register analysis actions
	r.register(analysisExec, ActionAnalyzeTaint, ActionAnalyzeProtoPollution, ActionAnalyzeHeaders)

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
		case ActionConclude, ActionPerformComplexTask, ActionEvolveCodebase:
			return nil, fmt.Errorf("%s should be handled by the Agent's cognitive loop, not dispatched to ExecutorRegistry", action.Type)
		default:
			return nil, fmt.Errorf("no executor registered for action type: %s", action.Type)
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
func NewBrowserExecutor(logger *zap.Logger, provider SessionProvider) *BrowserExecutor {
	e := &BrowserExecutor{
		logger:          logger.Named("browser_executor"),
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
	durationMs := 1000 // Default wait time.
	val, exists := action.Metadata["duration_ms"]
	if exists {
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
			e.logger.Warn("Invalid type for duration_ms, using default.", zap.Any("type", v))
		}
	}
	return session.WaitForAsync(ctx, durationMs)
}

// -- Codebase Executor --

// CodebaseExecutor is a specialized executor for actions that involve analyzing
// the local Go codebase, such as gathering context for the agent's mind.
type CodebaseExecutor struct {
	logger      *zap.Logger
	projectRoot string
}

var _ ActionExecutor = (*CodebaseExecutor)(nil) // Verify interface compliance.

// NewCodebaseExecutor creates a new CodebaseExecutor.
func NewCodebaseExecutor(logger *zap.Logger, projectRoot string) *CodebaseExecutor {
	return &CodebaseExecutor{
		logger:      logger.Named("codebase_executor"),
		projectRoot: projectRoot,
	}
}

// -- Shared Error Parsing --

// ParseBrowserError is a utility function that inspects an error returned from
// a browser operation and classifies it into a structured `ErrorCode`. This
// provides the agent's mind with more granular information about the nature of
// the failure (e.g., distinguishing a timeout from an element not being found),
// enabling more intelligent error handling and decision-making.
func ParseBrowserError(err error, action Action) (ErrorCode, map[string]interface{}) {
	errStr := err.Error()
	details := map[string]interface{}{
		"message": errStr,
		"action":  action.Type,
	}

	// 1. Check for parameter validation errors explicitly.
	// This prevents validation errors (which often contain the word "selector")
	// from being misclassified by subsequent checks.
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
	if strings.Contains(errStr, "net::ERR") {
		return ErrCodeNavigationError, details
	}

	// 3. Check for element lookup failures.
	// Removed the overly broad `strings.Contains(errStr, "selector")`.
	if strings.Contains(errStr, "no element found") || strings.Contains(errStr, "geometry retrieval failed") {
		details["selector"] = action.Selector
		return ErrCodeElementNotFound, details
	}

	return ErrCodeExecutionFailure, details
}
