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

// ExecutorRegistry manages and dispatches actions to specialized, non-interactive executors.
// Its role is focused on handling background tasks like codebase analysis or simple browser
// commands, while complex user-like interactions are handled by the Agent's humanoid controller.
type ExecutorRegistry struct {
	logger    *zap.Logger
	executors map[ActionType]ActionExecutor

	sessionProvider  SessionProvider
	humanoidProvider HumanoidProvider
	providerMu       sync.RWMutex
}

// NewExecutorRegistry creates and initializes the registry with its set of specialized executors.
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
	// Initialize System/API executors
	queryExec := NewQueryExecutor(globalCtx.DBPool, logger)
	// ScanExecutor needs GlobalContext to spawn sub-agents.
	scanExec := NewScanExecutor(logger, globalCtx)

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

	// Register System/API actions
	r.register(queryExec, ActionQueryFindings)
	r.register(scanExec, ActionStartScan)

	return r
}

// UpdateSessionProvider allows the Agent to dynamically set the session provider function
// once a browser session has been established. This method is thread-safe.
func (r *ExecutorRegistry) UpdateSessionProvider(provider SessionProvider) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	r.sessionProvider = provider
}

// UpdateHumanoidProvider allows the Agent to dynamically set the humanoid provider function
// once the Humanoid controller has been initialized. This method is thread-safe.
func (r *ExecutorRegistry) UpdateHumanoidProvider(provider HumanoidProvider) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	r.humanoidProvider = provider
}

// GetSessionProvider returns a function that safely retrieves the current session provider,
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

// GetHumanoidProvider returns a function that safely retrieves the current humanoid provider,
// preventing race conditions.
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

// register associates an executor with one or more action types.
func (r *ExecutorRegistry) register(exec ActionExecutor, types ...ActionType) {
	for _, t := range types {
		r.executors[t] = exec
	}
}

// Execute finds the appropriate executor for the given action and runs it.
// It provides a detailed error if an action is dispatched here that should have been
// handled by the Agent's primary action loop (e.g., humanoid or cognitive actions).
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

// ActionHandler defines the function signature for a specific browser action handler.
type ActionHandler func(ctx context.Context, session schemas.SessionContext, action Action) error

// BrowserExecutor implements the ActionExecutor interface for simple, non-interactive browser tasks.
type BrowserExecutor struct {
	logger          *zap.Logger
	sessionProvider SessionProvider
	handlers        map[ActionType]ActionHandler
}

var _ ActionExecutor = (*BrowserExecutor)(nil) // Verify interface compliance.

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

// Execute looks up and runs the appropriate handler for a given browser action.
func (e *BrowserExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	session := e.sessionProvider()
	if session == nil {
		// Return a structured result instead of a raw error for consistency.
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("cannot execute browser action (%s): no active browser session", action.Type)},
		}, nil
	}

	handler, ok := e.handlers[action.Type]
	if !ok {
		// This should ideally be caught by the registry, but acts as a safeguard.
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
		// If the handler fails, create a structured error response for the Mind.
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

// registerHandlers populates the internal map of action types to their handler functions.
func (e *BrowserExecutor) registerHandlers() {
	e.handlers[ActionNavigate] = e.handleNavigate
	e.handlers[ActionSubmitForm] = e.handleSubmitForm
	e.handlers[ActionScroll] = e.handleScroll
	e.handlers[ActionWaitForAsync] = e.handleWaitForAsync
}

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
	durationMs := 1000 // Default wait time.
	val, exists := action.Metadata["duration_ms"]
	if exists {
		switch v := val.(type) {
		case float64:
			durationMs = int(v)
		// Handle integer types individually to avoid panic on type assertion in multi-type case.
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

// CodebaseExecutor implements the ActionExecutor interface for tasks related to analyzing the local file system.
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

// ParseBrowserError analyzes an error from a browser operation and classifies it,
// returning a structured ErrorCode and details map for the Agent's Mind.
// It is exported to be used by other parts of the agent, such as the Humanoid controller.
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

}