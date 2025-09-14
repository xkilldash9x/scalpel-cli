package agent

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// SessionProvider is a function type that retrieves the currently active session.
type SessionProvider func() SessionContext

// --- Executor Registry (Implementation) ---

// ExecutorRegistry manages different executors and dispatches actions.
type ExecutorRegistry struct {
	logger    *zap.Logger
	executors map[ActionType]ActionExecutor

	// sessionProvider holds the current provider function, protected by a mutex for safe dynamic updates.
	sessionProvider SessionProvider
	providerMu      sync.RWMutex
}

// NewExecutorRegistry creates and initializes the registry.
func NewExecutorRegistry(logger *zap.Logger, projectRoot string) *ExecutorRegistry {
	r := &ExecutorRegistry{
		logger:          logger.Named("executor_registry"),
		executors:       make(map[ActionType]ActionExecutor),
		sessionProvider: nil, // Initialized as nil
	}

	// Initialize executors. We pass the registry's safe getter function.
	// This getter ensures that the latest session provider is used at execution time.
	safeProviderGetter := r.GetSessionProvider()

	browserExec := NewBrowserExecutor(logger, safeProviderGetter)
	codebaseExec := NewCodebaseExecutor(logger, projectRoot)

	// Register executors.
	r.register(browserExec,
		ActionNavigate, ActionClick, ActionInputText, ActionSubmitForm, ActionScroll, ActionWaitForAsync)

	r.register(codebaseExec,
		ActionGatherCodebaseContext)

	return r
}

// UpdateSessionProvider updates the provider function (called by Agent when session is ready).
func (r *ExecutorRegistry) UpdateSessionProvider(provider SessionProvider) {
	r.providerMu.Lock()
	defer r.providerMu.Unlock()
	r.sessionProvider = provider
}

// GetSessionProvider returns a function that safely retrieves the current session.
func (r *ExecutorRegistry) GetSessionProvider() SessionProvider {
	return func() SessionContext {
		r.providerMu.RLock()
		defer r.providerMu.RUnlock()
		if r.sessionProvider != nil {
			return r.sessionProvider()
		}
		return nil
	}
}

func (r *ExecutorRegistry) register(exec ActionExecutor, types ...ActionType) {
	for _, t := range types {
		r.executors[t] = exec
	}
}

// Execute finds the appropriate executor and runs the action.
func (r *ExecutorRegistry) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	executor, ok := r.executors[action.Type]
	if !ok {
		// ActionConclude is handled by the Agent, not the registry.
		if action.Type == ActionConclude {
			return nil, fmt.Errorf("ActionConclude should not be dispatched to ExecutorRegistry")
		}
		return nil, fmt.Errorf("no executor registered for action type: %s", action.Type)
	}

	return executor.Execute(ctx, action)
}

// -- Browser Executor --

// ActionHandler defines the function signature (using internal Action model).
type ActionHandler func(session SessionContext, action Action) error

// BrowserExecutor implements the agent.ActionExecutor interface.
type BrowserExecutor struct {
	logger          *zap.Logger
	sessionProvider SessionProvider
	handlers        map[ActionType]ActionHandler
}

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

func (e *BrowserExecutor) registerHandlers() {
	e.handlers[ActionNavigate] = e.handleNavigate
	e.handlers[ActionClick] = e.handleClick
	e.handlers[ActionInputText] = e.handleInputText
	e.handlers[ActionSubmitForm] = e.handleSubmitForm
	e.handlers[ActionScroll] = e.handleScroll
	e.handlers[ActionWaitForAsync] = e.handleWaitForAsync
}

// Execute looks up and runs the appropriate handler (using internal models).
func (e *BrowserExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	session := e.sessionProvider()
	if session == nil {
		// Pre-execution failure.
		return nil, fmt.Errorf("cannot execute browser action (%s): no active browser session", action.Type)
	}

	handler, ok := e.handlers[action.Type]
	if !ok {
		return nil, fmt.Errorf("BrowserExecutor internal error: handler not found for type: %s", action.Type)
	}

	err := handler(session, action)

	result := &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedDOMChange,
	}
	if err != nil {
		// Execution failure.
		result.Status = "failed"
		result.Error = err.Error()
		e.logger.Warn("Browser action execution failed", zap.String("action", string(action.Type)), zap.Error(err))
	}

	return result, nil
}

// -- Action Handlers --

func (e *BrowserExecutor) handleNavigate(session SessionContext, action Action) error {
	if action.Value == "" {
		return fmt.Errorf("ActionNavigate requires a 'value' (URL)")
	}
	return session.Navigate(action.Value)
}

func (e *BrowserExecutor) handleClick(session SessionContext, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionClick requires a 'selector'")
	}
	return session.Click(action.Selector)
}

func (e *BrowserExecutor) handleInputText(session SessionContext, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionInputText requires a 'selector'")
	}
	return session.Type(action.Selector, action.Value)
}

func (e *BrowserExecutor) handleSubmitForm(session SessionContext, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionSubmitForm requires a 'selector'")
	}
	return session.Submit(action.Selector)
}

func (e *BrowserExecutor) handleScroll(session SessionContext, action Action) error {
	direction := "down"
	if strings.EqualFold(action.Value, "up") {
		direction = "up"
	}
	return session.ScrollPage(direction)
}

func (e *BrowserExecutor) handleWaitForAsync(session SessionContext, action Action) error {
	durationMs := 1000 // Default wait time
	val, exists := action.Metadata["duration_ms"]
	if exists {
		// Handle different numeric types robustly
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
	return session.WaitForAsync(durationMs)
}