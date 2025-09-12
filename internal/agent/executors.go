package agent

import (
	"context"
	"fmt"
	"strings"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// SessionProvider is a function type that retrieves the currently active session.
// Uses SessionContext defined in internal/agent/interfaces.go
type SessionProvider func() SessionContext

// -- Browser Executor --

// ActionHandler defines the function signature for a specific browser action implementation.
type ActionHandler func(session SessionContext, action schemas.Action) error

// BrowserExecutor implements the schemas.ActionExecutor interface.
type BrowserExecutor struct {
	logger          *zap.Logger
	sessionProvider SessionProvider
	handlers map[schemas.ActionType]ActionHandler
}

// Statically assert that BrowserExecutor implements the ActionExecutor interface.
var _ schemas.ActionExecutor = (*BrowserExecutor)(nil)

// NewBrowserExecutor creates a new BrowserExecutor and registers all action handlers.
func NewBrowserExecutor(logger *zap.Logger, provider SessionProvider) *BrowserExecutor {
	e := &BrowserExecutor{
		logger:          logger.Named("browser_executor"),
		sessionProvider: provider,
		handlers: make(map[schemas.ActionType]ActionHandler, 8),
	}
	e.registerHandlers()
	return e
}

// registerHandlers initializes the map of action types to their handler functions.
func (e *BrowserExecutor) registerHandlers() {
	e.handlers[schemas.ActionNavigate] = e.handleNavigate
	e.handlers[schemas.ActionClick] = e.handleClick
	e.handlers[schemas.ActionInputText] = e.handleInputText
	e.handlers[schemas.ActionSubmitForm] = e.handleSubmitForm
	e.handlers[schemas.ActionScroll] = e.handleScroll
	e.handlers[schemas.ActionWaitForAsync] = e.handleWaitForAsync
}

// Execute looks up and runs the appropriate handler for a given browser action.
func (e *BrowserExecutor) Execute(ctx context.Context, action schemas.Action) (*schemas.ExecutionResult, error) {
	session := e.sessionProvider()
	if session == nil {
		// Pre-execution failure.
		return nil, fmt.Errorf("cannot execute browser action (%s): no active browser session", action.Type)
	}

	handler, ok := e.handlers[action.Type]
	if !ok {
		// Pre-execution failure.
		return nil, fmt.Errorf("BrowserExecutor cannot handle action type: %s", action.Type)
	}

	// The action is being attempted. The outcome is captured in the ExecutionResult.
	err := handler(session, action)

	result := &schemas.ExecutionResult{
		Status:          "success",
		ObservationType: schemas.ObservedDOMChange,
	}
	if err != nil {
		// Execution failure.
		result.Status = "failed"
		result.Error = err.Error()
		e.logger.Warn("Browser action execution failed", zap.String("action", string(action.Type)), zap.Error(err))
	}

	// The executor successfully attempted the action and is reporting the outcome.
	return result, nil
}

// -- Action Handlers --

func (e *BrowserExecutor) handleNavigate(session SessionContext, action schemas.Action) error {
	if action.Value == "" {
		return fmt.Errorf("ActionNavigate requires a 'value' (URL)")
	}
	return session.Navigate(action.Value)
}

func (e *BrowserExecutor) handleClick(session SessionContext, action schemas.Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionClick requires a 'selector'")
	}
	return session.Click(action.Selector)
}

func (e *BrowserExecutor) handleInputText(session SessionContext, action schemas.Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionInputText requires a 'selector'")
	}
	return session.Type(action.Selector, action.Value)
}

func (e *BrowserExecutor) handleSubmitForm(session SessionContext, action schemas.Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionSubmitForm requires a 'selector' for the form or a submit button")
	}
	return session.Submit(action.Selector)
}

func (e *BrowserExecutor) handleScroll(session SessionContext, action schemas.Action) error {
	direction := "down" // Default direction
	if strings.EqualFold(action.Value, "up") {
		direction = "up"
	}
	return session.ScrollPage(direction)
}

func (e *BrowserExecutor) handleWaitForAsync(session SessionContext, action schemas.Action) error {
	durationMs := 1000 // Default wait time
	val, exists := action.Metadata["duration_ms"]
	if exists {
		// Handle different numeric types robustly (JSON unmarshalling often yields float64).
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
			e.logger.Warn("Invalid type for duration_ms in WAIT_FOR_ASYNC, using default.",
				zap.String("type", fmt.Sprintf("%T", v)))
		}
	}
	return session.WaitForAsync(durationMs)
}