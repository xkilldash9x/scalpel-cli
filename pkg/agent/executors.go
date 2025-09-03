// -- pkg/agent/executors.go --
package agent

import (
	"context"
	"fmt"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"go.uber.org/zap"
)

// ActionExecutor defines the interface for components that execute actions decided by the Mind.
type ActionExecutor interface {
	// Execute performs the action. It returns (nil, err) for pre-flight errors (e.g., no session).
	// For executed actions, it returns (*ExecutionResult, nil), encapsulating the outcome.
	Execute(ctx context.Context, action Action) (*ExecutionResult, error)
}

// SessionProvider is a function type that returns the current active browser session.
type SessionProvider func() browser.SessionContext

// MissionContextProvider is a function type that returns the current mission details.
type MissionContextProvider func() Mission

// --- Browser Executor ---

// ActionHandler defines the function signature for a specific browser action implementation.
type ActionHandler func(session browser.SessionContext, action Action) error

// BrowserExecutor implements the ActionExecutor interface for browser interaction actions.
type BrowserExecutor struct {
	logger          *zap.Logger
	sessionProvider SessionProvider
	handlers        map[ActionType]ActionHandler
}

// NewBrowserExecutor creates a new BrowserExecutor and registers all action handlers.
func NewBrowserExecutor(logger *zap.Logger, provider SessionProvider) *BrowserExecutor {
	e := &BrowserExecutor{
		logger:          logger.Named("browser_executor"),
		sessionProvider: provider,
	}
	e.registerHandlers()
	return e
}

// registerHandlers initializes the map of action types to their handler functions.
func (e *BrowserExecutor) registerHandlers() {
	e.handlers = map[ActionType]ActionHandler{
		ActionNavigate:     e.handleNavigate,
		ActionClick:        e.handleClick,
		ActionInputText:    e.handleInputText,
		ActionSubmitForm:   e.handleSubmitForm,
		ActionScroll:       e.handleScroll,
		ActionWaitForAsync: e.handleWaitForAsync,
	}
}

// Execute looks up and runs the appropriate handler for a given browser action.
func (e *BrowserExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	session := e.sessionProvider()
	if session == nil {
		// This is a pre-execution failure; the action cannot be attempted.
		return nil, fmt.Errorf("cannot execute browser action (%s): No active browser session", action.Type)
	}

	handler, ok := e.handlers[action.Type]
	if !ok {
		// This is another pre-execution failure; the executor is not configured for this action.
		return nil, fmt.Errorf("BrowserExecutor cannot handle action type: %s", action.Type)
	}

	// The action is now being attempted. The outcome will be captured in the ExecutionResult.
	err := handler(session, action)

	result := &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedDOMChange, // A browser action always results in a potential DOM change
	}
	if err != nil {
		// The action was attempted but failed during execution (e.g., selector not found).
		result.Status = "failed"
		result.Error = err.Error()
	}

	// The executor successfully attempted the action and is reporting the outcome.
	// Therefore, the error return value is nil.
	return result, nil
}

// -- Action Handlers --

func (e *BrowserExecutor) handleNavigate(session browser.SessionContext, action Action) error {
	return session.Navigate(action.Value)
}

func (e *BrowserExecutor) handleClick(session browser.SessionContext, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionClick requires a 'selector'")
	}
	return session.Click(action.Selector)
}

func (e *BrowserExecutor) handleInputText(session browser.SessionContext, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionInputText requires a 'selector'")
	}
	return session.Type(action.Selector, action.Value)
}

func (e *BrowserExecutor) handleSubmitForm(session browser.SessionContext, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionSubmitForm requires a 'selector' for the form or a submit button")
	}
	return session.Submit(action.Selector)
}

func (e *BrowserExecutor) handleScroll(session browser.SessionContext, action Action) error {
	direction := "down"
	if action.Value == "up" {
		direction = "up"
	}
	return session.ScrollPage(direction)
}

func (e *BrowserExecutor) handleWaitForAsync(session browser.SessionContext, action Action) error {
	durationMs := 1000 // Default wait time
	val, exists := action.Metadata["duration_ms"]
	if exists {
		// Handle different numeric types robustly using a type switch.
		switch v := val.(type) {
		case float64: // Common for JSON unmarshaling
			durationMs = int(v)
		case int:
			durationMs = v
		case int64:
			durationMs = int(v)
		case float32:
			durationMs = int(v)
		default:
			// Log a warning and use default, rather than failing the action.
			e.logger.Warn("Invalid type for duration_ms in WAIT_FOR_ASYNC, using default.",
				zap.String("type", fmt.Sprintf("%T", v)))
		}
	}
	return session.WaitForAsync(durationMs)
}
