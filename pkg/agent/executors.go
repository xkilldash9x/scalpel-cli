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
	// Execute performs the action and returns the results (observations) and an error if it failed.
	// CORRECTED: The return type is now a strongly-typed struct instead of a generic map.
	Execute(ctx context.Context, action Action) (*ExecutionResult, error)
}

// SessionProvider is a function type that returns the current active browser session.
type SessionProvider func() browser.SessionContext

// MissionContextProvider is a function type that returns the current mission details.
type MissionContextProvider func() Mission

// --- Browser Executor ---

// BrowserExecutor implements the ActionExecutor interface for browser interaction actions.
type BrowserExecutor struct {
	logger          *zap.Logger
	sessionProvider SessionProvider
}

// NewBrowserExecutor creates a new BrowserExecutor.
func NewBrowserExecutor(logger *zap.Logger, provider SessionProvider) *BrowserExecutor {
	return &BrowserExecutor{
		logger:          logger.Named("browser_executor"),
		sessionProvider: provider,
	}
}

// Execute handles actions that require the browser environment.
func (e *BrowserExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	session := e.sessionProvider()
	if session == nil {
		// If there's no active session, the mission cannot proceed with browser actions.
		return nil, fmt.Errorf("cannot execute browser action (%s): No active browser session", action.Type)
	}

	var err error
	switch action.Type {
	case ActionNavigate:
		err = session.Navigate(action.Value)

	case ActionClick:
		if action.Selector == "" {
			return nil, fmt.Errorf("ActionClick requires a 'selector'")
		}
		err = session.Click(action.Selector)

	case ActionInputText:
		if action.Selector == "" {
			return nil, fmt.Errorf("ActionInputText requires a 'selector'")
		}
		err = session.Type(action.Selector, action.Value)

	case ActionSubmitForm:
		if action.Selector == "" {
			return nil, fmt.Errorf("ActionSubmitForm requires a 'selector' for the form or a submit button")
		}
		err = session.Submit(action.Selector)

	case ActionScroll:
		direction := "down"
		if action.Value == "up" {
			direction = "up"
		}
		err = session.ScrollPage(direction)

	case ActionWaitForAsync:
		durationMs := 1000 // Default wait time
		// Handle different numeric types that might come from JSON decoding (float64) or direct initialization (int).
		if dur, ok := action.Metadata["duration_ms"].(float64); ok {
			durationMs = int(dur)
		} else if dur, ok := action.Metadata["duration_ms"].(int); ok {
			durationMs = dur
		}
		err = session.WaitForAsync(durationMs)

	default:
		// This should ideally not happen if the Agent's executor registration is correct.
		return nil, fmt.Errorf("BrowserExecutor cannot handle action type: %s", action.Type)
	}

	// Browser actions primarily result in environmental changes observed by instrumentation.
	// The primary observation here is simply the success or failure of the execution itself.
	result := &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedDOMChange, // A browser action always results in a potential DOM change
	}
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	}
	return result, err
}
