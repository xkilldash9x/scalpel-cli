// internal/agent/executors_test.go
package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// -- BrowserExecutor Tests --

func TestBrowserExecutor_HandleNavigate(t *testing.T) {
	logger := zap.NewNop()
	mockSession := mocks.NewMockSessionContext()
	provider := func() schemas.SessionContext { return mockSession }
	executor := NewBrowserExecutor(logger, provider)

	// Test successful navigation
	action := Action{Type: ActionNavigate, Value: "https://example.com"}
	mockSession.On("Navigate", mock.Anything, "https://example.com").Return(nil).Once()
	err := executor.handleNavigate(context.Background(), mockSession, action)
	assert.NoError(t, err)

	// Test navigation failure
	expectedErr := errors.New("navigation failed")
	mockSession.On("Navigate", mock.Anything, "https://example.com").Return(expectedErr).Once()
	err = executor.handleNavigate(context.Background(), mockSession, action)
	assert.Equal(t, expectedErr, err)

	// Test missing URL
	action.Value = ""
	err = executor.handleNavigate(context.Background(), mockSession, action)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires a 'value'")
}

func TestBrowserExecutor_HandleSubmitForm(t *testing.T) {
	logger := zap.NewNop()
	mockSession := mocks.NewMockSessionContext()
	provider := func() schemas.SessionContext { return mockSession }
	executor := NewBrowserExecutor(logger, provider)

	action := Action{Type: ActionSubmitForm, Selector: "#form"}
	mockSession.On("Submit", mock.Anything, "#form").Return(nil).Once()
	err := executor.handleSubmitForm(context.Background(), mockSession, action)
	assert.NoError(t, err)

	action.Selector = ""
	err = executor.handleSubmitForm(context.Background(), mockSession, action)
	assert.Error(t, err)
}

func TestBrowserExecutor_HandleScroll(t *testing.T) {
	logger := zap.NewNop()
	mockSession := mocks.NewMockSessionContext()
	provider := func() schemas.SessionContext { return mockSession }
	executor := NewBrowserExecutor(logger, provider)

	action := Action{Type: ActionScroll, Value: "down"}
	mockSession.On("ScrollPage", mock.Anything, "down").Return(nil).Once()
	err := executor.handleScroll(context.Background(), mockSession, action)
	assert.NoError(t, err)

	action.Value = "up"
	mockSession.On("ScrollPage", mock.Anything, "up").Return(nil).Once()
	err = executor.handleScroll(context.Background(), mockSession, action)
	assert.NoError(t, err)

	action.Value = "" // Default to down
	mockSession.On("ScrollPage", mock.Anything, "down").Return(nil).Once()
	err = executor.handleScroll(context.Background(), mockSession, action)
	assert.NoError(t, err)
}

func TestBrowserExecutor_HandleWaitForAsync(t *testing.T) {
	logger := zap.NewNop()
	mockSession := mocks.NewMockSessionContext()
	provider := func() schemas.SessionContext { return mockSession }
	executor := NewBrowserExecutor(logger, provider)

	// Test with default duration
	action := Action{Type: ActionWaitForAsync}
	mockSession.On("WaitForAsync", mock.Anything, 1000).Return(nil).Once()
	err := executor.handleWaitForAsync(context.Background(), mockSession, action)
	assert.NoError(t, err)

	// Test with specified duration
	action.Metadata = map[string]interface{}{"duration_ms": 2500.0}
	mockSession.On("WaitForAsync", mock.Anything, 2500).Return(nil).Once()
	err = executor.handleWaitForAsync(context.Background(), mockSession, action)
	assert.NoError(t, err)

	// Test with invalid type (should use default)
	action.Metadata = map[string]interface{}{"duration_ms": "not-a-number"}
	mockSession.On("WaitForAsync", mock.Anything, 1000).Return(nil).Once()
	err = executor.handleWaitForAsync(context.Background(), mockSession, action)
	assert.NoError(t, err)
}

// -- ADJUSTMENT --
// Refactored TestExecutorRegistry_Execute into sub-tests for clarity and correctness.
func TestExecutorRegistry_Execute(t *testing.T) {
	logger := zap.NewNop()
	mockSession := mocks.NewMockSessionContext()
	provider := func() schemas.SessionContext { return mockSession }
	registry := NewExecutorRegistry(logger, ".")
	registry.UpdateSessionProvider(provider)

	t.Run("ValidBrowserAction", func(t *testing.T) {
		navAction := Action{Type: ActionNavigate, Value: "https://example.com"}
		mockSession.On("Navigate", mock.Anything, "https://example.com").Return(nil).Once()

		result, err := registry.Execute(context.Background(), navAction)

		// A successful action should return a "success" status and no error.
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "success", result.Status)
		mockSession.AssertExpectations(t)
	})

	t.Run("CodebaseActionDispatchFailsInUnitTest", func(t *testing.T) {
		// We expect an error here because the codebase executor needs a real file system.
		// This test just confirms the action is correctly dispatched to that executor.
		codeAction := Action{Type: ActionGatherCodebaseContext, Metadata: map[string]interface{}{"module_path": "."}}

		result, err := registry.Execute(context.Background(), codeAction)

		// The executor itself returns the failed result, not a raw error.
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, "failed", result.Status)
	})

	t.Run("UnregisteredAction", func(t *testing.T) {
		unknownAction := Action{Type: "ACTION_THAT_DOES_NOT_EXIST"}

		result, err := registry.Execute(context.Background(), unknownAction)

		// Unregistered actions should return a raw error from the registry.
		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "no executor registered")
	})

	t.Run("HumanoidActionDisallowed", func(t *testing.T) {
		// Actions handled by the agent's main loop should not be sent to the registry.
		clickAction := Action{Type: ActionClick}

		result, err := registry.Execute(context.Background(), clickAction)

		require.Error(t, err)
		require.Nil(t, result)
		require.Contains(t, err.Error(), "should be handled by the Agent")
	})
}

func TestParseBrowserError(t *testing.T) {
	// Test Element Not Found
	err := errors.New("cdp: no element found for selector")
	action := Action{Selector: "#id"}
	code, details := ParseBrowserError(err, action)
	assert.Equal(t, ErrCodeElementNotFound, code)
	assert.Equal(t, "#id", details["selector"])

	// Test Timeout Error
	err = errors.New("context deadline exceeded: waiting for element timed out")
	code, _ = ParseBrowserError(err, action)
	assert.Equal(t, ErrCodeTimeoutError, code)

	// Test Navigation Error
	err = errors.New("could not navigate: net::ERR_CONNECTION_REFUSED")
	code, _ = ParseBrowserError(err, action)
	assert.Equal(t, ErrCodeNavigationError, code)

	// Test Geometry Error
	err = errors.New("element is not interactable (zero size)")
	code, _ = ParseBrowserError(err, action)
	assert.Equal(t, ErrCodeHumanoidGeometryInvalid, code)

	// Test Generic Failure
	err = errors.New("some other random cdp error")
	code, _ = ParseBrowserError(err, action)
	assert.Equal(t, ErrCodeExecutionFailure, code)
}
