// File: internal/agent/executors_test.go
package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	// Using schemas to get the canonical interfaces.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// NOTE: MockSessionContext definition is now centralized in internal/agent/mocks_test.go.

// Test Setup Helper

// Creates a BrowserExecutor instance for testing.
func setupBrowserExecutor(t *testing.T, provideSession bool) (*BrowserExecutor, *MockSessionContext) {
	t.Helper()
	logger := zaptest.NewLogger(t)

	var mockSession *MockSessionContext
	// SessionProvider is defined as: type SessionProvider func() schemas.SessionContext
	var provider SessionProvider

	if provideSession {
		// MockSessionContext is defined in mocks_test.go and implements schemas.SessionContext.
		mockSession = new(MockSessionContext)
		// Provider function must return schemas.SessionContext.
		provider = func() schemas.SessionContext {
			return mockSession
		}
	} else {
		provider = func() schemas.SessionContext {
			return nil
		}
	}

	executor := NewBrowserExecutor(logger, provider)
	return executor, mockSession
}

// Test Cases: Initialization and Dispatch Logic

// Verifies all expected handlers are registered (white box).
func TestNewBrowserExecutor_Registration(t *testing.T) {
	executor, _ := setupBrowserExecutor(t, true)

	// Verify expected handlers (using internal ActionType).
	expectedHandlers := []ActionType{
		ActionNavigate,
		ActionClick,
		ActionInputText,
		ActionSubmitForm,
		ActionScroll,
		ActionWaitForAsync,
	}

	assert.Len(t, executor.handlers, len(expectedHandlers))
	for _, actionType := range expectedHandlers {
		_, exists := executor.handlers[actionType]
		assert.True(t, exists, fmt.Sprintf("Handler for %s should be registered", actionType))
	}
}

// Verifies error handling when the session provider returns nil.
func TestExecute_NoActiveSession(t *testing.T) {
	executor, _ := setupBrowserExecutor(t, false)
	ctx := context.Background()

	action := Action{Type: ActionClick, Selector: "#btn"}

	result, err := executor.Execute(ctx, action)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no active browser session")
}

// Test Cases: Execution Flow

// Verifies the structure of the result on successful execution.
func TestExecute_Success(t *testing.T) {
	executor, mockSession := setupBrowserExecutor(t, true)
	ctx := context.Background()

	action := Action{Type: ActionNavigate, Value: "http://test.com"}

	// The implementation (executors.go) explicitly passes context.Background() to session.Navigate.
	// We use mock.Anything to match this behavior reliably, as the test's 'ctx' won't match the implementation's context.Background().
	mockSession.On("Navigate", mock.Anything, "http://test.com").Return(nil).Once()

	result, err := executor.Execute(ctx, action)

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "success", result.Status)
	assert.Empty(t, result.Error)
	assert.Equal(t, ObservedDOMChange, result.ObservationType)
	mockSession.AssertExpectations(t)
}

// Verifies the structure of the result when the action itself fails.
func TestExecute_ActionFailure(t *testing.T) {
	executor, mockSession := setupBrowserExecutor(t, true)
	ctx := context.Background()

	action := Action{Type: ActionClick, Selector: "#missing"}
	expectedError := errors.New("element not found")

	// Update the mock expectation to account for the new context argument.
	// We use mock.Anything since the exact context instance doesn't matter for this test.
	mockSession.On("Click", mock.Anything, "#missing").Return(expectedError).Once()

	result, err := executor.Execute(ctx, action)

	// The executor successfully attempted the action (so 'err' is nil).
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "failed", result.Status)
	assert.Equal(t, expectedError.Error(), result.Error)
	mockSession.AssertExpectations(t)
}

// Test Cases: Specific Action Logic (Unit Tests)

// Verifies validation within handlers (e.g., missing selector).
func TestHandler_InputText_Validation(t *testing.T) {
	executor, mockSession := setupBrowserExecutor(t, true)

	action := Action{Type: ActionInputText, Value: "test"}

	// Execute the unexported handler directly (white box).
	// We pass the mockSession which implements schemas.SessionContext.
	err := executor.handleInputText(mockSession, action)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires a 'selector'")
	// Update the mock assertion to include the new context argument.
	mockSession.AssertNotCalled(t, "Type", mock.Anything, mock.Anything, mock.Anything)
}

// Verifies the robust parsing of the duration_ms metadata.
func TestHandler_WaitForAsync_MetadataParsing(t *testing.T) {
	tests := []struct {
		name             string
		metadata         map[string]interface{}
		expectedDuration int
	}{
		{"Default (No Metadata)", nil, 1000},
		{"Valid Int", map[string]interface{}{"duration_ms": 500}, 500},
		{"Valid Float64", map[string]interface{}{"duration_ms": 250.5}, 250},
		{"Valid Int64", map[string]interface{}{"duration_ms": int64(750)}, 750},
		{"Invalid Type (String)", map[string]interface{}{"duration_ms": "invalid"}, 1000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor, mockSession := setupBrowserExecutor(t, true)

			action := Action{Type: ActionWaitForAsync, Metadata: tt.metadata}

			// Update mock expectation to include the context argument.
			mockSession.On("WaitForAsync", mock.Anything, tt.expectedDuration).Return(nil).Once()

			// We pass the mockSession which implements schemas.SessionContext.
			err := executor.handleWaitForAsync(mockSession, action)

			require.NoError(t, err)
			mockSession.AssertExpectations(t)
		})
	}
}
