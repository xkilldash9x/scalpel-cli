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

	// The implementation uses schemas.ActionType, so we must import it for the tests.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
)


// Test Setup Helper


// Creates a BrowserExecutor instance for testing.
func setupBrowserExecutor(t *testing.T, provideSession bool) (*BrowserExecutor, *MockSessionContext) {
	t.Helper()
	logger := zaptest.NewLogger(t)

	var mockSession *MockSessionContext
	var provider SessionProvider

	if provideSession {
		mockSession = new(MockSessionContext)
		// Provider returns the initialized mock session.
		provider = func() interfaces.SessionContext {
			return mockSession
		}
	} else {
		// Provider returns nil (simulating no active session).
		provider = func() interfaces.SessionContext {
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

	// Verify expected handlers are present (white box access to 'handlers' map).
	expectedHandlers := []schemas.ActionType{
		schemas.ActionNavigate,
		schemas.ActionClick,
		schemas.ActionInputText,
		schemas.ActionSubmitForm,
		schemas.ActionScroll,
		schemas.ActionWaitForAsync,
	}

	assert.Len(t, executor.handlers, len(expectedHandlers))
	for _, actionType := range expectedHandlers {
		// Check the internal map directly.
		_, exists := executor.handlers[actionType]
		assert.True(t, exists, fmt.Sprintf("Handler for %s should be registered", actionType))
	}
}

// Verifies error handling when the session provider returns nil.
func TestExecute_NoActiveSession(t *testing.T) {
	executor, _ := setupBrowserExecutor(t, false) // Setup with no session provided.
	ctx := context.Background()

	action := schemas.Action{Type: schemas.ActionClick, Selector: "#btn"}

	// Execute
	result, err := executor.Execute(ctx, action)

	// Verify: This is a pre execution failure, so 'err' should not be nil.
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no active browser session")
}


// Test Cases: Execution Flow


// Verifies the structure of the result on successful execution.
func TestExecute_Success(t *testing.T) {
	executor, mockSession := setupBrowserExecutor(t, true)
	ctx := context.Background()

	action := schemas.Action{Type: schemas.ActionNavigate, Value: "http://test.com"}

	// Mock expectation
	mockSession.On("Navigate", "http://test.com").Return(nil).Once()

	// Execute
	result, err := executor.Execute(ctx, action)

	// Verify
	assert.NoError(t, err, "Executor should return nil error on successful action attempt")
	require.NotNil(t, result)
	assert.Equal(t, "success", result.Status)
	assert.Empty(t, result.Error)
	// Browser actions should typically result in DOM changes.
	assert.Equal(t, schemas.ObservedDOMChange, result.ObservationType)
	mockSession.AssertExpectations(t)
}

// Verifies the structure of the result when the action itself fails.
func TestExecute_ActionFailure(t *testing.T) {
	executor, mockSession := setupBrowserExecutor(t, true)
	ctx := context.Background()

	action := schemas.Action{Type: schemas.ActionClick, Selector: "#missing"}
	expectedError := errors.New("element not found")

	// Mock expectation: Action fails during execution.
	mockSession.On("Click", "#missing").Return(expectedError).Once()

	// Execute
	result, err := executor.Execute(ctx, action)

	// Verify: The executor successfully attempted the action (so 'err' is nil),
	// but the result indicates failure.
	assert.NoError(t, err, "Executor should return nil error even if the action failed")
	require.NotNil(t, result)
	assert.Equal(t, "failed", result.Status)
	assert.Equal(t, expectedError.Error(), result.Error)
	mockSession.AssertExpectations(t)
}


// Test Cases: Specific Action Logic (Unit Tests)


// Verifies validation within handlers (e.g., missing selector).
func TestHandler_InputText_Validation(t *testing.T) {
	executor, mockSession := setupBrowserExecutor(t, true)

	// ActionInputText without Selector
	action := schemas.Action{Type: schemas.ActionInputText, Value: "test"}

	// Execute the unexported handler directly (white box).
	err := executor.handleInputText(mockSession, action)

	// Verify
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires a 'selector'")
	// Ensure the session method was not called because validation failed first.
	mockSession.AssertNotCalled(t, "Type", mock.Anything, mock.Anything)
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
		// JSON often unmarshals numbers into interface{} as float64. Robustness is critical here.
		{"Valid Float64", map[string]interface{}{"duration_ms": 250.5}, 250},
		{"Valid Int64", map[string]interface{}{"duration_ms": int64(750)}, 750},
		{"Invalid Type (String)", map[string]interface{}{"duration_ms": "invalid"}, 1000}, // Should fallback to default
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor, mockSession := setupBrowserExecutor(t, true)

			action := schemas.Action{Type: schemas.ActionWaitForAsync, Metadata: tt.metadata}

			// Expect the WaitForAsync call with the correctly parsed duration
			mockSession.On("WaitForAsync", tt.expectedDuration).Return(nil).Once()

			// Execute the unexported handler directly (white box).
			err := executor.handleWaitForAsync(mockSession, action)

			// Verify
			require.NoError(t, err)
			mockSession.AssertExpectations(t)
		})
	}
}
