// internal/agent/executors_test.go
package agent

import ( // This is a comment to force a change
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// -- BrowserExecutor Tests --

// Setup helper for BrowserExecutor tests
func setupBrowserExecutorTest(t *testing.T) (*BrowserExecutor, *mocks.MockSessionContext) {
	logger := zaptest.NewLogger(t)
	mockSession := mocks.NewMockSessionContext()
	provider := func() schemas.SessionContext { return mockSession }
	executor := NewBrowserExecutor(logger, provider)
	return executor, mockSession
}

// NEW: TestBrowserExecutor_Execute_GeneralCases covers the main Execute logic.
func TestBrowserExecutor_Execute_GeneralCases(t *testing.T) {
	t.Run("NoActiveSession", func(t *testing.T) {
		executor, _ := setupBrowserExecutorTest(t)
		// Override provider to return nil
		executor.sessionProvider = func() schemas.SessionContext { return nil }

		action := Action{Type: ActionNavigate}
		result, err := executor.Execute(context.Background(), action)

		require.NoError(t, err)
		assert.Equal(t, "failed", result.Status)
		assert.Equal(t, ErrCodeExecutionFailure, result.ErrorCode)
		assert.Contains(t, result.ErrorDetails["message"], "no active browser session")
	})

	t.Run("HandlerNotFound", func(t *testing.T) {
		executor, _ := setupBrowserExecutorTest(t)
		// Use an action type not registered in BrowserExecutor
		action := Action{Type: ActionClick} // Click is handled by HumanoidExecutor

		result, err := executor.Execute(context.Background(), action)

		require.NoError(t, err)
		assert.Equal(t, "failed", result.Status)
		assert.Equal(t, ErrCodeUnknownAction, result.ErrorCode)
		assert.Contains(t, result.ErrorDetails["message"], "BrowserExecutor handler not found")
	})

	t.Run("HandlerReturnsError", func(t *testing.T) {
		executor, mockSession := setupBrowserExecutorTest(t)
		action := Action{Type: ActionNavigate, Value: "http://fail.com"}
		expectedErr := errors.New("net::ERR_CONNECTION_REFUSED")
		mockSession.On("Navigate", mock.Anything, action.Value).Return(expectedErr).Once()

		result, err := executor.Execute(context.Background(), action)

		require.NoError(t, err)
		assert.Equal(t, "failed", result.Status)
		// Check that the error is correctly parsed
		assert.Equal(t, ErrCodeNavigationError, result.ErrorCode)
		assert.Contains(t, result.ErrorDetails["message"], expectedErr.Error())
	})
}

func TestBrowserExecutor_HandleNavigate(t *testing.T) {
	executor, mockSession := setupBrowserExecutorTest(t)

	// Test successful navigation
	action := Action{Type: ActionNavigate, Value: "https://example.com"}
	mockSession.On("Navigate", mock.Anything, "https://example.com").Return(nil).Once()
	err := executor.handleNavigate(context.Background(), mockSession, action)
	assert.NoError(t, err)

	// Test navigation failure (covered by TestBrowserExecutor_Execute_GeneralCases)

	// Test missing URL
	action.Value = ""
	err = executor.handleNavigate(context.Background(), mockSession, action)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires a 'value'")
}

func TestBrowserExecutor_HandleSubmitForm(t *testing.T) {
	executor, mockSession := setupBrowserExecutorTest(t)

	action := Action{Type: ActionSubmitForm, Selector: "#form"}
	mockSession.On("Submit", mock.Anything, "#form").Return(nil).Once()
	err := executor.handleSubmitForm(context.Background(), mockSession, action)
	assert.NoError(t, err)

	action.Selector = ""
	err = executor.handleSubmitForm(context.Background(), mockSession, action)
	assert.Error(t, err)
}

func TestBrowserExecutor_HandleScroll(t *testing.T) {
	executor, mockSession := setupBrowserExecutorTest(t)

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
	executor, mockSession := setupBrowserExecutorTest(t)

	// Test with default duration
	action := Action{Type: ActionWaitForAsync}
	mockSession.On("WaitForAsync", mock.Anything, 1000).Return(nil).Once()
	err := executor.handleWaitForAsync(context.Background(), mockSession, action)
	assert.NoError(t, err)

	// Test with specified duration (float64 - common from JSON)
	action.Metadata = map[string]interface{}{"duration_ms": 2500.0}
	mockSession.On("WaitForAsync", mock.Anything, 2500).Return(nil).Once()
	err = executor.handleWaitForAsync(context.Background(), mockSession, action)
	assert.NoError(t, err)

	// NEW: Test with integer types
	t.Run("IntegerTypes", func(t *testing.T) {
		tests := []struct {
			val      interface{}
			expected int
		}{
			{int(1500), 1500},
			{int64(1600), 1600},
			{float32(1700.5), 1700},
		}

		for _, tt := range tests {
			action.Metadata = map[string]interface{}{"duration_ms": tt.val}
			mockSession.On("WaitForAsync", mock.Anything, tt.expected).Return(nil).Once()
			err = executor.handleWaitForAsync(context.Background(), mockSession, action)
			assert.NoError(t, err)
		}
	})

	// Test with invalid type (should use default)
	action.Metadata = map[string]interface{}{"duration_ms": "not-a-number"}
	mockSession.On("WaitForAsync", mock.Anything, 1000).Return(nil).Once()
	err = executor.handleWaitForAsync(context.Background(), mockSession, action)
	assert.NoError(t, err)
}

func TestExecutorRegistry_Execute(t *testing.T) {
	logger := zap.NewNop()
	mockSession := mocks.NewMockSessionContext()
	provider := func() schemas.SessionContext { return mockSession }

	// Create a mock GlobalContext, which is now required by the registry.
	mockGlobalCtx := &core.GlobalContext{
		Config:   &config.Config{},
		Logger:   logger,
		Adapters: make(map[schemas.TaskType]core.Analyzer),
	}

	registry := NewExecutorRegistry(logger, ".", mockGlobalCtx)
	registry.UpdateSessionProvider(provider)

	t.Run("ValidBrowserAction", func(t *testing.T) {
		navAction := Action{Type: ActionNavigate, Value: "https://example.com"}
		mockSession.On("Navigate", mock.Anything, "https://example.com").Return(nil).Once()

		result, err := registry.Execute(context.Background(), navAction)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "success", result.Status)
		mockSession.AssertExpectations(t)
	})

	t.Run("ValidAnalysisAction", func(t *testing.T) {
		mockAnalyzer := mocks.NewMockAnalyzer()
		mockGlobalCtx.Adapters[schemas.TaskAnalyzeHeaders] = mockAnalyzer

		analysisAction := Action{Type: ActionAnalyzeHeaders}
		mockSession.On("CollectArtifacts", mock.Anything).Return((*schemas.Artifacts)(nil), nil).Once()
		// The analysis executor expects the Analyze method to be called.
		mockAnalyzer.On("Name").Return("MockHeaderAnalyzer")
		mockAnalyzer.On("Type").Return(core.TypePassive).Maybe()
		mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Return(nil).Once()

		result, err := registry.Execute(context.Background(), analysisAction)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "success", result.Status)
		assert.Equal(t, ObservedAnalysisResult, result.ObservationType)
		mockAnalyzer.AssertExpectations(t)
	})

	t.Run("ValidRaceConditionAction", func(t *testing.T) {
		mockAnalyzer := mocks.NewMockAnalyzer()
		mockGlobalCtx.Adapters[schemas.TaskTestRaceCondition] = mockAnalyzer

		analysisAction := Action{Type: ActionTestRaceCondition}
		mockSession.On("CollectArtifacts", mock.Anything).Return((*schemas.Artifacts)(nil), nil).Once()
		mockAnalyzer.On("Name").Return("MockTimeslipAnalyzer")
		mockAnalyzer.On("Type").Return(core.TypeActive).Maybe()
		mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Return(nil).Once()

		result, err := registry.Execute(context.Background(), analysisAction)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "success", result.Status)
		assert.Equal(t, ObservedAnalysisResult, result.ObservationType)
		mockAnalyzer.AssertExpectations(t)
	})
	t.Run("ValidHumanoidAction_Integration", func(t *testing.T) {
		// This is a full integration test for the HumanoidExecutor via the registry.
		// 1. We use a real Humanoid instance.
		// 2. We give it a MOCKED session context as its executor.
		// 3. We verify that the humanoid's methods (e.g., IntelligentClick) are called,
		//    and that they in turn call the expected methods on the mocked session.
		mockSessionForHumanoid := mocks.NewMockSessionContext()
		h := humanoid.NewTestHumanoid(mockSessionForHumanoid, 1)

		humanoidProvider := func() *humanoid.Humanoid {
			return h
		}
		registry.UpdateHumanoidProvider(humanoidProvider)

		clickAction := Action{Type: ActionClick, Selector: "#button"}

		// Expect the humanoid to call the scroll script first to ensure visibility.
		// Return a JSON indicating the element is already visible.
		mockSessionForHumanoid.On("ExecuteScript", mock.Anything, mock.AnythingOfType("string"), mock.Anything).
			Return(json.RawMessage(`{"isIntersecting": true, "isComplete": true, "elementExists": true}`), nil).
			Once()

		// Expect the humanoid to try and get the element's geometry before clicking.
		// The center of this box is (10, 10).
		mockSessionForHumanoid.On("GetElementGeometry", mock.Anything, "#button").Return(&schemas.ElementGeometry{
			Vertices: []float64{7.5, 7.5, 12.5, 7.5, 12.5, 12.5, 7.5, 12.5},
			Width:    5, Height: 5,
		}, nil).Once()
		// Expect the final mouse press/release events.
		// The humanoid will perform several actions: sleep, move, press, release.
		// We allow any number of sleeps and moves, but require one press and one release.
		mockSessionForHumanoid.On("Sleep", mock.Anything, mock.Anything).Return(nil)
		mockSessionForHumanoid.On("DispatchMouseEvent", mock.Anything, mock.MatchedBy(func(e schemas.MouseEventData) bool { return e.Type == "mousePressed" })).Return(nil).Once()
		mockSessionForHumanoid.On("DispatchMouseEvent", mock.Anything, mock.MatchedBy(func(e schemas.MouseEventData) bool { return e.Type == "mouseReleased" })).Return(nil).Once()
		mockSessionForHumanoid.On("DispatchMouseEvent", mock.Anything, mock.AnythingOfType("schemas.MouseEventData")).Return(nil).Maybe()

		_, err := registry.Execute(context.Background(), clickAction)
		require.NoError(t, err)
		mockSessionForHumanoid.AssertExpectations(t)
	})

	t.Run("UnregisteredAction", func(t *testing.T) {
		unknownAction := Action{Type: "ACTION_THAT_DOES_NOT_EXIST"}
		result, err := registry.Execute(context.Background(), unknownAction)
		require.Error(t, err)
		require.Nil(t, result)
		assert.Contains(t, err.Error(), "no executor registered")
	})

	// NEW: Test actions that should be handled by the Agent loop
	t.Run("AgentLoopActions", func(t *testing.T) {
		actions := []ActionType{
			ActionConclude,
			ActionEvolveCodebase,
			ActionExecuteLoginSequence,
			ActionExploreApplication,
			ActionFuzzEndpoint,
		}
		for _, actionType := range actions {
			t.Run(string(actionType), func(t *testing.T) {
				action := Action{Type: actionType}
				result, err := registry.Execute(context.Background(), action)
				require.Error(t, err)
				require.Nil(t, result)
				assert.Contains(t, err.Error(), "should be handled by the Agent's cognitive loop")
			})
		}
	})
}

// NEW: TestExecutorRegistry_Providers tests the dynamic provider update mechanism.
func TestExecutorRegistry_Providers(t *testing.T) {
	logger := zap.NewNop()
	registry := NewExecutorRegistry(logger, ".", nil)

	// 1. Test initial state (should return nil)
	sessionGetter := registry.GetSessionProvider()
	assert.Nil(t, sessionGetter())

	humanoidGetter := registry.GetHumanoidProvider()
	assert.Nil(t, humanoidGetter())

	// 2. Update providers
	mockSession := mocks.NewMockSessionContext()
	sessionProvider := func() schemas.SessionContext { return mockSession }
	registry.UpdateSessionProvider(sessionProvider)

	dummyHumanoid := &humanoid.Humanoid{}
	humanoidProvider := func() *humanoid.Humanoid { return dummyHumanoid }
	registry.UpdateHumanoidProvider(humanoidProvider)

	// 3. Test updated state (use the original getters)
	assert.Equal(t, mockSession, sessionGetter())
	assert.Equal(t, dummyHumanoid, humanoidGetter())

	// 4. Test concurrent access (simple race detector check)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			registry.UpdateSessionProvider(sessionProvider)
			_ = registry.GetSessionProvider()()
		}()
	}
	wg.Wait()
}

func TestParseBrowserError(t *testing.T) {
	action := Action{Selector: "#id", Type: ActionClick}

	tests := []struct {
		name     string
		err      error
		expected ErrorCode
	}{
		{"Element Not Found (generic)", errors.New("browser: no element found for selector"), ErrCodeElementNotFound},
		{"Element Not Found (geometry)", errors.New("geometry retrieval failed"), ErrCodeElementNotFound},
		{"Timeout (generic)", errors.New("context deadline exceeded: waiting for element timed out"), ErrCodeTimeoutError},
		{"Timeout (specific)", errors.New("operation timeout"), ErrCodeTimeoutError},
		{"Navigation Error", errors.New("could not navigate: net::ERR_CONNECTION_REFUSED"), ErrCodeNavigationError},
		{"Validation Error (selector)", fmt.Errorf("ActionClick requires a 'selector'"), ErrCodeInvalidParameters},
		{"Validation Error (value)", fmt.Errorf("ActionInput requires a 'value'"), ErrCodeInvalidParameters},
		{"Validation Error (metadata)", fmt.Errorf("ActionDrag requires 'metadata.target_selector'"), ErrCodeInvalidParameters},
		{"Validation Error (metadata type)", fmt.Errorf("'metadata.target_selector' must be a non-empty string"), ErrCodeInvalidParameters},
		{"Generic Failure", errors.New("some other random internal browser error"), ErrCodeExecutionFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, details := ParseBrowserError(tt.err, action)
			assert.Equal(t, tt.expected, code)
			assert.Contains(t, details["message"], tt.err.Error())
			if code == ErrCodeElementNotFound {
				assert.Equal(t, action.Selector, details["selector"])
			}
		})
	}
}
