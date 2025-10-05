// internal/worker/adapters/agent_adapter_test.go
package adapters_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// Helper to setup AnalysisContext for AgentAdapter
func setupAgentContext(t *testing.T, params interface{}, bm schemas.BrowserManager) *core.AnalysisContext {
	t.Helper()
	return &core.AnalysisContext{
		Task: schemas.Task{
			TaskID:     "agent-task-1",
			Parameters: params,
			TargetURL:  "http://target.com",
		},
		Logger: zap.NewNop(),
		Global: &core.GlobalContext{
			BrowserManager: bm,
			FindingsChan:   make(chan schemas.Finding, 1),
		},
		Findings:  []schemas.Finding{},
		KGUpdates: &schemas.KnowledgeGraphUpdate{},
	}
}

func TestAgentAdapter_Analyze_ParameterValidation(t *testing.T) {
	adapter := adapters.NewAgentAdapter()
	mockBM := new(mocks.MockBrowserManager)

	tests := []struct {
		name          string
		params        interface{}
		expectedError string
	}{
		{
			name:          "Wrong Type",
			params:        12345,
			expectedError: "invalid parameters type for Agent mission; expected schemas.AgentMissionParams or *schemas.AgentMissionParams, got int",
		},
		{
			name:          "Nil Pointer",
			params:        (*schemas.AgentMissionParams)(nil),
			expectedError: "invalid parameters: nil pointer for Agent mission",
		},
		{
			name:          "Missing MissionBrief (Struct)",
			params:        schemas.AgentMissionParams{MissionBrief: ""},
			expectedError: "validation error: agent mission task is missing required 'MissionBrief'",
		},
        {
			name:          "Missing MissionBrief (Pointer)",
			params:        &schemas.AgentMissionParams{MissionBrief: ""},
			expectedError: "validation error: agent mission task is missing required 'MissionBrief'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := setupAgentContext(t, tt.params, mockBM)
			err := adapter.Analyze(context.Background(), ctx)
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err.Error())
		})
	}
}

func TestAgentAdapter_Analyze_BrowserManagerFailure(t *testing.T) {
	adapter := adapters.NewAgentAdapter()
	mockBM := new(mocks.MockBrowserManager)
	params := schemas.AgentMissionParams{MissionBrief: "Do the thing."}
	analysisCtx := setupAgentContext(t, params, mockBM)

	expectedError := errors.New("browser crashed")

	// Setup mock expectation: BrowserManager fails to create a context.
    // The adapter passes the Task struct as 'cfg', and empty strings for the template/config (mapped from initialURL/initialData).
	mockBM.On("NewAnalysisContext",
		mock.Anything, // context
		analysisCtx.Task, // cfg
		schemas.DefaultPersona,
		"", // taintTemplate (initialURL)
		"", // taintConfig (initialData)
		analysisCtx.Global.FindingsChan,
	).Return(nil, expectedError)

	err := adapter.Analyze(context.Background(), analysisCtx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create browser session for agent:")
	assert.ErrorIs(t, err, expectedError)
	mockBM.AssertExpectations(t)
}

// TestAgentAdapter_Analyze_EnsureSessionClosed verifies resource cleanup (defer session.Close()) occurs even if the agent logic fails.
func TestAgentAdapter_Analyze_EnsureSessionClosed(t *testing.T) {
	adapter := adapters.NewAgentAdapter()
	mockBM := new(mocks.MockBrowserManager)
    mockSession := new(mocks.MockSessionContext)
	params := schemas.AgentMissionParams{MissionBrief: "Test mission."}
	analysisCtx := setupAgentContext(t, params, mockBM)

    // Setup mock expectation: Session creation succeeds.
	mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(mockSession, nil)

    // Setup expectation that Close MUST be called.
    mockSession.On("Close", mock.Anything).Return(nil)

	// Execute Analyze. We expect this to fail because agent.New() dependencies are not met in the test,
    // but the session management (defer Close) should still occur.
	err := adapter.Analyze(context.Background(), analysisCtx)

    assert.Error(t, err)
    // The error should occur during agent initialization or execution.
    assert.Condition(t, func() bool {
        return errors.Contains(err.Error(), "failed to initialize agent") || errors.Contains(err.Error(), "agent mission failed")
    }, "Error should relate to agent logic, not session creation")

    // Verify that the mocks were interacted with correctly, especially Close().
	mockBM.AssertExpectations(t)
    mockSession.AssertExpectations(t)
}

// TestAgentAdapter_Analyze_ContextCancellation_DuringSessionCreation verifies the context is propagated to the BrowserManager.
func TestAgentAdapter_Analyze_ContextCancellation_DuringSessionCreation(t *testing.T) {
	adapter := adapters.NewAgentAdapter()
	mockBM := new(mocks.MockBrowserManager)
	params := schemas.AgentMissionParams{MissionBrief: "Test."}
	analysisCtx := setupAgentContext(t, params, mockBM)

	ctx, cancel := context.WithCancel(context.Background())

	// Mock BrowserManager to block until the context is cancelled.
	mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			// Simulate work until context is done
			<-args.Get(0).(context.Context).Done()
		}).
		Return(nil, context.Canceled)

	// Run Analyze in a goroutine.
	doneChan := make(chan error)
	go func() {
		doneChan <- adapter.Analyze(ctx, analysisCtx)
	}()

	// Wait briefly and then cancel the context.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Wait for the result.
	select {
	case err := <-doneChan:
		assert.Error(t, err)
		// The error should be the one returned by the BrowserManager (context.Canceled).
		assert.Contains(t, err.Error(), "failed to create browser session")
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("Test timed out waiting for Analyze to respect context cancellation.")
	}
}
