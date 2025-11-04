// File: internal/worker/adapters/agent_adapter_test.go
package adapters_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// NOTE: Testing the AgentAdapter focuses on the adapter's orchestration responsibilities:
// validation, resource management (browser session), and error handling, as mocking the internal 'agent' package logic is complex.

// Helper to setup AnalysisContext for AgentAdapter
func setupAgentContext(t *testing.T, params interface{}, mockBM *mocks.MockBrowserManager) *core.AnalysisContext {
	t.Helper()
	targetURL := "http://example.com/mission"
	parsedURL, _ := url.Parse(targetURL)
	findingsChan := make(chan schemas.Finding, 10)
	logger := zaptest.NewLogger(t)

	mockConfig := new(mocks.MockConfig)
	mockConfig.On("Agent").Return(config.AgentConfig{}) // Expect Agent() call and return a default config

	return &core.AnalysisContext{
		Task: schemas.Task{
			TaskID:     "task-agent-1",
			Type:       schemas.TaskAgentMission,
			Parameters: params,
			TargetURL:  targetURL,
		},
		TargetURL: parsedURL,
		Logger:    logger,
		Global: &core.GlobalContext{
			BrowserManager: mockBM,
			FindingsChan:   findingsChan,
			Config:         mockConfig,
			Logger:         logger, // Pass logger to the global context
		},
		Findings:  []schemas.Finding{},
		KGUpdates: &schemas.KnowledgeGraphUpdate{},
	}
}

func TestNewAgentAdapter(t *testing.T) {
	adapter := adapters.NewAgentAdapter()
	assert.Equal(t, "AgentAdapter", adapter.Name())
	assert.Equal(t, core.TypeAgent, adapter.Type())
}

func TestAgentAdapter_Analyze_ParameterValidation(t *testing.T) {
	adapter := adapters.NewAgentAdapter()
	mockBM := new(mocks.MockBrowserManager) // Not used in validation tests

	tests := []struct {
		name          string
		params        interface{}
		expectedError string
	}{
		{"Wrong Type", "invalid string", "invalid parameters type for Agent mission; expected schemas.AgentMissionParams or *schemas.AgentMissionParams, got string"},
		{"Nil Pointer", (*schemas.AgentMissionParams)(nil), "invalid parameters: nil pointer for Agent mission"},
		{"Empty MissionBrief (Struct)", schemas.AgentMissionParams{MissionBrief: ""}, "validation error: agent mission task is missing required 'MissionBrief'"},
		{"Empty MissionBrief (Pointer)", &schemas.AgentMissionParams{MissionBrief: ""}, "validation error: agent mission task is missing required 'MissionBrief'"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := setupAgentContext(t, tt.params, mockBM)
			err := adapter.Analyze(context.Background(), ctx)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestAgentAdapter_Analyze_ResourceHandling(t *testing.T) {
	adapter := adapters.NewAgentAdapter()
	params := schemas.AgentMissionParams{MissionBrief: "Find the login page"}

	t.Run("Nil BrowserManager", func(t *testing.T) {
		// Pass nil for the BrowserManager
		analysisCtx := setupAgentContext(t, params, nil)
		// Ensure it's nil if setupAgentContext didn't handle nil input correctly
		if analysisCtx.Global != nil {
			analysisCtx.Global.BrowserManager = nil
		}

		err := adapter.Analyze(context.Background(), analysisCtx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "BrowserManager is not available")
	})

	t.Run("Session Creation Fails", func(t *testing.T) {
		mockBM := new(mocks.MockBrowserManager)
		analysisCtx := setupAgentContext(t, params, mockBM)
		expectedErr := errors.New("browser crashed")

		mockBM.On("NewAnalysisContext",
			mock.Anything,
			analysisCtx.Task,
			schemas.DefaultPersona,
			"", "",
			analysisCtx.Global.FindingsChan,
		).Return(nil, expectedErr)

		err := adapter.Analyze(context.Background(), analysisCtx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create browser session for agent")
		mockBM.AssertExpectations(t)
	})

	t.Run("Session Is Closed On Agent Initialization Failure", func(t *testing.T) {
		// This test verifies that the session is closed (deferred) even if the steps after session creation fail.
		mockBM := new(mocks.MockBrowserManager)
		mockSession := mocks.NewMockSessionContext()
		analysisCtx := setupAgentContext(t, params, mockBM)

		// Setup successful session creation
		mockBM.On("NewAnalysisContext",
			mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
		).Return(mockSession, nil)

		// Expect the session to be closed when the adapter function returns.
		// We expect it to be called with context.Background() due to the improved defer.
		mockSession.On("Close", mock.MatchedBy(func(ctx context.Context) bool {
			// Check if it's a background context (or a derivative of it)
			return ctx == context.Background()
		})).Return(nil)

		// We expect agent.New() to fail because the mocks provided in setupAgentContext
		// (e.g., MockLLMClient) likely don't satisfy the requirements of the real agent.New().
		err := adapter.Analyze(context.Background(), analysisCtx)

		// We assert that an error occurred (initialization failure) AND that the session mocks were met (Close was called).
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize agent")

		mockSession.AssertExpectations(t)
		mockBM.AssertExpectations(t)
	})
}

// TestAgentAdapter_Analyze_ContextCancellation ensures the adapter respects context cancellation during resource acquisition.
func TestAgentAdapter_Analyze_ContextCancellation(t *testing.T) {
	adapter := adapters.NewAgentAdapter()
	mockBM := new(mocks.MockBrowserManager)
	params := schemas.AgentMissionParams{MissionBrief: "Test objective"}
	analysisCtx := setupAgentContext(t, params, mockBM)

	// Configure the mock browser manager to hang during session creation until the context is cancelled.
	mockBM.On("NewAnalysisContext",
		mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything,
	).Run(func(args mock.Arguments) {
		// Wait for the context provided to NewAnalysisContext (the first argument) to be done.
		<-args.Get(0).(context.Context).Done()
	}).Return(nil, context.Canceled) // Return the context error.

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately (or shortly after starting)

	err := adapter.Analyze(ctx, analysisCtx)

	require.Error(t, err)
	// The specific error from NewAnalysisContext should be propagated.
	assert.Contains(t, err.Error(), "failed to create browser session")
	assert.ErrorIs(t, err, context.Canceled)
	mockBM.AssertExpectations(t)
}
