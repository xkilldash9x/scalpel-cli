// internal/agent/analysis_executor_test.go
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// Setup function for AnalysisExecutor tests.
func setupAnalysisExecutorTest(t *testing.T) (*AnalysisExecutor, *mocks.MockSessionContext, *core.GlobalContext, *mocks.MockAnalyzer) {
	t.Helper()
	logger := observability.GetLogger()
	mockSession := new(mocks.MockSessionContext)
	mockAnalyzer := new(mocks.MockAnalyzer)

	provider := func() schemas.SessionContext { return mockSession }

	globalCtx := &core.GlobalContext{
		Logger:   logger,
		Adapters: make(map[schemas.TaskType]core.Analyzer),
	}
	// Register the mock analyzer for a specific task type.
	globalCtx.Adapters[schemas.TaskAnalyzeWebPageTaint] = mockAnalyzer

	executor := NewAnalysisExecutor(globalCtx, provider)

	return executor, mockSession, globalCtx, mockAnalyzer
}

// TestAnalysisExecutor_Execute_Success verifies the happy path, including context setup and result propagation.
func TestAnalysisExecutor_Execute_Success(t *testing.T) {
	executor, mockSession, _, mockAnalyzer := setupAnalysisExecutorTest(t)
	ctx := context.Background()

	action := Action{
		ID:     "action-1",
		Type:   ActionAnalyzeTaint,
		ScanID: "scan-1",
		Value:  "http://target.com/page", // Added value to test URL parsing
	}

	// Expectations for a successful execution
	mockAnalyzer.On("Name").Return("TestTaintAnalyzer").Maybe()
	mockAnalyzer.On("Type").Return(core.TypeActive).Maybe()

	// Expect artifact collection
	harRaw := json.RawMessage("{}")
	expectedArtifacts := &schemas.Artifacts{HAR: &harRaw}
	mockSession.On("CollectArtifacts", mock.Anything).Return(expectedArtifacts, nil).Once()

	// Define expected findings and KG updates that the analyzer will produce
	expectedFindings := []schemas.Finding{{ID: "finding-1"}}
	expectedKGUpdates := &schemas.KnowledgeGraphUpdate{
		NodesToAdd: []schemas.NodeInput{{ID: "node-1"}},
	}

	// Expect the Analyze method to be called and populate the context
	mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		analysisCtx := args.Get(1).(*core.AnalysisContext)
		// Verify context initialization
		assert.Equal(t, action.ID, analysisCtx.Task.TaskID)
		assert.Equal(t, expectedArtifacts, analysisCtx.Artifacts)
		assert.Equal(t, mockSession, analysisCtx.Session)
		require.NotNil(t, analysisCtx.TargetURL)
		assert.Equal(t, "http://target.com/page", analysisCtx.TargetURL.String())

		// Simulate the analyzer adding results
		analysisCtx.Findings = append(analysisCtx.Findings, expectedFindings...)
		analysisCtx.KGUpdates.NodesToAdd = append(analysisCtx.KGUpdates.NodesToAdd, expectedKGUpdates.NodesToAdd...)
	}).Return(nil).Once()

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "success", result.Status)
	assert.Equal(t, ObservedAnalysisResult, result.ObservationType)

	// Verify that the findings and KG updates are propagated to the ExecutionResult
	assert.Equal(t, expectedFindings, result.Findings)
	assert.Equal(t, expectedKGUpdates.NodesToAdd, result.KGUpdates.NodesToAdd)

	// Verify summary data
	data, ok := result.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, 1, data["findings_count"])
	assert.Equal(t, 1, data["kg_nodes_added"])

	mockSession.AssertExpectations(t)
	mockAnalyzer.AssertExpectations(t)
}

// TestAnalysisExecutor_Execute_AnalyzerFailure verifies error handling when the analyzer fails.
func TestAnalysisExecutor_Execute_AnalyzerFailure(t *testing.T) {
	executor, mockSession, _, mockAnalyzer := setupAnalysisExecutorTest(t)
	ctx := context.Background()

	action := Action{Type: ActionAnalyzeTaint}
	expectedError := errors.New("internal analyzer error")

	mockAnalyzer.On("Name").Return("TestTaintAnalyzer").Maybe()
	mockAnalyzer.On("Type").Return(core.TypeActive).Maybe()
	mockSession.On("CollectArtifacts", mock.Anything).Return(nil, nil).Once()
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage(`""`), nil).Maybe()
	mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Return(expectedError).Once()

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err) // Executor returns a failed result, not an error
	assert.Equal(t, "failed", result.Status)
	assert.Equal(t, ErrCodeAnalysisFailure, result.ErrorCode)
	assert.Contains(t, result.ErrorDetails["message"], expectedError.Error())
}

// TestAnalysisExecutor_Execute_NoSessionForActiveAnalyzer verifies the session requirement for active analyzers.
func TestAnalysisExecutor_Execute_NoSessionForActiveAnalyzer(t *testing.T) {
	executor, _, _, mockAnalyzer := setupAnalysisExecutorTest(t)
	ctx := context.Background()

	// Configure the executor with a nil session provider
	executor.sessionProvider = func() schemas.SessionContext { return nil }

	action := Action{Type: ActionAnalyzeTaint}

	// Configure the analyzer as Active
	mockAnalyzer.On("Name").Return("TestTaintAnalyzer").Maybe()
	mockAnalyzer.On("Type").Return(core.TypeActive).Once()

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "failed", result.Status)
	assert.Equal(t, ErrCodeExecutionFailure, result.ErrorCode)
	assert.Contains(t, result.ErrorDetails["message"], "No active browser session available")
}

// TestAnalysisExecutor_Execute_AdapterNotFound verifies handling when the required adapter is missing.
func TestAnalysisExecutor_Execute_AdapterNotFound(t *testing.T) {
	executor, _, globalCtx, _ := setupAnalysisExecutorTest(t)
	ctx := context.Background()

	// Ensure the adapter for this type is definitely not registered
	delete(globalCtx.Adapters, schemas.TaskAnalyzeHeaders)

	action := Action{Type: ActionAnalyzeHeaders}

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "failed", result.Status)
	assert.Equal(t, ErrCodeNotImplemented, result.ErrorCode)
	assert.Contains(t, result.ErrorDetails["message"], "Adapter not found")
}

// NEW: TestAnalysisExecutor_Execute_NilAdapters verifies handling when the adapter registry itself is nil.
func TestAnalysisExecutor_Execute_NilAdapters(t *testing.T) {
	executor, _, globalCtx, _ := setupAnalysisExecutorTest(t)
	ctx := context.Background()

	// Set the Adapters map to nil
	globalCtx.Adapters = nil

	action := Action{Type: ActionAnalyzeTaint}

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "failed", result.Status)
	assert.Equal(t, ErrCodeFeatureDisabled, result.ErrorCode)
	assert.Contains(t, result.ErrorDetails["message"], "Analysis adapter registry is not available")
}

// NEW: TestAnalysisExecutor_Execute_ArtifactCollectionFailure verifies that analysis proceeds even if artifact collection fails.
func TestAnalysisExecutor_Execute_ArtifactCollectionFailure(t *testing.T) {
	executor, mockSession, _, mockAnalyzer := setupAnalysisExecutorTest(t)
	ctx := context.Background()

	action := Action{Type: ActionAnalyzeTaint}

	mockAnalyzer.On("Name").Return("TestTaintAnalyzer").Maybe()
	mockAnalyzer.On("Type").Return(core.TypeActive).Maybe()

	// Mock artifact collection failure
	expectedErr := errors.New("browser artifact timeout")
	mockSession.On("CollectArtifacts", mock.Anything).Return(nil, expectedErr).Once()
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage(`""`), nil).Maybe()

	// Expect Analyze to still be called, but with nil artifacts
	mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		analysisCtx := args.Get(1).(*core.AnalysisContext)
		assert.Nil(t, analysisCtx.Artifacts, "Artifacts should be nil after collection failure")
	}).Return(nil).Once()

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "success", result.Status) // Analysis succeeded despite artifact failure
	mockSession.AssertExpectations(t)
	mockAnalyzer.AssertExpectations(t)
}

// NEW TEST: TestAnalysisExecutor_Execute_InvalidURLInActionValue verifies that an invalid URL string
// results in a nil TargetURL for the analyzer, rather than a partially parsed one.
func TestAnalysisExecutor_Execute_InvalidURLInActionValue(t *testing.T) {
	executor, mockSession, _, mockAnalyzer := setupAnalysisExecutorTest(t)
	ctx := context.Background()

	// Action with an invalid URL (contains a space)
	action := Action{
		Type:  ActionAnalyzeTaint,
		Value: "http://invalid url.com",
	}

	mockAnalyzer.On("Name").Return("TestTaintAnalyzer").Maybe()
	mockAnalyzer.On("Type").Return(core.TypeActive).Maybe()
	mockSession.On("CollectArtifacts", mock.Anything).Return(nil, nil).Once()

	// Expect Analyze to be called, but with a nil TargetURL because parsing should fail.
	mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		analysisCtx := args.Get(1).(*core.AnalysisContext)
		assert.Nil(t, analysisCtx.TargetURL, "TargetURL should be nil when parsing fails")
	}).Return(nil).Once()

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	assert.Equal(t, "success", result.Status) // Analysis proceeds even if URL is invalid
	mockAnalyzer.AssertExpectations(t)
}

// NEW: TestAnalysisExecutor_MapActionToTaskType verifies the mapping logic and error handling.
func TestAnalysisExecutor_MapActionToTaskType(t *testing.T) {
	executor, _, _, _ := setupAnalysisExecutorTest(t)

	tests := []struct {
		actionType ActionType
		expected   schemas.TaskType
		expectErr  bool
	}{
		{ActionAnalyzeTaint, schemas.TaskAnalyzeWebPageTaint, false},
		{ActionAnalyzeHeaders, schemas.TaskAnalyzeHeaders, false},
		{ActionClick, "", true}, // Unsupported type
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Action_%s", tt.actionType), func(t *testing.T) {
			taskType, err := executor.mapActionToTaskType(tt.actionType)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, taskType)
			}
		})
	}
}

// NEW TEST: TestAnalysisExecutor_Execute_PassiveAnalyzerNoSessionNoValue verifies that a passive analyzer
// does not panic when both the session is nil AND the Action.Value is empty.
func TestAnalysisExecutor_Execute_PassiveAnalyzerNoSessionNoValue(t *testing.T) {
	// This tests the fix for the nil pointer dereference when trying to get the URL from a nil session.

	executor, _, globalCtx, mockAnalyzer := setupAnalysisExecutorTest(t)
	ctx := context.Background()

	// Register the mock analyzer as Passive for a specific task type (e.g., Headers).
	// The setup function registers Taint by default, let's add Headers too.
	globalCtx.Adapters[schemas.TaskAnalyzeHeaders] = mockAnalyzer

	// Configure the executor with a nil session provider
	executor.sessionProvider = func() schemas.SessionContext { return nil }

	// Action with NO Value
	action := Action{Type: ActionAnalyzeHeaders, Value: ""}

	// Configure the analyzer as Passive
	mockAnalyzer.On("Name").Return("TestHeaderAnalyzer").Maybe()
	mockAnalyzer.On("Type").Return(core.TypePassive).Once()

	// Expect Analyze to be called, even with nil session and nil TargetURL
	mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		analysisCtx := args.Get(1).(*core.AnalysisContext)
		assert.Nil(t, analysisCtx.Session)
		assert.Nil(t, analysisCtx.TargetURL, "TargetURL should be nil if Action.Value is empty and Session is nil")
	}).Return(nil).Once()

	// Act: This should not panic
	_, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	mockAnalyzer.AssertExpectations(t)
}

// NEW TEST: TestAnalysisExecutor_Execute_DetermineTargetURL verifies the logic for setting the TargetURL in the context.
func TestAnalysisExecutor_Execute_DetermineTargetURL(t *testing.T) {
	// We need separate setups for each subtest to ensure clean mocks.
	ctx := context.Background()

	setupTest := func() (*AnalysisExecutor, *mocks.MockSessionContext, *mocks.MockAnalyzer) {
		executor, mockSession, _, mockAnalyzer := setupAnalysisExecutorTest(t)
		// Common expectations for the analyzer (it must run to check the context)
		mockAnalyzer.On("Name").Return("TestAnalyzer").Maybe()
		mockAnalyzer.On("Type").Return(core.TypeActive).Maybe()
		mockSession.On("CollectArtifacts", mock.Anything).Return(nil, nil).Maybe()
		return executor, mockSession, mockAnalyzer
	}

	t.Run("URLFromActionValue", func(t *testing.T) {
		executor, mockSession, mockAnalyzer := setupTest()
		action := Action{Type: ActionAnalyzeTaint, Value: "http://action.com/page"}

		// Ensure ExecuteScript is NOT called when Value is present
		mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage(`""`), nil).Maybe()

		mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			analysisCtx := args.Get(1).(*core.AnalysisContext)
			require.NotNil(t, analysisCtx.TargetURL)
			assert.Equal(t, "http://action.com/page", analysisCtx.TargetURL.String())
		}).Return(nil).Once()

		_, err := executor.Execute(ctx, action)
		require.NoError(t, err)
	})

	t.Run("URLFromSessionSuccess", func(t *testing.T) {
		executor, mockSession, mockAnalyzer := setupTest()
		action := Action{Type: ActionAnalyzeTaint, Value: ""} // Empty value
		expectedURL := "http://session.com/current"
		// Mock the JavaScript execution to return the URL (JSON encoded string)
		mockSession.On("ExecuteScript", mock.Anything, "return window.location.href", mock.Anything).
			Return(json.RawMessage(`"`+expectedURL+`"`), nil).Once()

		mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			analysisCtx := args.Get(1).(*core.AnalysisContext)
			require.NotNil(t, analysisCtx.TargetURL)
			assert.Equal(t, expectedURL, analysisCtx.TargetURL.String())
		}).Return(nil).Once()

		_, err := executor.Execute(ctx, action)
		require.NoError(t, err)
	})

	t.Run("URLFromSessionScriptFails", func(t *testing.T) {
		executor, mockSession, mockAnalyzer := setupTest()
		action := Action{Type: ActionAnalyzeTaint, Value: ""}
		// Mock script execution failure
		mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).
			Return(nil, errors.New("browser disconnected")).Once()

		mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
			analysisCtx := args.Get(1).(*core.AnalysisContext)
			// Should proceed with nil URL
			assert.Nil(t, analysisCtx.TargetURL)
		}).Return(nil).Once()

		_, err := executor.Execute(ctx, action)
		require.NoError(t, err)
	})
}
