// internal/worker/worker_integration_test.go
package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

func TestMonolithicWorker_Integration_ProcessTask_Success(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	task := schemas.Task{
		Type:      schemas.TaskAnalyzeHeaders,
		TargetURL: server.URL,
	}

	analysisCtx := &core.AnalysisContext{
		Task:   task,
		Logger: logger,
	}

	err = w.ProcessTask(context.Background(), analysisCtx)
	assert.NoError(t, err)
}

func TestMonolithicWorker_Integration_ProcessTask_AdapterNotFound(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	w, err := NewMonolithicWorker(cfg, logger, globalCtx, WithAnalyzers(make(core.AdapterRegistry)))
	require.NoError(t, err)

	task := schemas.Task{
		Type: "NON_EXISTENT_TASK",
	}

	analysisCtx := &core.AnalysisContext{
		Task:   task,
		Logger: logger,
	}

	err = w.ProcessTask(context.Background(), analysisCtx)
	assert.Error(t, err)
}

func TestMonolithicWorker_Integration_ProcessTask_HumanoidSequence(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSessionContext := new(mocks.MockSessionContext)
	globalCtx.BrowserManager = mockBrowserManager

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)

	task := schemas.Task{
		Type: schemas.TaskHumanoidSequence,
		Parameters: schemas.HumanoidSequenceParams{
			Steps: []schemas.HumanoidStep{
				{Action: schemas.HumanoidMove, Selector: "#test"},
			},
		},
	}

	analysisCtx := &core.AnalysisContext{
		Task:   task,
		Logger: logger,
	}

	mockBrowserManager.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSessionContext, nil)
	mockSessionContext.On("GetElementGeometry", mock.Anything, "#test").Return(&schemas.ElementGeometry{
		Vertices: []float64{0, 0, 10, 0, 10, 10, 0, 10},
		Width:    10,
		Height:   10,
	}, nil)
	mockSessionContext.On("DispatchMouseEvent", mock.Anything, mock.AnythingOfType("schemas.MouseEventData")).Return(nil)
	mockSessionContext.On("Sleep", mock.Anything, mock.AnythingOfType("time.Duration")).Return(nil)
	mockSessionContext.On("ExecuteScript", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(map[string]interface{}{
		"isIntersecting": true,
	}, nil)
	mockSessionContext.On("Close", mock.Anything).Return(nil)

	err = w.ProcessTask(context.Background(), analysisCtx)
	assert.NoError(t, err)

	mockBrowserManager.AssertExpectations(t)
	mockSessionContext.AssertExpectations(t)
}
