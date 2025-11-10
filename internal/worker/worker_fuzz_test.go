// internal/worker/worker_fuzz_test.go
//go:build go1.18
// +build go1.18

package worker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"go.uber.org/zap"
)

func Fuzz_remarshalParams(f *testing.F) {
	f.Add("test", 123)
	f.Fuzz(func(t *testing.T, name string, value int) {
		params := map[string]interface{}{
			"name":  name,
			"value": value,
		}

		var result struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}
		_ = remarshalParams(params, &result)
	})
}

func Fuzz_ProcessTask(f *testing.F) {
	cfg, logger, globalCtx := setupTestEnvironment(f)
	if logger == nil {
		logger = zap.NewNop()
	}
	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSessionContext := new(mocks.MockSessionContext)
	globalCtx.BrowserManager = mockBrowserManager
	globalCtx.FindingsChan = make(chan schemas.Finding)

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	if err != nil {
		f.Fatalf("failed to create worker: %v", err)
	}

	mockBrowserManager.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSessionContext, nil)
	mockSessionContext.On("Close", mock.Anything).Return(nil)

	f.Add("ANALYZE_HEADERS", "")
	f.Fuzz(func(t *testing.T, taskType string, missionBrief string) {
		if schemas.TaskType(taskType) == schemas.TaskAgentMission {
			return
		}

		task := schemas.Task{
			Type: schemas.TaskType(taskType),
			Parameters: schemas.AgentMissionParams{
				MissionBrief: missionBrief,
			},
		}

		analysisCtx := &core.AnalysisContext{
			Task:   task,
			Logger: logger,
			Global: w.GlobalCtx(),
		}

		_ = w.ProcessTask(context.Background(), analysisCtx)
	})
}
