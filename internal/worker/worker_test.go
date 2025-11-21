// internal/worker/worker_test.go
package worker_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/worker"
)

func TestMain(m *testing.M) {
	// Initialize the global logger for all tests in this package.
	// This prevents the fallback logger from being used, which can be noisy.
	cfg := config.NewDefaultConfig()
	observability.InitializeLogger(cfg.Logger())

	// Run all the tests.
	exitCode := m.Run()

	// Clean up and flush the logger.
	observability.Sync()
	os.Exit(exitCode)
}

// setupTestEnvironment prepares the basic components needed for worker tests.
func setupTestEnvironment(t testing.TB) (*config.Config, *zap.Logger, *core.GlobalContext) {
	t.Helper()

	// Initialize config with default values.
	cfg := config.NewDefaultConfig()
	logger := observability.GetLogger()

	// As the refactor progresses, other components like GlobalContext might
	// still expect the concrete *config.Config type.
	globalCtx := &core.GlobalContext{Config: cfg}

	return cfg, logger, globalCtx
}

// TestNewMonolithicWorker_Registration verifies all expected adapters are registered.
// This test ensures that when the worker is initialized, it correctly maps task
// types to their corresponding adapter implementations.
func TestNewMonolithicWorker_Registration(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	w, err := worker.NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err, "NewMonolithicWorker with default adapters failed")

	expectedTasks := []schemas.TaskType{
		schemas.TaskAnalyzeWebPageTaint,
		schemas.TaskAnalyzeWebPageProtoPP, // Added this to match the new adapter
		schemas.TaskTestAuthATO,
		schemas.TaskTestAuthIDOR,
		schemas.TaskAnalyzeHeaders,
		schemas.TaskAnalyzeJWT,
		schemas.TaskAgentMission,
		schemas.TaskTestRaceCondition,
	}

	for _, taskType := range expectedTasks {
		t.Run(string(taskType), func(t *testing.T) {
			analysisCtx := &core.AnalysisContext{
				Task:   schemas.Task{Type: taskType},
				Global: w.GlobalCtx(),
				Logger: logger,
			}

			// For this registration test, we don't care about the outcome, just that it doesn't panic
			// or return the "no adapter" error. Some adapters will error without a full context.
			err := w.ProcessTask(context.Background(), analysisCtx)

			// The primary goal of this test is to confirm an adapter is registered.
			// The most direct way to test this is to ensure we do NOT get the
			// "no adapter" error.
			if err != nil {
				assert.NotContains(t, err.Error(), "no adapter or direct handler registered for task type",
					"The adapter should be registered, but an unexpected error occurred.")
			}
		})
	}
}

func TestMonolithicWorker_ProcessTask_UnknownAdapter(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	// Create a worker with an explicitly empty analyzer map.
	w, err := worker.NewMonolithicWorker(cfg, logger, globalCtx, worker.WithAnalyzers(make(map[schemas.TaskType]core.Analyzer)))
	require.NoError(t, err, "NewMonolithicWorker with empty adapters failed")

	unknownTaskType := schemas.TaskType("NON_EXISTENT_TASK")
	analysisCtx := &core.AnalysisContext{
		Task:   schemas.Task{Type: unknownTaskType},
		Logger: logger,
	}

	err = w.ProcessTask(context.Background(), analysisCtx)

	assert.Error(t, err)
	// FIX: Updated the expected error message to match the more descriptive one in the code.
	assert.Contains(t, err.Error(), "no adapter or direct handler registered for task type 'NON_EXISTENT_TASK'")
}

// TestMonolithicWorker_ProcessTask_AdapterFailurePropagation tests that if an adapter
// returns an error, the worker correctly propagates that error up the call stack.
func TestMonolithicWorker_ProcessTask_AdapterFailurePropagation(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	// -- 1. Setup the mock analyzer --
	mockAnalyzer := new(mocks.MockAnalyzer)
	taskType := schemas.TaskAnalyzeJWT
	expectedError := errors.New("something went horribly wrong")

	// Configure the mock's expectations for methods that ARE called by ProcessTask.
	mockAnalyzer.On("Name").Return("MockJWTAdapter")
	mockAnalyzer.On("Analyze", mock.Anything, mock.AnythingOfType("*core.AnalysisContext")).Return(expectedError)
	// NOTE: We do not set an expectation for `Type()` because the code path
	// under test (`ProcessTask`) does not call it.

	// -- 2. Create the worker and inject the mock analyzer --
	analyzers := map[schemas.TaskType]core.Analyzer{
		taskType: mockAnalyzer,
	}
	w, err := worker.NewMonolithicWorker(cfg, logger, globalCtx, worker.WithAnalyzers(analyzers))
	require.NoError(t, err, "NewMonolithicWorker with mock adapter failed")

	// -- 3. Create the task and process it --
	analysisCtx := &core.AnalysisContext{
		Task:   schemas.Task{Type: taskType},
		Logger: logger,
	}
	err = w.ProcessTask(context.Background(), analysisCtx)

	// -- 4. Assert the outcome --
	require.Error(t, err, "ProcessTask should have returned an error")
	assert.Contains(t, err.Error(), "adapter 'MockJWTAdapter' failed during analysis")
	assert.True(t, errors.Is(err, expectedError), "The original error was not wrapped correctly")

	// Verify that all the mock's expectations were met.
	mockAnalyzer.AssertExpectations(t)
}

// TestMonolithicWorker_TimeslipAdapter_Success tests a successful run of the timeslip adapter.
func TestMonolithicWorker_TimeslipAdapter_Success(t *testing.T) {
	// 1. Setup Environment
	cfg, logger, globalCtx := setupTestEnvironment(t)
	w, err := worker.NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)

	// 2. Setup a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Hello, client")
	}))
	defer server.Close()

	// 3. Create the task
	task := schemas.Task{
		Type:      schemas.TaskTestRaceCondition,
		TargetURL: server.URL,
		ScanID:    uuid.New().String(),
		Parameters: schemas.RaceConditionParams{
			Method: "POST",
		},
	}
	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	analysisCtx := &core.AnalysisContext{
		Task:      task,
		Global:    globalCtx,
		TargetURL: parsedURL,
		Logger:    logger,
	}

	// 4. Process the task
	err = w.ProcessTask(context.Background(), analysisCtx)

	// 5. Assert the outcome
	require.NoError(t, err)
}