// internal/engine/engine_test.go
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// -- Mock Implementations --

// mockWorker simulates the behavior of the MonolithicWorker.
// We integrate testify/mock to allow assertions on whether the worker was called.
type mockWorker struct {
	mock.Mock
	// A function that can be customized per test to simulate different outcomes.
	processFunc func(ctx context.Context, analysisCtx *core.AnalysisContext) error
}

func (m *mockWorker) ProcessTask(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	// Record the call in the mock object
	m.Called(ctx, analysisCtx)

	if m.processFunc != nil {
		return m.processFunc(ctx, analysisCtx)
	}
	// Default behavior: do nothing and succeed.
	return nil
}

// -- Test Suite --

// Verification for Fix 1: Missing Dependency Validation
func TestTaskEngine_New_Validation(t *testing.T) {
	// Setup valid dependencies
	mockCfg := new(mocks.MockConfig)
	logger := zap.NewNop()
	store := new(mocks.MockStore)
	worker := &mockWorker{}
	// Minimal context is sufficient for initialization validation
	globalCtx := &core.GlobalContext{Config: &config.Config{}, Logger: logger}

	tests := []struct {
		name        string
		cfg         config.Interface
		logger      *zap.Logger
		store       Store
		worker      Worker
		globalCtx   *core.GlobalContext
		expectError bool
	}{
		{"All Valid", mockCfg, logger, store, worker, globalCtx, false},
		{"Nil Config", nil, logger, store, worker, globalCtx, true},
		{"Nil Logger", mockCfg, nil, store, worker, globalCtx, true},
		{"Nil Store", mockCfg, logger, nil, worker, globalCtx, true},
		{"Nil Worker", mockCfg, logger, store, nil, globalCtx, true},
		{"Nil GlobalCtx", mockCfg, logger, store, worker, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use require.NotPanics to catch the potential panic if logger is nil (which occurred before the fix).
			require.NotPanics(t, func() {
				engine, err := New(tt.cfg, tt.logger, tt.store, tt.worker, tt.globalCtx)
				if tt.expectError {
					require.Error(t, err)
					require.Nil(t, engine)
				} else {
					require.NoError(t, err)
					require.NotNil(t, engine)
				}
			})
		})
	}
}

// Verification for Fix 2: Re-entrant Start Method
func TestTaskEngine_StartIdempotencyAndRestart(t *testing.T) {
	// -- Setup --
	concurrency := 2
	mockCfg := new(mocks.MockConfig)
	engineCfg := config.EngineConfig{WorkerConcurrency: concurrency}
	mockCfg.On("Engine").Return(engineCfg)

	logger := zap.NewNop()
	store := new(mocks.MockStore)
	// Persistence is not the focus, but mock it just in case.
	store.On("PersistData", mock.Anything, mock.Anything).Return(nil).Maybe()

	var activeWorkers int32
	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			atomic.AddInt32(&activeWorkers, 1)
			defer atomic.AddInt32(&activeWorkers, -1)
			// Keep the worker busy briefly
			time.Sleep(50 * time.Millisecond)
			return nil
		},
	}
	worker.On("ProcessTask", mock.Anything, mock.Anything).Return(nil)

	globalCtx := &core.GlobalContext{Config: &config.Config{}, Logger: logger}
	engine, err := New(mockCfg, logger, store, worker, globalCtx)
	require.NoError(t, err)

	// -- Execution Phase 1: Initial Start and Idempotency Check --
	taskChan1 := make(chan schemas.Task, 10)
	engine.Start(context.Background(), taskChan1)
	// Call Start again immediately (it should be ignored).
	engine.Start(context.Background(), make(chan schemas.Task, 10))

	taskChan1 <- schemas.Task{TaskID: "task-1-1", TargetURL: "https://example.com"}
	taskChan1 <- schemas.Task{TaskID: "task-1-2", TargetURL: "https://example.com"}

	// Give workers time to pick up tasks
	time.Sleep(20 * time.Millisecond)

	// -- Assertion 1: Check worker count --
	// We expect the active worker count to be at most the configured concurrency.
	currentWorkers := atomic.LoadInt32(&activeWorkers)
	require.LessOrEqual(t, int(currentWorkers), concurrency, "More workers active than configured concurrency")

	// -- Execution Phase 2: Stop --
	close(taskChan1)
	engine.Stop()

	// -- Assertion 2: Workers should be stopped --
	require.Equal(t, int32(0), atomic.LoadInt32(&activeWorkers))

	// -- Execution Phase 3: Restart --
	taskChan3 := make(chan schemas.Task, 10)
	engine.Start(context.Background(), taskChan3) // This should work now

	taskChan3 <- schemas.Task{TaskID: "task-3-1", TargetURL: "https://example.com"}

	// Give workers time to pick up tasks
	time.Sleep(20 * time.Millisecond)

	// -- Assertion 3: Check worker count after restart --
	currentWorkers = atomic.LoadInt32(&activeWorkers)
	require.Greater(t, int(currentWorkers), 0, "No workers active after restart")

	// -- Cleanup --
	close(taskChan3)
	engine.Stop()
}

// Verification for Fix 3: Data Loss on Task Interruption (Timeout Case)
func TestTaskEngine_TimeoutPersistsPartialResults(t *testing.T) {
	// -- Setup --
	mockCfg := new(mocks.MockConfig)
	engineCfg := config.EngineConfig{
		WorkerConcurrency:  1,
		DefaultTaskTimeout: 50 * time.Millisecond, // Short timeout
	}
	mockCfg.On("Engine").Return(engineCfg)

	logger := zap.NewNop()
	store := new(mocks.MockStore)

	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			// 1. Add a finding immediately (partial result).
			analysisCtx.Findings = append(analysisCtx.Findings, schemas.Finding{ID: "partial-finding"})

			// 2. Wait until the context times out.
			<-ctx.Done()
			return ctx.Err() // Returns context.DeadlineExceeded
		},
	}
	worker.On("ProcessTask", mock.Anything, mock.Anything).Return(nil)

	globalCtx := &core.GlobalContext{Config: &config.Config{}, Logger: logger}
	engine, err := New(mockCfg, logger, store, worker, globalCtx)
	require.NoError(t, err)

	// Expect PersistData to be called because we found a partial result before the timeout.
	// This assertion fails before Fix 3 is applied.
	store.On("PersistData", mock.Anything, mock.MatchedBy(func(data *schemas.ResultEnvelope) bool {
		return len(data.Findings) == 1 && data.Findings[0].ID == "partial-finding"
	})).Return(nil).Once()

	// -- Execution --
	taskChan := make(chan schemas.Task, 1)
	engine.Start(context.Background(), taskChan)

	taskChan <- schemas.Task{TaskID: "task-timeout", TargetURL: "https://example.com"}
	close(taskChan)
	engine.Stop()

	// -- Assertions --
	store.AssertExpectations(t)
	worker.AssertExpectations(t)
}

// Verification for Fix 4: Insufficient Input Validation
func TestTaskEngine_InvalidTargetURL(t *testing.T) {
	// -- Setup --
	mockCfg := new(mocks.MockConfig)
	engineCfg := config.EngineConfig{WorkerConcurrency: 1}
	mockCfg.On("Engine").Return(engineCfg)

	logger := zap.NewNop()
	store := new(mocks.MockStore)
	// We don't expect the worker to be called for invalid URLs.
	worker := &mockWorker{}

	globalCtx := &core.GlobalContext{Config: &config.Config{}, Logger: logger}
	engine, err := New(mockCfg, logger, store, worker, globalCtx)
	require.NoError(t, err)

	// -- Execution --
	taskChan := make(chan schemas.Task, 6)
	engine.Start(context.Background(), taskChan)

	// Send various invalid or relative URLs
	taskChan <- schemas.Task{TaskID: "task-relative-path", TargetURL: "/path/to/resource"}
	taskChan <- schemas.Task{TaskID: "task-missing-host", TargetURL: "http://"}
	taskChan <- schemas.Task{TaskID: "task-invalid-format", TargetURL: "http://a b.com"} // Spaces cause url.Parse error
	taskChan <- schemas.Task{TaskID: "task-empty", TargetURL: ""}
	taskChan <- schemas.Task{TaskID: "task-no-scheme", TargetURL: "example.com"}
	taskChan <- schemas.Task{TaskID: "task-valid", TargetURL: "https://valid.com"} // Ensure a valid one still works

	// Expect the valid task to be processed
	worker.On("ProcessTask", mock.Anything, mock.MatchedBy(func(ac *core.AnalysisContext) bool {
		return ac.Task.TaskID == "task-valid"
	})).Return(nil).Once()

	close(taskChan)
	engine.Stop()

	// -- Assertions --
	// Assert that ProcessTask was only called once (for the valid task).
	worker.AssertNumberOfCalls(t, "ProcessTask", 1)
	worker.AssertExpectations(t)
	store.AssertNotCalled(t, "PersistData", mock.Anything, mock.Anything)
}

// Verification for Fix 5: Unnecessary Memory Allocation (Ensuring KG functionality remains)
func TestTaskEngine_KGUpdates_WorkerInitializes(t *testing.T) {
	// -- Setup --
	mockCfg := new(mocks.MockConfig)
	engineCfg := config.EngineConfig{WorkerConcurrency: 1}
	mockCfg.On("Engine").Return(engineCfg)

	logger := zap.NewNop()
	store := new(mocks.MockStore)

	// This worker simulates a task that finds KG information but no vulnerabilities.
	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			// Crucial: Mimic how a real worker must behave now that the engine initializes KGUpdates to nil.
			if analysisCtx.KGUpdates == nil {
				analysisCtx.KGUpdates = &schemas.KnowledgeGraphUpdate{
					NodesToAdd: []schemas.NodeInput{},
					EdgesToAdd: []schemas.EdgeInput{},
				}
			}

			analysisCtx.KGUpdates.NodesToAdd = append(analysisCtx.KGUpdates.NodesToAdd, schemas.NodeInput{
				Type: "TestNode",
			})
			return nil
		},
	}
	worker.On("ProcessTask", mock.Anything, mock.Anything).Return(nil)

	globalCtx := &core.GlobalContext{Config: &config.Config{}, Logger: logger}

	engine, err := New(mockCfg, logger, store, worker, globalCtx)
	require.NoError(t, err)

	// Expect PersistData to be called and validate the envelope contents.
	store.On("PersistData", mock.Anything, mock.MatchedBy(func(env *schemas.ResultEnvelope) bool {
		return env.TaskID == "task-kg" && len(env.Findings) == 0 && env.KGUpdates != nil && len(env.KGUpdates.NodesToAdd) == 1
	})).Return(nil).Once()

	// -- Execution --
	taskChan := make(chan schemas.Task, 1)
	engine.Start(context.Background(), taskChan)

	taskChan <- schemas.Task{TaskID: "task-kg", TargetURL: "https://example.com"}
	close(taskChan)
	engine.Stop()

	// -- Assertions --
	store.AssertExpectations(t)
	worker.AssertExpectations(t)
}

// TestTaskEngine_StartStop verifies the engine's core lifecycle: starting, processing tasks, and stopping gracefully.
// Also implicitly verifies Fix 5 (Optimization).
func TestTaskEngine_StartStop(t *testing.T) {
	// -- Setup --
	mockCfg := new(mocks.MockConfig)
	engineCfg := config.EngineConfig{
		WorkerConcurrency:  2,
		DefaultTaskTimeout: 5 * time.Second,
	}
	mockCfg.On("Engine").Return(engineCfg)

	logger := zap.NewNop()
	store := new(mocks.MockStore)

	// This mock worker will add a finding to each task it processes.
	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			analysisCtx.Findings = append(analysisCtx.Findings, schemas.Finding{ID: "finding-" + analysisCtx.Task.TaskID})
			// Note: This worker does NOT initialize KGUpdates.
			return nil
		},
	}
	worker.On("ProcessTask", mock.Anything, mock.Anything).Return(nil)

	// As core.GlobalContext has not been updated to use the config.Interface,
	// we provide a concrete config for it to satisfy the type checker.
	concreteCfgForContext := &config.Config{}

	// Create a global context for the engine.
	globalCtx := &core.GlobalContext{
		Config: concreteCfgForContext,
		Logger: logger,
	}

	engine, err := New(mockCfg, logger, store, worker, globalCtx)
	require.NoError(t, err)

	// -- Execution --
	taskChan := make(chan schemas.Task, 10)

	// Expect PersistData to be called for each successful task with findings.
	numTasks := 3
	// Verification for Fix 5: We verify that the KGUpdates in the envelope is indeed nil.
	store.On("PersistData", mock.Anything, mock.MatchedBy(func(env *schemas.ResultEnvelope) bool {
		return env.KGUpdates == nil && len(env.Findings) > 0
	})).Return(nil).Times(numTasks)

	engine.Start(context.Background(), taskChan)

	for i := 0; i < numTasks; i++ {
		taskChan <- schemas.Task{TaskID: fmt.Sprintf("task-%d", i), TargetURL: "https://example.com"}
	}
	close(taskChan) // Closing the channel signals the engine to shut down its workers.

	// Wait for the engine to stop gracefully.
	engine.Stop()

	// -- Assertions --
	store.AssertExpectations(t)
	worker.AssertExpectations(t)
}

// TestTaskEngine_WorkerError verifies that if a worker returns an error, the result is not persisted.
func TestTaskEngine_WorkerError(t *testing.T) {
	// -- Setup --
	mockCfg := new(mocks.MockConfig)
	engineCfg := config.EngineConfig{WorkerConcurrency: 1}
	mockCfg.On("Engine").Return(engineCfg)

	logger := zap.NewNop()
	store := new(mocks.MockStore)
	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			// Add findings but return a critical error.
			analysisCtx.Findings = append(analysisCtx.Findings, schemas.Finding{ID: "should-not-persist"})
			// Simulate a critical processing error (not timeout or cancellation).
			return errors.New("worker failed spectacularly")
		},
	}
	worker.On("ProcessTask", mock.Anything, mock.Anything).Return(nil)

	concreteCfgForContext := &config.Config{}
	globalCtx := &core.GlobalContext{Config: concreteCfgForContext, Logger: logger}

	engine, err := New(mockCfg, logger, store, worker, globalCtx)
	require.NoError(t, err)

	// -- Execution --
	taskChan := make(chan schemas.Task, 1)
	engine.Start(context.Background(), taskChan)

	taskChan <- schemas.Task{TaskID: "task-fail", TargetURL: "https://example.com"}
	close(taskChan)
	engine.Stop()

	// -- Assertions --
	// Fix 3 ensures that we only persist on cancellation/timeout, not critical errors.
	store.AssertNotCalled(t, "PersistData", mock.Anything, mock.Anything)
	worker.AssertExpectations(t)
}

// TestTaskEngine_NoResults verifies that no data is persisted if a task yields no findings or KG updates.
func TestTaskEngine_NoResults(t *testing.T) {
	// -- Setup --
	mockCfg := new(mocks.MockConfig)
	engineCfg := config.EngineConfig{WorkerConcurrency: 1}
	mockCfg.On("Engine").Return(engineCfg)

	logger := zap.NewNop()
	store := new(mocks.MockStore)
	worker := &mockWorker{
		// Default processFunc returns success with no findings.
	}
	worker.On("ProcessTask", mock.Anything, mock.Anything).Return(nil)

	concreteCfgForContext := &config.Config{}
	globalCtx := &core.GlobalContext{Config: concreteCfgForContext, Logger: logger}

	engine, err := New(mockCfg, logger, store, worker, globalCtx)
	require.NoError(t, err)

	// -- Execution --
	taskChan := make(chan schemas.Task, 1)
	engine.Start(context.Background(), taskChan)

	taskChan <- schemas.Task{TaskID: "task-no-findings", TargetURL: "https://example.com"}
	close(taskChan)
	engine.Stop()

	// -- Assertions --
	store.AssertNotCalled(t, "PersistData", mock.Anything, mock.Anything)
	worker.AssertExpectations(t)
}

// TestTaskEngine_ContextCancellation ensures workers shut down when the main context is cancelled.
// Also verifies Fix 3 (Data Loss on Interruption - Cancellation Case).
func TestTaskEngine_ContextCancellation(t *testing.T) {
	// -- Setup --
	mockCfg := new(mocks.MockConfig)
	// Set a long timeout so cancellation happens due to the parent context, not the task timeout.
	engineCfg := config.EngineConfig{WorkerConcurrency: 2, DefaultTaskTimeout: 5 * time.Minute}
	mockCfg.On("Engine").Return(engineCfg)

	logger := zap.NewNop()
	store := new(mocks.MockStore)

	// This worker will block until its context is cancelled, but adds a finding first.
	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			analysisCtx.Findings = append(analysisCtx.Findings, schemas.Finding{ID: "finding-before-cancel"})
			<-ctx.Done() // Wait for cancellation
			return ctx.Err()
		},
	}
	worker.On("ProcessTask", mock.Anything, mock.Anything).Return(nil)

	concreteCfgForContext := &config.Config{}
	globalCtx := &core.GlobalContext{Config: concreteCfgForContext, Logger: logger}

	engine, err := New(mockCfg, logger, store, worker, globalCtx)
	require.NoError(t, err)

	// Expect PersistData to be called because results were found before cancellation.
	// This assertion fails before Fix 3 is applied.
	store.On("PersistData", mock.Anything, mock.Anything).Return(nil).Twice()

	// -- Execution --
	ctx, cancel := context.WithCancel(context.Background())
	taskChan := make(chan schemas.Task, 2)
	engine.Start(ctx, taskChan)

	// Send tasks to get the workers busy.
	taskChan <- schemas.Task{TaskID: "task-1", TargetURL: "https://example.com"}
	taskChan <- schemas.Task{TaskID: "task-2", TargetURL: "https://example.com"}

	// Give workers a moment to start processing and add the finding.
	time.Sleep(100 * time.Millisecond)

	// Cancel the context and then try to stop the engine.
	cancel()
	engine.Stop() // This should return quickly because the workers respected the cancellation.

	// -- Assertions --
	// We assert that partial data IS persisted even during cancellation.
	store.AssertExpectations(t)
	worker.AssertExpectations(t)
}
