// internal/engine/engine_test.go
package engine

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Mock Implementations --

// mockWorker simulates the behavior of the MonolithicWorker.
type mockWorker struct {
	// A function that can be customized per test to simulate different outcomes.
	processFunc func(ctx context.Context, analysisCtx *core.AnalysisContext) error
}

func (m *mockWorker) ProcessTask(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	if m.processFunc != nil {
		return m.processFunc(ctx, analysisCtx)
	}
	// Default behavior: do nothing and succeed.
	return nil
}

// mockStore simulates the behavior of the store.Store service.
type mockStore struct {
	mu            sync.Mutex
	persistedData []*schemas.ResultEnvelope
	// A channel to signal when data has been persisted, for async testing.
	persisted chan struct{}
}

func newMockStore() *mockStore {
	return &mockStore{
		persistedData: make([]*schemas.ResultEnvelope, 0),
		persisted:     make(chan struct{}, 100), // Buffered channel
	}
}

func (m *mockStore) PersistData(ctx context.Context, data *schemas.ResultEnvelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.persistedData = append(m.persistedData, data)
	m.persisted <- struct{}{} // Signal that a result was received.
	return nil
}

func (m *mockStore) GetPersistedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.persistedData)
}

// mockBrowserManager is a minimal mock to satisfy the interface dependency.
type mockBrowserManager struct{}

func (m *mockBrowserManager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
) (schemas.SessionContext, error) {
	return nil, nil
}

func (m *mockBrowserManager) Shutdown(ctx context.Context) error {
	return nil
}

// mockKGClient is a minimal mock for the knowledge graph client dependency.
type mockKGClient struct{}

func (m *mockKGClient) AddNode(ctx context.Context, node schemas.Node) error { return nil }
func (m *mockKGClient) AddEdge(ctx context.Context, edge schemas.Edge) error { return nil }
func (m *mockKGClient) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	return schemas.Node{}, nil
}
func (m *mockKGClient) GetEdges(ctx context.Context, nodeID string) ([]schemas.Edge, error) {
	return nil, nil
}
func (m *mockKGClient) GetNeighbors(ctx context.Context, nodeID string) ([]schemas.Node, error) {
	return nil, nil
}

// -- Test Suite --

// TestTaskEngine_StartStop verifies the engine's core lifecycle: starting, processing tasks, and stopping gracefully.
func TestTaskEngine_StartStop(t *testing.T) {
	// -- Setup --
	cfg := &config.Config{
		Engine: config.EngineConfig{
			WorkerConcurrency:  2,
			DefaultTaskTimeout: 5 * time.Second,
		},
	}
	logger := zap.NewNop()
	store := newMockStore()

	// This mock worker will add a finding to each task it processes.
	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			analysisCtx.Findings = append(analysisCtx.Findings, schemas.Finding{ID: "finding-" + analysisCtx.Task.TaskID})
			return nil
		},
	}

	engine, err := New(cfg, logger, store, &mockBrowserManager{}, &mockKGClient{})
	require.NoError(t, err)

	// We need to replace the real worker with our mock.
	engine.worker = worker

	// -- Execution --
	taskChan := make(chan schemas.Task, 10)
	engine.Start(context.Background(), taskChan)

	numTasks := 3
	for i := 0; i < numTasks; i++ {
		taskChan <- schemas.Task{TaskID: fmt.Sprintf("task-%d", i), TargetURL: "https://example.com"}
	}
	close(taskChan) // Closing the channel signals the engine to shut down its workers.

	// Wait for the engine to stop gracefully.
	engine.Stop()

	// -- Assertions --
	assert.Equal(t, numTasks, store.GetPersistedCount(), "Should have persisted a result for each task")
}

// TestTaskEngine_WorkerError verifies that if a worker returns an error, the result is not persisted.
func TestTaskEngine_WorkerError(t *testing.T) {
	// -- Setup --
	cfg := &config.Config{Engine: config.EngineConfig{WorkerConcurrency: 1}}
	logger := zap.NewNop()
	store := newMockStore()
	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			// Simulate a processing error.
			return errors.New("worker failed spectacularly")
		},
	}

	engine, err := New(cfg, logger, store, &mockBrowserManager{}, &mockKGClient{})
	require.NoError(t, err)
	engine.worker = worker

	// -- Execution --
	taskChan := make(chan schemas.Task, 1)
	engine.Start(context.Background(), taskChan)

	taskChan <- schemas.Task{TaskID: "task-fail", TargetURL: "https://example.com"}
	close(taskChan)
	engine.Stop()

	// -- Assertions --
	assert.Equal(t, 0, store.GetPersistedCount(), "Should not persist results when worker fails")
}

// TestTaskEngine_NoResults verifies that no data is persisted if a task yields no findings or KG updates.
func TestTaskEngine_NoResults(t *testing.T) {
	// -- Setup --
	cfg := &config.Config{Engine: config.EngineConfig{WorkerConcurrency: 1}}
	logger := zap.NewNop()
	store := newMockStore()
	worker := &mockWorker{
		// Default processFunc returns success with no findings.
	}

	engine, err := New(cfg, logger, store, &mockBrowserManager{}, &mockKGClient{})
	require.NoError(t, err)
	engine.worker = worker

	// -- Execution --
	taskChan := make(chan schemas.Task, 1)
	engine.Start(context.Background(), taskChan)

	taskChan <- schemas.Task{TaskID: "task-no-findings", TargetURL: "https://example.com"}
	close(taskChan)
	engine.Stop()

	// -- Assertions --
	assert.Equal(t, 0, store.GetPersistedCount(), "Should not persist data when there are no results")
}

// TestTaskEngine_ContextCancellation ensures workers shut down when the main context is cancelled.
func TestTaskEngine_ContextCancellation(t *testing.T) {
	// -- Setup --
	cfg := &config.Config{Engine: config.EngineConfig{WorkerConcurrency: 2}}
	logger := zap.NewNop()
	store := newMockStore()

	// This worker will block until its context is cancelled.
	worker := &mockWorker{
		processFunc: func(ctx context.Context, analysisCtx *core.AnalysisContext) error {
			<-ctx.Done() // Wait for cancellation
			return ctx.Err()
		},
	}

	engine, err := New(cfg, logger, store, &mockBrowserManager{}, &mockKGClient{})
	require.NoError(t, err)
	engine.worker = worker

	// -- Execution --
	ctx, cancel := context.WithCancel(context.Background())
	taskChan := make(chan schemas.Task, 2)
	engine.Start(ctx, taskChan)

	// Send tasks to get the workers busy.
	taskChan <- schemas.Task{TaskID: "task-1", TargetURL: "https://example.com"}
	taskChan <- schemas.Task{TaskID: "task-2", TargetURL: "https://example.com"}

	// Give workers a moment to start processing.
	time.Sleep(100 * time.Millisecond)

	// Cancel the context and then try to stop the engine.
	cancel()
	engine.Stop() // This should return quickly because the workers respected the cancellation.

	// -- Assertions --
	// The main assertion is that the Stop() call completes without a timeout.
	// We also expect no data to be persisted because the tasks were cancelled.
	assert.Equal(t, 0, store.GetPersistedCount(), "No results should be persisted on context cancellation")
}
