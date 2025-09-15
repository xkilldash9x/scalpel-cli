// internal/orchestrator/orchestrator_test.go
package orchestrator

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// -- Mock Implementations for Testing --

// mockDiscoveryEngine is a mock for the DiscoveryEngine interface.
type mockDiscoveryEngine struct {
	mu           sync.Mutex
	startCalled  bool
	stopCalled   bool
	startTargets []string
	startError   error // -- allows us to simulate errors --
	taskChan     chan schemas.Task
}

func (m *mockDiscoveryEngine) Start(ctx context.Context, targets []string) (<-chan schemas.Task, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalled = true
	m.startTargets = targets
	if m.startError != nil {
		return nil, m.startError
	}
	m.taskChan = make(chan schemas.Task, 1) // Buffered to prevent blocking
	return m.taskChan, nil
}

func (m *mockDiscoveryEngine) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled = true
	if m.taskChan != nil {
		close(m.taskChan)
	}
}

// mockTaskEngine is a mock for the TaskEngine interface.
type mockTaskEngine struct {
	mu          sync.Mutex
	startCalled bool
	stopCalled  bool
	task        schemas.Task // -- captures the last task received --
	wg          sync.WaitGroup
}

func (m *mockTaskEngine) Start(ctx context.Context, taskChan <-chan schemas.Task) {
	m.mu.Lock()
	m.startCalled = true
	m.mu.Unlock()

	// -- a little goroutine to simulate task consumption --
	go func() {
		for task := range taskChan {
			m.mu.Lock()
			m.task = task
			m.mu.Unlock()
			m.wg.Done() // Signal that a task was received
		}
	}()
}

func (m *mockTaskEngine) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled = true
}

// -- Test Fixture Setup --

type orchestratorTestFixture struct {
	Logger          *zap.Logger
	Config          *config.Config
	DiscoveryEngine *mockDiscoveryEngine
	TaskEngine      *mockTaskEngine
}

// setupTest creates a fresh fixture for each test to ensure isolation.
func setupTest(t *testing.T) *orchestratorTestFixture {
	t.Helper()
	return &orchestratorTestFixture{
		Logger:          zap.NewNop(), // Use Nop logger for clean test output
		Config:          &config.Config{},
		DiscoveryEngine: &mockDiscoveryEngine{},
		TaskEngine:      &mockTaskEngine{},
	}
}

// -- Test Cases --

func TestNewOrchestrator(t *testing.T) {
	t.Parallel()
	fixture := setupTest(t)

	t.Run("should create orchestrator with valid dependencies", func(t *testing.T) {
		t.Parallel()
		orch, err := New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)
		require.NoError(t, err)
		assert.NotNil(t, orch)
	})

	t.Run("should return error with nil dependencies", func(t *testing.T) {
		t.Parallel()
		_, err := New(nil, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)
		assert.Error(t, err, "Should fail with nil config")

		_, err = New(fixture.Config, nil, fixture.DiscoveryEngine, fixture.TaskEngine)
		assert.Error(t, err, "Should fail with nil logger")

		_, err = New(fixture.Config, fixture.Logger, nil, fixture.TaskEngine)
		assert.Error(t, err, "Should fail with nil discovery engine")

		_, err = New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, nil)
		assert.Error(t, err, "Should fail with nil task engine")
	})
}

func TestOrchestrator_StartScan(t *testing.T) {

	t.Run("should correctly manage engine lifecycle", func(t *testing.T) {
		fixture := setupTest(t)
		orch, _ := New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)

		// -- use a context we can cancel to signal shutdown --
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		targets := []string{"https://example.com"}
		scanID := "test-scan-123"

		// -- the orchestrator runs in a goroutine so it doesn't block --
		go func() {
			err := orch.StartScan(ctx, targets, scanID)
			assert.NoError(t, err, "StartScan should not return an error on graceful shutdown")
		}()

		// -- a bit of a pause to let the engines start up --
		time.Sleep(100 * time.Millisecond)

		// -- assert that the engines were started correctly --
		fixture.DiscoveryEngine.mu.Lock()
		assert.True(t, fixture.DiscoveryEngine.startCalled, "DiscoveryEngine.Start should have been called")
		assert.Equal(t, targets, fixture.DiscoveryEngine.startTargets, "DiscoveryEngine started with wrong targets")
		fixture.DiscoveryEngine.mu.Unlock()

		fixture.TaskEngine.mu.Lock()
		assert.True(t, fixture.TaskEngine.startCalled, "TaskEngine.Start should have been called")
		fixture.TaskEngine.mu.Unlock()

		// -- simulate a discovered task --
		fixture.TaskEngine.wg.Add(1) // Expect one task
		fixture.DiscoveryEngine.taskChan <- schemas.Task{TaskID: "task-abc"}
		fixture.TaskEngine.wg.Wait() // Wait for the task engine to process it

		fixture.TaskEngine.mu.Lock()
		assert.Equal(t, "task-abc", fixture.TaskEngine.task.TaskID, "TaskEngine did not receive the correct task")
		fixture.TaskEngine.mu.Unlock()

		// -- signal shutdown and wait for it to complete --
		cancel()
		time.Sleep(600 * time.Millisecond) // Allow for shutdown sleep in orchestrator

		// -- assert that the engines were stopped --
		fixture.DiscoveryEngine.mu.Lock()
		assert.True(t, fixture.DiscoveryEngine.stopCalled, "DiscoveryEngine.Stop should have been called")
		fixture.DiscoveryEngine.mu.Unlock()

		fixture.TaskEngine.mu.Lock()
		assert.True(t, fixture.TaskEngine.stopCalled, "TaskEngine.Stop should have been called")
		fixture.TaskEngine.mu.Unlock()
	})

	t.Run("should return error if discovery engine fails to start", func(t *testing.T) {
		fixture := setupTest(t)
		// -- configure the mock to return an error --
		startErr := errors.New("discovery failed")
		fixture.DiscoveryEngine.startError = startErr

		orch, _ := New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)
		err := orch.StartScan(context.Background(), []string{"test"}, "scan-fail")

		require.Error(t, err)
		assert.ErrorIs(t, err, startErr, "Error from discovery engine should be propagated")

		// -- ensure other engines were not started or stopped --
		assert.False(t, fixture.TaskEngine.startCalled, "TaskEngine should not be started if discovery fails")
		assert.False(t, fixture.DiscoveryEngine.stopCalled, "DiscoveryEngine.Stop should not be called on start failure")
	})
}
