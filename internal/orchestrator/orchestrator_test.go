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
	mu            sync.Mutex
	startCalled   bool
	stopCalled    bool
	receivedTasks []schemas.Task // -- captures all tasks received --
	wg            sync.WaitGroup
}

func (m *mockTaskEngine) Start(ctx context.Context, taskChan <-chan schemas.Task) {
	m.mu.Lock()
	m.startCalled = true
	m.receivedTasks = []schemas.Task{}
	m.mu.Unlock()

	// -- a little goroutine to simulate task consumption --
	go func() {
		for task := range taskChan {
			m.mu.Lock()
			m.receivedTasks = append(m.receivedTasks, task)
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
	Logger *zap.Logger
	// REFACTOR: The fixture now holds the interface type.
	Config          config.Interface
	DiscoveryEngine *mockDiscoveryEngine
	TaskEngine      *mockTaskEngine
}

// setupTest creates a fresh fixture for each test to ensure isolation.
func setupTest(t *testing.T) *orchestratorTestFixture {
	t.Helper()
	return &orchestratorTestFixture{
		Logger: zap.NewNop(), // Use Nop logger for clean test output
		// REFACTOR: Use the default constructor for a properly initialized config.
		Config:          config.NewDefaultConfig(),
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

		// -- Set expectations for the number of tasks BEFORE starting --
		expectedTaskCount := 4 // 1 discovery + 3 orchestrator
		fixture.TaskEngine.wg.Add(expectedTaskCount)

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
		fixture.DiscoveryEngine.taskChan <- schemas.Task{TaskID: "task-discovery"}
		fixture.TaskEngine.wg.Wait() // Wait for all tasks to be processed

		// -- verify received tasks --
		fixture.TaskEngine.mu.Lock()
		assert.Len(t, fixture.TaskEngine.receivedTasks, expectedTaskCount, "Should have received all tasks")
		// -- check for a specific discovery task --
		foundDiscoveryTask := false
		for _, task := range fixture.TaskEngine.receivedTasks {
			if task.TaskID == "task-discovery" {
				foundDiscoveryTask = true
				break
			}
		}
		assert.True(t, foundDiscoveryTask, "Did not receive the discovery task")
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

	t.Run("should dispatch high-level tasks with correct non-nil parameters", func(t *testing.T) {
		t.Parallel()
		fixture := setupTest(t)
		// Enable the scanners that dispatch high-level tasks.
		cfg := fixture.Config.(*config.Config) // Cast to concrete type to modify
		cfg.ScannersCfg.Active.Auth.IDOR.Enabled = true
		cfg.ScannersCfg.Active.Auth.ATO.Enabled = true

		orch, _ := New(cfg, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Expect 3 high-level tasks (IDOR, ATO, Agent)
		fixture.TaskEngine.wg.Add(3)

		go func() {
			_ = orch.StartScan(ctx, []string{"https://example.com"}, "test-params-scan")
		}()

		// Wait for the 3 tasks to be dispatched and received.
		fixture.TaskEngine.wg.Wait()

		// Make a copy of the received tasks for safe concurrent access.
		fixture.TaskEngine.mu.Lock()
		receivedTasks := make([]schemas.Task, len(fixture.TaskEngine.receivedTasks))
		copy(receivedTasks, fixture.TaskEngine.receivedTasks)
		fixture.TaskEngine.mu.Unlock()

		// --- Assertions ---
		require.Len(t, receivedTasks, 3, "Expected exactly 3 high-level tasks to be dispatched")

		taskParamsByType := make(map[schemas.TaskType]interface{})
		for _, task := range receivedTasks {
			taskParamsByType[task.Type] = task.Parameters
		}

		// Check IDOR task
		idorParams, ok := taskParamsByType[schemas.TaskTestAuthIDOR]
		require.True(t, ok, "IDOR task was not dispatched")
		assert.NotNil(t, idorParams, "IDOR task parameters should not be nil")
		assert.IsType(t, schemas.IDORTaskParams{}, idorParams, "IDOR task parameters have incorrect type")

		// Check ATO task
		atoParams, ok := taskParamsByType[schemas.TaskTestAuthATO]
		require.True(t, ok, "ATO task was not dispatched")
		assert.NotNil(t, atoParams, "ATO task parameters should not be nil")
		assert.IsType(t, schemas.ATOTaskParams{}, atoParams, "ATO task parameters have incorrect type")

		// Check Agent Mission task
		agentParams, ok := taskParamsByType[schemas.TaskAgentMission]
		require.True(t, ok, "Agent Mission task was not dispatched")
		assert.NotNil(t, agentParams, "Agent Mission task parameters should not be nil")
		mission, ok := agentParams.(schemas.AgentMissionParams)
		require.True(t, ok, "Agent Mission task parameters have incorrect type")
		assert.NotEmpty(t, mission.MissionBrief, "Agent mission brief should not be empty")
	})
}
