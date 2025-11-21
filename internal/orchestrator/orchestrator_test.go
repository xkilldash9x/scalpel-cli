// internal/orchestrator/orchestrator_test.go
package orchestrator

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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
	closed       bool // Fix 4: Tracks if taskChan is closed
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
	// Initialize if not already set by a specific test (e.g., for deadlock testing)
	if m.taskChan == nil {
		m.taskChan = make(chan schemas.Task, 1) // Buffered to prevent blocking
	}
	m.closed = false
	return m.taskChan, nil
}

func (m *mockDiscoveryEngine) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalled = true
	// Fix 4: Prevent panic if Stop is called multiple times.
	if m.taskChan != nil && !m.closed {
		close(m.taskChan)
		m.closed = true
	}
}

// mockTaskEngine is a mock for the TaskEngine interface.
type mockTaskEngine struct {
	mu             sync.Mutex
	startCalled    bool
	stopCalled     bool
	receivedTasks  []schemas.Task // -- captures all tasks received --
	wg             sync.WaitGroup
	consume        bool         // Control whether the engine consumes tasks (for deadlock testing)
	tasksRemaining atomic.Int32 // Fix 5: Atomic counter for safe WaitGroup handling.
}

// ExpectTasks sets the number of tasks the mock should wait for.
func (m *mockTaskEngine) ExpectTasks(count int) {
	m.wg.Add(count)
	m.tasksRemaining.Store(int32(count))
}

// WaitForTasks waits until the expected number of tasks have been received.
func (m *mockTaskEngine) WaitForTasks(t *testing.T, timeout time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(timeout):
		t.Fatal("Timeout waiting for TaskEngine to process tasks")
	}
}

func (m *mockTaskEngine) Start(ctx context.Context, taskChan <-chan schemas.Task) {
	m.mu.Lock()
	m.startCalled = true
	m.receivedTasks = []schemas.Task{}

	// If consume is false, we return without starting the consumer goroutine.
	if !m.consume {
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()

	// -- a little goroutine to simulate task consumption --
	go func() {
		for task := range taskChan {
			m.mu.Lock()
			m.receivedTasks = append(m.receivedTasks, task)
			m.mu.Unlock()

			// Fix 5: Safely decrement WaitGroup using atomic CAS loop.
			for {
				remaining := m.tasksRemaining.Load()
				if remaining <= 0 {
					// No more tasks expected, do not call wg.Done().
					break
				}
				// Attempt to decrement the counter atomically.
				if m.tasksRemaining.CompareAndSwap(remaining, remaining-1) {
					// Successfully decremented, now call wg.Done().
					m.wg.Done()
					break
				}
				// CAS failed (due to concurrency), loop again to retry.
			}
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
	// Initialize default config and enable relevant scanners for comprehensive testing
	cfg := config.NewDefaultConfig()
	cfg.ScannersCfg.Active.Auth.IDOR.Enabled = true
	cfg.ScannersCfg.Active.Auth.ATO.Enabled = true

	return &orchestratorTestFixture{
		Logger:          zap.NewNop(), // Use Nop logger for clean test output
		Config:          cfg,
		DiscoveryEngine: &mockDiscoveryEngine{},
		TaskEngine:      &mockTaskEngine{consume: true}, // Default behavior
	}
}

// -- Test Cases --

// Verification for Fix 4
func TestMockDiscoveryEngine_DoubleStop(t *testing.T) {
	t.Parallel()
	mock := &mockDiscoveryEngine{}
	_, _ = mock.Start(context.Background(), []string{"test"})
	assert.NotPanics(t, func() {
		mock.Stop()
		mock.Stop()
	})
}

// Verification for Fix 5
func TestMockTaskEngine_ExtraTasks(t *testing.T) {
	t.Parallel()
	mock := &mockTaskEngine{consume: true}
	taskChan := make(chan schemas.Task, 5)

	mock.ExpectTasks(2)
	mock.Start(context.Background(), taskChan)

	// Send more tasks than expected
	assert.NotPanics(t, func() {
		taskChan <- schemas.Task{TaskID: "task-1"}
		taskChan <- schemas.Task{TaskID: "task-2"}
		taskChan <- schemas.Task{TaskID: "task-3"} // Extra task
	})

	// Wait should return when 2 tasks are processed
	mock.WaitForTasks(t, 1*time.Second)

	// Ensure processing continues and doesn't panic on the extra task
	time.Sleep(50 * time.Millisecond)

	mock.mu.Lock()
	defer mock.mu.Unlock()
	assert.Len(t, mock.receivedTasks, 3)
	assert.Equal(t, int32(0), mock.tasksRemaining.Load())
}

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

	// Verification for Fix 1
	t.Run("should return error immediately if targets list is empty", func(t *testing.T) {
		fixture := setupTest(t)
		// Scanners relying on targets[0] are enabled in setupTest
		orch, _ := New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)

		// Call StartScan with an empty slice
		err := orch.StartScan(context.Background(), []string{}, "scan-empty")

		// Assert that an error is returned
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty target list")

		// Assert that engines were not started
		assert.False(t, fixture.DiscoveryEngine.startCalled, "DiscoveryEngine should not be started with empty targets")
		assert.False(t, fixture.TaskEngine.startCalled, "TaskEngine should not be started with empty targets")
	})

	// Verification for Fix 3
	t.Run("should not deadlock if context is cancelled while dispatching tasks", func(t *testing.T) {
		// This test specifically targets the potential deadlock when the task channel is full/unconsumed.
		fixture := setupTest(t)
		// Configure the TaskEngine mock to NOT consume tasks, simulating a stalled engine.
		fixture.TaskEngine.consume = false

		// Ensure high-level tasks are enabled (done in setupTest) so the orchestrator tries to send them.

		orch, _ := New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)

		ctx, cancel := context.WithCancel(context.Background())
		targets := []string{"https://example.com"}
		scanID := "test-deadlock"

		scanDone := make(chan struct{})

		go func() {
			// StartScan should return because the sends are context-aware.
			err := orch.StartScan(ctx, targets, scanID)
			assert.NoError(t, err, "StartScan should handle cancellation gracefully even if stalled")
			close(scanDone)
		}()

		// Allow the orchestrator time to start up and attempt to dispatch the first task.
		time.Sleep(100 * time.Millisecond)

		// Cancel the context. This should interrupt the blocked send operation.
		cancel()

		// Wait for StartScan to complete or the test to time out.
		select {
		case <-scanDone:
			// Success: StartScan returned gracefully.
		case <-time.After(2 * time.Second):
			t.Fatal("Test timed out: StartScan likely deadlocked during shutdown.")
		}
	})

	t.Run("should correctly manage engine lifecycle", func(t *testing.T) {
		fixture := setupTest(t)
		// Scanners are enabled in setupTest
		orch, _ := New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)

		// -- use a context we can cancel to signal shutdown --
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// -- Set expectations for the number of tasks BEFORE starting --
		// 1 discovery + 3 orchestrator (IDOR, ATO, Agent Mission)
		expectedTaskCount := 4
		fixture.TaskEngine.ExpectTasks(expectedTaskCount)

		targets := []string{"https://example.com"}
		scanID := "test-scan-123"

		// -- the orchestrator runs in a goroutine so it doesn't block --
		// Use a wait group to ensure the goroutine finishes before final assertions
		var scanWg sync.WaitGroup
		scanWg.Add(1)
		go func() {
			defer scanWg.Done()
			err := orch.StartScan(ctx, targets, scanID)
			// The implementation specifically handles context cancellation and returns nil.
			assert.NoError(t, err, "StartScan should not return an error on graceful shutdown")
		}()

		// -- a bit of a pause to let the engines start up --
		time.Sleep(100 * time.Millisecond)

		// -- assert that the engines were started correctly --
		fixture.DiscoveryEngine.mu.Lock()
		assert.True(t, fixture.DiscoveryEngine.startCalled, "DiscoveryEngine.Start should have been called")
		discoveryChan := fixture.DiscoveryEngine.taskChan
		fixture.DiscoveryEngine.mu.Unlock()

		// FIX: Acquire the lock before reading TaskEngine state
		fixture.TaskEngine.mu.Lock()
		assert.True(t, fixture.TaskEngine.startCalled, "TaskEngine.Start should have been called")
		fixture.TaskEngine.mu.Unlock()

		// -- simulate a discovered task --
		if discoveryChan == nil {
			t.Fatal("Discovery channel is nil")
		}
		// Add TargetURL to the discovery task for consistency check
		discoveryChan <- schemas.Task{TaskID: "task-discovery", TargetURL: "https://example.com/discovered"}

		// Wait for all tasks to be processed by the TaskEngine
		fixture.TaskEngine.WaitForTasks(t, 2*time.Second)

		// -- verify received tasks --
		fixture.TaskEngine.mu.Lock()
		assert.Len(t, fixture.TaskEngine.receivedTasks, expectedTaskCount, "Should have received all tasks")

		// Verification for Fix 2: Ensure all tasks (including Agent Mission) have TargetURL
		for _, task := range fixture.TaskEngine.receivedTasks {
			assert.NotEmpty(t, task.TargetURL, "Task %s (%s) should have a TargetURL", task.TaskID, task.Type)
		}
		fixture.TaskEngine.mu.Unlock()

		// -- signal shutdown and wait for it to complete --
		cancel()

		// Wait for the StartScan goroutine to finish.
		scanDone := make(chan struct{})
		go func() {
			scanWg.Wait()
			close(scanDone)
		}()

		select {
		case <-scanDone:
			// StartScan finished
		case <-time.After(2 * time.Second): // Includes the 500ms sleep in orchestrator
			t.Fatal("Timeout waiting for StartScan to finish after context cancellation")
		}

		// -- assert that the engines were stopped --
		assert.True(t, fixture.DiscoveryEngine.stopCalled, "DiscoveryEngine.Stop should have been called")
		assert.True(t, fixture.TaskEngine.stopCalled, "TaskEngine.Stop should have been called")
	})

	t.Run("should return error if discovery engine fails to start", func(t *testing.T) {
		fixture := setupTest(t)
		// -- configure the mock to return an error --
		startErr := errors.New("discovery failed")
		fixture.DiscoveryEngine.startError = startErr

		orch, _ := New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)
		// We must provide a target due to Fix 1.
		err := orch.StartScan(context.Background(), []string{"test"}, "scan-fail")

		require.Error(t, err)
		assert.ErrorIs(t, err, startErr, "Error from discovery engine should be propagated")

		// -- ensure other engines were not started or stopped --
		assert.False(t, fixture.TaskEngine.startCalled, "TaskEngine should not be started if discovery fails")
		assert.False(t, fixture.DiscoveryEngine.stopCalled, "DiscoveryEngine.Stop should not be called on start failure")
	})

	// Simplified version of the parameters test, focusing on verification of fixes 1 & 2.
	t.Run("should dispatch high-level tasks with correct parameters and TargetURL", func(t *testing.T) {
		fixture := setupTest(t)
		// Scanners are already enabled in setupTest

		orch, _ := New(fixture.Config, fixture.Logger, fixture.DiscoveryEngine, fixture.TaskEngine)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		// Expect 3 high-level tasks (IDOR, ATO, Agent)
		fixture.TaskEngine.ExpectTasks(3)
		targetURL := "https://example.com"

		go func() {
			_ = orch.StartScan(ctx, []string{targetURL}, "test-params-scan")
		}()

		// Wait for the 3 tasks to be dispatched and received.
		fixture.TaskEngine.WaitForTasks(t, 1*time.Second)

		// Make a copy of the received tasks for safe access.
		fixture.TaskEngine.mu.Lock()
		receivedTasks := make([]schemas.Task, len(fixture.TaskEngine.receivedTasks))
		copy(receivedTasks, fixture.TaskEngine.receivedTasks)
		fixture.TaskEngine.mu.Unlock()

		// --- Assertions ---
		require.Len(t, receivedTasks, 3, "Expected exactly 3 high-level tasks to be dispatched")

		for _, task := range receivedTasks {
			assert.Equal(t, targetURL, task.TargetURL, "TargetURL should match primary target for task type %s", task.Type)
			assert.NotNil(t, task.Parameters, "Parameters should not be nil for task type %s", task.Type)
		}
	})
}
