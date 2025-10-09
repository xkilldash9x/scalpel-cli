package analyst_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/analyst"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
)

// SetupTestEnvironment handles the dependency on finding the project root by creating a temporary environment.
func SetupTestEnvironment(t *testing.T) func() {
	tempDir := t.TempDir()
	// Create a dummy go.mod so determineProjectRoot() succeeds.
	err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module test\n"), 0644)
	require.NoError(t, err)

	// Change CWD to the temporary directory.
	originalWD, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(tempDir)
	require.NoError(t, err)

	return func() {
		os.Chdir(originalWD)
	}
}

// TestAnalyst_GracefulShutdownUnderLoad verifies Strategy 2.2 and Strategy 1.1.
func TestAnalyst_GracefulShutdownUnderLoad(t *testing.T) {
	// Strategy 1.1: Goroutine Leak Detection for the entire stack.
	defer goleak.VerifyNone(t)

	cleanup := SetupTestEnvironment(t)
	defer cleanup()

	logger := zaptest.NewLogger(t)
	mockLLM := new(mocks.MockLLMClient)
	mockKG := new(mocks.MockKGClient)

	// Setup: We want the OODA loop "stuck" mid-process (e.g., Synthesizer waiting for LLM).
	// Create the master context.
	masterCtx, cancelMaster := context.WithCancel(context.Background())

	// Configure mocks: KG proceeds, LLM blocks until context is cancelled.
	mockKG.On("QueryImprovementHistory", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)

	// Mock Chronicler calls (using AddNode based on Chronicler implementation).
	// Use .Maybe() as these might not be called if the process is cancelled early.
	mockKG.On("AddNode", mock.Anything, mock.Anything).Return(nil).Maybe()

	// This simulates the long running operation (Strategy 2.2: loaded state).
	// FIX: Ensure the mock respects the specific context passed to Generate.
	mockLLM.On("Generate", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			// The context passed here is derived from masterCtx.
			ctx := args.Get(0).(context.Context)
			<-ctx.Done() // Block until the specific context passed to Generate is cancelled
		}).
		Return("", context.Canceled)

	// Initialize and Start the Analyst.
	a, err := analyst.NewImprovementAnalyst(logger, &config.Config{}, mockLLM, mockKG)
	require.NoError(t, err)

	runErrorChan := make(chan error)
	go func() {
		runErrorChan <- a.Run(masterCtx, "Test objective under load", []string{})
	}()

	// Wait for the system to start and reach the blocked state.
	// Default synthesizer settle time is 500ms.
	time.Sleep(750 * time.Millisecond)

	// Strategy 2.2: Cancel the master context (simulate SIGTERM) while under load.
	cancelMaster()

	// Verification: Assert prompt and graceful return.
	select {
	case err := <-runErrorChan:
		// Strategy 1.2: Must return context.Canceled.
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second): // Increased timeout for race detector overhead
		t.Fatal("Analyst Run did not return promptly after cancellation under load. Potential deadlock during shutdown.")
	}

	// goleak check ensures all components (Observer, Decider, etc.) terminated.
}

// TestAnalyst_RobustTimeoutPattern verifies Strategy 3.1.
func TestAnalyst_RobustTimeoutPattern(t *testing.T) {
	// Add leak detection to ensure graceful shutdown even on timeout.
	defer goleak.VerifyNone(t)

	// Strategy 3.1 / R4 FIX: Implement the t.Deadline() pattern, but also enforce a short test duration.
	// The previous implementation relied solely on the external -timeout flag.
	// If run without -timeout, the test would take 10 minutes (the default go test timeout).
	testCtx := context.Background()

	// Define the maximum duration for this specific test. Increased slightly for race detector.
	const maxTestDuration = 8 * time.Second

	// Calculate the desired deadline.
	desiredDeadline := time.Now().Add(maxTestDuration)

	// Check if the global test runner deadline (t.Deadline()) is sooner.
	if globalDeadline, ok := t.Deadline(); ok && globalDeadline.Before(desiredDeadline) {
		// If the global deadline is sooner, respect it and add a small buffer for cleanup.
		desiredDeadline = globalDeadline.Add(-500 * time.Millisecond)
	}

	var cancel context.CancelFunc
	testCtx, cancel = context.WithDeadline(testCtx, desiredDeadline)
	// Use t.Cleanup instead of defer for better lifecycle management in tests.
	t.Cleanup(cancel)

	cleanup := SetupTestEnvironment(t)
	defer cleanup()

	logger := zaptest.NewLogger(t)
	mockLLM := new(mocks.MockLLMClient)
	mockKG := new(mocks.MockKGClient)

	// Configure mocks: LLM takes longer than the testCtx allows.
	mockKG.On("QueryImprovementHistory", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	// Mock Chronicler calls (using AddNode).
	mockKG.On("AddNode", mock.Anything, mock.Anything).Return(nil).Maybe()

	// The LLM respects the context passed to it, which is derived from testCtx.
	// FIX: Ensure the mock respects the specific context passed to Generate.
	mockLLM.On("Generate", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			ctx := args.Get(0).(context.Context)
			<-ctx.Done() // Block until the specific context passed to Generate is cancelled (by the timeout)
		}).
		Return("", context.Canceled) // Return Canceled as the Generate implementation wraps the specific context error.
	a, err := analyst.NewImprovementAnalyst(logger, &config.Config{}, mockLLM, mockKG)
	require.NoError(t, err)

	// R5 FIX: Run the analyst in a separate goroutine to avoid potential deadlocks
	// involving testing.T synchronization during logging when the main test goroutine is blocked.
	runErrorChan := make(chan error, 1)
	go func() {
		runErrorChan <- a.Run(testCtx, "Test timeout behavior", []string{})
	}()

	// Wait for completion or timeout.
	select {
	case err = <-runErrorChan:
		// Proceed to assertions.
	case <-time.After(maxTestDuration + 5*time.Second): // Timeout slightly longer than the context timeout
		t.Fatal("Analyst Run did not return promptly after context timeout. Potential deadlock.")
	}

	// Strategy 3.1 Benefit: Precise assertion that the application code returned the specific context error.
	if testCtx.Err() == context.DeadlineExceeded {
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	} else if testCtx.Err() == context.Canceled {
		assert.ErrorIs(t, err, context.Canceled)
	} else if err != nil {
		t.Errorf("Expected context error (DeadlineExceeded or Canceled), but got: %v", err)
	} else {
		t.Errorf("Expected context error, but got nil")
	}
}
