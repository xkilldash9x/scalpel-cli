// File: cmd/scalpel/main_test.go
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Setup Helpers ---

// resetMocks restores the original function implementations.
func resetMocks() {
	osWriteFile = os.WriteFile
	osExecutable = os.Executable
	execCommandContext = exec.CommandContext
	triggerSelfHeal = triggerMetalyst
	// FIX: Update the reset value to match the new default (5 minutes).
	selfHealTimeout = 5 * time.Minute
	osExit = os.Exit
}

// ... (TestIsValidationMode and TestHandlePanic remain the same) ...

// --- 1. Unit Testing: triggerMetalyst() ---
// Uses the TestHelperProcess technique to mock exec.Command.

func TestTriggerMetalyst(t *testing.T) {
	originalArgs := os.Args
	testExecutable := os.Args[0]
	defer func() {
		os.Args = originalArgs
		resetMocks()
	}()

	// Helper to create the mock exec.CommandContext
	mockExecCommandContext := func(expectedArgs []string, exitCode int, hang bool) func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return func(ctx context.Context, name string, args ...string) *exec.Cmd {
			cs := []string{"-test.run=TestHelperProcess", "--"}
			cs = append(cs, args...)
			// Use CommandContext so the OS respects the context deadline.
			cmd := exec.CommandContext(ctx, testExecutable, cs...)
			cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
			cmd.Env = append(cmd.Env, fmt.Sprintf("EXPECTED_ARGS=%s", strings.Join(expectedArgs, "|")))
			cmd.Env = append(cmd.Env, fmt.Sprintf("HELPER_EXIT_CODE=%d", exitCode))
			if hang {
				cmd.Env = append(cmd.Env, "HELPER_HANG=1")
			}
			return cmd
		}
	}

	// Test Case 1 (Correct Command Construction)
	t.Run("Correct Command Construction", func(t *testing.T) {
		resetMocks()
		os.Args = []string{"./scalpel", "scan", "-d", "5", "target.com"}
		fakePath := "/usr/bin/scalpel"

		osExecutable = func() (string, error) {
			return fakePath, nil
		}

		expectedArgs := []string{
			"self-heal",
			fmt.Sprintf("--panic-log=%s", panicLogFile),
			// Ensure comma-separated original-args are formatted properly.
			"--original-args=scan,-d,5,target.com",
		}

		execCommandContext = mockExecCommandContext(expectedArgs, 0, false)

		// Execute
		err := triggerMetalyst()

		// Assertion (verification happens in TestHelperProcess)
		assert.NoError(t, err)
	})

	// Test Case 2 (Sub-process Failure)
	t.Run("Sub-process Failure", func(t *testing.T) {
		resetMocks()
		os.Args = []string{"./scalpel"}
		osExecutable = func() (string, error) { return "/bin/scalpel", nil }

		// Mock command to return exit code 1.
		execCommandContext = mockExecCommandContext([]string{}, 1, false)

		err := triggerMetalyst()
		// FIX: Use require.Error to halt the test on failure and prevent the nil-pointer panic.
		require.Error(t, err)
		assert.Contains(t, err.Error(), "self-heal command execution failed")
	})

	// 4. Auditing for Context: Context Propagation (Cancellation Test)
	t.Run("Context Timeout Respected (Cancellation)", func(t *testing.T) {
		resetMocks()
		os.Args = []string{"./scalpel"}
		osExecutable = func() (string, error) { return "/bin/scalpel", nil }

		// Set a very short timeout
		selfHealTimeout = 100 * time.Millisecond

		// Mock exec.CommandContext to simulate a long-running process (hang=true).
		execCommandContext = mockExecCommandContext([]string{}, 0, true)

		startTime := time.Now()
		err := triggerMetalyst()
		duration := time.Since(startTime)

		// Assertions: The function must return an error related to the timeout/kill.
		// FIX: Use require.Error to ensure an error was returned before checking its content.
		require.Error(t, err)

		// The exact error depends on the OS ("signal: killed" or "context deadline exceeded").
		isTimeoutError := strings.Contains(err.Error(), "killed") || strings.Contains(err.Error(), "context deadline exceeded")
		assert.True(t, isTimeoutError, "Expected error related to 'killed' or 'context deadline exceeded', got: %v", err)

		// Ensure it didn't run significantly longer than the timeout.
		assert.Less(t, duration, 1*time.Second, "Test took too long (%v), suggesting the context timeout was not respected.", duration)
	})
}

// TestHelperProcess is used by TestTriggerMetalyst to mock the execution of a sub-process.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	// Simulate hanging process for context timeout tests
	if os.Getenv("HELPER_HANG") == "1" {
		time.Sleep(5 * time.Second) // Sleep longer than the test's timeout
		os.Exit(0)                  // Should not be reached if context works.
	}

	// Get desired exit code
	exitCodeStr := os.Getenv("HELPER_EXIT_CODE")
	var exitCode int
	fmt.Sscanf(exitCodeStr, "%d", &exitCode)

	// Verify arguments (for Command Construction test)
	args := os.Args
	for len(args) > 0 {
		if args[0] == "--" {
			args = args[1:]
			break
		}
		args = args[1:]
	}

	expectedArgsStr := os.Getenv("EXPECTED_ARGS")
	// Only verify args if success (exitCode 0) is expected and args were provided.
	if expectedArgsStr != "" && exitCode == 0 {
		expectedArgs := strings.Split(expectedArgsStr, "|")

		if len(args) != len(expectedArgs) {
			fmt.Fprintf(os.Stderr, "Argument count mismatch: got %d, want %d\n", len(args), len(expectedArgs))
			os.Exit(1) // Fail the helper process if args mismatch
		}

		for i, arg := range args {
			if arg != expectedArgs[i] {
				fmt.Fprintf(os.Stderr, "Argument mismatch at index %d: got '%s', want '%s'\n", i, arg, expectedArgs[i])
				os.Exit(1) // Fail the helper process if args mismatch
			}
		}
	}

	// FIX: The Go test runner can swallow exit codes. To reliably signal failure,
	// print an error and then exit. This ensures the parent process sees a failure.
	if exitCode != 0 {
		fmt.Fprintf(os.Stderr, "Simulating command failure with exit code %d\n", exitCode)
	}
	os.Exit(exitCode)
}
