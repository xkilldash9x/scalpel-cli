// File: cmd/scalpel/main.go
/*
Copyright © 2025 Kyle McAllister (xkilldash9x@proton.me)
*/

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/xkilldash9x/scalpel-cli/cmd"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

const panicLogFile = "panic.log"

const asciiArt = `
    /\
   /  \		   "Precision is the difference 
  / /\ \       between a butcher and surgeon."
 / /  \ \
 \ \__/ / 	        [ scalpel-cli v0.1.0  ]
  \____/	 	+---------------------+
   |  |		 	| 07 Analysis Modules |
   |  |		 	| 39 Payload Exploits |
			+---------------------+

`

// Define function variables for dependency injection/mocking in tests.
var (
	osWriteFile        = os.WriteFile
	osExecutable       = os.Executable
	execCommandContext = exec.CommandContext
	// Allows mocking os.Exit in tests.
	osExit = os.Exit
	// Allows overriding the timeout in tests.
	// FIX: Reduced default timeout from 30m to 5m for better responsiveness if self-heal fails.
	selfHealTimeout = 5 * time.Minute
	// Allows mocking the trigger function within handlePanic for isolation.
	triggerSelfHeal = triggerMetalyst
)

// main is the entry point of the application.
func main() {
	// Step 1.1: The Sentinel - Global Panic Handler
	defer handlePanic()

	// Set up a context that listens for interrupt signals (SIGINT, SIGTERM) for graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// If arguments are passed, execute the command directly and exit.
	if len(os.Args) > 1 {
		if err := cmd.Execute(ctx); err != nil {
			// Check if the error is context.Canceled (e.g., graceful shutdown during scan initiated by Ctrl+C)
			// cmd.Execute handles the logging, we just handle the exit code.
			if errors.Is(err, context.Canceled) {
				osExit(0) // Exit cleanly on graceful shutdown
			} else {
				osExit(1) // Exit with error code on failure
			}
		}
		return
	}

	// -- Interactive Mode --
	fmt.Print(asciiArt)
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("scalpel-cli > ")
		if !scanner.Scan() {
			break // Exit on EOF (Ctrl+D)
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" {
			break
		}

		// Execute the command entered in the interactive session
		executeInteractiveCommand(ctx, line)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
		osExit(1)
	}

	fmt.Println("Exiting scalpel-cli.")
}

// executeInteractiveCommand parses and runs the command from the interactive shell.
func executeInteractiveCommand(ctx context.Context, line string) {
	// Create a new, clean command instance for each execution.
	// This is critical for ensuring flags from one command don't leak into the next.
	rootCmd := cmd.NewRootCommand()

	args := strings.Fields(line)
	rootCmd.SetArgs(args)

	// Execute the command, capturing panics to avoid crashing the interactive session.
	func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "Error: Command panicked: %v\n", r)
				// Optionally print stack trace for debugging
				// debug.PrintStack()
			}
		}()
		if err := rootCmd.ExecuteContext(ctx); err != nil {
			// In interactive mode, we print the error but do not exit the shell.
			// Errors logged by cmd.Execute (including context.Canceled) are sufficient.
			// If we wanted cleaner output for Ctrl+C during an interactive scan:
			// if errors.Is(err, context.Canceled) {
			// 	 fmt.Fprintln(os.Stderr, "\nCommand aborted.")
			// }
		}
	}()
}

// handlePanic is the implementation of the Sentinel for non-interactive mode.
func handlePanic() {
	if r := recover(); r != nil {
		// Panic occurred.

		// Ensure logs are flushed before proceeding.
		observability.Sync()

		// Check if we are running in validation mode
		if isValidationMode() {
			// If a panic occurs during validation, we must not intercept it.
			fmt.Fprintf(os.Stderr, "[VALIDATION MODE] Panic detected during validation run. Aborting.\n")
			// Re-panic so the process exits with a non-zero status code.
			panic(r)
		}

		stackTrace := debug.Stack()
		panicMessage := fmt.Sprintf("panic: %v\n\n%s", r, stackTrace)

		// Log the panic to the dedicated file. (Use injected variable)
		if err := osWriteFile(panicLogFile, []byte(panicMessage), 0644); err != nil {
			// If logging fails, print to stderr as a fallback.
			fmt.Fprintf(os.Stderr, "CRITICAL: Failed to write panic log: %v\n", err)
			fmt.Fprintf(os.Stderr, "Panic details:\n%s\n", panicMessage)
			osExit(1)
			return // Return facilitates testing when osExit is mocked.
		}

		fmt.Fprintf(os.Stderr, "\n----------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "CRASH DETECTED. Initiating autonomous self-healing process (Metalyst).\n")
		fmt.Fprintf(os.Stderr, "Details logged to %s\n", panicLogFile)
		fmt.Fprintf(os.Stderr, "----------------------------------------------------------------\n\n")

		// Trigger the Metalyst (Step 1.1 Output). (Use injected variable)
		if err := triggerSelfHeal(); err != nil {
			fmt.Fprintf(os.Stderr, "CRITICAL: Self-healing process failed to start or complete: %v\n", err)
			osExit(1)
			return
		}

		// If triggerMetalyst returns successfully, the self-healing process has completed successfully.
		fmt.Fprintf(os.Stderr, "\n----------------------------------------------------------------\n")
		fmt.Fprintf(os.Stderr, "Self-healing process completed. Please review the changes and restart the command if necessary.\n")
		fmt.Fprintf(os.Stderr, "----------------------------------------------------------------\n")
		osExit(0)
	}
}

// isValidationMode checks if the --validate-fix flag is present.
func isValidationMode() bool {
	// This check must be fast and reliable within the panic handler.
	for _, arg := range os.Args {
		if arg == "--validate-fix" {
			return true
		}
	}
	return false
}

// triggerMetalyst re-executes the binary with the 'self-heal' command.
func triggerMetalyst() error {
	// Find the path to the currently running executable. (Use injected variable)
	executable, err := osExecutable()
	if err != nil {
		return fmt.Errorf("failed to find executable path: %w", err)
	}

	// Get the original arguments (excluding the executable name itself)
	originalArgs := os.Args[1:]

	// Construct the arguments for the self-heal command
	args := []string{
		"self-heal",
		fmt.Sprintf("--panic-log=%s", panicLogFile),
		// Pass the original arguments using the StringSliceVar format (comma-separated) for robustness.
		fmt.Sprintf("--original-args=%s", strings.Join(originalArgs, ",")),
	}

	// Execute the self-heal command with the configurable timeout.
	// Use context.Background() as the parent to ensure the self-heal process isn't tied to the potentially canceling main context.
	ctx, cancel := context.WithTimeout(context.Background(), selfHealTimeout)
	defer cancel()

	// Use injected variable.
	cmd := execCommandContext(ctx, executable, args...)
	// Inherit stdio, and working directory. The environment is inherited automatically.
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		// This captures failures in the self-heal process itself.
		return fmt.Errorf("self-heal command execution failed: %w", err)
	}

	return nil
}
