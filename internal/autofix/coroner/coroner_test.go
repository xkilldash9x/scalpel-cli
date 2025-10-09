// internal/autofix/coroner/coroner_test.go
package coroner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Sample panic logs for testing

const (
	// Standard application panic (e.g., nil pointer dereference)
	panicStandard = `panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation]

goroutine 1 [running]:
github.com/xkilldash9x/scalpel-cli/internal/config.Initialize(0x0)
	/Users/testuser/go/src/github.com/xkilldash9x/scalpel-cli/internal/config/config.go:55 +0x1a
main.main()
	/Users/testuser/go/src/github.com/xkilldash9x/scalpel-cli/cmd/scalpel/main.go:25 +0x27
`

	// Panic occurring deeper in the stack, requiring filtering of stdlib and runtime frames.
	panicDeepStack = `panic: index out of range [10] with length 5

goroutine 5 [running]:
net/http.(*conn).serve.func1(0xc000168000)
	/usr/local/go/src/net/http/server.go:1850 +0x139
panic(0x1333c80, 0x1641930)
	/usr/local/go/src/runtime/panic.go:1047 +0x266
github.com/xkilldash9x/scalpel-cli/internal/analyzer.(*Analyzer).processFile(0xc000144180, {0x13e1940, 0xc000162000})
	/app/src/internal/analyzer/analyzer.go:150 +0x5a5
github.com/xkilldash9x/scalpel-cli/internal/analyzer.(*Analyzer).Analyze.func1(0xc000144180, {0x13e1940, 0xc000162000})
	/app/src/internal/analyzer/analyzer.go:80 +0x65
`

	// Panic originating from the Go runtime only (should fail to find application location).
	panicRuntimeOnly = `panic: synchronization error

goroutine 1 [running]:
runtime.throw(0x134f4f5, 0x14)
	/usr/local/go/src/runtime/panic.go:1198 +0x71
runtime.unlock(0x0)
	/usr/local/go/src/runtime/mutex.go:83 +0x2a
`
	// Panic that includes the Sentinel's recovery function itself (main.main.func1), which must be filtered.
	panicInRecoveryHandler = `panic: something went wrong during recovery setup

goroutine 1 [running]:
main.main.func1(0xc00007cf18)
	/app/cmd/scalpel/main.go:45 +0x152 // This is the recovery handler
panic(0x1333c80, 0xc00007cf30)
	/usr/local/go/src/runtime/panic.go:1047 +0x266
main.triggerActualPanic()
	/app/cmd/scalpel/utils.go:10 +0x45 // This is the target frame
main.main()
	/app/cmd/scalpel/main.go:60 +0x38
`

	// Atypical panic format (e.g. deadlock detection).
	panicAtypicalFormat = `fatal error: all goroutines are asleep - deadlock!

goroutine 1 [chan receive]:
main.main()
	/Users/testuser/deadlock.go:10 +0x45
`
)

// TestParser_Parse uses table-driven tests to validate the core parsing logic.
func TestParser_Parse(t *testing.T) {
	t.Parallel()
	parser := NewParser()

	testCases := []struct {
		name           string
		input          string
		expectedReport *IncidentReport
		expectError    bool
		errorMsg       string
	}{
		{
			name:  "Standard Application Panic",
			input: panicStandard,
			expectedReport: &IncidentReport{
				Message:      "runtime error: invalid memory address or nil pointer dereference",
				FilePath:     "/Users/testuser/go/src/github.com/xkilldash9x/scalpel-cli/internal/config/config.go",
				LineNumber:   55,
				FunctionName: "github.com/xkilldash9x/scalpel-cli/internal/config.Initialize",
			},
		},
		{
			name:  "Deep Stack Panic (Filtering Stdlib/Runtime)",
			input: panicDeepStack,
			expectedReport: &IncidentReport{
				Message: "index out of range [10] with length 5",
				// Should correctly identify the analyzer package after skipping net/http and runtime.
				FilePath:     "/app/src/internal/analyzer/analyzer.go",
				LineNumber:   150,
				FunctionName: "github.com/xkilldash9x/scalpel-cli/internal/analyzer.(*Analyzer).processFile",
			},
		},
		{
			name:        "Runtime Only Panic",
			input:       panicRuntimeOnly,
			expectError: true,
			errorMsg:    "could not reliably determine panic location",
		},
		{
			name:  "Panic Filtering Recovery Handler",
			input: panicInRecoveryHandler,
			expectedReport: &IncidentReport{
				Message: "something went wrong during recovery setup",
				// Should skip main.main.func1 in cmd/scalpel/main.go
				FilePath:     "/app/cmd/scalpel/utils.go",
				LineNumber:   10,
				FunctionName: "main.triggerActualPanic",
			},
		},
		{
			name:  "Atypical Panic Format (Deadlock)",
			input: panicAtypicalFormat,
			expectedReport: &IncidentReport{
				Message:      "fatal error: all goroutines are asleep - deadlock!", // Should capture the whole first line
				FilePath:     "/Users/testuser/deadlock.go",
				LineNumber:   10,
				FunctionName: "main.main",
			},
		},
		{
			name:        "Empty Input",
			input:       "",
			expectError: true,
			errorMsg:    "panic log is empty",
		},
		{
			name:        "Truncated Input (Missing Location Line)",
			input:       "panic: oops\n\ngoroutine 1 [running]:\nmain.func1()",
			expectError: true,
			errorMsg:    "could not reliably determine panic location",
		},
		{
			name:        "Not a Panic Log (No recognizable stack frames)",
			input:       "INFO: Application started\nWARN: Low memory",
			expectError: true,
			errorMsg:    "could not reliably determine panic location",
		},
	}

	for _, tc := range testCases {
		// Capture loop variable for parallel execution
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lines := strings.Split(tc.input, "\n")
			// Handle the edge case of an empty string input
			if tc.input == "" {
				lines = []string{}
			}

			report, err := parser.Parse(lines)

			if tc.expectError {
				assert.Error(t, err)
				assert.Nil(t, report)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, report)

				// Compare fields individually for clearer failure diagnostics
				assert.Equal(t, tc.expectedReport.Message, report.Message)
				assert.Equal(t, tc.expectedReport.FilePath, report.FilePath)
				assert.Equal(t, tc.expectedReport.LineNumber, report.LineNumber)
				assert.Equal(t, tc.expectedReport.FunctionName, report.FunctionName)
				// Ensure the full stack trace is preserved
				assert.Equal(t, tc.input, report.StackTrace)
			}
		})
	}
}

// TestParser_ParseFile tests the file I/O aspects of the parser.
func TestParser_ParseFile(t *testing.T) {
	parser := NewParser()
	// Use t.TempDir() for automatic cleanup of test files
	tempDir := t.TempDir()

	t.Run("Successful Parse", func(t *testing.T) {
		logPath := filepath.Join(tempDir, "success.log")
		err := os.WriteFile(logPath, []byte(panicStandard), 0644)
		require.NoError(t, err)

		report, err := parser.ParseFile(logPath)
		require.NoError(t, err)
		assert.Equal(t, 55, report.LineNumber)
		assert.Equal(t, "runtime error: invalid memory address or nil pointer dereference", report.Message)
	})

	t.Run("File Not Found", func(t *testing.T) {
		logPath := filepath.Join(tempDir, "nonexistent.log")
		_, err := parser.ParseFile(logPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open panic log file")
	})

	t.Run("Empty File", func(t *testing.T) {
		logPath := filepath.Join(tempDir, "empty.log")
		err := os.WriteFile(logPath, []byte(""), 0644)
		require.NoError(t, err)

		_, err = parser.ParseFile(logPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "panic log is empty")
	})
}
