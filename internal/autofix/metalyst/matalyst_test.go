// File: internal/autofix/metalyst/metalyst_test.go
package metalyst

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/autofix/coroner"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
)

// -- Test Helper Functions --

// setupTestEnvironment creates an isolated environment for integration tests.
func setupTestEnvironment(t *testing.T) (string, func()) {
	t.Helper()

	// Configure the logger to write to the test's output.
	testLogCfg := config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	}
	// Use NewTestingWriter to get an io.Writer for the test runner.
	testWriter := zapcore.AddSync(zaptest.NewTestingWriter(t))
	observability.Initialize(testLogCfg, testWriter)

	// Create temporary directory for the test environment.
	tempDir, err := os.MkdirTemp("", "metalyst-test-*")
	require.NoError(t, err)

	// Initialize Git repository.
	runCmd(t, tempDir, "git", "init", "-b", "main")
	runCmd(t, tempDir, "git", "config", "user.name", "Test Bot")
	runCmd(t, tempDir, "git", "config", "user.email", "testbot@example.com")

	// Create basic Go project structure.
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte("module test/metalyst\n\ngo 1.22\n"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "cmd/scalpel"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "internal/utils"), 0755))
	mainGoContent := `package main
import "fmt"
func main() { fmt.Println("Hello World") }
`
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "cmd/scalpel/main.go"), []byte(mainGoContent), 0644))
	runCmd(t, tempDir, "git", "add", ".")
	runCmd(t, tempDir, "git", "commit", "-m", "Initial commit")

	originalCWD, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tempDir))

	// Cleanup function to restore state after the test.
	cleanup := func() {
		os.Chdir(originalCWD)
		os.RemoveAll(tempDir)
		// Crucial for test isolation: Reset the global logger.
		observability.ResetForTest()
	}

	return tempDir, cleanup
}

// runCmd executes a command in the specified directory and asserts success.
func runCmd(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, fmt.Sprintf("Command failed: %s %s\nOutput: %s", name, strings.Join(args, " "), string(output)))
	return strings.TrimSpace(string(output))
}

// requireExternalTools checks for 'git' and optionally 'go'. Skips the test if not found.
func requireExternalTools(t *testing.T, checkGo bool) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git not found in PATH, skipping integration test.")
	}
	if checkGo {
		if _, err := exec.LookPath("go"); err != nil {
			t.Skip("Go compiler (go) not found in PATH, skipping integration test.")
		}
	}
}

// -- Unit/Integration Tests --

// TestDetermineProjectRoot tests the strategies for finding the project root.
func TestDetermineProjectRoot(t *testing.T) {
	// These tests manipulate CWD and environment variables and cannot run in parallel.

	t.Run("Strategy 1: Inside Git Repo", func(t *testing.T) {
		requireExternalTools(t, false)
		projectRoot, cleanup := setupTestEnvironment(t)
		defer cleanup()

		determinedRoot, err := determineProjectRoot()
		require.NoError(t, err)

		cleanExpected, _ := filepath.EvalSymlinks(projectRoot)
		cleanGot, _ := filepath.EvalSymlinks(determinedRoot)
		assert.Equal(t, cleanExpected, cleanGot)

		subDir := filepath.Join(projectRoot, "internal/utils")
		require.NoError(t, os.Chdir(subDir))
		defer os.Chdir(projectRoot)

		determinedRootFromSub, err := determineProjectRoot()
		require.NoError(t, err)
		cleanGotSub, _ := filepath.EvalSymlinks(determinedRootFromSub)
		assert.Equal(t, cleanExpected, cleanGotSub)
	})

	t.Run("Strategy 2: Fallback to go.mod (Git hidden)", func(t *testing.T) {
		tempDir := t.TempDir()
		projectDir := filepath.Join(tempDir, "project")
		subDir := filepath.Join(projectDir, "subdir/deep")
		require.NoError(t, os.MkdirAll(subDir, 0755))
		require.NoError(t, os.WriteFile(filepath.Join(projectDir, "go.mod"), []byte("module test"), 0644))

		originalPath := os.Getenv("PATH")
		emptyPath := t.TempDir()
		os.Setenv("PATH", emptyPath)
		defer os.Setenv("PATH", originalPath)

		originalCWD, _ := os.Getwd()
		require.NoError(t, os.Chdir(subDir))
		defer os.Chdir(originalCWD)

		determinedRoot, err := determineProjectRoot()
		require.NoError(t, err)
		cleanExpected, _ := filepath.EvalSymlinks(projectDir)
		cleanGot, _ := filepath.EvalSymlinks(determinedRoot)
		assert.Equal(t, cleanExpected, cleanGot)
	})

	t.Run("Failure: No Repo or go.mod Found", func(t *testing.T) {
		tempDir := t.TempDir()
		originalCWD, _ := os.Getwd()
		require.NoError(t, os.Chdir(tempDir))
		defer os.Chdir(originalCWD)

		_, err := determineProjectRoot()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "could not find project root")
	})
}

// TestNormalizePath tests the path resolution heuristics.
func TestNormalizePath(t *testing.T) {
	requireExternalTools(t, false)
	projectRoot, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create specific files for testing heuristics
	// 1. Unique file
	require.NoError(t, os.MkdirAll(filepath.Join(projectRoot, "pkg/config"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(projectRoot, "pkg/config/settings.go"), []byte("package config"), 0644))
	// 2. Ambiguous files
	require.NoError(t, os.WriteFile(filepath.Join(projectRoot, "internal/utils/helper.go"), []byte("package utils"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(projectRoot, "pkg/utils"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(projectRoot, "pkg/utils/helper.go"), []byte("package utils"), 0644))
	// 3. Directories that should be skipped
	require.NoError(t, os.MkdirAll(filepath.Join(projectRoot, "vendor/pkg"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(projectRoot, "vendor/pkg/settings.go"), []byte("vendor"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(projectRoot, "bin"), 0755))

	m, err := NewMetalyst(&config.Config{}, new(mocks.MockLLMClient))
	require.NoError(t, err)

	testCases := []struct {
		name        string
		crashPath   string
		expectedRel string
		expectedAbs string
		expectError bool
	}{
		{
			name:        "1. Already Relative Path (Valid)",
			crashPath:   "cmd/scalpel/main.go",
			expectedRel: "cmd/scalpel/main.go",
			expectedAbs: filepath.Join(projectRoot, "cmd/scalpel/main.go"),
		},
		{
			name:        "1. Already Relative Path (Invalid)",
			crashPath:   "cmd/scalpel/nonexistent.go",
			expectError: true,
		},
		{
			name:        "2. Absolute Path (Direct Match)",
			crashPath:   filepath.Join(projectRoot, "pkg/config/settings.go"),
			expectedRel: "pkg/config/settings.go",
			expectedAbs: filepath.Join(projectRoot, "pkg/config/settings.go"),
		},
		{
			name:        "2. Absolute Path (Outside Project)",
			crashPath:   "/tmp/outside.go",
			expectError: true,
		},
		{
			name:        "3. Heuristic Search (Unique Match)",
			crashPath:   "/build/src/project/cmd/scalpel/main.go",
			expectedRel: "cmd/scalpel/main.go",
			expectedAbs: filepath.Join(projectRoot, "cmd/scalpel/main.go"),
		},
		{
			name:        "3. Heuristic Search (Multiple Matches)",
			crashPath:   "/build/src/project/helper.go",
			expectError: true,
		},
		{
			name:        "3. Heuristic Search (No Match)",
			crashPath:   "/build/src/project/unique_file_not_found.go",
			expectError: true,
		},
		{
			name:        "3. Heuristic Search (Ignores Vendor)",
			crashPath:   "/build/src/project/settings.go",
			expectedRel: "pkg/config/settings.go",
			expectedAbs: filepath.Join(projectRoot, "pkg/config/settings.go"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			relPath, absPath, err := m.normalizePath(tc.crashPath)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedRel, relPath)
				cleanExpected, _ := filepath.EvalSymlinks(tc.expectedAbs)
				cleanGot, _ := filepath.EvalSymlinks(absPath)
				assert.Equal(t, cleanExpected, cleanGot)
			}
		})
	}
}

// TestParseLLMResponse tests the JSON parsing logic, including LLM quirks.
func TestParseLLMResponse(t *testing.T) {
	t.Parallel()
	m := &Metalyst{}
	validPatch := `--- a/file.go
+++ b/file.go
@@ -1 +1 @@
-old
+new
`
	testCases := []struct {
		name             string
		input            string
		expectedAnalysis *AnalysisResult
		expectError      bool
	}{
		{
			name:  "Valid JSON Response",
			input: fmt.Sprintf(`{"explanation": "E", "root_cause": "R", "confidence": 0.95, "patch": %q}`, validPatch),
			expectedAnalysis: &AnalysisResult{
				Explanation: "E",
				RootCause:   "R",
				Confidence:  0.95,
				Patch:       validPatch,
			},
		},
		{
			name:  "Valid JSON with Markdown Wrapper (```json)",
			input: fmt.Sprintf("```json\n{\n\"explanation\": \"E\",\n\"root_cause\": \"R\",\n\"confidence\": 0.8,\n\"patch\": %q\n}\n```", validPatch),
			expectedAnalysis: &AnalysisResult{
				Explanation: "E",
				RootCause:   "R",
				Confidence:  0.8,
				Patch:       validPatch,
			},
		},
		{
			name: "Patch Field Contains Markdown Diff Block (```diff)",
			input: fmt.Sprintf(`{
                "explanation": "E",
                "root_cause": "R",
                "confidence": 0.9,
                "patch": %q
            }`, fmt.Sprintf("```diff\n%s\n```", validPatch)),
			expectedAnalysis: &AnalysisResult{
				Explanation: "E",
				RootCause:   "R",
				Confidence:  0.9,
				Patch:       validPatch,
			},
		},
		{
			name:        "Invalid JSON Format",
			input:       `{"explanation": "Missing brace"}`,
			expectError: true,
		},
		{
			name:        "Missing Required Field (Patch)",
			input:       `{"explanation": "E", "root_cause": "R", "confidence": 1.0}`,
			expectError: true,
		},
		{
			name: "Invalid Patch Format (Missing headers)",
			input: `{
				"explanation": "E",
				"root_cause": "R",
				"confidence": 0.5,
				"patch": "@@ -1 +1 @@\n-old\n+new"
			}`,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			analysis, err := m.parseLLMResponse(tc.input)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedAnalysis, analysis)
			}
		})
	}
}

// TestExtractCodeContext tests the helper function for extracting source code snippets.
func TestExtractCodeContext(t *testing.T) {
	t.Parallel()
	// This source code has 14 lines of content plus a trailing newline.
	// The function correctly handles this by treating it as 14 lines.
	sourceCode := `package main

import "fmt"

// Line 5
func main() {
    a := 1
    b := 0
    // Line 9 - The crash!
    c := a / b // Line 10
    fmt.Println(c)
}

// Line 14
`

	t.Run("Middle of File", func(t *testing.T) {
		context := extractCodeContext(sourceCode, 10, 5)
		// This expected string now correctly reflects the dynamic padding.
		expected := `    8:     b := 0
    9:     // Line 9 - The crash!
-> 10:     c := a / b // Line 10
   11:     fmt.Println(c)
   12: }`
		assert.Equal(t, expected, context)
	})

	t.Run("Start of File", func(t *testing.T) {
		context := extractCodeContext(sourceCode, 1, 5)
		expected := `-> 1: package main
   2: 
   3: import "fmt"
   4: 
   5: // Line 5`
		assert.Equal(t, expected, context)
	})

	t.Run("End of File", func(t *testing.T) {
		context := extractCodeContext(sourceCode, 14, 5)
		// This assertion is now correct for the given source code.
		expected := `   10:     c := a / b // Line 10
   11:     fmt.Println(c)
   12: }
   13: 
-> 14: // Line 14`
		assert.Equal(t, expected, context)
	})

	t.Run("Invalid Line Number", func(t *testing.T) {
		// Requesting line 15 when there are only 14 should fail.
		context := extractCodeContext(sourceCode, 15, 5)
		assert.Equal(t, "// Context unavailable: Invalid line number.", context)

		contextZero := extractCodeContext(sourceCode, 0, 5)
		assert.Equal(t, "// Context unavailable: Invalid line number.", contextZero)
	})
}

// TestAnalyzeAndGeneratePatch validates the orchestration of the analysis phase.
func TestAnalyzeAndGeneratePatch(t *testing.T) {
	requireExternalTools(t, false)
	projectRoot, cleanup := setupTestEnvironment(t)
	defer cleanup()

	buggyFilePath := "internal/utils/crash.go"
	localBuggyPath := filepath.Join(projectRoot, buggyFilePath)
	sourceCode := `package utils

// This function crashes if input is nil
func Process(input *string) int {
    return len(*input) // Line 5
}
`
	require.NoError(t, os.WriteFile(localBuggyPath, []byte(sourceCode), 0644))

	expectedPatch := "--- a/internal/utils/crash.go\n+++ b/internal/utils/crash.go\n@@ -3,5 +3,7 @@\n // This function crashes if input is nil\n func Process(input *string) int {\n+\tif input == nil {\n+\t\treturn 0\n+\t}\n \treturn len(*input) // Line 5\n }\n"
	mockLLM := new(mocks.MockLLMClient)
	response := AnalysisResult{
		Explanation: "Added nil check.",
		RootCause:   "Nil pointer dereference.",
		Confidence:  0.98,
		Patch:       expectedPatch,
	}
	respBytes, err := json.Marshal(response)
	require.NoError(t, err)

	mockLLM.On("Generate",
		mock.Anything,
		mock.MatchedBy(func(req schemas.GenerationRequest) bool {
			assert.Contains(t, req.UserPrompt, "File (Relative Path for Patch): internal/utils/crash.go")
			assert.Contains(t, req.UserPrompt, "Line: 5")
			assert.Contains(t, req.UserPrompt, "-> 5:     return len(*input) // Line 5")
			return true
		}),
	).Return(string(respBytes), nil)

	m, err := NewMetalyst(&config.Config{}, mockLLM)
	require.NoError(t, err)

	report := &coroner.IncidentReport{
		FilePath:   buggyFilePath,
		LineNumber: 5,
	}

	ctx := context.Background()
	analysis, err := m.analyzeAndGeneratePatch(ctx, report, localBuggyPath)

	require.NoError(t, err)
	assert.Equal(t, 0.98, analysis.Confidence)
	assert.Equal(t, expectedPatch, analysis.Patch)
	mockLLM.AssertExpectations(t)

	// Test failure scenario: File read error
	t.Run("File Read Failure", func(t *testing.T) {
		_, err := m.analyzeAndGeneratePatch(ctx, report, "/tmp/nonexistent.go")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read source code file")
	})
}

// TestGitOperations tests the git patch, commit, and revert functions.
func TestGitOperations(t *testing.T) {
	requireExternalTools(t, false)
	projectRoot, cleanup := setupTestEnvironment(t)
	defer cleanup()

	m, err := NewMetalyst(&config.Config{}, new(mocks.MockLLMClient))
	require.NoError(t, err)

	// 1. Create and commit a file to patch
	targetFile := filepath.Join(projectRoot, "data.txt")
	initialContent := "Line 1\nLine 2\nLine 3\n"
	require.NoError(t, os.WriteFile(targetFile, []byte(initialContent), 0644))
	runCmd(t, projectRoot, "git", "add", "data.txt")
	runCmd(t, projectRoot, "git", "commit", "-m", "Add data")

	// 2. Define the patch
	patch := `--- a/data.txt
+++ b/data.txt
@@ -1,3 +1,3 @@
 Line 1
-Line 2
+Line Two (Patched)
 Line 3
`

	// 3. Test ApplyPatch
	t.Run("ApplyPatch", func(t *testing.T) {
		err = m.applyPatch(patch)
		require.NoError(t, err)

		// Verify changes
		content, err := os.ReadFile(targetFile)
		require.NoError(t, err)
		expectedContent := "Line 1\nLine Two (Patched)\nLine 3\n"
		assert.Equal(t, expectedContent, string(content))
		status := runCmd(t, projectRoot, "git", "status", "--porcelain")
		assert.Equal(t, "M data.txt", status)
	})

	// 4. Test CommitFix
	t.Run("CommitFix", func(t *testing.T) {
		analysis := &AnalysisResult{
			RootCause:   "Typo correction",
			Confidence:  0.995, // Will be rounded to 1.00 in the message
			Explanation: "Fixed typo in line 2.",
		}
		err = m.commitFix(analysis)
		require.NoError(t, err)

		// Verify commit message and clean working directory
		logOutput := runCmd(t, projectRoot, "git", "log", "-1", "--pretty=%B")
		assert.Contains(t, logOutput, "fix: [Auto-Heal] Typo correction")
		assert.Contains(t, logOutput, "Confidence: 1.00")
		status := runCmd(t, projectRoot, "git", "status", "--porcelain")
		assert.Empty(t, status)
	})

	// 5. Test RevertPatch
	t.Run("RevertPatch", func(t *testing.T) {
		// Apply a new change that is not committed
		revertPatch := `--- a/data.txt
+++ b/data.txt
@@ -1,3 +1,4 @@
 Line 1
 Line Two (Patched)
 Line 3
+Line 4 (Added)
`
		require.NoError(t, m.applyPatch(revertPatch))
		content, _ := os.ReadFile(targetFile)
		assert.Contains(t, string(content), "Line 4 (Added)")

		// Revert it
		err = m.revertPatch(revertPatch)
		require.NoError(t, err)

		// Verify reversion brings it back to the last committed state
		content, _ = os.ReadFile(targetFile)
		expectedContent := "Line 1\nLine Two (Patched)\nLine 3\n"
		assert.Equal(t, expectedContent, string(content))
		// Status should be clean as the revert restored the file to the committed state.
		status := runCmd(t, projectRoot, "git", "status", "--porcelain")
		assert.Empty(t, status)
	})
}

// TestRecompile tests the go build process.
func TestRecompile(t *testing.T) {
	requireExternalTools(t, true)
	projectRoot, cleanup := setupTestEnvironment(t)
	defer cleanup()

	m, err := NewMetalyst(&config.Config{}, new(mocks.MockLLMClient))
	require.NoError(t, err)

	t.Run("Successful Compilation", func(t *testing.T) {
		ctx := context.Background()
		binaryPath, err := m.recompile(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, binaryPath)
		defer os.Remove(binaryPath)
	})

	t.Run("Compilation Failure", func(t *testing.T) {
		mainFile := filepath.Join(projectRoot, "cmd/scalpel/main.go")
		originalContent, _ := os.ReadFile(mainFile)
		err := os.WriteFile(mainFile, []byte("package main\nfunc main() { syntax error }"), 0644)
		require.NoError(t, err)
		defer os.WriteFile(mainFile, originalContent, 0644)

		ctx := context.Background()
		_, err = m.recompile(ctx)
		assert.Error(t, err)
	})

	t.Run("Context Cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := m.recompile(ctx)
		assert.Error(t, err)
		assert.True(t, strings.Contains(err.Error(), "context canceled") || strings.Contains(err.Error(), "killed"),
			"Expected context cancellation or kill error, got: %v", err)
	})
}

// TestApplyAndValidate_E2E_Workflow tests the entire validation lifecycle.
func TestApplyAndValidate_E2E_Workflow(t *testing.T) {
	requireExternalTools(t, true)
	projectRoot, cleanup := setupTestEnvironment(t)
	defer cleanup()

	m, err := NewMetalyst(&config.Config{}, new(mocks.MockLLMClient))
	require.NoError(t, err)

	buggyMainContent := `package main
import (
    "fmt"
    "os"
)

func main() {
    // The buggy behavior
    if len(os.Args) > 1 && os.Args[1] == "trigger_bug" {
        fmt.Println("Bug triggered!")
        os.Exit(1) // <-- The bug
    }
    fmt.Println("Success!")
}
`
	mainFile := filepath.Join(projectRoot, "cmd/scalpel/main.go")
	require.NoError(t, os.WriteFile(mainFile, []byte(buggyMainContent), 0644))
	runCmd(t, projectRoot, "git", "commit", "-am", "Add buggy main.go")

	// --- Test Case 1: Successful Fix ---
	t.Run("Successful Fix", func(t *testing.T) {
		patch := `--- a/cmd/scalpel/main.go
+++ b/cmd/scalpel/main.go
@@ -8,8 +8,7 @@
 func main() {
     // The buggy behavior
     if len(os.Args) > 1 && os.Args[1] == "trigger_bug" {
-        fmt.Println("Bug triggered!")
-        os.Exit(1) // <-- The bug
+        // Bug fixed, do nothing special
     }
     fmt.Println("Success!")
 }
`
		analysis := &AnalysisResult{Patch: patch}
		ctx := context.Background()

		err = m.applyAndValidate(ctx, analysis, []string{"trigger_bug"})
		require.NoError(t, err, "applyAndValidate should succeed when the patch fixes the issue")

		content, err := os.ReadFile(mainFile)
		require.NoError(t, err)
		assert.NotContains(t, string(content), "os.Exit(1)")

		// Cleanup: Revert changes manually to prepare for the next test case
		require.NoError(t, m.revertPatch(patch))
	})

	// --- Test Case 2: Validation Fails (Revert) ---
	t.Run("Validation Fails and Reverts", func(t *testing.T) {
		// Define a patch that does NOT fix the issue (e.g., adds a comment)
		patch := `--- a/cmd/scalpel/main.go
+++ b/cmd/scalpel/main.go
@@ -7,6 +7,7 @@
 
 func main() {
     // The buggy behavior
+    // This comment does not fix the bug.
     if len(os.Args) > 1 && os.Args[1] == "trigger_bug" {
         fmt.Println("Bug triggered!")
         os.Exit(1) // <-- The bug
`
		analysis := &AnalysisResult{Patch: patch}
		ctx := context.Background()

		// Run the workflow
		err = m.applyAndValidate(ctx, analysis, []string{"trigger_bug"})

		// Verification
		assert.Error(t, err, "applyAndValidate should fail if validation fails")
		assert.Contains(t, err.Error(), "fix validation failed")

		// Crucial: Verify that the changes were automatically reverted by the defer logic
		content, err := os.ReadFile(mainFile)
		require.NoError(t, err)
		assert.Equal(t, buggyMainContent, string(content), "Changes should have been reverted")

		// Verify git status is clean after revert
		status := runCmd(t, projectRoot, "git", "status", "--porcelain")
		assert.Empty(t, status, "Git repository should be clean after revert")
	})

	// --- Test Case 3: Compilation Fails (Revert) ---
	t.Run("Compilation Fails and Reverts", func(t *testing.T) {
		// Define a patch that introduces a syntax error
		patch := `--- a/cmd/scalpel/main.go
+++ b/cmd/scalpel/main.go
@@ -6,7 +6,7 @@
 )
 
 func main() {
-    // The buggy behavior
+    syntax error here
     if len(os.Args) > 1 && os.Args[1] == "trigger_bug" {
         fmt.Println("Bug triggered!")
         os.Exit(1) // <-- The bug
`
		analysis := &AnalysisResult{Patch: patch}
		ctx := context.Background()

		// Run the workflow
		err = m.applyAndValidate(ctx, analysis, []string{"trigger_bug"})

		// Verification
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "recompilation failed")

		// Crucial: Verify that the changes were reverted
		content, err := os.ReadFile(mainFile)
		require.NoError(t, err)
		assert.Equal(t, buggyMainContent, string(content), "Changes should have been reverted after compile failure")
	})
}
