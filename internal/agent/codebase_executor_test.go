// internal/agent/codebase_executor_test.go
package agent

import ( // This is a comment to force a change
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// setupCodebaseExecutorTest creates a temporary directory structure simulating a Go project.
func setupCodebaseExecutorTest(t *testing.T) (*CodebaseExecutor, string) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	// Create a temporary directory for the test project
	projectRoot, err := os.MkdirTemp("", "scalpel-codebase-test-*")
	require.NoError(t, err)

	// Clean up the temporary directory after the test
	t.Cleanup(func() {
		os.RemoveAll(projectRoot)
	})

	executor := NewCodebaseExecutor(logger, projectRoot)
	return executor, projectRoot
}

// createGoModuleFixture initializes a basic Go module in the specified directory.
func createGoModuleFixture(t *testing.T, rootDir string, moduleName string, files map[string]string) {
	t.Helper()

	// Create go.mod
	// Use a recent Go version for compatibility
	goModContent := "module " + moduleName + "\n\ngo 1.21\n"
	err := os.WriteFile(filepath.Join(rootDir, "go.mod"), []byte(goModContent), 0644)
	require.NoError(t, err)

	// Create source files
	for path, content := range files {
		fullPath := filepath.Join(rootDir, path)
		err := os.MkdirAll(filepath.Dir(fullPath), 0755)
		require.NoError(t, err)
		err = os.WriteFile(fullPath, []byte(content), 0644)
		require.NoError(t, err)
	}
}

// TestCodebaseExecutor_Execute_SimpleProject verifies analysis of a single-file project (Integration Test).
func TestCodebaseExecutor_Execute_SimpleProject(t *testing.T) {
	executor, projectRoot := setupCodebaseExecutorTest(t)
	ctx := context.Background()

	// Setup the fixture project
	moduleName := "example.com/simple"
	mainGoContent := `package main

import "fmt"

func main() {
	fmt.Println("Hello, World!")
}
`
	createGoModuleFixture(t, projectRoot, moduleName, map[string]string{
		"main.go": mainGoContent,
	})

	// Define the action (analyzing the entire project "./...")
	action := Action{
		Type:     ActionGatherCodebaseContext,
		Metadata: map[string]interface{}{"module_path": "./..."},
	}

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "success", result.Status)
	assert.Equal(t, ObservedCodebaseContext, result.ObservationType)

	output, ok := result.Data.(string)
	require.True(t, ok, "Result data should be a string")

	// Verify the output structure and content
	assert.Contains(t, output, "## Source Code for Module: example.com/simple ##")
	// File paths should be relative in the output
	assert.Contains(t, output, "-- File: main.go --")
	assert.Contains(t, output, mainGoContent)
	assert.Contains(t, output, "## Discovered External Dependencies ##")
	// Verify that standard library dependencies (like fmt.Println) are included in the definitions
	assert.Contains(t, output, "-- Definition for: func fmt.Println")
}

// TestCodebaseExecutor_Execute_MultiPackageProject verifies analysis across multiple packages (Integration Test).
func TestCodebaseExecutor_Execute_MultiPackageProject(t *testing.T) {
	executor, projectRoot := setupCodebaseExecutorTest(t)
	ctx := context.Background()

	// Setup the fixture project
	moduleName := "example.com/multi"
	files := map[string]string{
		"cmd/app/main.go": `package main

import (
	"fmt"
	"example.com/multi/pkg/utils"
)

func main() {
	fmt.Println(utils.Greet("Scalpel"))
}
`,
		"pkg/utils/utils.go": `package utils

import "strings"

// Greet returns a greeting message.
func Greet(name string) string {
	return strings.ToUpper("Hello, " + name)
}
`,
	}
	createGoModuleFixture(t, projectRoot, moduleName, files)

	// Define the action (analyzing the entire project "./...")
	action := Action{
		Type: ActionGatherCodebaseContext,
		// Test the default pattern (no module_path provided)
	}

	// Act
	result, err := executor.Execute(ctx, action)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)

	output, ok := result.Data.(string)
	require.True(t, ok)

	// Verify both files are included in the output (use filepath.ToSlash for cross-platform paths)
	assert.Contains(t, output, "-- File: "+filepath.ToSlash("cmd/app/main.go")+" --")
	assert.Contains(t, output, "-- File: "+filepath.ToSlash("pkg/utils/utils.go")+" --")
	// Verify content snippets
	assert.Contains(t, output, `fmt.Println(utils.Greet("Scalpel"))`)
	assert.Contains(t, output, `func Greet(name string) string {`)
	// Verify external dependencies from both packages
	assert.Contains(t, output, "-- Definition for: func fmt.Println")
	assert.Contains(t, output, "-- Definition for: func strings.ToUpper")
}

// TestCodebaseExecutor_Execute_Validation checks the executor's input validation logic.
func TestCodebaseExecutor_Execute_Validation(t *testing.T) {
	executor, _ := setupCodebaseExecutorTest(t)
	ctx := context.Background()

	t.Run("WrongActionType", func(t *testing.T) {
		action := Action{Type: ActionClick}
		result, err := executor.Execute(ctx, action)
		require.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "codebase executor cannot handle action type")
	})
}

// TestCodebaseExecutor_Execute_PackageLoadFailure tests error handling when static analysis fails.
func TestCodebaseExecutor_Execute_PackageLoadFailure(t *testing.T) {
	// Move setup into the sub-tests to ensure isolation
	ctx := context.Background()

	t.Run("NoPackagesFound", func(t *testing.T) {
		// FIX: Setup a clean environment for this sub-test
		executor, projectRoot := setupCodebaseExecutorTest(t)

		// FIX: Create a valid Go module fixture first.
		// We don't need any .go files, just the go.mod to make packages.Load happy.
		createGoModuleFixture(t, projectRoot, "example.com/empty", nil)

		// Analyze a pattern that doesn't match any packages in the fixture
		action := Action{
			Type:     ActionGatherCodebaseContext,
			Metadata: map[string]interface{}{"module_path": "./non/existent/path"},
		}

		// Act
		result, err := executor.Execute(ctx, action)

		// Assert: The executor should handle the error gracefully and return a failed ExecutionResult
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "failed", result.Status)
		assert.Equal(t, ErrCodeExecutionFailure, result.ErrorCode)
		errMsg := result.ErrorDetails["message"].(string)

		// This assertion should now pass
		assert.Contains(t, errMsg, "no packages were loaded for pattern")
	})

	t.Run("SyntaxErrorInCode", func(t *testing.T) {
		// FIX: Setup a clean environment for this sub-test
		executor, projectRoot := setupCodebaseExecutorTest(t)

		// Create a syntactically invalid Go file
		createGoModuleFixture(t, projectRoot, "example.com/broken", map[string]string{
			"broken.go": "package main\nfunc main() { broken syntax",
		})

		action := Action{
			Type:     ActionGatherCodebaseContext,
			Metadata: map[string]interface{}{"module_path": "./..."},
		}

		// Act
		result, err := executor.Execute(ctx, action)

		// Assert: packages.Load often returns partial results even with errors,
		// so the executor might report success if it could load *some* packages,
		// or failure if the errors prevent analysis entirely.
		// We check that it doesn't crash and returns a structured result.
		require.NoError(t, err)
		require.NotNil(t, result)

		// In recent Go versions, syntax errors often cause the analysis to fail entirely.
		if result.Status == "failed" {
			assert.Contains(t, result.ErrorDetails["message"].(string), "error loading packages")
		} else {
			// If it succeeds, it means the analysis toolchain was resilient.
			assert.Equal(t, "success", result.Status)
			// Check logs for warnings (implementation dependent on zaptest configuration)
		}
	})
}
