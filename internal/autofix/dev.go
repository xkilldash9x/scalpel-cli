// internal/autofix/dev.go
package autofix

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/your-username/scalpel-cli/api/schemas"
	"github.com/your-username/scalpel-cli/internal/config"
)

// Developer automates the TDD cycle and Git workflow in an isolated environment
// to safely test and apply fixes.
type Developer struct {
	logger          *zap.Logger
	llmClient       schemas.LLMClient
	cfg             *config.AutofixConfig
	// sourceProjectRoot is the absolute path to the primary local repository,
	// which serves as the source for cloning.
	sourceProjectRoot string
}

// NewDeveloper initializes a new autonomous developer service. It requires the project's
// root path to create isolated workspaces for its tasks.
func NewDeveloper(logger *zap.Logger, llmClient schemas.LLMClient, cfg *config.AutofixConfig, sourceProjectRoot string) *Developer {
	return &Developer{
		logger:          logger.Named("autofix-developer"),
		llmClient:       llmClient,
		cfg:             cfg,
		sourceProjectRoot: sourceProjectRoot,
	}
}

// ValidateAndCommit is the main entry point for the auto-fix process. It orchestrates the entire
// TDD workflow within a temporary, isolated clone of the project repository.
func (d *Developer) ValidateAndCommit(ctx context.Context, report PostMortem, analysis *AnalysisResult) error {
	d.logger.Info("Starting validation and commit process.", zap.String("incident_id", report.IncidentID))

	// 1. Create an isolated workspace by cloning the source repository.
	workspace, cleanup, err := d.prepareWorkspace(ctx, report.IncidentID)
	if err != nil {
		return fmt.Errorf("failed to prepare isolated workspace: %w", err)
	}

	// Defer cleanup, but allow configuration to keep the workspace on failure for debugging.
	validationSuccessful := false
	defer func() {
		if !validationSuccessful && d.cfg.KeepWorkspaceOnFailure {
			d.logger.Warn("Validation failed. Keeping temporary workspace for debugging.", zap.String("workspace", workspace))
		} else {
			cleanup()
		}
	}()

	// 2. Resolve file paths to be relative to the new workspace.
	wsFilePath, wsTestFilePath, err := d.resolveWorkspacePaths(workspace, report.FilePath)
	if err != nil {
		return err
	}

	// 3. Generate a new test case that reproduces the panic.
	testFuncName, err := d.generateTestCase(ctx, report, wsTestFilePath)
	if err != nil {
		return fmt.Errorf("failed to generate reproducing test case: %w", err)
	}

	// 4. Run the new test to confirm it fails as expected ("Red" phase).
	if err := d.runSpecificTest(ctx, workspace, wsTestFilePath, testFuncName, true); err != nil {
		return fmt.Errorf("generated test case did not fail as expected: %w", err)
	}

	// 5. Apply the patch within the workspace.
	if err := d.applyPatch(ctx, workspace, analysis.Patch, wsFilePath); err != nil {
		return fmt.Errorf("failed to apply generated patch: %w", err)
	}
	d.logger.Info("Patch applied successfully within workspace.", zap.String("file", report.FilePath))

	// 6. Run the full test suite to ensure the fix works and introduced no regressions ("Green" phase).
	if err := d.runSpecificTest(ctx, workspace, wsTestFilePath, testFuncName, false); err != nil {
		return fmt.Errorf("fix validation failed: new test case still fails after patch: %w", err)
	}
	if err := d.runFullTestSuite(ctx, workspace); err != nil {
		return fmt.Errorf("regression detected: full test suite failed after patch: %w", err)
	}
	d.logger.Info("Patch validated successfully. All tests passing in workspace.")

	// 7. Create a pull request from the workspace.
	if err := d.createPullRequest(ctx, workspace, report, analysis); err != nil {
		// Even if PR creation fails, the local validation succeeded. We still mark it as such.
		validationSuccessful = true
		return fmt.Errorf("failed to create pull request: %w", err)
	}

	validationSuccessful = true
	d.logger.Info("Process complete. Pull request created successfully.")
	return nil
}

// -- Workspace and File Management --

// prepareWorkspace creates a clean, isolated environment by cloning the source project
// into a new temporary directory. It returns the path to the workspace and a cleanup function.
func (d *Developer) prepareWorkspace(ctx context.Context, incidentID string) (workspaceDir string, cleanup func(), err error) {
	d.logger.Info("Preparing isolated workspace via git clone.", zap.String("source", d.sourceProjectRoot))
	
	// Create a unique temporary directory for the clone.
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("scalpel-autofix-%s-", incidentID))
	if err != nil {
		return "", nil, fmt.Errorf("could not create temp dir: %w", err)
	}

	cleanupFunc := func() {
		if err := os.RemoveAll(tempDir); err != nil {
			d.logger.Error("Failed to clean up temporary workspace.", zap.String("dir", tempDir), zap.Error(err))
		} else {
			d.logger.Info("Temporary workspace cleaned up.", zap.String("dir", tempDir))
		}
	}

	// Clone the local repository into the temporary directory.
	cmd := exec.CommandContext(ctx, "git", "clone", d.sourceProjectRoot, tempDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		cleanupFunc() // Clean up immediately on clone failure.
		return "", nil, fmt.Errorf("failed to clone source repository: %w\nOutput: %s", err, string(output))
	}

	d.logger.Info("Workspace created.", zap.String("path", tempDir))
	return tempDir, cleanupFunc, nil
}

// resolveWorkspacePaths translates an absolute path from the source project to its
// equivalent path within the isolated workspace.
func (d *Developer) resolveWorkspacePaths(workspace string, originalFilePath string) (wsFilePath, wsTestFilePath string, err error) {
	relPath, err := filepath.Rel(d.sourceProjectRoot, originalFilePath)
	if err != nil {
		return "", "", fmt.Errorf("could not determine relative path for '%s': %w", originalFilePath, err)
	}

	wsFilePath = filepath.Join(workspace, relPath)
	wsTestFilePath = strings.Replace(wsFilePath, ".go", "_test.go", 1)
	return
}

// -- TDD Workflow --

// generateTestCase uses the LLM to write a new Go test function that reproduces the crash.
func (d *Developer) generateTestCase(ctx context.Context, report PostMortem, wsTestFilePath string) (string, error) {
	d.logger.Info("Generating new test case to reproduce panic.", zap.String("target_file", wsTestFilePath))
	
	// Ensure the directory for the test file exists in the workspace.
	if err := os.MkdirAll(filepath.Dir(wsTestFilePath), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory for new test file: %w", err)
	}

	// Read existing test file content, or use a template if it doesn't exist.
	sourceBytes, err := os.ReadFile(wsTestFilePath)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to read test file '%s': %w", wsTestFilePath, err)
	}
	
	// Placeholder if the test file is new.
	if os.IsNotExist(err) {
		pkgName := filepath.Base(filepath.Dir(wsTestFilePath))
		sourceBytes = []byte(fmt.Sprintf("package %s\n", pkgName))
	}
	
	prompt := d.constructTestGenPrompt(report, wsTestFilePath, string(sourceBytes))
	req := schemas.GenerationRequest{
		SystemPrompt: "You are a senior Go developer specializing in writing precise, targeted test cases to reproduce bugs.",
		UserPrompt:   prompt,
		Tier:         schemas.TierPowerful,
		Options:      schemas.GenerationOptions{Temperature: 0.1},
	}

	newTestCode, err := d.llmClient.Generate(ctx, req)
	if err != nil {
		return "", fmt.Errorf("llm failed to generate test code: %w", err)
	}

	newTestCode = strings.Trim(newTestCode, "\n\t `go") // Clean up markdown fences
	funcName := extractTestFuncName(newTestCode)
	if funcName == "" {
		return "", fmt.Errorf("could not extract function name from generated test code: %s", newTestCode)
	}

	// Append the new test to the existing test file in the workspace.
	f, err := os.OpenFile(wsTestFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to open test file for appending: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString("\n\n" + newTestCode); err != nil {
		return "", fmt.Errorf("failed to write new test to file: %w", err)
	}

	d.logger.Info("New test case generated and added to workspace.", zap.String("function", funcName))
	return funcName, nil
}

// constructTestGenPrompt builds the detailed prompt for the LLM.
func (d *Developer) constructTestGenPrompt(report PostMortem, testFilePath, fileContent string) string {
	return fmt.Sprintf(`
You are an expert Go developer specializing in testing. Based on the provided post-mortem and the contents of the corresponding test file, create a new, self-contained test function that specifically reproduces the panic.

**Post-Mortem Analysis:**
- Panic Message: %s
- File & Line: %s:%d
- Triggering HTTP Request: %s

**Existing Test File Contents (%s):**
---
%s
---

**Instructions:**
1.  Analyze the panic and the triggering request to understand the root cause.
2.  Write a new Go test function with a descriptive name (e.g., TestMyFunction_PanicOnNilInput).
3.  The test must set up the exact conditions that lead to the panic described.
4.  Do NOT add any checks to recover from the panic (e.g., using 'recover'). The test is *supposed* to fail by panicking.
5.  Ensure all necessary imports are included if the test requires new packages.
6.  Return ONLY the raw Go code for the new function, without any explanations or markdown formatting.
`, report.PanicMessage, report.FilePath, report.LineNumber, report.TriggeringRequest.RawRequest, testFilePath, fileContent)
}


// runSpecificTest executes a single test function within the workspace.
func (d *Developer) runSpecificTest(ctx context.Context, workspace, filePath, funcName string, expectPanic bool) error {
	d.logger.Info("Running specific test in workspace.",
		zap.String("test", funcName),
		zap.String("workspace", workspace),
		zap.Bool("expect_panic", expectPanic))
	
	// The last argument to `go test` should be the package path, not the file path.
	pkgPath := filepath.Dir(filePath)
	
	cmd := exec.CommandContext(ctx, "go", "test", "-v", "-run", fmt.Sprintf("^%s$", funcName), ".")
	cmd.Dir = pkgPath // Run the test from the package's directory within the workspace.
	output, err := cmd.CombinedOutput()

	if expectPanic {
		if err != nil {
			// Success: The test command failed, which is what we expect from a panic.
			d.logger.Info("Test panicked as expected.", zap.String("test", funcName))
			return nil
		}
		// Failure: The test command succeeded, but we expected a panic.
		return fmt.Errorf("test passed but was expected to panic. Output:\n%s", string(output))
	}

	// Expecting success
	if err != nil {
		// Failure: The test failed when it should have passed.
		return fmt.Errorf("test failed unexpectedly after patch. Error: %w. Output:\n%s", err, string(output))
	}
	d.logger.Info("Test passed successfully.", zap.String("test", funcName))
	return nil
}

// runFullTestSuite executes all tests in the project within the workspace.
func (d *Developer) runFullTestSuite(ctx context.Context, workspace string) error {
	d.logger.Info("Running full project test suite in workspace.", zap.String("workspace", workspace))
	cmd := exec.CommandContext(ctx, "go", "test", "-v", "./...")
	cmd.Dir = workspace
	output, err := cmd.CombinedOutput(); 
	if err != nil {
		return fmt.Errorf("full test suite failed. Error: %w. Output:\n%s", err, string(output))
	}
	
	d.logger.Info("Full test suite passed in workspace.")
	return nil
}

// applyPatch uses 'git apply' to stage the patch in the workspace. This is safer
// and more idiomatic than the 'patch' command.
func (d *Developer) applyPatch(ctx context.Context, workspace, patch, filePath string) error {
	d.logger.Info("Applying patch with 'git apply'.", zap.String("workspace", workspace))

	// git apply is better, but patch is a good fallback. Let's stick with a more robust git native approach.
	// We need to apply the patch relative to the project root.
	
	// Create a temporary patch file
	patchFile, err := os.CreateTemp(workspace, "fix-*.patch")
	if err != nil {
		return fmt.Errorf("failed to create temp patch file: %w", err)
	}
	defer os.Remove(patchFile.Name())
	
	if _, err := patchFile.WriteString(patch); err != nil {
		return fmt.Errorf("failed to write to temp patch file: %w", err)
	}
	patchFile.Close()


	cmd := exec.CommandContext(ctx, "git", "apply", "--ignore-whitespace", patchFile.Name())
	cmd.Dir = workspace
	
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git apply command failed: %w. Output: %s", err, string(output))
	}
	
	return nil
}

// -- Git and PR Management --

// createPullRequest automates the Git and PR creation process from the workspace.
func (d *Developer) createPullRequest(ctx context.Context, workspace string, report PostMortem, analysis *AnalysisResult) error {
	d.logger.Info("Creating pull request from workspace.", zap.String("workspace", workspace))
	
	branchName := fmt.Sprintf("fix/autofix-%s-%s", report.IncidentID[:8], time.Now().Format("20060102-150405"))
	commitTitle := fmt.Sprintf("fix: Resolve panic in %s", filepath.Base(report.FilePath))
	commitBody := fmt.Sprintf("Automated fix for panic: %s\n\n**Root Cause Analysis:**\n%s", report.PanicMessage, analysis.Explanation)
	commitMessage := fmt.Sprintf("%s\n\n%s", commitTitle, commitBody)

	// This assumes 'gh' CLI is installed and configured.
	commands := [][]string{
		{"git", "config", "user.name", d.cfg.GitAuthorName},
		{"git", "config", "user.email", d.cfg.GitAuthorEmail},
		{"git", "checkout", "-b", branchName},
		{"git", "add", "."},
		{"git", "commit", "-m", commitMessage},
		{"git", "push", "origin", branchName},
		{"gh", "pr", "create", "--title", commitTitle, "--body", commitBody},
	}

	for _, args := range commands {
		d.logger.Debug("Executing git command", zap.String("command", strings.Join(args, " ")))
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Dir = workspace // All commands run from the workspace root.
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to execute command '%s': %w\nOutput: %s", strings.Join(args, " "), err, string(output))
		}
	}

	d.logger.Info("Successfully created pull request.", zap.String("branch", branchName))
	return nil
}

// -- Helpers --

// extractTestFuncName uses regex to find the name of a Go test function.
func extractTestFuncName(code string) string {
	// Catches functions like "func TestMyThing(t *testing.T)"
	re := regexp.MustCompile(`func\s+(Test[A-Za-z0-9_]+)\s*\(`)
	matches := re.FindStringSubmatch(code)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}