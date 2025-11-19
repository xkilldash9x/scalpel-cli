// internal/autofix/dev.go
package autofix

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	gogitHTTP "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v58/github"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/llmutil"
)

// Developer is a component of the self-healing system responsible for Phase 3:
// validating a proposed patch in an isolated environment using a test-driven
// development (TDD) cycle and, if successful, automating the Git workflow to
// create a pull request.
type Developer struct {
	logger            *zap.Logger
	llmClient         schemas.LLMClient
	cfg               *config.AutofixConfig
	sourceProjectRoot string
	githubClient      *github.Client
	gitAuth           *gogitHTTP.BasicAuth
	ghConfig          *config.GitHubConfig
	gitConfig         *config.GitConfig
}

// NewDeveloper creates and initializes a new instance of the Developer. It
// authenticates with the configured GitHub token to ensure it can create pull
// requests.
func NewDeveloper(logger *zap.Logger, llmClient schemas.LLMClient, cfg *config.AutofixConfig, sourceProjectRoot string) (*Developer, error) {
	if !cfg.Enabled {
		return &Developer{logger: logger.Named("autofix-developer"), cfg: cfg}, nil
	}

	ghClient := github.NewClient(nil).WithAuthToken(cfg.GitHub.Token)
	gitAuth := &gogitHTTP.BasicAuth{
		Username: "x-access-token",
		Password: cfg.GitHub.Token,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if user, _, err := ghClient.Users.Get(ctx, ""); err != nil {
		logger.Error("Failed to authenticate with GitHub using provided token.", zap.Error(err))
		return nil, fmt.Errorf("GitHub authentication failed: %w", err)
	} else {
		logger.Info("Successfully authenticated with GitHub for Autofix.", zap.String("github_user", user.GetLogin()))
	}

	return &Developer{
		logger:            logger.Named("autofix-developer"),
		llmClient:         llmClient,
		cfg:               cfg,
		sourceProjectRoot: sourceProjectRoot,
		githubClient:      ghClient,
		gitAuth:           gitAuth,
		ghConfig:          &cfg.GitHub,
		gitConfig:         &cfg.Git,
	}, nil
}

// ValidateAndCommit orchestrates the entire auto-fix process. It prepares an
// isolated workspace, generates a new test case to reproduce the panic, applies
// the provided patch, and runs the test suite to validate the fix. If successful,
// it creates a pull request.
func (d *Developer) ValidateAndCommit(ctx context.Context, report PostMortem, analysis *AnalysisResult) error {
	if d.githubClient == nil {
		return fmt.Errorf("developer service not fully initialized (Autofix might be disabled)")
	}

	d.logger.Info("Starting validation and commit process.", zap.String("incident_id", report.IncidentID))

	workspacePath, cleanup, err := d.prepareWorkspace(ctx, report.IncidentID)
	if err != nil {
		return fmt.Errorf("failed to prepare isolated workspace: %w", err)
	}

	validationSuccessful := false
	defer func() {
		if !validationSuccessful && d.cfg.KeepWorkspaceOnFailure {
			d.logger.Warn("Validation failed. Keeping temporary workspace for debugging.", zap.String("workspace", workspacePath))
		} else {
			cleanup()
		}
	}()

	wsFilePath := filepath.Join(workspacePath, report.FilePath)
	wsTestFilePath := strings.Replace(wsFilePath, ".go", "_test.go", 1)
	if _, err := os.Stat(wsFilePath); os.IsNotExist(err) {
		return fmt.Errorf("file path from report '%s' not found in cloned workspace", report.FilePath)
	}

	testFuncName, err := d.generateTestCase(ctx, report, wsTestFilePath)
	if err != nil {
		d.logger.Warn("Failed to generate reproducing test case. Proceeding with patch and full suite validation.", zap.Error(err))
		testFuncName = ""
	}

	if testFuncName != "" {
		if err := d.runSpecificTest(ctx, workspacePath, wsTestFilePath, testFuncName, true); err != nil {
			return fmt.Errorf("generated test case did not fail as expected: %w", err)
		}
	}

	if err := d.applyPatch(ctx, workspacePath, analysis.Patch); err != nil {
		return fmt.Errorf("failed to apply generated patch: %w", err)
	}
	d.logger.Info("Patch applied successfully within workspace.", zap.String("file", report.FilePath))

	if testFuncName != "" {
		if err := d.runSpecificTest(ctx, workspacePath, wsTestFilePath, testFuncName, false); err != nil {
			return fmt.Errorf("fix validation failed: new test case still fails after patch: %w", err)
		}
	}
	if err := d.runFullTestSuite(ctx, workspacePath); err != nil {
		return fmt.Errorf("regression detected: full test suite failed after patch: %w", err)
	}
	d.logger.Info("Patch validated successfully. All tests passing in workspace.")

	if err := d.createPullRequest(ctx, workspacePath, report, analysis); err != nil {
		validationSuccessful = true // Validation succeeded even if PR fails
		return fmt.Errorf("failed to create pull request: %w", err)
	}

	validationSuccessful = true
	d.logger.Info("Process complete. Pull request created successfully.")
	return nil
}

// prepareWorkspace creates an isolated environment by cloning the target GitHub repository.
func (d *Developer) prepareWorkspace(ctx context.Context, incidentID string) (workspaceDir string, cleanup func(), err error) {
	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", d.ghConfig.RepoOwner, d.ghConfig.RepoName)
	d.logger.Info("Preparing isolated workspace via remote go-git clone.", zap.String("repo_url", repoURL))

	tempDir, err := os.MkdirTemp("", fmt.Sprintf("scalpel-ws-%s-", incidentID[:8]))
	if err != nil {
		return "", nil, fmt.Errorf("could not create temp dir: %w", err)
	}
	cleanupFunc := func() {
		if err := os.RemoveAll(tempDir); err != nil {
			d.logger.Error("Failed to clean up temporary workspace.", zap.String("dir", tempDir), zap.Error(err))
		}
	}

	_, err = git.PlainCloneContext(ctx, tempDir, false, &git.CloneOptions{
		URL:           repoURL,
		Auth:          d.gitAuth,
		Progress:      nil,
		ReferenceName: plumbing.NewBranchReferenceName(d.ghConfig.BaseBranch),
		SingleBranch:  true,
		Depth:         1,
	})
	if err != nil {
		cleanupFunc()
		return "", nil, fmt.Errorf("failed to clone remote repository using go-git: %w", err)
	}

	d.logger.Info("Workspace created.", zap.String("path", tempDir))
	return tempDir, cleanupFunc, nil
}

// generateTestCase uses the LLM to write a new Go test function.
func (d *Developer) generateTestCase(ctx context.Context, report PostMortem, wsTestFilePath string) (string, error) {
	d.logger.Info("Generating new test case to reproduce panic.", zap.String("target_file", wsTestFilePath))
	if err := os.MkdirAll(filepath.Dir(wsTestFilePath), 0755); err != nil {
		return "", fmt.Errorf("failed to create directory for new test file: %w", err)
	}

	sourceBytes, err := os.ReadFile(wsTestFilePath)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("failed to read test file '%s': %w", wsTestFilePath, err)
	}
	if os.IsNotExist(err) {
		pkgName := filepath.Base(filepath.Dir(wsTestFilePath))
		if pkgName == "." || pkgName == "/" {
			return "", fmt.Errorf("could not determine package name for path: %s", wsTestFilePath)
		}
		sourceBytes = []byte(fmt.Sprintf("package %s\n\nimport \"testing\"\n", pkgName))
	}

	prompt := d.constructTestGenPrompt(report, wsTestFilePath, string(sourceBytes))
	req := schemas.GenerationRequest{
		SystemPrompt: "You are a senior Go developer specializing in writing precise, targeted test cases to reproduce bugs. Ensure tests are idiomatic and include necessary imports.",
		UserPrompt:   prompt,
		Tier:         schemas.TierPowerful,
		Options:      schemas.GenerationOptions{Temperature: llmutil.Float64Ptr(0.1)},
	}

	newTestCode, err := d.llmClient.Generate(ctx, req)
	if err != nil {
		return "", fmt.Errorf("llm failed to generate test code: %w", err)
	}

	newTestCode = cleanLLMCodeOutput(newTestCode)
	funcName := extractTestFuncName(newTestCode)
	if funcName == "" {
		return "", fmt.Errorf("could not extract function name from generated test code: %s", newTestCode)
	}

	f, err := os.OpenFile(wsTestFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to open test file for appending: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString("\n\n" + newTestCode); err != nil {
		return "", fmt.Errorf("failed to write new test to file: %w", err)
	}
	return funcName, nil
}

// constructTestGenPrompt builds the detailed prompt for the LLM.
func (d *Developer) constructTestGenPrompt(report PostMortem, testFilePath, fileContent string) string {
	triggeringReqDetails := "N/A (Correlation unavailable)"
	if report.TriggeringRequest != nil {
		triggeringReqDetails = report.TriggeringRequest.RawRequest
	}
	return fmt.Sprintf(`
You are an expert Go developer specializing in testing. Based on the provided post-mortem and the contents of the corresponding test file, create a new, self-contained test function that specifically reproduces the panic.

**Post-Mortem Analysis:**
- Panic Message: %s
- File & Line: %s:%d
- Triggering HTTP Request: %s

**Existing Test File Contents (%s):**
`+"```go"+`
%s
`+"```"+`

**Instructions:**
1.  Analyze the panic and the triggering request to understand the root cause.
2.  Write a new Go test function with a descriptive name (e.g., TestAutofix_Incident_%s).
3.  The test must set up the exact conditions that lead to the panic described.
4.  Do NOT add any checks to recover from the panic (e.g., using 'recover'). The test is *supposed* to fail by panicking.
5.  Ensure all necessary imports are included if the test requires new packages.
6.  Return ONLY the raw Go code for the new function (and any new imports), without any explanations or markdown formatting.
`, report.PanicMessage, report.FilePath, report.LineNumber, triggeringReqDetails, testFilePath, fileContent, report.IncidentID[:8])
}

// runSpecificTest executes a single test function.
func (d *Developer) runSpecificTest(ctx context.Context, _, filePath, funcName string, expectPanic bool) error {
	d.logger.Info("Running specific test in workspace.", zap.String("test", funcName), zap.Bool("expect_panic", expectPanic))
	pkgPath := filepath.Dir(filePath)
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(testCtx, "go", "test", "-v", "-count=1", "-run", fmt.Sprintf("^%s$", funcName), ".")
	cmd.Dir = pkgPath
	output, err := cmd.CombinedOutput()

	if testCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("test execution timed out")
	}
	if expectPanic {
		if err != nil {
			d.logger.Info("Test failed/panicked as expected.", zap.String("test", funcName))
			return nil
		}
		return fmt.Errorf("test passed but was expected to panic/fail. Output:\n%s", string(output))
	}
	if err != nil {
		return fmt.Errorf("test failed unexpectedly after patch. Error: %w. Output:\n%s", err, string(output))
	}
	return nil
}

// runFullTestSuite executes all tests.
func (d *Developer) runFullTestSuite(ctx context.Context, workspace string) error {
	d.logger.Info("Running full project test suite in workspace.")
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(testCtx, "go", "test", "-v", "-count=1", "./...")
	cmd.Dir = workspace
	output, err := cmd.CombinedOutput()

	if testCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("full test suite execution timed out")
	}
	if err != nil {
		return fmt.Errorf("full test suite failed. Error: %w. Output:\n%s", err, string(output))
	}
	return nil
}

// applyPatch uses 'git apply'.
func (d *Developer) applyPatch(ctx context.Context, workspace, patch string) error {
	d.logger.Info("Applying patch with 'git apply'.")
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("'git' command not found in PATH. Cannot apply patch")
	}
	cmd := exec.CommandContext(ctx, "git", "apply", "--verbose", "--3way", "-")
	cmd.Dir = workspace
	cmd.Stdin = strings.NewReader(patch)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git apply failed: %w. Output: %s", err, string(output))
	}
	return nil
}

// createPullRequest handles the Git workflow and creates the PR.
func (d *Developer) createPullRequest(ctx context.Context, workspace string, report PostMortem, analysis *AnalysisResult) error {
	d.logger.Info("Starting Git workflow and PR creation.")

	repo, err := git.PlainOpen(workspace)
	if err != nil {
		return fmt.Errorf("failed to open git repository in workspace: %w", err)
	}
	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	branchName := fmt.Sprintf("fix/autofix-%s-%s", report.IncidentID[:8], time.Now().Format("20060102T150405"))
	commitTitle := fmt.Sprintf("fix(autofix): Resolve panic in %s (Incident %s)", filepath.Base(report.FilePath), report.IncidentID[:8])
	commitBody := fmt.Sprintf("Automated fix for panic detected by scalpel-cli.\n\n**Incident ID:** %s\n**Panic Message:** `%s`\n\n**Root Cause Analysis (AI Generated):**\n%s\n\n**Confidence Score:** %.2f",
		report.IncidentID, report.PanicMessage, analysis.Explanation, analysis.Confidence)
	commitMessage := fmt.Sprintf("%s\n\n%s", commitTitle, commitBody)

	// FIX: The original logic failed because it tried to create a branch from the current
	// HEAD and then commit, but the working tree was already clean. The correct flow is
	// to add the changes, commit them, and then create the new branch pointing to that commit.
	if err := w.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		return fmt.Errorf("failed to stage changes: %w", err)
	}

	commitHash, err := w.Commit(commitMessage, &git.CommitOptions{
		Author: &object.Signature{
			Name:  d.gitConfig.AuthorName,
			Email: d.gitConfig.AuthorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to commit changes: %w", err)
	}

	branchRefName := plumbing.NewBranchReferenceName(branchName)
	newBranchRef := plumbing.NewHashReference(branchRefName, commitHash)
	if err := repo.Storer.SetReference(newBranchRef); err != nil {
		return fmt.Errorf("failed to create new branch reference '%s': %w", branchName, err)
	}

	d.logger.Info("Pushing branch to GitHub.", zap.String("branch", branchName))
	err = repo.PushContext(ctx, &git.PushOptions{
		RemoteName: "origin",
		Auth:       d.gitAuth,
		RefSpecs:   []gitconfig.RefSpec{gitconfig.RefSpec(fmt.Sprintf("+%s:%s", branchRefName, branchRefName))},
	})
	if err != nil {
		return fmt.Errorf("failed to push branch '%s' to remote: %w", branchName, err)
	}

	d.logger.Info("Creating Pull Request via GitHub API.")
	newPR := &github.NewPullRequest{
		Title:               github.String(commitTitle),
		Head:                github.String(branchName),
		Base:                github.String(d.ghConfig.BaseBranch),
		Body:                github.String(commitBody),
		MaintainerCanModify: github.Bool(true),
	}
	pr, _, err := d.githubClient.PullRequests.Create(ctx, d.ghConfig.RepoOwner, d.ghConfig.RepoName, newPR)
	if err != nil {
		return fmt.Errorf("failed to create GitHub Pull Request: %w", err)
	}

	d.logger.Info("Successfully created pull request.", zap.String("url", pr.GetHTMLURL()))
	return nil
}

// extractTestFuncName uses regex to find the name of a Go test function.
func extractTestFuncName(code string) string {
	re := regexp.MustCompile(`func\s+(Test[A-Za-z0-9_]+)\s*\(`)
	matches := re.FindStringSubmatch(code)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// cleanLLMCodeOutput removes common markdown artifacts from LLM responses.
func cleanLLMCodeOutput(code string) string {
	re := regexp.MustCompile("(?s)```(?:go(?:lang)?)?\\s*(.*?)```")
	matches := re.FindStringSubmatch(code)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return strings.TrimSpace(code)
}
