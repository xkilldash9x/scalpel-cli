// internal/autofix/metalyst/metalyst.go
package metalyst

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/autofix/coroner"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/llmutil"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// Metalyst (Meta-Analyst) orchestrates the self-healing process for the scalpel-cli tool itself.
type Metalyst struct {
	logger      *zap.Logger
	cfg         *config.Config
	llmClient   schemas.LLMClient
	coroner     *coroner.Parser
	projectRoot string
}

// AnalysisResult holds the response from the LLM.
type AnalysisResult struct {
	Explanation string  `json:"explanation"`
	RootCause   string  `json:"root_cause"`
	Confidence  float64 `json:"confidence"`
	Patch       string  `json:"patch"`
}

// NewMetalyst initializes the self-healing orchestrator.
func NewMetalyst(cfg *config.Config, llmClient schemas.LLMClient) (*Metalyst, error) {
	// Let's get the global logger instance.
	logger := observability.GetLogger()

	// Determine the project root. This is crucial for applying patches and recompiling.
	projectRoot, err := determineProjectRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine project root. Ensure git is installed or run from the repository root: %w", err)
	}

	logger.Info("Metalyst initialized.", zap.String("project_root", projectRoot))

	return &Metalyst{
		// We'll create a named child logger for this specific component.
		// Makes filtering logs way easier down the road.
		logger:      logger.Named("metalyst"),
		cfg:         cfg,
		llmClient:   llmClient,
		coroner:     coroner.NewParser(),
		projectRoot: projectRoot,
	}, nil
}

// determineProjectRoot tries to find the root of the repository.
func determineProjectRoot() (string, error) {
	// Strategy 1: Try using git
	if _, err := exec.LookPath("git"); err == nil {
		cmd := exec.Command("git", "rev-parse", "--show-toplevel")
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output)), nil
		}
	}

	// Strategy 2: Fallback to finding go.mod by walking up from CWD.
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // Reached the root filesystem
		}
		dir = parent
	}

	return "", fmt.Errorf("could not find project root (no git repository or go.mod found in CWD or parent directories)")
}

// Run executes the self-healing workflow.
func (m *Metalyst) Run(ctx context.Context, panicLogPath string, originalArgs []string) error {
	m.logger.Info("Starting self-healing workflow.", zap.String("panic_log", panicLogPath))

	// Step 1.3 (Using 1.2): Diagnose - Parse the panic log
	report, err := m.coroner.ParseFile(panicLogPath)
	if err != nil {
		return fmt.Errorf("failed to parse panic log: %w", err)
	}

	// Path Normalization
	normalizedPath, localPath, err := m.normalizePath(report.FilePath)
	if err != nil {
		m.logger.Error("Could not normalize crash path to local project structure. Aborting.", zap.Error(err))
		return fmt.Errorf("path normalization failed: %w", err)
	}
	m.logger.Info("Path normalized.", zap.String("relative_path", normalizedPath), zap.String("local_path", localPath))

	report.FilePath = normalizedPath // Use relative path for prompt/patch

	// Step 1.3: Diagnose - Analyze and generate patch
	analysis, err := m.analyzeAndGeneratePatch(ctx, report, localPath)
	if err != nil {
		return fmt.Errorf("failed to analyze crash and generate patch: %w", err)
	}
	m.logger.Info("Patch generated.", zap.Float64("confidence", analysis.Confidence))

	// Step 1.4: The Surgeon - Apply and Validate
	if err := m.applyAndValidate(ctx, analysis, originalArgs); err != nil {
		m.logger.Error("Failed to apply and validate fix. Changes reverted.", zap.Error(err))
		m.logFailedAttempt(report, analysis, err)
		return fmt.Errorf("validation failed: %w", err)
	}

	// Step 1.4 Success: Commit the fix
	if err := m.commitFix(analysis); err != nil {
		m.logger.Error("Failed to commit the validated fix. Fix is applied locally but not committed.", zap.Error(err))
	} else {
		m.logger.Info("Self-healing successful. Fix applied, validated, and committed.")
	}

	// Clean up the panic log file
	_ = os.Remove(panicLogPath)
	return nil
}

// normalizePath maps an absolute path from a stack trace to the relative path within the local project root,
// and also returns the absolute local path to the file. Uses heuristics for environment discrepancies.
func (m *Metalyst) normalizePath(crashPath string) (normalizedRelativePath string, localAbsolutePath string, err error) {
	// 1. Handle already relative paths
	if !filepath.IsAbs(crashPath) {
		localPath := filepath.Join(m.projectRoot, crashPath)
		if _, err := os.Stat(localPath); err == nil {
			return filepath.ToSlash(crashPath), localPath, nil
		}
	}

	// 2. Check if the absolute path matches the local structure directly.
	if _, err := os.Stat(crashPath); err == nil {
		relPath, err := filepath.Rel(m.projectRoot, crashPath)
		if err == nil && !strings.HasPrefix(relPath, "..") {
			return filepath.ToSlash(relPath), crashPath, nil
		}
	}

	// 3. Heuristic: Search the project structure if absolute paths differ.
	m.logger.Info("Absolute path mismatch detected. Attempting heuristic path resolution.", zap.String("crash_path", crashPath))
	crashFileName := filepath.Base(crashPath)
	var potentialMatches []string

	// Walk the project directory
	walkErr := filepath.Walk(m.projectRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			name := info.Name()
			if name == "vendor" || name == ".git" || name == "bin" {
				return filepath.SkipDir
			}
			return nil
		}

		if info.Name() == crashFileName {
			potentialMatches = append(potentialMatches, path)
		}
		return nil
	})

	if walkErr != nil {
		m.logger.Warn("Error during path normalization search.", zap.Error(walkErr))
	}

	// Handle search results
	if len(potentialMatches) == 1 {
		localPath := potentialMatches[0]
		relPath, err := filepath.Rel(m.projectRoot, localPath)
		if err == nil {
			m.logger.Info("Normalized path using heuristic search.", zap.String("original", crashPath), zap.String("normalized", relPath))
			return filepath.ToSlash(relPath), localPath, nil
		}
	}

	if len(potentialMatches) > 1 {
		return "", "", fmt.Errorf("found multiple potential matches (%d) for '%s'. Cannot reliably normalize path. Matches: %v", len(potentialMatches), crashFileName, potentialMatches)
	}

	return "", "", fmt.Errorf("could not find local file corresponding to crash path '%s' in project root '%s'", crashPath, m.projectRoot)
}

// --- Step 1.3: The Diagnostician (Analysis) ---

// analyzeAndGeneratePatch takes the normalized report and the local absolute path to the source file.
func (m *Metalyst) analyzeAndGeneratePatch(ctx context.Context, report *coroner.IncidentReport, localSourcePath string) (*AnalysisResult, error) {
	// Read the source code (Step 1.3 Logic)
	sourceCode, err := os.ReadFile(localSourcePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read source code file '%s' (local path: %s): %w", report.FilePath, localSourcePath, err)
	}

	// Construct the prompt (Step 1.3 Logic)
	prompt := m.constructPrompt(report, string(sourceCode))

	// Call the LLM
	req := schemas.GenerationRequest{
		SystemPrompt: m.getSystemPrompt(),
		UserPrompt:   prompt,
		Tier:         schemas.TierPowerful,
		Options: schemas.GenerationOptions{
			ForceJSONFormat: true,
			Temperature:     llmutil.Float64Ptr(0.1),
		},
	}

	analysisCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	response, err := m.llmClient.Generate(analysisCtx, req)
	if err != nil {
		return nil, fmt.Errorf("LLM generation failed: %w", err)
	}

	// Parse the response
	return m.parseLLMResponse(response)
}

func (m *Metalyst) getSystemPrompt() string {
	return `You are the 'Metalyst', an expert Go developer AI specialized in debugging and self-healing the 'scalpel-cli' application.
Your task is to analyze the provided Go source code context, the precise panic report, and the full stack trace.
You must generate a minimal, idiomatic, and robust patch to fix the root cause of the panic.
Adhere strictly to Go best practices.
Your response must be in the required JSON format. The patch must be in unified diff format (git diff), using the relative file paths provided.
Ensure patch headers use 'a/' and 'b/' prefixes.`
}

func (m *Metalyst) constructPrompt(report *coroner.IncidentReport, sourceCode string) string {
	// report.FilePath is already normalized (relative).
	relFilePath := report.FilePath
	contextLines := extractCodeContext(sourceCode, report.LineNumber, 15)

	// Construct the prompt (Step 1.3 Logic)
	return fmt.Sprintf(`
The 'scalpel-cli' application panicked. Analyze the report and source code to generate a fix.

**Objective:**
1. Identify the precise root cause of the panic.
2. Explain the bug and the proposed fix concisely.
3. Assess the confidence score (0.0 to 1.0) of the fix.
4. Generate a patch in standard 'git diff' (unified) format. The patch MUST use the relative file path provided.

**Panic Details:**
- Message: %s
- File (Relative Path for Patch): %s
- Line: %d
- Function: %s

**Full Stack Trace:**
`+"```"+`
%s
`+"```"+`

**Relevant Source Code Context (Around Line %d in %s):**
`+"```go"+`
%s
`+"```"+`

**Response Format (Strict JSON):**
{
  "explanation": "Explanation of the bug and fix.",
  "root_cause": "Concise description (e.g., 'Nil pointer dereference on config struct').",
  "confidence": 0.95,
  "patch": "The 'git diff' formatted patch string."
}

Example patch format within the JSON (ensure paths start with a/ and b/):
"patch": "--- a/%s\n+++ b/%s\n@@ -40,7 +40,9 @@ func InitializeConfig() error {\n     // existing code\n+    if viper.GetViper() == nil {\n+        return fmt.Errorf(\"Viper not initialized\")\n+    }\n     // more code\n }"
`,
		report.Message, relFilePath, report.LineNumber, report.FunctionName,
		report.StackTrace,
		report.LineNumber, relFilePath, contextLines,
		relFilePath, relFilePath,
	)
}

// Helper to extract context (similar logic exists in internal/autofix/analyzer.go)
func extractCodeContext(sourceCode string, lineNum int, contextSize int) string {
	lines := strings.Split(sourceCode, "\n")

	// Remove the trailing empty string if the source ends with a newline
	// to prevent off-by-one errors in line count.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if lineNum <= 0 || lineNum > len(lines) {
		return "// Context unavailable: Invalid line number."
	}

	// Calculate the starting and ending lines for the context window.
	start := lineNum - contextSize/2 - 1
	if start < 0 {
		start = 0
	}
	end := start + contextSize
	if end > len(lines) {
		end = len(lines)
	}
	if end-start < contextSize && start > 0 {
		start = end - contextSize
		if start < 0 {
			start = 0
		}
	}

	// Determine the max width needed for line number alignment dynamically.
	// This is based on the highest line number we are going to display.
	maxLineNum := end
	if maxLineNum == 0 { // handle empty source
		return ""
	}
	lineWidth := int(math.Log10(float64(maxLineNum))) + 1

	var contextLines []string
	for i := start; i < end; i++ {
		var prefix string
		currentLineNum := i + 1

		if currentLineNum == lineNum {
			// Highlighted line: "-> [N]: "
			prefix = fmt.Sprintf("-> %*d: ", lineWidth, currentLineNum)
		} else {
			// Context line: "   [N]: " (3 spaces to align with "-> ")
			prefix = fmt.Sprintf("   %*d: ", lineWidth, currentLineNum)
		}
		contextLines = append(contextLines, prefix+lines[i])
	}
	return strings.Join(contextLines, "\n")
}

var patchRegex = regexp.MustCompile("(?s)```(?:diff|patch)?\\s*(.*?)```")

func (m *Metalyst) parseLLMResponse(response string) (*AnalysisResult, error) {
	var result AnalysisResult
	response = strings.TrimSpace(response)
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
		response = strings.TrimSuffix(response, "```")
	}
	response = strings.TrimSpace(response)

	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LLM JSON response: %w. Raw response (truncated): %.500s", err, response)
	}

	// If the patch is wrapped in a markdown block, extract its content.
	if strings.HasPrefix(result.Patch, "```") {
		matches := patchRegex.FindStringSubmatch(result.Patch)
		if len(matches) > 1 {
			// Normalize the patch: trim whitespace, then ensure one trailing newline.
			// This is robust against LLM formatting quirks.
			result.Patch = strings.TrimSpace(matches[1]) + "\n"
		}
	}

	if result.Patch == "" || result.RootCause == "" {
		return nil, fmt.Errorf("LLM response is missing required fields (patch or root_cause)")
	}

	if !strings.HasPrefix(result.Patch, "--- a/") || !strings.Contains(result.Patch, "+++ b/") {
		return nil, fmt.Errorf("LLM response 'patch' field is not in valid unified diff format. Patch:\n%s", result.Patch)
	}

	return &result, nil
}

// --- Step 1.4: The Surgeon (Patching & Validation) ---

func (m *Metalyst) applyAndValidate(ctx context.Context, analysis *AnalysisResult, originalArgs []string) error {
	// Step 1.4 Logic: Apply the patch
	if err := m.applyPatch(analysis.Patch); err != nil {
		return fmt.Errorf("failed to apply patch: %w", err)
	}

	validationSucceeded := false

	// Ensure we revert the changes if validation fails (Step 1.4 Failure)
	defer func() {
		if !validationSucceeded {
			m.logger.Info("Validation did not succeed, reverting changes.")
			if err := m.revertPatch(analysis.Patch); err != nil {
				m.logger.Error("CRITICAL: Failed to revert patch automatically. Manual intervention required.", zap.Error(err))
			}
		}
	}()

	// Step 1.4 Logic: Recompile the binary
	m.logger.Info("Recompiling binary...")
	// Compile to a temporary location for safety.
	binaryPath, err := m.recompile(ctx)
	if err != nil {
		return fmt.Errorf("recompilation failed: %w", err)
	}
	defer os.Remove(binaryPath) // Clean up the temporary binary
	m.logger.Info("Recompilation successful.", zap.String("temp_binary_path", binaryPath))

	// Step 1.4 Logic: Re-run the original command
	m.logger.Info("Validating fix by re-running original command...", zap.Strings("args", originalArgs))
	if err := m.validateFix(ctx, binaryPath, originalArgs); err != nil {
		return fmt.Errorf("fix validation failed: %w", err)
	}

	// Success
	validationSucceeded = true
	return nil
}

func (m *Metalyst) applyPatch(patchContent string) error {
	// Use 'git apply'.
	cmd := exec.Command("git", "apply", "-v", "-")
	cmd.Dir = m.projectRoot
	cmd.Stdin = strings.NewReader(patchContent)

	if output, err := cmd.CombinedOutput(); err != nil {
		m.logger.Error("Git apply failed.", zap.String("output", string(output)))
		return fmt.Errorf("git apply failed: %w. Output: %s", err, string(output))
	}
	m.logger.Info("Patch applied successfully.")
	return nil
}

func (m *Metalyst) revertPatch(patchContent string) error {
	m.logger.Info("Attempting to revert patch...")
	// Use 'git apply -R'.
	cmd := exec.Command("git", "apply", "-R", "-v", "-")
	cmd.Dir = m.projectRoot
	cmd.Stdin = strings.NewReader(patchContent)

	if output, err := cmd.CombinedOutput(); err != nil {
		m.logger.Error("Git apply -R (revert) failed.", zap.String("output", string(output)))
		return fmt.Errorf("git revert failed: %w. Output: %s", err, string(output))
	}
	m.logger.Info("Patch reverted successfully.")
	return nil
}

func (m *Metalyst) recompile(ctx context.Context) (string, error) {
	// Define the output path for the new binary
	outputPath := filepath.Join(m.projectRoot, "scalpel-cli-fixed-validation")
	if runtime.GOOS == "windows" {
		outputPath += ".exe"
	}

	// The main entry point of the application
	mainPath := "./cmd/scalpel"

	cmd := exec.CommandContext(ctx, "go", "build", "-o", outputPath, mainPath)
	cmd.Dir = m.projectRoot
	cmd.Env = os.Environ()

	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build failed: %w. Output: %s", err, string(output))
	}

	return outputPath, nil
}

func (m *Metalyst) validateFix(ctx context.Context, binaryPath string, originalArgs []string) error {
	// Step 1.4 Logic: Add the special --validate-fix flag
	args := append(originalArgs, "--validate-fix")

	validationCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(validationCtx, binaryPath, args...)
	// Crucially: Run the command from the original working directory where the crash occurred.
	cwd, _ := os.Getwd()
	cmd.Dir = cwd
	cmd.Env = os.Environ()

	// Capture output for debugging.
	output, err := cmd.CombinedOutput()

	if err != nil {
		// A non-zero exit code means the fix was insufficient (either panicked again or returned an error).
		m.logger.Warn("Validation run failed (exited with error).", zap.Error(err), zap.String("output", string(output)))
		return fmt.Errorf("validation command failed: %w. Output: %s", err, string(output))
	}

	m.logger.Info("Validation run completed successfully (exited with 0).")
	return nil
}

func (m *Metalyst) commitFix(analysis *AnalysisResult) error {
	m.logger.Info("Committing the fix...")
	// Stage changes.
	cmdAdd := exec.Command("git", "add", ".")
	cmdAdd.Dir = m.projectRoot
	if output, err := cmdAdd.CombinedOutput(); err != nil {
		return fmt.Errorf("git add failed: %w. Output: %s", err, string(output))
	}

	// FIX: Explicitly round confidence to 2 decimal places to avoid floating point inconsistencies.
	confidence := math.Round(analysis.Confidence*100) / 100
	commitMsg := fmt.Sprintf("fix: [Auto-Heal] %s\n\nConfidence: %.2f\nExplanation: %s", analysis.RootCause, confidence, analysis.Explanation)
	cmdCommit := exec.Command("git", "commit", "-m", commitMsg)
	cmdCommit.Dir = m.projectRoot

	if output, err := cmdCommit.CombinedOutput(); err != nil {
		return fmt.Errorf("git commit failed (ensure git identity is configured): %w. Output: %s", err, string(output))
	}
	m.logger.Info("Fix committed successfully.")
	return nil
}

func (m *Metalyst) logFailedAttempt(report *coroner.IncidentReport, analysis *AnalysisResult, err error) {
	// Placeholder for logging failed attempts (Step 1.4 Failure)
	m.logger.Warn("Self-healing attempt failed and logged for review.",
		zap.String("file", report.FilePath),
		zap.String("root_cause_guess", analysis.RootCause),
		zap.NamedError("validation_error", err))
}
