// internal/autofix/analyzer.go
package autofix

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Analyzer uses an LLM to analyze the source code and generate a patch.
type Analyzer struct {
	logger      *zap.Logger
	llmClient   schemas.LLMClient
	projectRoot string
}

// NewAnalyzer initializes a new code analysis service.
func NewAnalyzer(logger *zap.Logger, llmClient schemas.LLMClient, projectRoot string) *Analyzer { // This is a comment to force a change
	return &Analyzer{
		logger:      logger.Named("autofix-analyzer"),
		llmClient:   llmClient,
		projectRoot: projectRoot,
	}
}

// GeneratePatch is the main entry point for Phase 2.
func (a *Analyzer) GeneratePatch(ctx context.Context, report PostMortem) (*AnalysisResult, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	a.logger.Info("Starting analysis and patch generation (Phase 2)...", zap.String("incident_id", report.IncidentID))

	filePath := report.FilePath
	if !filepath.IsAbs(filePath) && a.projectRoot != "" {
		filePath = filepath.Join(a.projectRoot, filePath)
	}

	sourceCode, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read source code file '%s' (resolved path: %s): %w", report.FilePath, filePath, err)
	}

	prompt, err := a.constructPrompt(report, string(sourceCode))
	if err != nil {
		return nil, fmt.Errorf("failed to construct LLM prompt: %w", err)
	}

	req := schemas.GenerationRequest{
		SystemPrompt: a.getSystemPrompt(),
		UserPrompt:   prompt,
		Tier:         schemas.TierPowerful,
		Options: schemas.GenerationOptions{
			ForceJSONFormat: true,
			Temperature:     0.1,
		},
	}

	analysisCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	response, err := a.llmClient.Generate(analysisCtx, req)
	if err != nil {
		return nil, fmt.Errorf("LLM generation failed: %w", err)
	}

	result, err := a.parseLLMResponse(response)
	if err != nil {
		a.logger.Error("Failed to parse LLM response.", zap.Error(err), zap.String("raw_response", response))
		return nil, err
	}

	a.logger.Info("Patch generated successfully.", zap.Float64("confidence", result.Confidence))
	return result, nil
}

func (a *Analyzer) getSystemPrompt() string {
	return `You are an expert Go developer and debugging assistant. Your task is to analyze the provided Go source code context, crash report, and stack trace. You must generate a precise, minimal, and idiomatic patch to fix the root cause of the panic. Adhere strictly to Go best practices. Your response must be in the required JSON format, and the patch must be in unified diff format.`
}

// constructPrompt builds the comprehensive prompt.
func (a *Analyzer) constructPrompt(report PostMortem, sourceCode string) (string, error) {
	filePathForDiff := filepath.ToSlash(report.FilePath)
	contextLines := extractCodeContext(sourceCode, report.LineNumber, 5) // Use a smaller context size for the prompt

	return fmt.Sprintf(`
	Analyze the following Go code and crash report.
	
	**Objective:**
	1.  Identify the precise root cause of the panic.
	2.  Explain the bug and the proposed fix.
	3.  Assess the confidence score (0.0 to 1.0) of the fix.
	4.  Generate a patch in the standard 'git diff' (unified) format. The patch MUST be relative to the project root.
	
	**Crash Details:**
	- Panic Message: %s
	- File: %s
	- Line: %d
	
	**Stack Trace:**
	`+"```\n%s\n```"+`
	
	**Relevant Source Code Context (Around Line %d):**
	`+"```go\n%s\n```"+`
	
	**Response Format (Strict JSON):**
	{
	  "explanation": "Markdown explanation of the bug and fix.",
	  "root_cause": "A concise description of the issue (e.g., 'Nil pointer dereference').",
	  "confidence": 0.95,
	  "patch": "The 'git diff' formatted patch string."
	}
	
	Example patch format within the JSON:
	"patch": "--- a/%s\n+++ b/%s\n@@ -10,6 +10,9 @@ func MyFunction(input *MyStruct) {\n+    if input == nil {\n+        // Handle nil input\n+        return\n+    }\n     input.DoSomething()\n }"
	`, report.PanicMessage, report.FilePath, report.LineNumber, report.FullStackTrace, report.LineNumber, contextLines, filePathForDiff, filePathForDiff), nil
}

// patchRegex extracts content if the LLM mistakenly wraps the patch in markdown.
var patchRegex = regexp.MustCompile("(?s)```(?:diff|patch)?\\s*(.*?)```")

// parseLLMResponse extracts the structured data from the LLM's JSON output.
func (a *Analyzer) parseLLMResponse(response string) (*AnalysisResult, error) {
	var result AnalysisResult
	response = strings.TrimSpace(response)
	response = strings.TrimPrefix(response, "```json")
	response = strings.TrimSuffix(response, "```")

	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LLM JSON response: %w", err)
	}

	result.Patch = strings.TrimSpace(result.Patch)
	if strings.HasPrefix(result.Patch, "```") {
		matches := patchRegex.FindStringSubmatch(result.Patch)
		if len(matches) > 1 {
			result.Patch = strings.TrimSpace(matches[1])
		}
	}

	if result.Explanation == "" || result.Patch == "" || result.RootCause == "" {
		return nil, fmt.Errorf("LLM response is missing required fields (explanation, patch, or root_cause)")
	}

	if !strings.HasPrefix(result.Patch, "--- a/") || !strings.Contains(result.Patch, "+++ b/") {
		return nil, fmt.Errorf("LLM response 'patch' field is not in unified diff format. Patch:\n%s", result.Patch)
	}

	if result.Confidence <= 0.0 || result.Confidence > 1.0 {
		a.logger.Warn("Invalid confidence score received, clamping to range.", zap.Float64("received_confidence", result.Confidence))
		if result.Confidence <= 0.0 {
			result.Confidence = 0.01
		} else {
			result.Confidence = 1.0
		}
	}
	return &result, nil
}

// extractCodeContext extracts lines around the panic location.
func extractCodeContext(sourceCode string, lineNum int, contextSize int) string {
	lines := strings.Split(sourceCode, "\n")
	if lineNum <= 0 || lineNum > len(lines) {
		return "// Context unavailable: Invalid line number."
	}
	start := lineNum - contextSize/2 - 1
	if start < 0 {
		start = 0
	}
	// FIX: Corrected the end boundary calculation.
	end := start + contextSize
	if end > len(lines) {
		end = len(lines)
	}
	var contextLines []string
	for i := start; i < end; i++ {
		prefix := fmt.Sprintf("%4d: ", i+1)
		if i+1 == lineNum {
			prefix = fmt.Sprintf("->%2d: ", i+1) // Highlight the specific line
		}
		contextLines = append(contextLines, prefix+lines[i])
	}
	return strings.Join(contextLines, "\n")
}
