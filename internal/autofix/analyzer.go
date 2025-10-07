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

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Analyzer uses an LLM to analyze the source code and generate a patch.
type Analyzer struct {
	logger    *zap.Logger
	llmClient schemas.LLMClient
}

// NewAnalyzer initializes a new code analysis service.
func NewAnalyzer(logger *zap.Logger, llmClient schemas.LLMClient) *Analyzer {
	return &Analyzer{
		logger:    logger.Named("autofix-analyzer"),
		llmClient: llmClient,
	}
}

// GeneratePatch is the main entry point for Phase 2.
func (a *Analyzer) GeneratePatch(ctx context.Context, report PostMortem) (*AnalysisResult, error) {
	a.logger.Info("Starting analysis and patch generation (Phase 2)...", zap.String("incident_id", report.IncidentID))

	// 1. Retrieve source code.
	sourceCode, err := os.ReadFile(report.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read source code file '%s': %w", report.FilePath, err)
	}

	// 2. Construct prompt.
	prompt, err := a.constructPrompt(report, string(sourceCode))
	if err != nil {
		return nil, fmt.Errorf("failed to construct LLM prompt: %w", err)
	}

	// 3. Query the LLM.
	req := schemas.GenerationRequest{
		SystemPrompt: a.getSystemPrompt(),
		UserPrompt:   prompt,
		Tier:         schemas.TierPowerful,
		Options: schemas.GenerationOptions{
			ForceJSONFormat: true,
			Temperature:     0.1, // High precision required for fixes.
		},
	}

	response, err := a.llmClient.Generate(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("LLM generation failed: %w", err)
	}

	// 4. Parse response.
	result, err := a.parseLLMResponse(response)
	if err != nil {
		a.logger.Error("Failed to parse LLM response.", zap.Error(err), zap.String("raw_response", response))
		return nil, err
	}

	a.logger.Info("Patch generated successfully.", zap.Float64("confidence", result.Confidence))
	return result, nil
}

func (a *Analyzer) getSystemPrompt() string {
	return `You are an expert Go developer and security engineer. Your task is to analyze the provided code, crash report (post-mortem), and triggering request. You must generate a precise, minimal, and idiomatic patch to fix the root cause of the panic. Adhere strictly to Go best practices and provide your response in the required JSON format.`
}

// constructPrompt builds the comprehensive prompt.
func (a *Analyzer) constructPrompt(report PostMortem, sourceCode string) (string, error) {
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}

	// Ensure file paths use forward slashes for git diff compatibility.
	filePathForDiff := filepath.ToSlash(report.FilePath)

	return fmt.Sprintf(`
Analyze the following Go code and crash report.

**Objective:**
1.  Identify the precise root cause of the panic.
2.  Explain the bug and the proposed fix.
3.  Assess the confidence score (0.0 to 1.0) of the fix.
4.  Generate a patch in the standard 'git diff' (unified) format. The patch MUST be relative to the project root.

**Post-Mortem Report:**
%s

**Source Code (%s):**
`+"```go"+`
%s
`+"```"+`

**Response Format (Strict JSON):**
{
  "explanation": "Markdown explanation of the bug and fix.",
  "root_cause": "A concise description of the issue (e.g., 'Nil pointer dereference').",
  "confidence": 0.95,
  "patch": "The 'git diff' formatted patch string."
}

Example patch format within the JSON:
"patch": "--- a/%s\n+++ b/%s\n@@ -10,6 +10,9 @@ func MyFunction(input *MyStruct) {\n+    if input == nil {\n+        // Handle nil input\n+        return\n+    }\n     input.DoSomething()\n }"
`, string(reportJSON), report.FilePath, sourceCode, filePathForDiff, filePathForDiff), nil
}

// patchRegex extracts content if the LLM mistakenly wraps the patch in markdown.
var patchRegex = regexp.MustCompile("(?s)```(?:diff|patch)?\\s*(.*?)```")

// parseLLMResponse extracts the structured data from the LLM's JSON output.
func (a *Analyzer) parseLLMResponse(response string) (*AnalysisResult, error) {
	var result AnalysisResult
	// Clean potential markdown artifacts around the JSON.
	response = strings.TrimSpace(response)
	response = strings.TrimPrefix(response, "```json")
	response = strings.TrimSuffix(response, "```")

	if err := json.Unmarshal([]byte(response), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LLM JSON response: %w", err)
	}

	// Sanitize the patch if wrapped in markdown.
	result.Patch = strings.TrimSpace(result.Patch)
	if strings.HasPrefix(result.Patch, "```") {
		matches := patchRegex.FindStringSubmatch(result.Patch)
		if len(matches) > 1 {
			result.Patch = strings.TrimSpace(matches[1])
		}
	}

	// Validate required fields.
	if result.Explanation == "" || result.Patch == "" || result.RootCause == "" {
		return nil, fmt.Errorf("LLM response is missing required fields (explanation, patch, or root_cause)")
	}

	// Validate patch format (basic check for unified diff headers).
	if !strings.HasPrefix(result.Patch, "--- a/") || !strings.Contains(result.Patch, "+++ b/") {
		return nil, fmt.Errorf("LLM response 'patch' field is not in unified diff format. Patch:\n%s", result.Patch)
	}

	// Validate and clamp confidence score.
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