package results

import (
	"fmt"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// RunPipeline orchestrates the entire results processing flow:
// 1. Normalizes raw findings into a standard format.
// 2. Prioritizes the normalized findings based on a scoring configuration.
// 3. Generates a final, comprehensive report.
func RunPipeline(findings []schemas.Finding, config ScoreConfig) (*Report, error) {
	// Step 1: Normalize each finding
	var normalizedFindings []NormalizedFinding
	for _, f := range findings {
		// The conversion happens here, wrapping the original finding
		normalizedFinding := Normalize(f)
		normalizedFindings = append(normalizedFindings, normalizedFinding)
	}

	// Step 2: Prioritize the list of normalized findings
	prioritizedFindings, err := Prioritize(normalizedFindings, config)
	if err != nil {
		return nil, fmt.Errorf("error prioritizing findings: %w", err)
	}

	// Step 3: Generate the final report
	report, err := GenerateReport(prioritizedFindings)
	if err != nil {
		return nil, fmt.Errorf("error generating report: %w", err)
	}

	return report, nil
}
