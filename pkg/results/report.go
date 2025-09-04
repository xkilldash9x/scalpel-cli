package results

import "fmt"

// GenerateReport compiles the final list of prioritized findings into a Report struct.
// It also creates a textual summary of the results.
func GenerateReport(findings []NormalizedFinding) (*Report, error) {
	summary := fmt.Sprintf("Generated report with %d prioritized findings.", len(findings))

	report := &Report{
		Findings: findings,
		Summary:  summary,
	}

	return report, nil
}
