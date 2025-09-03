// -- pkg/results/report.go --
package results

import (
	"encoding/json"
	"time"
)

// Report is the final, structured output of the pipeline.
type Report struct {
	ScanID      string               `json:"scan_id"`
	GeneratedAt time.Time            `json:"generated_at"`
	Summary     map[string]int       `json:"summary"`
	Findings    []PrioritizedFinding `json:"findings"`
}

// GenerateReport creates the final report from prioritized findings.
func GenerateReport(findings []PrioritizedFinding, scanID string) (*Report, error) {
	summary := make(map[string]int)
	for _, f := range findings {
		summary[f.Severity]++
	}

	return &Report{
		ScanID:      scanID,
		GeneratedAt: time.Now().UTC(),
		Summary:     summary,
		Findings:    findings,
	}, nil
}

// ToJSON converts the report to a JSON string.
func (r *Report) ToJSON() (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
