// -- pkg/results/report.go --
package results

import (
	"encoding/json"
	"io"
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

// REFACTORED (Performance): WriteJSON streams the report to an io.Writer.
// This is significantly more memory-efficient for large reports than marshaling to a string.
func (r *Report) WriteJSON(w io.Writer) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

// ToJSONBytes marshals the report to a byte slice. Use this when the full
// payload must be held in memory.
func (r *Report) ToJSONBytes() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}