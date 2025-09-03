// -- pkg/results/prioritize.go --
package results

import "sort"

// PrioritizedFinding adds a calculated score to a finding.
type PrioritizedFinding struct {
	NormalizedFinding
	Score float64
}

// Prioritize scores and sorts findings based on their attributes.
func Prioritize(findings []NormalizedFinding) []PrioritizedFinding {
	prioritized := make([]PrioritizedFinding, len(findings))

	severityScores := map[string]float64{
		"Critical": 100.0,
		"High":     80.0,
		"Medium":   50.0,
		"Low":      20.0,
		"Info":     5.0,
	}

	for i, f := range findings {
		score := severityScores[f.Severity]

		// Add bonus points for confirmed findings (e.g., from taint analysis).
		if strings.Contains(f.Description, "[CONFIRMED EXECUTION]") {
			score *= 1.5
		}

		prioritized[i] = PrioritizedFinding{
			NormalizedFinding: f,
			Score:             score,
		}
	}

	// Sort findings from highest score to lowest.
	sort.Slice(prioritized, func(i, j int) bool {
		return prioritized[i].Score > prioritized[j].Score
	})

	return prioritized
}
