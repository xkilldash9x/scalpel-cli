// -- pkg/results/prioritize.go --
package results

import "sort"

// PrioritizedFinding adds a calculated score to a finding.
type PrioritizedFinding struct {
	NormalizedFinding
	Score float64
}

// REFACTORED (Architecture): ScoreConfig holds the injectable parameters for scoring findings.
type ScoreConfig struct {
	SeverityWeights        map[string]float64
	ConfirmedBonusMultiplier float64
}

// Prioritize scores and sorts findings based on the provided configuration.
// REFACTORED: The function now accepts a ScoreConfig struct for flexibility and testability.
func Prioritize(findings []NormalizedFinding, config ScoreConfig) []PrioritizedFinding {
	prioritized := make([]PrioritizedFinding, len(findings))

	for i, f := range findings {
		// Use the injected severity weights. Default to 0 if severity is unknown.
		score := config.SeverityWeights[f.Severity]

		// REFACTORED (Architecture): Use the structured 'IsConfirmed' field instead of string matching.
		if f.IsConfirmed {
			// Use the injected multiplier.
			score *= config.ConfirmedBonusMultiplier
		}

		prioritized[i] = PrioritizedFinding{
			NormalizedFinding: f,
			Score:             score,
		}
	}

	// REFACTORED (Readability/Determinism): Use a stable sort to ensure consistent ordering
	// for findings with the same score.
	sort.SliceStable(prioritized, func(i, j int) bool {
		return prioritized[i].Score > prioritized[j].Score
	})

	return prioritized
}