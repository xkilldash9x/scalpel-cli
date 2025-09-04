package results

import (
	"sort"
)

// Prioritize sorts a slice of NormalizedFinding based on a calculated score.
// The score is determined by weights defined in the ScoreConfig. This allows for
// a flexible reordering of findings based on their perceived importance.
func Prioritize(findings []NormalizedFinding, config ScoreConfig) ([]NormalizedFinding, error) {
	// First, calculate the score for each finding
	for i := range findings {
		if weight, ok := config.SeverityWeights[findings[i].NormalizedSeverity]; ok {
			findings[i].Score = weight
		} else {
			findings[i].Score = 0.0 // Default score for unknown severities
		}
	}

	// Now, sort the findings slice in-place based on the calculated score
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Score > findings[j].Score
	})

	return findings, nil
}
