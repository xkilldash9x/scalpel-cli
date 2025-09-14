package results

import (
	"context"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Defines the parameters for the prioritization process.
type ScoreConfig struct {
	// Keys should correspond to the canonical StandardSeverity strings.
	SeverityWeights map[string]float64
}

// Defines an interface for CWE data retrieval.
// REFACTORED: Updated interface to accept context.Context for cancellation/timeout propagation.
type CWEProvider interface {
	GetFullName(ctx context.Context, cweID string) (string, bool)
}

// Holds all configuration required for the results pipeline.
// REFACTORED: Introduced to centralize configuration and dependencies.
type PipelineConfig struct {
	ScoreConfig ScoreConfig
	// CWEProvider is optional. If nil, enrichment will be skipped.
	CWEProvider CWEProvider
}

// Represents a finding that has been standardized.
type NormalizedFinding struct {
	schemas.Finding
	Score              float64
	NormalizedSeverity string
}
