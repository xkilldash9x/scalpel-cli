// -- pkg/results/pipeline.go --
package results

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldashx/evolution-scalpel/pkg/store"
)

// Pipeline orchestrates the post-processing of scan findings.
type Pipeline struct {
	store  *store.Store
	logger *zap.Logger
}

// NewPipeline creates a new results processing pipeline.
func NewPipeline(store *store.Store, logger *zap.Logger) *Pipeline {
	return &Pipeline{
		store:  store,
		logger: logger.Named("results-pipeline"),
	}
}

// ProcessScanResults runs the full post-processing workflow for a given scan.
func (p *Pipeline) ProcessScanResults(ctx context.Context, scanID string) (*Report, error) {
	p.logger.Info("Starting results processing pipeline", zap.String("scan_id", scanID))

	// 1. Ingestion: Fetch raw findings from the database.
	rawFindings, err := p.store.GetFindingsByScanID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest findings from store: %w", err)
	}
	p.logger.Debug("Ingested raw findings", zap.Int("count", len(rawFindings)))

	// 2. Normalization: Convert raw findings into a consistent internal format.
	normalizedFindings := Normalize(rawFindings)
	p.logger.Debug("Normalized findings")

	// 3. Enrichment: Add context from external sources or heuristics.
	enrichedFindings, err := Enrich(ctx, normalizedFindings, p.logger)
	if err != nil {
		// Log the error but continue processing with what we have.
		p.logger.Warn("An error occurred during enrichment", zap.Error(err))
	}
	p.logger.Debug("Enriched findings")

	// 4. Prioritization: Score and rank the findings based on severity, confidence, and context.
	prioritizedFindings := Prioritize(enrichedFindings)
	p.logger.Debug("Prioritized findings")

	// 5. Reporting: Generate the final, human-readable report.
	report, err := GenerateReport(prioritizedFindings, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate final report: %w", err)
	}
	p.logger.Info("Successfully generated report", zap.Int("total_findings", len(report.Findings)))

	return report, nil
}
