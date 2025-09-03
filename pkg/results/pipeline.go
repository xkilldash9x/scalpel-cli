// -- pkg/results/pipeline.go --
package results

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// REFACTORED (Architecture): Define an interface for data storage.
// This decouples the pipeline from the concrete store.Store implementation.
type FindingStorer interface {
	GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error)
}

// Pipeline orchestrates the post-processing of scan findings.
// REFACTORED: Now holds interfaces and configurations for dependency injection.
type Pipeline struct {
	store       FindingStorer
	cweProvider CWEProvider
	scoreConfig ScoreConfig
	logger      *zap.Logger
}

// NewPipeline creates a new results processing pipeline.
// REFACTORED: The constructor now accepts dependencies (interfaces and config).
func NewPipeline(store FindingStorer, provider CWEProvider, config ScoreConfig, logger *zap.Logger) *Pipeline {
	return &Pipeline{
		store:       store,
		cweProvider: provider,
		scoreConfig: config,
		logger:      logger.Named("results-pipeline"),
	}
}

// ProcessScanResults runs the full post-processing workflow for a given scan.
func (p *Pipeline) ProcessScanResults(ctx context.Context, scanID string) (*Report, error) {
	p.logger.Info("Starting results processing pipeline", zap.String("scan_id", scanID))

	// 1. Ingestion: Fetch raw findings from the database via the interface.
	rawFindings, err := p.store.GetFindingsByScanID(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to ingest findings from store: %w", err)
	}
	p.logger.Debug("Ingested raw findings", zap.Int("count", len(rawFindings)))

	if len(rawFindings) == 0 {
		p.logger.Info("No findings to process for this scan.")
		// Return an empty but valid report.
		return GenerateReport([]PrioritizedFinding{}, scanID)
	}

	// 2. Normalization: Convert raw findings into a consistent internal format.
	normalizedFindings := Normalize(rawFindings)
	p.logger.Debug("Normalized findings")

	// This slice will hold the results of the last successful stage.
	findingsToProcess := normalizedFindings

	// 3. Enrichment: Add context from external sources or heuristics.
	// REFACTORED (Error Handling): Correctly handle a failure in the enrichment step.
	enrichedFindings, err := Enrich(ctx, normalizedFindings, p.cweProvider)
	if err != nil {
		// Log the error but continue processing with the unenriched (normalized) data.
		p.logger.Warn("An error occurred during enrichment; proceeding with unenriched data", zap.Error(err))
	} else if enrichedFindings != nil {
		// Only update the working slice if enrichment was successful.
		findingsToProcess = enrichedFindings
		p.logger.Debug("Enriched findings")
	}

	// 4. Prioritization: Score and rank the findings based on severity, confidence, and context.
	// REFACTORED: Pass the injectable score configuration.
	prioritizedFindings := Prioritize(findingsToProcess, p.scoreConfig)
	p.logger.Debug("Prioritized findings")

	// 5. Reporting: Generate the final, human-readable report.
	report, err := GenerateReport(prioritizedFindings, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate final report: %w", err)
	}
	p.logger.Info("Successfully generated report", zap.Int("total_findings", len(report.Findings)))

	return report, nil
}