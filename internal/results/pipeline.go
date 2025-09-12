// internal/results/pipeline.go
package results

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/results/providers"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
	"go.uber.org/zap"
)

// Repository defines the interface for accessing stored scan data.
// Implemented by store.Store.
type Repository interface {
	GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error)
}

// Pipeline manages the processing of raw findings into a final report.
type Pipeline struct {
	store    Repository
	enricher *Enricher
	logger   *zap.Logger
}

// NewPipeline creates a new results processing pipeline.
func NewPipeline(store *store.Store, logger *zap.Logger) *Pipeline {
	// Initialize providers for enrichment
	cweProvider := providers.NewInMemoryCWEProvider()
	enricher := NewEnricher(cweProvider, logger)

	return &Pipeline{
		store:    store,
		enricher: enricher,
		logger:   logger.Named("results_pipeline"),
	}
}

// Report represents the final aggregated scan report.
type Report struct {
	ScanID   string            `json:"scan_id"`
	Findings []schemas.Finding `json:"findings"`
	Summary  map[string]int    `json:"summary"`
}

// ToJSON serializes the report to a JSON byte slice.
func (r *Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}


// ProcessScanResults retrieves, normalizes, enriches, and prioritizes findings for a scan.
func (p *Pipeline) ProcessScanResults(ctx context.Context, scanID string) (*Report, error) {
	p.logger.Info("Starting results processing", zap.String("scan_id", scanID))

	// 1. Retrieval
	findings, err := p.store.GetFindingsByScanID(ctx, scanID)
	if err != nil {
		return nil, err
	}
	p.logger.Info("Retrieved raw findings", zap.Int("count", len(findings)))

	// 2. Normalization & Deduplication (if necessary, can be added here)

	// 3. Enrichment
	for i := range findings {
		// Corrected: Call EnrichFinding method on the enricher instance.
		p.enricher.EnrichFinding(&findings[i])
	}

	// 4. Prioritization (Sorting)
	p.prioritize(findings)

	// 5. Aggregation (Summary)
	summary := p.generateSummary(findings)

	report := &Report{
		ScanID:   scanID,
		Findings: findings,
		Summary:  summary,
	}

	p.logger.Info("Results processing complete")
	return report, nil
}

func (p *Pipeline) prioritize(findings []schemas.Finding) {
	// Sort findings by severity (Critical first)
	severityOrder := map[schemas.Severity]int{
		schemas.SeverityCritical:    1,
		schemas.SeverityHigh:        2,
		schemas.SeverityMedium:      3,
		schemas.SeverityLow:         4,
		schemas.SeverityInformational: 5,
	}

	sort.Slice(findings, func(i, j int) bool {
		orderI, okI := severityOrder[findings[i].Severity]
		if !okI { orderI = 99 }
		orderJ, okJ := severityOrder[findings[j].Severity]
		if !okJ { orderJ = 99 }

		if orderI != orderJ {
			return orderI < orderJ
		}
		// Secondary sort by vulnerability name
		return findings[i].Vulnerability.Name < findings[j].Vulnerability.Name
	})
}

func (p *Pipeline) generateSummary(findings []schemas.Finding) map[string]int {
	summary := make(map[string]int)
	summary["total"] = len(findings)
	for _, f := range findings {
		summary[string(f.Severity)]++
	}
	return summary
}