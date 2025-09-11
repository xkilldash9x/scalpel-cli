// internal/results/enrich.go
package results

import (
	"context"
	"fmt"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	// Assuming a provider package for CWE lookups
	"github.com/xkilldash9x/scalpel-cli/internal/results/providers"
)

// Enricher enhances findings by adding external context, such as CWE names.
type Enricher struct {
	cweProvider providers.CWEProvider
}

// NewEnricher creates a new enricher with the given CWE provider.
func NewEnricher(provider providers.CWEProvider) *Enricher {
	return &Enricher{
		cweProvider: provider,
	}
}

// EnrichFindings iterates over findings and adds enrichment data.
func (e *Enricher) EnrichFindings(ctx context.Context, findings []schemas.Finding) ([]schemas.Finding, error) {
	// Gracefully skip enrichment if no provider is configured.
	if e.cweProvider == nil {
		return findings, nil
	}

	for i := range findings {
		// Check for cancellation before processing each item.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("enrichment cancelled: %w", ctx.Err())
		default:
			// Continue processing
		}
		// Enrich the finding in place.
		e.enrichCWE(ctx, &findings[i])
	}
	return findings, nil
}

// enrichCWE adds CWE information to a single finding.
func (e *Enricher) enrichCWE(ctx context.Context, finding *schemas.Finding) {
	// Check if there are any CWEs to process.
	if len(finding.CWE) == 0 {
		return
	}

	// Use the primary CWE ID (first element) for enrichment.
	primaryCWE := finding.CWE[0]

	// Get the full name from the provider, passing the context.
	if fullName, ok := e.cweProvider.GetFullName(ctx, primaryCWE); ok {
		// If the finding's vulnerability name is not already set,
		// populate it with the full CWE name for better context.
		if finding.Vulnerability.Name == "" {
			finding.Vulnerability.Name = fullName
		}
	}
}