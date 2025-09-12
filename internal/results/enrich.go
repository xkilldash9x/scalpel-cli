// internal/results/enrich.go
package results

import (
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/results/providers"
	"go.uber.org/zap"
)

// Enricher is responsible for enhancing findings with additional context.
type Enricher struct {
	cweProvider providers.CWEProvider
	logger      *zap.Logger
}

// NewEnricher creates a new Enricher instance.
func NewEnricher(cweProvider providers.CWEProvider, logger *zap.Logger) *Enricher {
	return &Enricher{
		cweProvider: cweProvider,
		logger:      logger.Named("enricher"),
	}
}

// EnrichFinding enhances a single finding.
func (e *Enricher) EnrichFinding(finding *schemas.Finding) {
	e.enrichCWE(finding)
	// Add other enrichment steps here (e.g., CVSS calculation, asset context from KG)
}

func (e *Enricher) enrichCWE(finding *schemas.Finding) {
	if len(finding.CWE) == 0 || e.cweProvider == nil {
		return
	}

	// We only use the first CWE ID for enrichment currently.
	cweID := finding.CWE[0]

	entry, err := e.cweProvider.GetCWE(cweID)
	if err != nil {
		// CWEProvider implementation changed to not return error on not found, but keeping check for safety.
		e.logger.Debug("Could not retrieve CWE details", zap.String("cwe_id", cweID), zap.Error(err))
		return
	}

	// Update the vulnerability name/description if the current one is generic and we have a better one from CWE data.
	isGenericName := finding.Vulnerability.Name == "" || finding.Vulnerability.Name == "Unclassified Vulnerability"
	// Example of a specific name from HeadersAnalyzer: "Missing Security Header: X-Frame-Options"

	// If the name is very generic, replace it. If it's specific (like the header example), keep it but enrich description.
	if isGenericName && entry.Name != "" {
		finding.Vulnerability.Name = entry.Name
	}

	// Enrich description if the current one is empty or very short.
	if len(finding.Vulnerability.Description) < 20 && entry.Description != "" {
		finding.Vulnerability.Description = entry.Description
	}
}