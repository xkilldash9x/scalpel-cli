// -- pkg/results/enrich.go --
package results

import (
	"context"
	"fmt"
)

// REFACTORED (Architecture): Define an interface for CWE data retrieval.
// This decouples the enrichment logic from the data source.
type CWEProvider interface {
	GetFullName(cweID string) (string, bool)
}

// Enrich adds external context to normalized findings using a CWEProvider.
// REFACTORED: The function now depends on the CWEProvider interface, not a hardcoded map.
func Enrich(ctx context.Context, findings []NormalizedFinding, provider CWEProvider) ([]NormalizedFinding, error) {
	// Gracefully skip enrichment if no provider is configured.
	if provider == nil {
		return findings, nil
	}

	for i := range findings {
		if findings[i].CWE == "" {
			continue
		}
		if fullName, ok := provider.GetFullName(findings[i].CWE); ok {
			// Prepend the full name to the description for more context.
			findings[i].Description = fmt.Sprintf("[%s] %s", fullName, findings[i].Description)
		}
	}

	return findings, nil
}