// -- pkg/results/enrich.go --
package results

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// Enrich adds external context to normalized findings.
func Enrich(ctx context.Context, findings []NormalizedFinding, logger *zap.Logger) ([]NormalizedFinding, error) {
	// Example enrichment: Fetch full CWE name from an external (or cached) source.
	// This is a placeholder for a real implementation.
	cweDatabase := map[string]string{
		"CWE-79":  "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
		"CWE-89":  "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
		"CWE-639": "Authorization Bypass Through User-Controlled Key",
	}

	for i := range findings {
		if fullName, ok := cweDatabase[findings[i].CWE]; ok {
			// Prepend the full name to the description for more context.
			findings[i].Description = fmt.Sprintf("[%s] %s", fullName, findings[i].Description)
		}
	}

	return findings, nil
}
