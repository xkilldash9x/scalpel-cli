package results

import "github.com/xkilldash9x/scalpel-cli/pkg/schemas"

// Normalize takes a raw schema.Finding and converts it into the standardized
// NormalizedFinding format. This is where you could implement logic to
// standardize severity levels (e.g., mapping "High", "high", "HIGH" to a single value).
func Normalize(finding schemas.Finding) NormalizedFinding {
	// Simple pass-through for now, but can be expanded with more complex logic.
	return NormalizedFinding{
		Finding:            finding,
		NormalizedSeverity: finding.Severity, // Or apply mapping logic here
	}
}
