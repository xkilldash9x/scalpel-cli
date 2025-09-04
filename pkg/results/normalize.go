package results

import "github.com/xkilldash9x/scalpel-cli/pkg/schemas"

// Normalize converts a raw finding into a normalized finding.
func Normalize(finding schemas.Finding) NormalizedFinding {
	// For now, we'll just pass the finding through.
	// In a real implementation, we would normalize the severity, etc.
	return NormalizedFinding{
		Finding:            finding,
		NormalizedSeverity: string(finding.Severity), // Explicitly cast to string
	}
}