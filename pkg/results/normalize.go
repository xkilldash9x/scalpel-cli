// -- pkg/results/normalize.go --
package results

import (
	"strings"

	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// NormalizedFinding is the common internal structure for processing.
type NormalizedFinding struct {
	schemas.Finding
	UniqueKey string
	// Add other normalized fields as needed.
}

// Normalize converts raw findings into a consistent format for processing.
func Normalize(rawFindings []schemas.Finding) []NormalizedFinding {
	normalized := make([]NormalizedFinding, len(rawFindings))
	for i, f := range rawFindings {
		// Example normalization: Create a unique key for deduplication.
		key := strings.ToLower(fmt.Sprintf("%s:%s:%s", f.Target, f.Vulnerability, f.Module))

		// Example data cleaning: Trim whitespace.
		f.Description = strings.TrimSpace(f.Description)
		f.Vulnerability = strings.TrimSpace(f.Vulnerability)

		normalized[i] = NormalizedFinding{
			Finding:   f,
			UniqueKey: key,
		}
	}
	// Future logic could include deduplication based on the UniqueKey.
	return normalized
}
