// -- pkg/results/normalize.go --
package results

import (
	"crypto/sha1"
	"encoding/hex"
	"io"
	"strings"

	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// NormalizedFinding is the common internal structure for processing.
// REFACTORED: Added a structured 'IsConfirmed' field to avoid magic string checks later.
type NormalizedFinding struct {
	schemas.Finding
	UniqueKey   string
	IsConfirmed bool
}

// Normalize converts raw findings into a consistent format for processing.
func Normalize(rawFindings []schemas.Finding) []NormalizedFinding {
	normalized := make([]NormalizedFinding, len(rawFindings))
	// REFACTORED: Reuse a single hash object to minimize allocations in the loop.
	hasher := sha1.New()

	for i, f := range rawFindings {
		// Data cleaning: Trim whitespace.
		f.Description = strings.TrimSpace(f.Description)
		f.Vulnerability = strings.TrimSpace(f.Vulnerability)

		// REFACTORED (Performance/Robustness): Generate a robust key using SHA-1.
		// This is more performant than fmt.Sprintf/strings.ToLower in a loop and
		// avoids separator collision issues.
		hasher.Reset()
		// Use a null byte as a guaranteed safe separator.
		io.WriteString(hasher, strings.ToLower(f.Target))
		hasher.Write([]byte{0})
		io.WriteString(hasher, strings.ToLower(f.Vulnerability))
		hasher.Write([]byte{0})
		io.WriteString(hasher, strings.ToLower(f.Module))
		key := hex.EncodeToString(hasher.Sum(nil))

		// REFACTORED (Architecture): Determine confirmation status from structured data or heuristics
		// during normalization, not in later stages.
		isConfirmed := strings.Contains(f.Description, "[CONFIRMED EXECUTION]")

		normalized[i] = NormalizedFinding{
			Finding:     f,
			UniqueKey:   key,
			IsConfirmed: isConfirmed,
		}
	}
	// Future logic could include deduplication based on the UniqueKey.
	return normalized
}