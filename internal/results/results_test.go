// internal/results/results_test.go
package results

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Creates a sample schemas.Finding for testing input.
func newRawFinding(id, severity, cwe, description string) schemas.Finding {
	return schemas.Finding{
		ID:          id,
		Severity:    schemas.Severity(severity),
		CWE:         []string{cwe}, // The fix is to wrap the `cwe` string in a slice.
		Description: description,
	}
}

// Test Cases: Normalization (normalize.go)

// Rigorously verifies the internal mapping logic.
// This critical white box test ensures robustness against diverse tool outputs.
func TestNormalizeSeverity_WhiteBox(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected StandardSeverity
	}{
		// Standard Cases
		{"Critical", "CRITICAL", SeverityCritical},
		{"High", "HIGH", SeverityHigh},

		// Case Variations
		{"Mixed Case (Medium)", "Medium", SeverityMedium},
		{"Lower Case (Low)", "low", SeverityLow},

		// Whitespace Handling
		{"Whitespace (Info)", "  INFO  ", SeverityInfo},

		// Aliases and Synonyms
		{"Alias (Fatal)", "FATAL", SeverityCritical},
		{"Alias (Important)", "Important", SeverityHigh},
		{"Alias (Error)", "Error", SeverityHigh},
		{"Alias (Moderate)", "Moderate", SeverityMedium},
		{"Alias (Warning)", "Warning", SeverityMedium},
		{"Alias (Informational)", "Informational", SeverityInfo},
		{"Alias (Negligible)", "Negligible", SeverityInfo},

		// Unknown and Empty
		{"Unknown Value", "CVSS 9.0", SeverityUnknown},
		{"Empty String", "", SeverityUnknown},
		{"Whitespace Only", "    ", SeverityUnknown},
	}

	for _, tt := range tests {
		tc := tt // Capture range variable for parallel execution
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Testing the unexported function directly.
			result := normalizeSeverity(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Verifies the Normalize function correctly converts the struct
// and applies the severity normalization logic.
func TestNormalize_Integration(t *testing.T) {
	t.Parallel()
	rawFinding := newRawFinding("F1", "Moderate", "CWE-79", "Description")

	normalized := Normalize(rawFinding)

	// Verify data integrity (original data preserved)
	assert.Equal(t, "F1", normalized.ID)
	assert.Equal(t, schemas.Severity("Moderate"), normalized.Finding.Severity, "Original severity must be preserved")

	// Verify normalization logic applied
	assert.Equal(t, string(SeverityMedium), normalized.NormalizedSeverity)

	// Verify initialization
	assert.Equal(t, 0.0, normalized.Score)
}