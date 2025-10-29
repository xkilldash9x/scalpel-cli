package timeslip

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- 1.3. Fingerprinting Tests ---

// Helper to get the default exclusion map for testing
func getDefaultExclusions() map[string]bool {
	// Use the exported constant from types.go
	return DefaultExcludedHeaders
}

func TestGenerateFingerprint_Stability(t *testing.T) {
	statusCode := 200
	headers := http.Header{
		"Content-Type": {"application/json"},
		"Server":       {"Nginx"},
	}
	body := []byte(`{"status":"ok", "data":[1,2,3]}`)

	// Use a specific exclusion map for stability testing (e.g., excluding Server)
	exclusions := map[string]bool{"Server": true}

	// Generate fingerprint twice with identical input
	fp1 := GenerateFingerprint(statusCode, headers, body, exclusions)
	fp2 := GenerateFingerprint(statusCode, headers, body, exclusions)

	// Assertions
	assert.Equal(t, fp1, fp2, "Fingerprints must be stable for identical inputs")
	assert.NotEmpty(t, fp1)
}

func TestGenerateFingerprint_Sensitivity(t *testing.T) {
	baseStatus := 200
	baseHeaders := http.Header{"Content-Type": {"text/plain"}}
	baseBody := []byte("Hello World")

	// Use an empty map for sensitivity tests (no exclusions)
	noExclusions := map[string]bool{}

	baseFP := GenerateFingerprint(baseStatus, baseHeaders, baseBody, noExclusions)

	t.Run("Change Status Code", func(t *testing.T) {
		fp := GenerateFingerprint(201, baseHeaders, baseBody, noExclusions)
		assert.NotEqual(t, baseFP, fp)
	})

	t.Run("Change Body Content", func(t *testing.T) {
		fp := GenerateFingerprint(baseStatus, baseHeaders, []byte("Hello Moon"), noExclusions)
		assert.NotEqual(t, baseFP, fp)
	})

	t.Run("Change Included Header Value", func(t *testing.T) {
		headers := baseHeaders.Clone()
		headers.Set("Content-Type", "application/json")
		fp := GenerateFingerprint(baseStatus, headers, baseBody, noExclusions)
		assert.NotEqual(t, baseFP, fp)
	})
}

func TestGenerateFingerprint_Insensitivity_ExcludedHeaders(t *testing.T) {
	baseStatus := 200
	baseBody := []byte("Content")
	baseHeaders := http.Header{
		"Content-Type": {"text/plain"}, // Included header
		// Excluded headers (as defined in types.go DefaultExcludedHeaders)
		"Date":       {"Day 1"},
		"Set-Cookie": {"Session=1"},
		"Etag":       {"ETAG1"},
	}

	// FIX: Get the default exclusions which the test relies on.
	defaultExclusions := getDefaultExclusions()

	// Pass the correct exclusion map instead of nil.
	baseFP := GenerateFingerprint(baseStatus, baseHeaders, baseBody, defaultExclusions)

	t.Run("Change Date", func(t *testing.T) {
		headers := baseHeaders.Clone()
		headers.Set("Date", "Day 2")
		fp := GenerateFingerprint(baseStatus, headers, baseBody, defaultExclusions)
		assert.Equal(t, baseFP, fp, "Changes to 'Date' should not affect fingerprint")
	})

	t.Run("Add Excluded Header (X-Request-Id)", func(t *testing.T) {
		headers := baseHeaders.Clone()
		headers.Set("X-Request-Id", "UUID-123")
		fp := GenerateFingerprint(baseStatus, headers, baseBody, defaultExclusions)
		assert.Equal(t, baseFP, fp, "Adding 'X-Request-Id' should not affect fingerprint")
	})
}

func TestGenerateFingerprint_Canonicalization(t *testing.T) {
	// Verify order and capitalization are ignored
	status := 200
	body := []byte("data")

	headers1 := http.Header{
		"B-Header": {"ValueB"},
		"A-Header": {"ValueA"},
	}

	headers2 := http.Header{
		"a-header": {"ValueA"},
		"b-header": {"ValueB"},
	}

	// Canonicalization shouldn't depend on exclusions.
	noExclusions := map[string]bool{}

	fp1 := GenerateFingerprint(status, headers1, body, noExclusions)
	fp2 := GenerateFingerprint(status, headers2, body, noExclusions)

	assert.Equal(t, fp1, fp2, "Header order and capitalization should not affect fingerprint")
}

// Benchmark for performance validation and sync.Pool utilization
func BenchmarkGenerateFingerprint(b *testing.B) {
	statusCode := 200
	body := make([]byte, 1024) // 1KB body
	headers := http.Header{
		"Content-Type":   []string{"application/json"},
		"Server":         []string{"Nginx"},
		"Date":           []string{"Mon, 02 Jan 2006 15:04:05 MST"},
		"X-Custom-Field": []string{"Value1"},
	}

	// Use default exclusions for realistic benchmarking
	defaultExclusions := getDefaultExclusions()

	b.ReportAllocs()
	b.ResetTimer()
	// If sync.Pool (hasherPool) is working, allocs/op should be low.
	for i := 0; i < b.N; i++ {
		GenerateFingerprint(statusCode, headers, body, defaultExclusions)
	}
}
