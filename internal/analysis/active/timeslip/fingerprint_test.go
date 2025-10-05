package timeslip

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- 1.3. Fingerprinting Tests ---

func TestGenerateFingerprint_Stability(t *testing.T) {
	statusCode := 200
	headers := http.Header{
		"Content-Type": {"application/json"},
		"Server":       {"Nginx"},
	}
	body := []byte(`{"status":"ok", "data":[1,2,3]}`)

	// Generate fingerprint twice with identical input
	fp1 := GenerateFingerprint(statusCode, headers, body)
	fp2 := GenerateFingerprint(statusCode, headers, body)

	// Assertions
	assert.Equal(t, fp1, fp2, "Fingerprints must be stable for identical inputs")
	assert.NotEmpty(t, fp1)
}

func TestGenerateFingerprint_Sensitivity(t *testing.T) {
	baseStatus := 200
	baseHeaders := http.Header{"Content-Type": {"text/plain"}}
	baseBody := []byte("Hello World")

	baseFP := GenerateFingerprint(baseStatus, baseHeaders, baseBody)

	t.Run("Change Status Code", func(t *testing.T) {
		fp := GenerateFingerprint(201, baseHeaders, baseBody)
		assert.NotEqual(t, baseFP, fp)
	})

	t.Run("Change Body Content", func(t *testing.T) {
		fp := GenerateFingerprint(baseStatus, baseHeaders, []byte("Hello Moon"))
		assert.NotEqual(t, baseFP, fp)
	})

	t.Run("Change Included Header Value", func(t *testing.T) {
		headers := baseHeaders.Clone()
		headers.Set("Content-Type", "application/json")
		fp := GenerateFingerprint(baseStatus, headers, baseBody)
		assert.NotEqual(t, baseFP, fp)
	})
}

func TestGenerateFingerprint_Insensitivity_ExcludedHeaders(t *testing.T) {
	baseStatus := 200
	baseBody := []byte("Content")
	baseHeaders := http.Header{
		"Content-Type": {"text/plain"}, // Included header
		// Excluded headers (as defined in fingerprint.go lines 15-30)
		"Date":         {"Day 1"},
		"Set-Cookie":   {"Session=1"},
		"Etag":         {"ETAG1"},
	}

	baseFP := GenerateFingerprint(baseStatus, baseHeaders, baseBody)

	t.Run("Change Date", func(t *testing.T) {
		headers := baseHeaders.Clone()
		headers.Set("Date", "Day 2")
		fp := GenerateFingerprint(baseStatus, headers, baseBody)
		assert.Equal(t, baseFP, fp, "Changes to 'Date' should not affect fingerprint")
	})

	t.Run("Add Excluded Header (X-Request-Id)", func(t *testing.T) {
		headers := baseHeaders.Clone()
		headers.Set("X-Request-Id", "UUID-123")
		fp := GenerateFingerprint(baseStatus, headers, baseBody)
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

	fp1 := GenerateFingerprint(status, headers1, body)
	fp2 := GenerateFingerprint(status, headers2, body)

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

	b.ReportAllocs()
	b.ResetTimer()
	// If sync.Pool (hasherPool) is working, allocs/op should be low.
	for i := 0; i < b.N; i++ {
		GenerateFingerprint(statusCode, headers, body)
	}
}