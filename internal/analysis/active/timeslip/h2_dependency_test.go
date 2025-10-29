// internal/analysis/active/timeslip/h2_dependency_test.go
package timeslip

import (
	"bytes"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2/hpack"
)

// TestPrepareH2Requests validates the mutation logic for H2 requests.
func TestPrepareH2Requests(t *testing.T) {
	candidate := &RaceCandidate{
		Body:    []byte(`{"id":"{{NONCE}}"}`),
		Headers: http.Header{"X-Token": {"{{UUID}}"}, "User-Agent": {"TestAgent"}},
	}
	count := 3

	requests, err := prepareH2Requests(candidate, count)
	require.NoError(t, err)
	require.Len(t, requests, count)

	uniqueNonces := make(map[string]bool)
	uniqueUUIDs := make(map[string]bool)

	for _, req := range requests {
		// Verify body mutation
		assert.NotContains(t, string(req.body), "{{NONCE}}")
		// Extract nonce (simplified: {"id":"123456789012"})
		nonce := string(req.body[8:20])
		uniqueNonces[nonce] = true

		// Verify header mutation
		token := req.headers.Get("X-Token")
		assert.NotEqual(t, "{{UUID}}", token)
		assert.Len(t, token, 36)
		uniqueUUIDs[token] = true

		// Verify other headers are preserved
		assert.Equal(t, "TestAgent", req.headers.Get("User-Agent"))
	}

	assert.Len(t, uniqueNonces, count, "Nonces should be unique")
	assert.Len(t, uniqueUUIDs, count, "UUIDs should be unique")
}

// TestEncodeHeaders validates the complex process of encoding HTTP headers into HPACK format,
// including pseudo-headers, overrides (Host/:authority), and automatic Content-Length generation.
func TestEncodeHeaders(t *testing.T) {
	// Setup HPACK encoder/decoder and buffer for the test
	hbuf := new(bytes.Buffer)
	encoder := hpack.NewEncoder(hbuf)
	// Decoder is needed to verify the encoded output
	decoder := hpack.NewDecoder(4096, nil)

	method := "POST"
	body := []byte("test body") // Length 9
	targetURL, _ := url.Parse("https://example.com/path?query=1")
	headers := http.Header{
		"Content-Type": {"application/json"},
		// Host header should be used for :authority
		"Host":     {"override.com"},
		"X-Custom": {"Value"},
		// Explicit Content-Length should be ignored in favor of actual body length
		"Content-Length": {"1000"},
	}

	encodedBlock, err := encodeHeaders(encoder, hbuf, method, body, headers, targetURL)
	require.NoError(t, err)

	// Decode to verify the contents
	decodedFields, err := decoder.DecodeFull(encodedBlock)
	require.NoError(t, err)

	// Convert decoded fields to a map for easy assertions
	decodedMap := make(map[string]string)
	for _, field := range decodedFields {
		decodedMap[field.Name] = field.Value
	}

	// Assertions for Pseudo-headers (must be present and correct)
	assert.Equal(t, "POST", decodedMap[":method"])
	assert.Equal(t, "https", decodedMap[":scheme"])
	// :authority must use the Host header value if provided
	assert.Equal(t, "override.com", decodedMap[":authority"])
	assert.Equal(t, "/path?query=1", decodedMap[":path"])

	// Assertions for Content-Length (must match the actual body length)
	assert.Equal(t, "9", decodedMap["content-length"])

	// Assertions for Regular headers (must be lowercase in H2)
	assert.Equal(t, "application/json", decodedMap["content-type"])
	assert.Equal(t, "Value", decodedMap["x-custom"])

	// Assertions for Exclusions (Host header itself must not be present)
	assert.Empty(t, decodedMap["host"])
}

// TestEncodeHeaders_NoBody_GET validates encoding for requests without bodies.
func TestEncodeHeaders_NoBody_GET(t *testing.T) {
	hbuf := new(bytes.Buffer)
	encoder := hpack.NewEncoder(hbuf)
	decoder := hpack.NewDecoder(4096, nil)

	targetURL, _ := url.Parse("http://example.com/")
	headers := http.Header{} // No Host header provided

	encodedBlock, err := encodeHeaders(encoder, hbuf, "GET", nil, headers, targetURL)
	require.NoError(t, err)

	decodedFields, _ := decoder.DecodeFull(encodedBlock)
	decodedMap := make(map[string]string)
	for _, field := range decodedFields {
		decodedMap[field.Name] = field.Value
	}

	assert.Equal(t, "GET", decodedMap[":method"])
	assert.Equal(t, "http", decodedMap[":scheme"])
	// :authority should default to URL host if Host header is absent
	assert.Equal(t, "example.com", decodedMap[":authority"])
	assert.Equal(t, "/", decodedMap[":path"])
	// Content-Length must be absent for requests without bodies
	assert.Empty(t, decodedMap["content-length"], "Content-Length should be absent for GET")
}
