// internal/analysis/active/timeslip/h1_singlebyte_test.go
package timeslip

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/network"
)

// TestSetupConnectionDetails validates the configuration of the DialerConfig
// based on the target URL, specifically focusing on TLS settings and ALPN for H1 Pipelining.
func TestSetupConnectionDetails(t *testing.T) {
	t.Run("HTTP Configuration", func(t *testing.T) {
		targetURL, _ := url.Parse("http://example.com")
		dialerConfig := network.NewDialerConfig()
		// Start with a TLS config to ensure it gets nil'd for HTTP
		dialerConfig.TLSConfig = &tls.Config{}

		address, err := setupConnectionDetails(targetURL, dialerConfig, false)
		require.NoError(t, err)

		assert.Equal(t, "example.com:80", address)
		assert.Nil(t, dialerConfig.TLSConfig, "TLSConfig should be nil for HTTP")
	})

	t.Run("HTTPS Configuration and ALPN Enforcement", func(t *testing.T) {
		targetURL, _ := url.Parse("https://example.com:8443")
		dialerConfig := network.NewDialerConfig()
		// Initialize with some existing TLS settings
		dialerConfig.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}

		address, err := setupConnectionDetails(targetURL, dialerConfig, false)
		require.NoError(t, err)

		assert.Equal(t, "example.com:8443", address)
		require.NotNil(t, dialerConfig.TLSConfig)

		// CRITICAL: Verify ALPN is forced to "http/1.1" for pipelining.
		assert.Equal(t, []string{"http/1.1"}, dialerConfig.TLSConfig.NextProtos)

		// Verify other settings are preserved (cloned correctly)
		assert.Equal(t, uint16(tls.VersionTLS12), dialerConfig.TLSConfig.MinVersion)
		assert.False(t, dialerConfig.TLSConfig.InsecureSkipVerify)
	})

	t.Run("HTTPS InsecureSkipVerify", func(t *testing.T) {
		targetURL, _ := url.Parse("https://example.com")
		dialerConfig := network.NewDialerConfig()
		dialerConfig.TLSConfig = &tls.Config{}

		// Test enabling InsecureSkipVerify
		_, err := setupConnectionDetails(targetURL, dialerConfig, true)
		require.NoError(t, err)
		assert.True(t, dialerConfig.TLSConfig.InsecureSkipVerify)
	})

	t.Run("Unsupported Scheme", func(t *testing.T) {
		targetURL, _ := url.Parse("ftp://example.com")
		dialerConfig := network.NewDialerConfig()
		_, err := setupConnectionDetails(targetURL, dialerConfig, false)
		assert.ErrorIs(t, err, ErrConfigurationError)
	})
}

// TestPreparePipelinedRequests validates the serialization of HTTP requests into raw bytes,
// ensuring correct headers for pipelining, mutation application, and handling of request bodies.
func TestPreparePipelinedRequests(t *testing.T) {
	candidate := &RaceCandidate{
		Method: "POST",
		URL:    "http://example.com/api",
		Body:   []byte(`{"id":"{{NONCE}}"}`),
		Headers: http.Header{
			"Content-Type": {"application/json"},
			"X-Token":      {"{{UUID}}"},
		},
	}
	concurrency := 3
	host := "example.com"

	requests, err := preparePipelinedRequests(candidate, concurrency, host)
	require.NoError(t, err)
	require.Len(t, requests, concurrency)

	// Verify structure and key properties of the raw requests
	uniqueNonces := make(map[string]bool)
	uniqueUUIDs := make(map[string]bool)

	for i, reqBytes := range requests {
		// 1. Request Line
		assert.Contains(t, string(reqBytes), "POST /api HTTP/1.1\r\n", "Request %d missing correct request line", i)

		// 2. Host Header
		assert.Contains(t, string(reqBytes), "Host: example.com\r\n", "Request %d missing Host header", i)

		// 3. Pipelining Headers
		assert.Contains(t, string(reqBytes), "Connection: keep-alive\r\n", "Request %d missing Connection: keep-alive", i)
		// Crucial check: Ensure 'Expect: 100-continue' is absent
		assert.NotContains(t, string(reqBytes), "Expect: 100-continue\r\n", "Request %d should not have Expect: 100-continue", i)

		// 4. Content-Length (should match the mutated body length)
		// Split headers and body
		parts := bytes.SplitN(reqBytes, []byte("\r\n\r\n"), 2)
		require.Len(t, parts, 2, "Request %d malformed (no body separator)", i)
		headerPart := parts[0]
		body := parts[1]

		expectedLengthHeader := fmt.Sprintf("Content-Length: %d\r\n", len(body))
		assert.Contains(t, string(headerPart), expectedLengthHeader, "Request %d has incorrect Content-Length", i)

		// 5. Mutations
		assert.NotContains(t, string(body), "{{NONCE}}")
		assert.NotContains(t, string(headerPart), "{{UUID}}")

		// Extract Nonce ({"id":"123456789012"})
		nonce := string(body[8:20])
		uniqueNonces[nonce] = true

		// Extract UUID from header (simplified extraction)
		tokenHeaderStart := bytes.Index(headerPart, []byte("X-Token: "))
		require.Greater(t, tokenHeaderStart, -1)
		// UUID length is 36
		uuid := string(headerPart[tokenHeaderStart+9 : tokenHeaderStart+9+36])
		uniqueUUIDs[uuid] = true
	}

	assert.Len(t, uniqueNonces, concurrency, "Nonces should be unique")
	assert.Len(t, uniqueUUIDs, concurrency, "UUIDs should be unique")
}

// TestPreparePipelinedRequests_GET validates specific behavior for GET requests.
func TestPreparePipelinedRequests_GET(t *testing.T) {
	// Test GET request specific behavior (no body, no Content-Length, no Expect header)
	candidate := &RaceCandidate{
		Method: "GET",
		// Mutation in the URL path/query
		URL: "http://example.com/resource?q={{NONCE}}",
	}

	requests, err := preparePipelinedRequests(candidate, 2, "example.com")
	require.NoError(t, err)
	require.Len(t, requests, 2)

	req1 := string(requests[0])
	req2 := string(requests[1])

	assert.NotEqual(t, req1, req2, "Requests should be mutated differently (different nonces)")
	assert.Contains(t, req1, "GET /resource?q=")
	assert.NotContains(t, req1, "Content-Length:")
	assert.NotContains(t, req1, "Expect:")
	// GET request must end with double CRLF (empty body)
	assert.True(t, bytes.HasSuffix(requests[0], []byte("\r\n\r\n")), "GET request must end with double CRLF")
}
