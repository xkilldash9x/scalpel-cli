// pkg/analysis/active/timeslip/fingerprint.go
package timeslip

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Headers to exclude from fingerprinting as they are often volatile, connection-specific, or derived from the body.
var excludedHeaders = map[string]bool{
	"Date":              true,
	"Set-Cookie":        true, // Often contains unique tokens per response.
	"X-Request-Id":      true,
	"X-Trace-Id":        true,
	"Cf-Ray":            true,
	"Etag":              true, // Derived from content, which we hash separately.
	"Last-Modified":     true,
	"Expires":           true,
	"Cache-Control":     true,
	"Content-Length":    true, // Derived from body length.
	"Connection":        true,
	"Keep-Alive":        true,
	"Server-Timing":     true,
	"Age":               true,
}

// GenerateFingerprint creates a composite hash representing the unique state of the response.
// It combines the Status Code, canonicalized headers, and the response body hash.
func GenerateFingerprint(statusCode int, headers http.Header, body []byte) string {
	hasher := sha256.New()

	// 1. Include Status Code.
	hasher.Write([]byte(fmt.Sprintf("STATUS:%d;", statusCode)))

	// 2. Include Canonicalized Headers.
	headerFingerprint := canonicalizeHeaders(headers)
	hasher.Write([]byte("HEADERS:"))
	hasher.Write(headerFingerprint)
	hasher.Write([]byte(";"))

	// 3. Include Body Hash.
	// Hashing the body content itself ensures content changes are detected.
	bodyHash := sha256.Sum256(body)
	hasher.Write([]byte("BODY:"))
	hasher.Write(bodyHash[:])

	// Final composite hash.
	return hex.EncodeToString(hasher.Sum(nil))
}

// canonicalizeHeaders creates a stable string representation of the headers.
func canonicalizeHeaders(headers http.Header) []byte {
	keys := make([]string, 0, len(headers))
	for k := range headers {
		// Use the canonical MIME header key format for consistency.
		canonicalKey := http.CanonicalHeaderKey(k)
		if !excludedHeaders[canonicalKey] {
			keys = append(keys, canonicalKey)
		}
	}

	// Sort keys to ensure consistent order regardless of server implementation.
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		// Combine all values for the header key.
		// Note: The order of values matters; http.Header preserves the order received.
		values := headers[k]
		// We join them with a comma.
		normalizedValue := strings.Join(values, ",")

		// Write format: lowercase_key:value|
		fmt.Fprintf(&buf, "%s:%s|", strings.ToLower(k), normalizedValue)
	}

	return buf.Bytes()
}