// pkg/analysis/active/timeslip/fingerprint.go
package timeslip

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// Pool for sha256 hashers to reduce allocation overhead.
var hasherPool = sync.Pool{
	New: func() interface{} {
		return sha256.New()
	},
}

func getHasher() hash.Hash { return hasherPool.Get().(hash.Hash) }
func putHasher(h hash.Hash) {
	h.Reset()
	hasherPool.Put(h)
}

// GenerateFingerprint creates a composite hash representing the unique state of the response.
// It combines the Status Code, canonicalized headers, and the response body hash.
func GenerateFingerprint(statusCode int, headers http.Header, body []byte) string {
	// Use pooled hasher.
	hasher := getHasher()
	defer putHasher(hasher)

	// 1. Include Status Code. (Optimized)
	statusBuf := make([]byte, 0, 20) // Pre-allocate space
	statusBuf = append(statusBuf, "STATUS:"...)
	statusBuf = strconv.AppendInt(statusBuf, int64(statusCode), 10)
	statusBuf = append(statusBuf, ';')
	hasher.Write(statusBuf)

	// 2. Include Canonicalized Headers. (Optimized)
	hasher.Write([]byte("HEADERS:"))
	// Write headers directly to the hasher.
	canonicalizeHeaders(hasher, headers)
	hasher.Write([]byte(";"))

	// 3. Include Body Hash.
	// Hashing the body content itself ensures content changes are detected.
	bodyHash := sha256.Sum256(body)
	hasher.Write([]byte("BODY:"))
	hasher.Write(bodyHash[:])

	// Final composite hash.
	return hex.EncodeToString(hasher.Sum(nil))
}

// canonicalizeHeaders writes a stable representation directly to the writer (hasher).
func canonicalizeHeaders(w io.Writer, headers http.Header) {
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

	for _, k := range keys {
		values := headers[k]
		// We join them with a comma.
		normalizedValue := strings.Join(values, ",")

		// Write format: lowercase_key:value|
		// Use direct writes instead of Fprintf.
		io.WriteString(w, strings.ToLower(k))
		io.WriteString(w, ":")
		io.WriteString(w, normalizedValue)
		io.WriteString(w, "|")
	}
}
