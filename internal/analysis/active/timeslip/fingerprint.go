// internal/analysis/active/timeslip/fingerprint.go
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
// It combines the Status Code, canonicalized headers (using the provided excludeMap), and the response body hash.
func GenerateFingerprint(statusCode int, headers http.Header, body []byte, excludeMap map[string]bool) string {
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
	// Write headers directly to the hasher, using the exclusion map.
	canonicalizeHeaders(hasher, headers, excludeMap)
	hasher.Write([]byte(";"))

	// 3. Include Body Hash.
	// Hashing the body content itself ensures content changes are detected.
	bodyHash := sha256.Sum256(body)
	hasher.Write([]byte("BODY:"))
	hasher.Write(bodyHash[:])

	// Final composite hash.
	return hex.EncodeToString(hasher.Sum(nil))
}

// canonicalizeHeaders writes a stable representation of headers directly to the writer (hasher).
func canonicalizeHeaders(w io.Writer, headers http.Header, excludeMap map[string]bool) {
	// Collect all original keys that are not on the exclusion list.
	keys := make([]string, 0, len(headers))
	for k := range headers {
		// Check the canonical version of the key against the provided exclusion list.
		// FIX: Added nil check for excludeMap for defensive programming (treat nil map as empty map).
		if excludeMap == nil || !excludeMap[http.CanonicalHeaderKey(k)] {
			keys = append(keys, k)
		}
	}

	// Sort the original keys using a case-insensitive comparison for stable order.
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})

	// Iterate through the deterministically sorted keys.
	for _, k := range keys {
		// Use the original key `k` to retrieve the correct values.
		values := headers[k]

		// Sort values to handle multi-value headers consistently, regardless of the order the server returned them.
		sort.Strings(values)
		normalizedValue := strings.Join(values, ",")

		// Write the canonicalized representation: lowercase_key:value|
		io.WriteString(w, strings.ToLower(k))
		io.WriteString(w, ":")
		io.WriteString(w, normalizedValue)
		io.WriteString(w, "|")
	}
}
