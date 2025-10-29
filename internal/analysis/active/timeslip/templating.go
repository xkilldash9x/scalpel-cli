// internal/analysis/active/timeslip/templating.go
package timeslip

import (
	"bytes"
	// Rename crypto/rand to avoid collision with math/rand
	crypto_rand "crypto/rand"
	"encoding/binary"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Template variables recognized by the mutation engine.
var (
	templateUUID     = []byte("{{UUID}}")
	templateNonce    = []byte("{{NONCE}}")
	templateUUIDStr  = "{{UUID}}"
	templateNonceStr = "{{NONCE}}"
)

// rngPool provides a pool of concurrency-safe PRNG instances.
// Updated to use crypto/rand for seeding to ensure unpredictability and avoid seed collisions.
var rngPool = sync.Pool{
	New: func() interface{} {
		var seed int64
		// Read 8 bytes from crypto/rand and convert to int64 for the seed.
		err := binary.Read(crypto_rand.Reader, binary.BigEndian, &seed)
		if err != nil {
			// Fallback if crypto/rand fails (e.g., system entropy pool exhausted).
			// This is less secure but prevents the application from crashing.
			seed = time.Now().UnixNano()
		}

		// Use the strong seed, but the fast (non-cryptographic) math/rand algorithm.
		//nolint:gosec // Weak RNG algorithm is acceptable here; we use a strong seed.
		src := rand.NewSource(seed)
		return rand.New(src)
	},
}

// getRNG retrieves an RNG instance from the pool.
func getRNG() *rand.Rand {
	return rngPool.Get().(*rand.Rand)
}

// putRNG returns an RNG instance to the pool.
func putRNG(rng *rand.Rand) {
	rngPool.Put(rng)
}

// MutateRequest applies template substitutions to the request body and headers.
// It generates unique values for each call.
func MutateRequest(body []byte, headers http.Header) ([]byte, http.Header, error) {
	mutatedBody := body
	mutatedHeaders := headers.Clone()

	// FIX: Ensure the headers map is initialized if the input was nil (Clone() returns nil if input is nil).
	// This prevents "panic: assignment to entry in nil map" in downstream consumers
	// (like h1_singlebyte.go) that might try to Set headers on the result.
	if mutatedHeaders == nil {
		mutatedHeaders = make(http.Header)
	}

	const templateMarker = "{{"

	// Optimization: Check if any mutation is actually needed.
	needsMutation := bytes.Contains(body, []byte(templateMarker))
	if !needsMutation {
	headerCheck:
		// We check the original headers for the marker, as mutatedHeaders might be empty if input was nil.
		for _, values := range headers {
			for _, value := range values {
				// Use strings.Contains to avoid allocation.
				if strings.Contains(value, templateMarker) {
					needsMutation = true
					break headerCheck
				}
			}
		}
	}

	if !needsMutation {
		return mutatedBody, mutatedHeaders, nil
	}

	// Generate unique values for this specific mutation instance.
	uniqueUUID := uuid.NewString()
	uniqueNonce := generateNonce()

	// Apply mutations to the body.
	if bytes.Contains(mutatedBody, templateUUID) {
		mutatedBody = bytes.ReplaceAll(mutatedBody, templateUUID, []byte(uniqueUUID))
	}
	if bytes.Contains(mutatedBody, templateNonce) {
		mutatedBody = bytes.ReplaceAll(mutatedBody, templateNonce, []byte(uniqueNonce))
	}

	// Apply mutations to headers.
	for key, values := range mutatedHeaders {
		for i, value := range values {
			originalValue := value
			value = strings.ReplaceAll(value, templateUUIDStr, uniqueUUID)
			value = strings.ReplaceAll(value, templateNonceStr, uniqueNonce)

			if value != originalValue {
				mutatedHeaders[key][i] = value
			}
		}
	}

	return mutatedBody, mutatedHeaders, nil
}

// generateNonce creates a simple random 12-digit nonce using a pooled PRNG.
func generateNonce() string {
	rng := getRNG()
	defer putRNG(rng)

	// Accessing the instance 'rng' is concurrency-safe.
	nonce := rng.Int63n(900000000000) + 100000000000
	return strconv.FormatInt(nonce, 10)
}
