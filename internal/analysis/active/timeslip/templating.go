// pkg/analysis/active/timeslip/templating.go
package timeslip

import (
	"bytes"
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
var rngPool = sync.Pool{
	New: func() interface{} {
		// Seed each new PRNG uniquely upon creation.
		//nolint:gosec // Weak RNG is acceptable here.
		src := rand.NewSource(time.Now().UnixNano())
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
	const templateMarker = "{{"

	// Optimization: Check if any mutation is actually needed.
	needsMutation := bytes.Contains(body, []byte(templateMarker))
	if !needsMutation {
	headerCheck:
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
