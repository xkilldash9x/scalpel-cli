// pkg/analysis/active/timeslip/templating.go
package timeslip

import (
	"bytes"
	"math/rand"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Template variables recognized by the mutation engine.
var (
	templateUUID  = []byte("{{UUID}}")
	templateNonce = []byte("{{NONCE}}")
)

var (
	// Initialize a source for random numbers.
	// Use a mutex-protected source for thread-safety when generating nonces concurrently across many goroutines.
	rndSource = rand.New(rand.NewSource(time.Now().UnixNano()))
	rndMutex  sync.Mutex
)

// MutateRequest applies template substitutions to the request body and headers.
// It generates unique values for each call.
func MutateRequest(body []byte, headers http.Header) ([]byte, http.Header, error) {
	mutatedBody := body
	mutatedHeaders := headers.Clone()

	// Optimization: Check if any mutation is actually needed before generating values.
	needsMutation := bytes.Contains(body, []byte("{{"))
	if !needsMutation {
	headerCheck:
		for _, values := range headers {
			for _, value := range values {
				if bytes.Contains([]byte(value), []byte("{{")) {
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
			mutatedValue := []byte(value)
			mutated := false
			if bytes.Contains(mutatedValue, templateUUID) {
				mutatedValue = bytes.ReplaceAll(mutatedValue, templateUUID, []byte(uniqueUUID))
				mutated = true
			}
			if bytes.Contains(mutatedValue, templateNonce) {
				mutatedValue = bytes.ReplaceAll(mutatedValue, templateNonce, []byte(uniqueNonce))
				mutated = true
			}
			if mutated {
				mutatedHeaders[key][i] = string(mutatedValue)
			}
		}
	}

	return mutatedBody, mutatedHeaders, nil
}

// generateNonce creates a simple random 12-digit nonce.
func generateNonce() string {
	rndMutex.Lock()
	defer rndMutex.Unlock()
	// Generate a random number between 10^11 and 10^12 - 1.
	nonce := rndSource.Int63n(900000000000) + 100000000000
	return strconv.FormatInt(nonce, 10)
}