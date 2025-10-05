package timeslip

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- 1.4. Templating Tests ---

func TestMutateRequest_ApplicationAndConsistency(t *testing.T) {
	originalBody := []byte(`{"id":"{{UUID}}", "token":"{{NONCE}}"}`)
	originalHeaders := http.Header{
		"Authorization": {"Bearer {{UUID}}"},
		"X-Request-Id":  {"{{NONCE}}"},
	}

	// Execute mutation
	mutatedBody, mutatedHeaders, err := MutateRequest(originalBody, originalHeaders)
	require.NoError(t, err)

	// Verify replacements occurred
	assert.NotContains(t, string(mutatedBody), "{{UUID}}")
	assert.NotContains(t, string(mutatedBody), "{{NONCE}}")

	// Verify consistency: the same generated UUID/Nonce must be used in both body and headers for this call
	generatedUUID := strings.TrimPrefix(mutatedHeaders.Get("Authorization"), "Bearer ")
	generatedNonce := mutatedHeaders.Get("X-Request-Id")

	assert.NotEmpty(t, generatedUUID)
	assert.NotEmpty(t, generatedNonce)

	assert.Contains(t, string(mutatedBody), generatedUUID)
	assert.Contains(t, string(mutatedBody), generatedNonce)
}

func TestMutateRequest_Uniqueness(t *testing.T) {
	templateBody := []byte(`{"id":"{{UUID}}", "nonce":"{{NONCE}}"}`)

	// Execute first mutation
	body1, _, err1 := MutateRequest(templateBody, http.Header{})
	require.NoError(t, err1)

	// Execute second mutation
	body2, _, err2 := MutateRequest(templateBody, http.Header{})
	require.NoError(t, err2)

	// Assertions: Results must be different
	assert.NotEqual(t, body1, body2, "Consecutive calls produced identical mutations")
}

func TestMutateRequest_OptimizationPath(t *testing.T) {
	// Input without any template markers
	body := []byte(`{"id":"fixed-id"}`)
	headers := http.Header{"Authorization": {"Bearer fixed-token"}}

	mutatedBody, mutatedHeaders, err := MutateRequest(body, headers)
	require.NoError(t, err)

	// Verify that the inputs are returned unchanged (optimization path)
	assert.Equal(t, body, mutatedBody)
	// Headers are cloned, so we check content equality
	assert.Equal(t, headers, mutatedHeaders)

    // Advanced check: Verify the pointer to the body slice data is the same (no allocation)
	if len(body) > 0 && len(mutatedBody) > 0 {
        // This confirms the optimization mentioned in templating.go (lines 43-59)
	    assert.Same(t, &body[0], &mutatedBody[0], "Body slice pointer changed even without mutation, optimization failed.")
    }
}

func TestGenerateNonce(t *testing.T) {
	nonce1 := generateNonce()
	nonce2 := generateNonce()

	// Check format (12 digits as defined in templating.go line 88)
	assert.Len(t, nonce1, 12)
	assert.NotEqual(t, nonce1, nonce2, "Nonces should be unique")
}