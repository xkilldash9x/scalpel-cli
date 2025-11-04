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
	originalURL := "https://example.com/api/{{UUID}}"

	// Execute mutation
	candidate := &RaceCandidate{
		Body:    originalBody,
		Headers: originalHeaders,
		URL:     originalURL,
	}
	mutatedBody, mutatedHeaders, mutatedURL, err := MutateRequest(candidate)
	require.NoError(t, err)

	// Verify replacements occurred
	assert.NotContains(t, string(mutatedBody), "{{UUID}}")
	assert.NotContains(t, string(mutatedBody), "{{NONCE}}")

	// Verify consistency: the same generated UUID/Nonce must be used in body, headers, and URL.
	generatedUUID := strings.TrimPrefix(mutatedHeaders.Get("Authorization"), "Bearer ")
	generatedNonce := mutatedHeaders.Get("X-Request-Id")

	assert.NotEmpty(t, generatedUUID)
	assert.NotEmpty(t, generatedNonce)

	assert.Contains(t, string(mutatedBody), generatedUUID)
	assert.Contains(t, string(mutatedBody), generatedNonce)
	assert.Contains(t, mutatedURL, generatedUUID)
	assert.NotContains(t, mutatedURL, "{{UUID}}")
}

func TestMutateRequest_Uniqueness(t *testing.T) {
	templateBody := []byte(`{"id":"{{UUID}}", "nonce":"{{NONCE}}"}`)

	// Execute first mutation
	candidate1 := &RaceCandidate{Body: templateBody, Headers: http.Header{}}
	body1, _, _, err1 := MutateRequest(candidate1)
	require.NoError(t, err1)

	// Execute second mutation
	candidate2 := &RaceCandidate{Body: templateBody, Headers: http.Header{}}
	body2, _, _, err2 := MutateRequest(candidate2)
	require.NoError(t, err2)

	// Assertions: Results must be different
	assert.NotEqual(t, body1, body2, "Consecutive calls produced identical mutations")
}

func TestMutateRequest_OptimizationPath(t *testing.T) {
	// Input without any template markers
	body := []byte(`{"id":"fixed-id"}`)
	headers := http.Header{"Authorization": {"Bearer fixed-token"}}
	url := "http://example.com/fixed"

	candidate := &RaceCandidate{
		Body:    body,
		Headers: headers,
		URL:     url,
	}
	mutatedBody, mutatedHeaders, mutatedURL, err := MutateRequest(candidate)
	require.NoError(t, err)

	// Verify that the inputs are returned (headers are cloned, body/url are the same).
	assert.Equal(t, url, mutatedURL)
	assert.Equal(t, body, mutatedBody)
	assert.Equal(t, headers, mutatedHeaders)

	// Advanced check: Verify the pointer to the body slice data is the same (no allocation)
	if len(body) > 0 && len(mutatedBody) > 0 {
		assert.Same(t, &body[0], &mutatedBody[0], "Body slice pointer changed even without mutation, optimization failed.")
	}
}

// Test case for ensuring headers are initialized even if input headers are nil.
func TestMutateRequest_NilHeadersInitialization(t *testing.T) {
	// Case 1: No mutation needed
	candidate1 := &RaceCandidate{
		Body:    []byte("no templates"),
		Headers: nil, // Nil headers
		URL:     "http://example.com",
	}
	_, mutatedHeaders1, _, err1 := MutateRequest(candidate1)
	require.NoError(t, err1)
	// Headers should be initialized to an empty map, not nil, to prevent panics downstream.
	assert.NotNil(t, mutatedHeaders1)
	assert.Empty(t, mutatedHeaders1)

	// Case 2: Mutation needed (e.g., in URL)
	candidate2 := &RaceCandidate{
		Body:    []byte("no templates"),
		Headers: nil,
		URL:     "http://example.com/{{NONCE}}",
	}
	_, mutatedHeaders2, _, err2 := MutateRequest(candidate2)
	require.NoError(t, err2)
	assert.NotNil(t, mutatedHeaders2)
}

func TestGenerateNonce(t *testing.T) {
	nonce1 := generateNonce()
	nonce2 := generateNonce()

	// Check format (12 digits)
	assert.Len(t, nonce1, 12)
	assert.NotEqual(t, nonce1, nonce2, "Nonces should be unique")
}
