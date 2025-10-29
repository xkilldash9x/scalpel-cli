// internal/analysis/active/timeslip/graphql_async_test.go
package timeslip

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConstructBatchedGraphQL validates the creation of the batched request payload,
// including the uniqueness of mutations applied to each operation.
func TestConstructBatchedGraphQL(t *testing.T) {
	candidate := &RaceCandidate{
		// A representative GraphQL mutation using both UUID and NONCE templates
		Body: []byte(`{"query":"mutation { action(id: \"{{UUID}}\", nonce: \"{{NONCE}}\") }"}`),
	}
	concurrency := 5

	batchedBody, err := constructBatchedGraphQL(candidate, concurrency)
	require.NoError(t, err)

	// 1. Verify it's a valid JSON array
	var parsed []map[string]interface{}
	err = json.Unmarshal(batchedBody, &parsed)
	require.NoError(t, err, "Batched body should be valid JSON array")

	// 2. Verify the count
	assert.Len(t, parsed, concurrency)

	// 3. Verify uniqueness (mutations were applied)
	uniqueUUIDs := make(map[string]bool)
	uniqueNonces := make(map[string]bool)

	for _, op := range parsed {
		query, ok := op["query"].(string)
		require.True(t, ok)

		// Check that templates are gone
		assert.NotContains(t, query, "{{UUID}}")
		assert.NotContains(t, query, "{{NONCE}}")

		// Extract UUID and Nonce (simplified extraction for testing)
		// This extraction is brittle but sufficient for this specific test structure.
		startUUID := len(`mutation { action(id: \"`)
		// UUID length is 36
		uuid := query[startUUID : startUUID+36]
		uniqueUUIDs[uuid] = true

		startNonce := startUUID + 36 + len(`\", nonce: \"`)
		// Nonce length is 12
		nonce := query[startNonce : startNonce+12]
		uniqueNonces[nonce] = true
	}

	assert.Len(t, uniqueUUIDs, concurrency, "All UUIDs should be unique")
	assert.Len(t, uniqueNonces, concurrency, "All Nonces should be unique")
}

// TestConstructBatchedGraphQL_Errors validates input validation for the batch construction.
func TestConstructBatchedGraphQL_Errors(t *testing.T) {
	t.Run("Invalid Input (Not Object)", func(t *testing.T) {
		// GraphQL operations must be JSON objects
		candidate := &RaceCandidate{Body: []byte(`["array"]`)}
		_, err := constructBatchedGraphQL(candidate, 2)
		assert.ErrorIs(t, err, ErrConfigurationError)
		assert.Contains(t, err.Error(), "must be a JSON object")
	})

	t.Run("Empty Input", func(t *testing.T) {
		candidate := &RaceCandidate{Body: []byte(` `)}
		_, err := constructBatchedGraphQL(candidate, 2)
		assert.ErrorIs(t, err, ErrConfigurationError)
	})
}

// TestHandleNonBatchedGraphQLResponse validates the fallback mechanism when a server
// responds with a single GraphQL result instead of a batched array.
func TestHandleNonBatchedGraphQLResponse(t *testing.T) {
	// Setup
	config := &Config{}
	oracle, _ := NewSuccessOracle(config, true) // Initialize Oracle in GraphQL mode
	excludeMap := config.GetExcludedHeaders()
	duration := 100 * time.Millisecond

	// Case 1: Success Response
	parsedRespSuccess := &ParsedResponse{
		StatusCode: 200,
		Headers:    http.Header{"Content-Type": {"application/json"}, "X-Cache": {"HIT"}},
		Body:       []byte(`{"data": {"result": "ok"}}`),
	}

	resultSuccess := handleNonBatchedGraphQLResponse(parsedRespSuccess, duration, oracle, excludeMap)

	assert.Equal(t, AsyncGraphQL, resultSuccess.Strategy)
	assert.Equal(t, duration, resultSuccess.Duration)
	require.Len(t, resultSuccess.Responses, 1)

	respSuccess := resultSuccess.Responses[0]
	// Oracle should correctly identify this as a GraphQL success
	assert.True(t, respSuccess.IsSuccess)
	assert.NotEmpty(t, respSuccess.Fingerprint)
	assert.Equal(t, parsedRespSuccess.Body, respSuccess.SpecificBody)

	// Case 2: Failure Response (GraphQL Error)
	parsedRespFailure := &ParsedResponse{
		StatusCode: 200, // HTTP OK, but GraphQL application error
		Headers:    http.Header{"Content-Type": {"application/json"}},
		Body:       []byte(`{"errors": [{"message": "fail"}]}`),
	}

	resultFailure := handleNonBatchedGraphQLResponse(parsedRespFailure, duration, oracle, excludeMap)
	require.Len(t, resultFailure.Responses, 1)
	// Oracle should correctly identify this as a GraphQL failure
	assert.False(t, resultFailure.Responses[0].IsSuccess)
}
