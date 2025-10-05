package timeslip

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper to initialize an oracle for testing
func setupOracle(t *testing.T, config *Config, isGraphQL bool) *SuccessOracle {
	oracle, err := NewSuccessOracle(config, isGraphQL)
	// Handle potential regex compilation errors during setup
	if err != nil && config != nil && (config.Success.BodyRegex != "" || config.Success.HeaderRegex != "") {
		t.Fatalf("Failed to setup oracle due to config error: %v", err)
	}
	return oracle
}

// Helper to create a mock RaceResponse for oracle tests.
func oracleMockResponse(statusCode int, body string, headers http.Header) *RaceResponse {
	resp := mockResponse("", false, 100) // Fingerprint and duration don't matter here
	resp.ParsedResponse.StatusCode = statusCode
	resp.ParsedResponse.Body = []byte(body)
	resp.SpecificBody = []byte(body)
	resp.ParsedResponse.Headers = headers
	return resp
}

// --- 1.2. Success Oracle Tests ---

func TestNewSuccessOracle_Initialization(t *testing.T) {
	t.Run("Invalid Body Regex", func(t *testing.T) {
		config := &Config{Success: SuccessCondition{BodyRegex: "["}}
		_, err := NewSuccessOracle(config, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid BodyRegex")
	})

	t.Run("Invalid Header Regex", func(t *testing.T) {
		config := &Config{Success: SuccessCondition{HeaderRegex: "("}}
		_, err := NewSuccessOracle(config, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HeaderRegex")
	})
}

func TestOracle_CheckStatusCode(t *testing.T) {
	t.Run("Default Behavior (2xx/3xx)", func(t *testing.T) {
		oracle := setupOracle(t, &Config{}, false)

		assert.True(t, oracle.checkStatusCode(200))
		assert.True(t, oracle.checkStatusCode(302))
		assert.False(t, oracle.checkStatusCode(404))
	})

	t.Run("Configured Status Codes", func(t *testing.T) {
		config := &Config{Success: SuccessCondition{StatusCodes: []int{201, 400}}}
		oracle := setupOracle(t, config, false)

		assert.False(t, oracle.checkStatusCode(200))
		assert.True(t, oracle.checkStatusCode(201))
		assert.True(t, oracle.checkStatusCode(400))
	})
}

func TestOracle_IsSuccess_Regex(t *testing.T) {
	config := &Config{
		Success: SuccessCondition{
			BodyRegex:   `"status":"active"`,
			HeaderRegex: `^X-API-Version: \d+\.\d+`,
		},
	}
	oracle := setupOracle(t, config, false)

	headersMatch := http.Header{"X-API-Version": {"1.5"}}
	headersMismatch := http.Header{"X-API-Version": {"v2"}}

	t.Run("Both Match", func(t *testing.T) {
		resp := oracleMockResponse(200, `{"status":"active"}`, headersMatch)
		assert.True(t, oracle.IsSuccess(resp))
	})

	t.Run("Body Mismatch", func(t *testing.T) {
		resp := oracleMockResponse(200, `{"status":"inactive"}`, headersMatch)
		assert.False(t, oracle.IsSuccess(resp))
	})

	t.Run("Header Mismatch", func(t *testing.T) {
		resp := oracleMockResponse(200, `{"status":"active"}`, headersMismatch)
		assert.False(t, oracle.IsSuccess(resp))
	})
}

// --- Test GraphQL Spec Compliance ---

func TestIsGraphQLSpecSuccess(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"Success (No Errors Key)", `{"data": {"id": 1}}`, true},
		{"Success (Errors Key Null)", `{"data": {}, "errors": null}`, true},
		{"Failure (Errors Key Populated)", `{"errors": [{"message": "fail"}]}`, false},
		{"Failure (Not JSON Object)", `[1, 2, 3]`, false},
		{"Failure (Empty Body)", ` `, false},
		{"Failure (Invalid JSON)", `{"data": {unquoted}}`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isGraphQLSpecSuccess([]byte(tt.body))
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOracle_GraphQLIntegration(t *testing.T) {
	// Initialize Oracle in GraphQL mode
	oracle := setupOracle(t, &Config{}, true)

	// HTTP 200, GraphQL Success
	respSuccess := oracleMockResponse(200, `{"data":{}}`, http.Header{})
	// HTTP 200, GraphQL Failure (errors present)
	respGraphQLError := oracleMockResponse(200, `{"errors":[{"msg":"fail"}]}`, http.Header{})
	// HTTP 500 (Transport error)
	respHTTPError := oracleMockResponse(500, `{"data":{}}`, http.Header{})

	assert.True(t, oracle.IsSuccess(respSuccess))
	// Crucial test: Must return false even if HTTP is 200 if GQL errors exist
	assert.False(t, oracle.IsSuccess(respGraphQLError))
	// Must return false if HTTP status is failure
	assert.False(t, oracle.IsSuccess(respHTTPError))
}

func TestOracle_ErrorResponse(t *testing.T) {
	oracle := setupOracle(t, &Config{}, false)
	resp := &RaceResponse{Error: fmt.Errorf("timeout")}
	assert.False(t, oracle.IsSuccess(resp))
}