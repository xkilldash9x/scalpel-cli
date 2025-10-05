// internal/worker/adapters/ato_adapter_test.go
package adapters_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// Helper to setup AnalysisContext for ATOAdapter
func setupATOContext(t *testing.T, params interface{}) *core.AnalysisContext {
	t.Helper()
	return &core.AnalysisContext{
		Task: schemas.Task{
			TaskID:     "task-ato-1",
			Type:       schemas.TaskTestAuthATO,
			Parameters: params,
		},
		Logger:    zap.NewNop(),
		Global:    &core.GlobalContext{},
		Findings:  []schemas.Finding{},
	}
}

func TestATOAdapter_Analyze_ParameterValidation(t *testing.T) {
	adapter := adapters.NewATOAdapter()

	tests := []struct {
		name          string
		params        interface{}
		expectedError string
	}{
		{
			name:          "Wrong Type",
			params:        "invalid string",
			expectedError: "invalid parameters type for ATO task; expected schemas.ATOTaskParams or *schemas.ATOTaskParams, got string",
		},
		{
			name:          "Nil Pointer",
			params:        (*schemas.ATOTaskParams)(nil),
			expectedError: "invalid parameters: nil pointer for ATO task",
		},
		{
			name:          "Empty Usernames (Struct)",
			params:        schemas.ATOTaskParams{Usernames: []string{}},
			expectedError: "'usernames' parameter must be a non-empty array of strings",
		},
        {
			name:          "Empty Usernames (Pointer)",
			params:        &schemas.ATOTaskParams{Usernames: []string{}},
			expectedError: "'usernames' parameter must be a non-empty array of strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := setupATOContext(t, tt.params)
			err := adapter.Analyze(context.Background(), ctx)
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err.Error())
		})
	}
}

func TestATOAdapter_Analyze_SuccessAndEnumeration(t *testing.T) {
	// 1. Setup Mock Server
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)

        // NOTE: This test relies on the internal password list used by ato.GenerateSprayingPayloads.
        // Assuming 'password123' is one of them.
		username := body["username"]
        password := body["password"]

		switch {
        case username == "admin" && password == "password123":
			// Case 1: Successful login
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"status": "success", "token": "abc"}`)
        case username == "existing_user":
            // Case 2: User Enumeration (different response message)
            w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"status": "failure", "message": "Incorrect password"}`)
		default:
            // Case 3: Generic failure
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"status": "failure", "message": "Invalid credentials"}`)
		}
	}))
	defer server.Close()

	// 2. Setup Adapter and Context
	adapter := adapters.NewATOAdapter()
	adapter.SetHttpClient(server.Client()) // Inject the test server's client

	params := schemas.ATOTaskParams{Usernames: []string{"user1", "admin", "existing_user"}}
	analysisCtx := setupATOContext(t, params)
	analysisCtx.Task.TargetURL = server.URL

	// 3. Execute Analysis
	err := adapter.Analyze(context.Background(), analysisCtx)
	assert.NoError(t, err)

	// 4. Assertions
	assert.GreaterOrEqual(t, requestCount, 3)
	require.NotEmpty(t, analysisCtx.Findings)

    foundSuccess := false
    foundEnum := false

    for _, finding := range analysisCtx.Findings {
        if finding.Vulnerability.Name == "Successful Login with Weak Credentials" {
            foundSuccess = true
            assert.Equal(t, schemas.SeverityHigh, finding.Severity)
            assert.Contains(t, finding.Description, "user 'admin'")
	        assert.Contains(t, finding.Evidence, `"statusCode":200`)
        }
        if finding.Vulnerability.Name == "User Enumeration on Login Form" {
            foundEnum = true
            assert.Equal(t, schemas.SeverityMedium, finding.Severity)
            assert.Contains(t, finding.Description, "user 'existing_user'")
        }
    }
    assert.True(t, foundSuccess, "Expected successful login finding")
    assert.True(t, foundEnum, "Expected user enumeration finding")
}

// Tests cancellation between requests (testing the throttle and loop select{})
func TestATOAdapter_Analyze_ContextCancellation_InLoop(t *testing.T) {
	adapter := adapters.NewATOAdapter()

	// Many usernames to ensure the loop runs long enough
	params := schemas.ATOTaskParams{Usernames: make([]string, 100)}
	analysisCtx := setupATOContext(t, params)
	analysisCtx.Task.TargetURL = "http://localhost:9999" // Target doesn't matter

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel very quickly
	time.AfterFunc(10*time.Millisecond, cancel)

	startTime := time.Now()
	err := adapter.Analyze(ctx, analysisCtx)
	duration := time.Since(startTime)

	// Must return context.Canceled error
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)

	// Must finish quickly (100 users * N passwords * 200ms throttle = very long normally)
	assert.Less(t, duration.Seconds(), 1.0, "Analysis should stop promptly upon cancellation")
}

// Tests cancellation while an HTTP request is in flight.
func TestATOAdapter_Analyze_ContextCancellation_DuringHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Server that hangs until the client cancels the request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wait for the request context (which inherits from the parent ctx) to be cancelled
        <-r.Context().Done()
	}))
	defer server.Close()

	adapter := adapters.NewATOAdapter()
	// Crucial: Use the server's client, which correctly propagates request contexts
	adapter.SetHttpClient(server.Client())

	params := schemas.ATOTaskParams{Usernames: []string{"user1"}}
	analysisCtx := setupATOContext(t, params)
	analysisCtx.Task.TargetURL = server.URL

	// Cancel shortly after the request likely started
	time.AfterFunc(100*time.Millisecond, cancel)

	startTime := time.Now()
	err := adapter.Analyze(ctx, analysisCtx)
	duration := time.Since(startTime)

	// The Analyze loop should detect the parent context cancellation
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	// Should finish quickly
	assert.Less(t, duration.Seconds(), 1.0, "HTTP request should be canceled")
}

// TestATOAdapter_Analyze_HTTPFailureResilience verifies that individual network failures don't stop the scan.
func TestATOAdapter_Analyze_HTTPFailureResilience(t *testing.T) {
	adapter := adapters.NewATOAdapter()
	// Use a client with a very short timeout
	adapter.SetHttpClient(&http.Client{Timeout: 1 * time.Millisecond})

	params := schemas.ATOTaskParams{Usernames: []string{"user1", "user2"}}
	analysisCtx := setupATOContext(t, params)
	// A non-routable IP address to induce connection errors
	analysisCtx.Task.TargetURL = "http://10.255.255.1"

	// Set a global timeout to prevent the test from hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := adapter.Analyze(ctx, analysisCtx)

	// The analysis should complete without returning an error; individual request failures are logged internally but don't stop the process.
	assert.NoError(t, err)
	assert.Empty(t, analysisCtx.Findings)
}
