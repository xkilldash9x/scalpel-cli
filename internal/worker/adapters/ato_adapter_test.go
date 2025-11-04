// File: internal/worker/adapters/ato_adapter_test.go
package adapters_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// Helper to setup AnalysisContext for ATOAdapter
func setupATOContext(t *testing.T, params interface{}, targetURL string) *core.AnalysisContext {
	t.Helper()

	// Parse the URL if provided.
	var parsedURL *url.URL
	if targetURL != "" {
		var err error
		parsedURL, err = url.Parse(targetURL)
		// Allow parsing failure if the test specifically intends to test invalid URLs, but typically we want valid ones.
		if err != nil && targetURL != "http://127.0.0.1:9999" { // Allow dummy non-routable URL
			require.NoError(t, err, "Test setup failed: invalid target URL")
		}
	}

	return &core.AnalysisContext{
		Task: schemas.Task{
			TaskID:     "task-ato-1",
			Type:       schemas.TaskTestAuthATO,
			Parameters: params,
			TargetURL:  targetURL,
		},
		TargetURL: parsedURL,
		Logger:    zaptest.NewLogger(t),
		Global:    &core.GlobalContext{},
		Findings:  []schemas.Finding{},
	}
}

// TestATOAdapter_SetHttpClient verifies the client setter/getter logic.
func TestATOAdapter_SetHttpClient(t *testing.T) {
	adapter := adapters.NewATOAdapter()
	defaultClient := adapter.GetHttpClient()
	require.NotNil(t, defaultClient)

	newClient := &http.Client{Timeout: 1 * time.Second}
	adapter.SetHttpClient(newClient)
	assert.Equal(t, newClient, adapter.GetHttpClient())

	// Setting nil should not overwrite the existing client.
	adapter.SetHttpClient(nil)
	assert.Equal(t, newClient, adapter.GetHttpClient())
}

// TestATOAdapter_Analyze_NilHttpClient ensures the adapter fails defensively if the client is somehow nil.
func TestATOAdapter_Analyze_NilHttpClient(t *testing.T) {
	// Bypassing the constructor to force the httpClient to be nil.
	adapterBypass := &adapters.ATOAdapter{}
	// Initialize BaseAnalyzer manually to prevent nil panics if logger was accessed before the check.
	adapterBypass.BaseAnalyzer = *core.NewBaseAnalyzer("TestATO", "Desc", core.TypeActive, zap.NewNop())

	params := schemas.ATOTaskParams{Usernames: []string{"user1"}}
	analysisCtx := setupATOContext(t, params, "http://example.com")

	err := adapterBypass.Analyze(context.Background(), analysisCtx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "critical error: HTTP client not initialized")
}

func TestATOAdapter_Analyze_ParameterValidation(t *testing.T) {
	adapter := adapters.NewATOAdapter()
	dummyURL := "http://example.com/login"

	tests := []struct {
		name          string
		params        interface{}
		expectedError string
	}{
		{"Wrong Type", "invalid string", "invalid parameters type for ATO task; expected schemas.ATOTaskParams or *schemas.ATOTaskParams, got string"},
		{"Nil Pointer", (*schemas.ATOTaskParams)(nil), "invalid parameters: nil pointer for ATO task"},
		{"Empty Usernames (Struct)", schemas.ATOTaskParams{Usernames: []string{}}, "'usernames' parameter must be a non-empty array of strings"},
		{"Empty Usernames (Pointer)", &schemas.ATOTaskParams{Usernames: []string{}}, "'usernames' parameter must be a non-empty array of strings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := setupATOContext(t, tt.params, dummyURL)
			err := adapter.Analyze(context.Background(), ctx)
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err.Error())
		})
	}
}

func TestATOAdapter_Analyze_SuccessAndEnumeration(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		var body map[string]string
		// Added error handling for JSON decoding
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, `{"error": "invalid json"}`)
			return
		}
		username := body["username"]

		switch {
		case username == "admin":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"status": "success", "token": "abc"}`)
		case username == "existing_user":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"status": "failure", "message": "Incorrect password"}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"status": "failure", "message": "Invalid credentials"}`)
		}
	}))
	defer server.Close()

	adapter := adapters.NewATOAdapter()
	adapter.SetHttpClient(server.Client())
	params := schemas.ATOTaskParams{Usernames: []string{"user1", "admin", "existing_user"}}
	analysisCtx := setupATOContext(t, params, server.URL)

	err := adapter.Analyze(context.Background(), analysisCtx)
	assert.NoError(t, err)

	require.NotEmpty(t, analysisCtx.Findings)
	foundSuccess, foundEnum := false, false
	for _, finding := range analysisCtx.Findings {
		if finding.Vulnerability.Name == "Successful Login with Weak Credentials" {
			foundSuccess = true
		}
		if finding.Vulnerability.Name == "User Enumeration on Login Form" {
			foundEnum = true
		}
	}
	assert.True(t, foundSuccess, "Expected successful login finding")
	assert.True(t, foundEnum, "Expected user enumeration finding")
	// 3 users * 16 default passwords = 48 requests (based on log output)
	assert.Equal(t, 48, requestCount, "Expected 48 total requests")
}

func TestATOAdapter_Analyze_ContextCancellation_InLoop(t *testing.T) {
	adapter := adapters.NewATOAdapter()
	// Large list to ensure the loop runs long enough to be cancelled.
	usernames := make([]string, 100)
	for i := range usernames {
		usernames[i] = fmt.Sprintf("user%d", i)
	}
	params := schemas.ATOTaskParams{Usernames: usernames}
	analysisCtx := setupATOContext(t, params, "http://127.0.0.1:9999")

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after starting
	time.AfterFunc(50*time.Millisecond, cancel)

	err := adapter.Analyze(ctx, analysisCtx)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestATOAdapter_Analyze_ContextCancellation_DuringHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang until the request context is cancelled
		<-r.Context().Done()
	}))
	defer server.Close()

	adapter := adapters.NewATOAdapter()
	adapter.SetHttpClient(server.Client())
	params := schemas.ATOTaskParams{Usernames: []string{"user1"}}
	analysisCtx := setupATOContext(t, params, server.URL)

	// Cancel shortly after the request starts
	time.AfterFunc(100*time.Millisecond, cancel)

	err := adapter.Analyze(ctx, analysisCtx)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestATOAdapter_Analyze_HTTPFailureResilience(t *testing.T) {
	// Create a server and immediately close it to simulate a connection refused error.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Server should not have been contacted")
	}))
	targetURL := server.URL
	server.Close()

	adapter := adapters.NewATOAdapter()
	// Set a short timeout on the client
	adapter.SetHttpClient(&http.Client{Timeout: 1 * time.Second})

	params := schemas.ATOTaskParams{Usernames: []string{"user1", "user2"}}
	analysisCtx := setupATOContext(t, params, targetURL)

	// The test makes 2*16=32 requests with a 200ms throttle, requiring >6.4s. Increase timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The adapter should log the errors but continue processing other attempts and return nil.
	err := adapter.Analyze(ctx, analysisCtx)
	assert.NoError(t, err)
	assert.Empty(t, analysisCtx.Findings)
}

// Test Case: Ensure TargetURL nil pointer is handled in performLoginAttempt.
func TestATOAdapter_Analyze_NilTargetURL(t *testing.T) {
	adapter := adapters.NewATOAdapter()
	params := schemas.ATOTaskParams{Usernames: []string{"user1"}}
	// Setup context with an empty string URL, resulting in a nil parsed URL.
	analysisCtx := setupATOContext(t, params, "")

	// The analysis should proceed, but the individual attempt should log an error internally and return early.
	// The overall Analyze function should complete successfully.
	err := adapter.Analyze(context.Background(), analysisCtx)
	assert.NoError(t, err)
	assert.Empty(t, analysisCtx.Findings)
}
