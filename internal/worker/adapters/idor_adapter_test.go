// File: internal/worker/adapters/idor_adapter_test.go
package adapters_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require" // Import require
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// Helper to create a testable AnalysisContext for IDOR.
func setupIDORContext(t *testing.T, targetURL string, task schemas.Task) *core.AnalysisContext {
	t.Helper()

	var parsedURL *url.URL
	// Handle the case where targetURL might be empty or invalid.
	if targetURL != "" {
		// We allow invalid URLs here if the test specifically intends to test that scenario (e.g., network errors).
		parsedURL, _ = url.Parse(targetURL)
	}

	// Initialize a concrete AnalysisContext for the test.
	ctx := &core.AnalysisContext{
		Task:      task,
		TargetURL: parsedURL,
		Logger:    zaptest.NewLogger(t),
		Findings:  []schemas.Finding{}, // Initialize slice to capture findings
		Global:    &core.GlobalContext{},
	}
	return ctx
}

func TestIDORAdapter_Analyze_ParameterValidation(t *testing.T) {
	adapter := adapters.NewIDORAdapter(zaptest.NewLogger(t))
	ctx := context.Background()

	// Dummy server for valid cases (as the adapter needs to make a baseline request)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"id": 1, "data": "baseline"}`)
	}))
	defer ts.Close()

	// Inject the test server's client.
	adapter.SetHttpClient(ts.Client())

	tests := []struct {
		name       string
		parameters interface{}
		targetURL  string
		wantErr    bool
		errMsg     string
	}{
		{"Valid Struct", schemas.IDORTaskParams{HTTPMethod: "GET"}, ts.URL, false, ""},
		{"Valid Pointer", &schemas.IDORTaskParams{HTTPMethod: "GET"}, ts.URL, false, ""},
		{"Nil Pointer", (*schemas.IDORTaskParams)(nil), ts.URL, true, "nil pointer for IDOR task"},
		{"Wrong Type (Struct)", schemas.ATOTaskParams{}, ts.URL, true, "invalid parameters type for IDOR task"},
		{"Wrong Type (String)", "invalid", ts.URL, true, "invalid parameters type for IDOR task"},
		// Test Case: Missing TargetURL (results in nil TargetURL in context)
		{"Missing TargetURL", schemas.IDORTaskParams{HTTPMethod: "GET"}, "", true, "TargetURL is required but missing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := schemas.Task{
				TaskID:     "task-1",
				TargetURL:  tt.targetURL,
				Parameters: tt.parameters,
			}
			analysisCtx := setupIDORContext(t, tt.targetURL, task)

			err := adapter.Analyze(ctx, analysisCtx)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIDORAdapter_Analyze_BaselineRequestBehavior(t *testing.T) {
	// Initialize adapter inside the loop to use the specific test server's client.
	ctx := context.Background()

	tests := []struct {
		name         string
		statusCode   int
		responseBody string
		targetURL    string
		wantErr      bool
		errMsg       string
	}{
		{"Success 200 OK", http.StatusOK, `{"id": 1, "data": "ok"}`, "", false, ""},
		{"Failure 404 (Skip Scan)", http.StatusNotFound, `{"error": "not found"}`, "", false, ""},
		{"Failure 500 (Skip Scan)", http.StatusInternalServerError, `{"error": "server error"}`, "", false, ""},
		// Use an invalid port to cause a network error (connection refused).
		{"Network Error", 0, "", "http://127.0.0.1:1", true, "baseline request failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				fmt.Fprintln(w, tt.responseBody)
			}))
			defer ts.Close()

			adapter := adapters.NewIDORAdapter(zaptest.NewLogger(t))
			// Inject the specific client for this test server.
			adapter.SetHttpClient(ts.Client())

			target := ts.URL
			if tt.targetURL != "" {
				target = tt.targetURL
				// Use a default client for network error tests as the test server won't be used.
				adapter.SetHttpClient(http.DefaultClient)
			}

			task := schemas.Task{
				TaskID:    "task-1",
				TargetURL: target,
				// Use parameters that won't trigger IDOR findings (no identifiers)
				Parameters: schemas.IDORTaskParams{HTTPMethod: "GET", HTTPBody: "no ids"},
			}
			analysisCtx := setupIDORContext(t, target, task)

			err := adapter.Analyze(ctx, analysisCtx)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
			// Ensure no findings were generated in any of these scenarios
			assert.Empty(t, analysisCtx.Findings)
		})
	}
}

// Test IDOR Detection logic, focusing on the semantic comparison aspect across different locations.
func TestIDORAdapter_Analyze_DetectionScenarios(t *testing.T) {
	ctx := context.Background()

	// Server logic: Simulates responses based on the requested ID and vulnerability flag.
	handler := func(isVulnerable bool, useSemanticEquivalence bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Read body for POST requests
			bodyBytes, _ := io.ReadAll(r.Body)
			body := string(bodyBytes)

			// Determine the requested ID (simplified simulation)
			// Ensure we only check body if the method is appropriate (e.g., POST)
			isBaseline := r.URL.Path == "/users/123" || r.URL.Query().Get("id") == "123" || (r.Method == "POST" && body == `{"user_id":123}`)
			isTest := r.URL.Path == "/users/124" || r.URL.Query().Get("id") == "124" || (r.Method == "POST" && body == `{"user_id":124}`)

			if isBaseline {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{"id": 123, "name": "Alice", "role": "user", "timestamp": 1000}`)
			} else if isTest {
				if isVulnerable {
					w.WriteHeader(http.StatusOK)
					if useSemanticEquivalence {
						// Vulnerable: Returns data for ID 124, structure is the same.
						fmt.Fprintln(w, `{"id": 124, "name": "Bob", "role": "user", "timestamp": 1005}`)
					} else {
						// Vulnerable, but response structure changes significantly (NOT detected by semantic comparison).
						fmt.Fprintln(w, `{"id": 124, "name": "Admin", "role": "admin", "secret_key": "xyz", "extra_field": true}`)
					}
				} else {
					// Secure: Returns an error.
					w.WriteHeader(http.StatusForbidden)
					fmt.Fprintln(w, `{"error": "unauthorized"}`)
				}
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}

	tests := []struct {
		name                   string
		isVulnerable           bool
		useSemanticEquivalence bool
		method                 string
		path                   string
		body                   string
		headers                map[string]string // Added headers field
		wantFindings           int
	}{
		// Path-based IDOR
		{"Vulnerable (Path, Semantic)", true, true, "GET", "/users/123", "", nil, 1},
		{"Vulnerable (Path, Structural Diff)", true, false, "GET", "/users/123", "", nil, 0},
		{"Secure (Path)", false, true, "GET", "/users/123", "", nil, 0},

		// Query-based IDOR
		{"Vulnerable (Query, Semantic)", true, true, "GET", "/users?id=123", "", nil, 1},

		// Body-based IDOR (JSON)
		// FIX: Added Content-Type header so the identifier extractor parses the JSON body.
		{"Vulnerable (Body, Semantic)", true, true, "POST", "/users", `{"user_id":123}`, map[string]string{"Content-Type": "application/json"}, 1},

		// No Identifiers
		{"No Identifiers Found", true, true, "GET", "/profile", "", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(handler(tt.isVulnerable, tt.useSemanticEquivalence))
			defer ts.Close()

			adapter := adapters.NewIDORAdapter(zaptest.NewLogger(t))
			adapter.SetHttpClient(ts.Client())

			targetURL := ts.URL + tt.path
			task := schemas.Task{
				TaskID:    "task-idor",
				TargetURL: targetURL,
				Parameters: schemas.IDORTaskParams{
					HTTPMethod:  tt.method,
					HTTPBody:    tt.body,
					HTTPHeaders: tt.headers, // Pass headers
				},
			}
			analysisCtx := setupIDORContext(t, targetURL, task)

			err := adapter.Analyze(ctx, analysisCtx)
			assert.NoError(t, err)

			// FIX: Use require.Len to stop execution if the length is wrong, preventing the panic.
			require.Len(t, analysisCtx.Findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				finding := analysisCtx.Findings[0]
				assert.Equal(t, schemas.SeverityHigh, finding.Severity)
				assert.Equal(t, "Insecure Direct Object Reference (IDOR)", finding.Vulnerability.Name)
				// Assuming the internal idor logic increments the number (123 -> 124)
				assert.Contains(t, finding.Description, "123")
				assert.Contains(t, finding.Description, "124")
				assert.Equal(t, []string{"CWE-639"}, finding.CWE)
			}
		})
	}
}

func TestIDORAdapter_Analyze_ContextCancellation(t *testing.T) {
	// Server that hangs until its context is cancelled
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return // Client cancelled the request
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	adapter := adapters.NewIDORAdapter(zaptest.NewLogger(t))
	adapter.SetHttpClient(ts.Client())

	task := schemas.Task{
		TaskID:     "task-cancel",
		TargetURL:  ts.URL,
		Parameters: schemas.IDORTaskParams{HTTPMethod: "GET"},
	}
	analysisCtx := setupIDORContext(t, ts.URL, task)

	// Create a context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := adapter.Analyze(ctx, analysisCtx)

	// Expect the context error to be returned directly when cancelled during the baseline request.
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
}

// Test case added to increase coverage: Handling network errors during the testing phase.
func TestIDORAdapter_Analyze_NetworkErrorDuringTest(t *testing.T) {
	adapter := adapters.NewIDORAdapter(zaptest.NewLogger(t))
	ctx := context.Background()

	// Use the shared mock transport helper
	client := newMockClient(func(req *http.Request) (*http.Response, error) {
		// Inject error only during the testing phase (when the body is modified)
		if req.Method == "POST" {
			bodyBytes, _ := io.ReadAll(req.Body)
			if string(bodyBytes) != `{"id":1}` { // Check if it's not the baseline request
				return nil, errors.New("simulated network error during test request")
			}
		}
		// Return a basic response for the baseline request.
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"id": 1, "status": "ok"}`)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	adapter.SetHttpClient(client)

	targetURL := "http://mockserver/test"
	task := schemas.Task{
		TaskID:    "task-network-test",
		TargetURL: targetURL,
		// Include an identifier to ensure the testing phase is reached.
		// FIX: Must include Content-Type for identifier extraction to work on the body.
		Parameters: schemas.IDORTaskParams{
			HTTPMethod:  "POST",
			HTTPBody:    `{"id":1}`,
			HTTPHeaders: map[string]string{"Content-Type": "application/json"},
		},
	}
	analysisCtx := setupIDORContext(t, targetURL, task)

	// Execute analysis
	err := adapter.Analyze(ctx, analysisCtx)

	// Assertions: The analysis should complete without error, even if individual test requests fail due to network issues.
	assert.NoError(t, err)
	assert.Empty(t, analysisCtx.Findings)
}