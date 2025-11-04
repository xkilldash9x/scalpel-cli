// internal/worker/adapters/idor_adapter_test.go
package adapters_test

import ( // This is a comment to force a change
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	// Assuming these import paths based on the provided files
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// Helper to create a testable AnalysisContext.
// We assume core.AnalysisContext manages findings internally and exposes them via a slice (e.g., ctx.Findings).
// We also assume that the AnalysisContext struct has an AddFinding method that appends to this slice.
func setupIDORContext(t *testing.T, targetURL string, task schemas.Task) *core.AnalysisContext {
	parsedURL, err := url.Parse(targetURL)
	require.NoError(t, err)

	// Initialize a concrete AnalysisContext for the test.
	ctx := &core.AnalysisContext{
		Task:      task,
		TargetURL: parsedURL,
		Logger:    zaptest.NewLogger(t),
		Findings:  []schemas.Finding{}, // Initialize slice to capture findings
		Global:    &core.GlobalContext{},
	}

	// NOTE: For this test to work, the actual implementation of core.AnalysisContext
	// must have a method `AddFinding(f schemas.Finding)` that appends to the `Findings` slice.
	/*
	   Example implementation assumed in core/context.go:
	   func (c *AnalysisContext) AddFinding(f schemas.Finding) {
	       c.Findings = append(c.Findings, f)
	   }
	*/
	return ctx
}

func TestIDORAdapter_Analyze_ParameterValidation(t *testing.T) {
	adapter := adapters.NewIDORAdapter()
	ctx := context.Background()

	// Dummy server for valid cases (as the adapter needs to make a baseline request)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	tests := []struct {
		name       string
		parameters interface{}
		wantErr    bool
		errMsg     string
	}{
		{"Valid Struct", schemas.IDORTaskParams{HTTPMethod: "GET"}, false, ""},
		{"Valid Pointer", &schemas.IDORTaskParams{HTTPMethod: "GET"}, false, ""},
		{"Nil Pointer", (*schemas.IDORTaskParams)(nil), true, "nil pointer for IDOR task"},
		{"Wrong Type (Struct)", schemas.ATOTaskParams{}, true, "invalid parameters type for IDOR task"},
		{"Wrong Type (String)", "invalid", true, "invalid parameters type for IDOR task"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := schemas.Task{
				TaskID:     "task-1",
				TargetURL:  ts.URL,
				Parameters: tt.parameters,
			}
			analysisCtx := setupIDORContext(t, ts.URL, task)

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
	adapter := adapters.NewIDORAdapter()
	ctx := context.Background()

	tests := []struct {
		name       string
		statusCode int
		targetURL  string
		wantErr    bool
		errMsg     string
	}{
		{"Success 200 OK", http.StatusOK, "", false, ""},
		{"Failure 404 (Skip Scan)", http.StatusNotFound, "", false, ""},
		{"Failure 500 (Skip Scan)", http.StatusInternalServerError, "", false, ""},
		{"Network Error", 0, "http://127.0.0.1:0", true, "baseline request failed"}, // Invalid port causes network error
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer ts.Close()

			target := ts.URL
			if tt.targetURL != "" {
				target = tt.targetURL
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

// Test IDOR Detection logic. This relies on the internal idor package (not provided)
// correctly identifying and modifying IDs (e.g., incrementing integers).
func TestIDORAdapter_Analyze_DetectionScenarios(t *testing.T) {
	adapter := adapters.NewIDORAdapter()
	ctx := context.Background()

	// Server logic: Determines if the response indicates vulnerability or security.
	handler := func(isVulnerable bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Check ID in the URL Path (e.g., /users/123)
			if r.URL.Path == "/users/123" {
				w.WriteHeader(http.StatusOK) // Baseline always succeeds
			} else if r.URL.Path != "/" {
				if isVulnerable {
					w.WriteHeader(http.StatusOK) // Vulnerable: other IDs succeed
				} else {
					w.WriteHeader(http.StatusForbidden) // Secure: other IDs fail
				}
			} else {
				// Fallback for requests without path IDs
				w.WriteHeader(http.StatusOK)
			}
		}
	}

	tests := []struct {
		name         string
		isVulnerable bool
		path         string
		wantFindings int
	}{
		{"Vulnerable Endpoint (Path ID)", true, "/users/123", 1},
		{"Secure Endpoint (Path ID)", false, "/users/123", 0},
		{"No Identifiers Found", true, "/profile", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(handler(tt.isVulnerable))
			defer ts.Close()

			targetURL := ts.URL + tt.path
			task := schemas.Task{
				TaskID:     "task-idor",
				TargetURL:  targetURL,
				Parameters: schemas.IDORTaskParams{HTTPMethod: "GET"},
			}
			analysisCtx := setupIDORContext(t, targetURL, task)

			err := adapter.Analyze(ctx, analysisCtx)
			assert.NoError(t, err)
			assert.Len(t, analysisCtx.Findings, tt.wantFindings)

			if tt.wantFindings > 0 {
				finding := analysisCtx.Findings[0]
				assert.Equal(t, schemas.SeverityHigh, finding.Severity)
				assert.Equal(t, "Insecure Direct Object Reference (IDOR)", finding.Vulnerability.Name)
				assert.Contains(t, finding.Description, "123")
				// Assuming the internal idor logic increments the number (123 -> 124)
				assert.Contains(t, finding.Description, "124")
				assert.Equal(t, []string{"CWE-639"}, finding.CWE)
			}
		})
	}
}

func TestIDORAdapter_Analyze_ContextCancellation(t *testing.T) {
	adapter := adapters.NewIDORAdapter()

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

	// Expect an error indicating the context was cancelled during the baseline HTTP request
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "baseline request failed")
	// Ensure the underlying error is context related
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
}
