// internal/worker/adapters/ato_adapter_test.go
package adapters_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// Helper to setup AnalysisContext for ATOAdapter
func setupATOContext(t *testing.T, params interface{}) *core.AnalysisContext {
	t.Helper()
	// Create a default config to ensure Global.Config is not nil.
	defaultConfig := config.NewDefaultConfig()
	return &core.AnalysisContext{
		Task: schemas.Task{
			TaskID:     "task-ato-1",
			Type:       schemas.TaskTestAuthATO,
			Parameters: params,
		},
		Logger: zap.NewNop(),
		Global: &core.GlobalContext{
			Config: defaultConfig,
		},
		Findings: []schemas.Finding{},
	}
}

func TestATOAdapter_Analyze_ParameterValidation(t *testing.T) {
	adapter := adapters.NewATOAdapter()

	// Determine the expected path for SecLists for robust error message checking.
	home, err := homedir.Dir()
	require.NoError(t, err, "Failed to get home directory for test setup")
	expectedSecListsPath := filepath.Join(home, "SecLists")
	expectedErr := fmt.Sprintf("SecLists directory not found at '%s'. Please install SecLists or configure the correct path.", expectedSecListsPath)

	tests := []struct {
		name          string
		params        interface{}
		expectedError string
	}{
		{"Wrong Type", "invalid string", "invalid parameters type for ATO task; expected schemas.ATOTaskParams or *schemas.ATOTaskParams, got string"},
		{"Nil Pointer", (*schemas.ATOTaskParams)(nil), "invalid parameters: nil pointer for ATO task"},
		{"Empty Usernames (Struct)", schemas.ATOTaskParams{Usernames: []string{}}, expectedErr},
		{"Empty Usernames (Pointer)", &schemas.ATOTaskParams{Usernames: []string{}}, expectedErr},
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
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
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
	analysisCtx := setupATOContext(t, params)
	analysisCtx.Task.TargetURL = server.URL
	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	analysisCtx.TargetURL = parsedURL
	err = adapter.Analyze(context.Background(), analysisCtx)
	assert.NoError(t, err)

	require.NotEmpty(t, analysisCtx.Findings)
	foundSuccess, foundEnum := false, false
	for _, finding := range analysisCtx.Findings {
		// Refactored: Assert against VulnerabilityName
		if finding.VulnerabilityName == "Successful Login with Weak Credentials" {
			foundSuccess = true
		}
		// Refactored: Assert against VulnerabilityName
		if finding.VulnerabilityName == "User Enumeration on Login Form" {
			foundEnum = true
		}
	}
	assert.True(t, foundSuccess, "Expected successful login finding")
	assert.True(t, foundEnum, "Expected user enumeration finding")
}

func TestATOAdapter_Analyze_ContextCancellation_InLoop(t *testing.T) {
	adapter := adapters.NewATOAdapter()
	params := schemas.ATOTaskParams{Usernames: make([]string, 100)}
	analysisCtx := setupATOContext(t, params)
	analysisCtx.Task.TargetURL = "http://localhost:9999"
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(10*time.Millisecond, cancel)
	err := adapter.Analyze(ctx, analysisCtx)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestATOAdapter_Analyze_ContextCancellation_DuringHTTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	adapter := adapters.NewATOAdapter()
	adapter.SetHttpClient(server.Client())
	params := schemas.ATOTaskParams{Usernames: []string{"user1"}}
	analysisCtx := setupATOContext(t, params)
	analysisCtx.Task.TargetURL = server.URL
	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	analysisCtx.TargetURL = parsedURL
	time.AfterFunc(100*time.Millisecond, cancel)
	err = adapter.Analyze(ctx, analysisCtx)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}

func TestATOAdapter_Analyze_HTTPFailureResilience(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("Server should not have been contacted")
	}))
	targetURL := server.URL
	server.Close()

	adapter := adapters.NewATOAdapter()
	adapter.SetHttpClient(&http.Client{Timeout: 2 * time.Second})

	params := schemas.ATOTaskParams{Usernames: []string{"user1"}}
	analysisCtx := setupATOContext(t, params)
	analysisCtx.Task.TargetURL = targetURL
	parsedURL, err := url.Parse(targetURL)
	require.NoError(t, err)
	analysisCtx.TargetURL = parsedURL

	// Increased timeout from 3s to 5s. The throttled loop needs more
	// time to finish all attempts before the context deadline is hit.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = adapter.Analyze(ctx, analysisCtx)
	assert.NoError(t, err)
	assert.Empty(t, analysisCtx.Findings)
}
