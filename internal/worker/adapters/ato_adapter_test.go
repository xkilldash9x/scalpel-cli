// internal/worker/adapters/ato_adapter_test.go
package adapters_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	// Removed mitchellh/go-homedir as it's less critical for the revised test logic.
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// Helper to setup AnalysisContext for ATOAdapter
func setupATOContext(t *testing.T, params interface{}, cfg config.Interface) *core.AnalysisContext {
	t.Helper()
	if cfg == nil {
		cfg = config.NewDefaultConfig()
	}

	return &core.AnalysisContext{
		Task: schemas.Task{
			TaskID:     "task-ato-1",
			Type:       schemas.TaskTestAuthATO,
			Parameters: params,
		},
		Logger: zap.NewNop(),
		Global: &core.GlobalContext{
			Config: cfg,
		},
		Findings: []schemas.Finding{},
	}
}

func TestATOAdapter_Analyze_ParameterValidation(t *testing.T) {
	adapter := adapters.NewATOAdapter()

	// Define the expected error when no usernames are provided AND SecLists isn't configured.
	expectedErrNoUsernames := "no usernames provided in task parameters and SecLists path is not configured in config.yaml"

	tests := []struct {
		name          string
		params        interface{}
		expectedError string
	}{
		{"Wrong Type", "invalid string", "invalid parameters type for ATO task; expected schemas.ATOTaskParams or *schemas.ATOTaskParams, got string"},
		{"Nil Pointer", (*schemas.ATOTaskParams)(nil), "invalid parameters: nil pointer for ATO task"},
		// Updated tests: When Usernames list is empty, it attempts to load from SecLists.
		// Since the default config has an empty SecListsPath, it should return the specific configuration error.
		{"Empty Usernames (Struct)", schemas.ATOTaskParams{Usernames: []string{}}, expectedErrNoUsernames},
		{"Empty Usernames (Pointer)", &schemas.ATOTaskParams{Usernames: []string{}}, expectedErrNoUsernames},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use default config (SecListsPath="")
			ctx := setupATOContext(t, tt.params, nil)
			err := adapter.Analyze(context.Background(), ctx)
			assert.Error(t, err)
			assert.Equal(t, tt.expectedError, err.Error())
		})
	}
}

// TestATOAdapter_Analyze_SecListsLoading tests the fallback mechanism to load usernames from SecLists.
func TestATOAdapter_Analyze_SecListsLoading(t *testing.T) {
	adapter := adapters.NewATOAdapter()

	// 1. Setup a mock SecLists directory
	tempDir := t.TempDir()
	userDir := filepath.Join(tempDir, "Usernames")
	err := os.Mkdir(userDir, 0755)
	require.NoError(t, err)

	usernameFile := filepath.Join(userDir, "top-usernames-shortlist.txt")
	content := "user1\n#comment\nuser2\n"
	err = os.WriteFile(usernameFile, []byte(content), 0644)
	require.NoError(t, err)

	// 2. Configure the analyzer to use this mock directory
	cfg := config.NewDefaultConfig()
	atoCfg := cfg.Scanners().Active.Auth.ATO
	atoCfg.SecListsPath = tempDir
	cfg.SetATOConfig(atoCfg)

	// 3. Setup a mock server to count requests
	requestUsernames := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		requestUsernames = append(requestUsernames, body["username"])
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	adapter.SetHttpClient(server.Client())

	// 4. Run analysis with empty Usernames parameter
	params := schemas.ATOTaskParams{Usernames: []string{}}
	analysisCtx := setupATOContext(t, params, cfg)
	analysisCtx.Task.TargetURL = server.URL
	parsedURL, _ := url.Parse(server.URL)
	analysisCtx.TargetURL = parsedURL

	err = adapter.Analyze(context.Background(), analysisCtx)
	assert.NoError(t, err)

	// 5. Assertions
	// We expect 2 users * 16 passwords = 32 attempts total.
	assert.Len(t, requestUsernames, 32)
	// Check if the loaded usernames were used (order depends on password iteration)
	assert.Contains(t, requestUsernames, "user1")
	assert.Contains(t, requestUsernames, "user2")
}

func TestATOAdapter_Analyze_SuccessAndEnumeration(t *testing.T) {
	var requestCount int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		// Check default field names
		username := body["username"]

		switch {
		case username == "admin":
			w.WriteHeader(http.StatusOK)
			// Include JWT to trigger improved heuristic
			fmt.Fprintln(w, `{"status": "success", "token": "abc.def.ghi"}`)
		case username == "existing_user":
			w.WriteHeader(http.StatusUnauthorized)
			// Keyword defined in models.go
			fmt.Fprintln(w, `{"status": "failure", "message": "Incorrect password"}`)
		case username == "mfa_user":
			// Keyword defined in models.go
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `{"status": "pending", "message": "OTP required"}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintln(w, `{"status": "failure", "message": "Invalid credentials"}`)
		}
	}))
	defer server.Close()

	adapter := adapters.NewATOAdapter()
	adapter.SetHttpClient(server.Client())
	params := schemas.ATOTaskParams{Usernames: []string{"user1", "admin", "existing_user", "mfa_user"}}
	analysisCtx := setupATOContext(t, params, nil)
	analysisCtx.Task.TargetURL = server.URL
	parsedURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	analysisCtx.TargetURL = parsedURL
	err = adapter.Analyze(context.Background(), analysisCtx)
	assert.NoError(t, err)

	require.NotEmpty(t, analysisCtx.Findings)
	foundSuccess, foundEnum, foundMFA := false, false, false
	for _, finding := range analysisCtx.Findings {
		// VULN FIX Check: Ensure password is redacted in the description
		assert.NotContains(t, finding.Description, "using a common weak password ('")
		assert.Contains(t, finding.Description, "(redacted)")

		if finding.VulnerabilityName == "Successful Login with Weak Credentials" {
			foundSuccess = true
			assert.Equal(t, schemas.SeverityHigh, finding.Severity)
		}
		if finding.VulnerabilityName == "User Enumeration on Login Form" {
			foundEnum = true
		}
		if finding.VulnerabilityName == "Weak Credentials Accepted (MFA Present)" {
			foundMFA = true
			// Severity should be Medium when MFA is detected by the adapter logic.
			assert.Equal(t, schemas.SeverityMedium, finding.Severity)
		}
	}
	assert.True(t, foundSuccess, "Expected successful login finding")
	assert.True(t, foundEnum, "Expected user enumeration finding")
	assert.True(t, foundMFA, "Expected MFA finding")
}

func TestATOAdapter_Analyze_ContextCancellation_InLoop(t *testing.T) {
	adapter := adapters.NewATOAdapter()
	// Create a large list of usernames to ensure the loop runs long enough to be cancelled.
	usernames := make([]string, 1000)
	for i := range usernames {
		usernames[i] = fmt.Sprintf("user%d", i)
	}
	params := schemas.ATOTaskParams{Usernames: usernames}
	analysisCtx := setupATOContext(t, params, nil)
	analysisCtx.Task.TargetURL = "http://localhost:9999" // Dummy URL as HTTP requests will likely fail or be cancelled
	parsedURL, _ := url.Parse("http://localhost:9999")
	analysisCtx.TargetURL = parsedURL

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after a short duration.
	time.AfterFunc(10*time.Millisecond, cancel)
	err := adapter.Analyze(ctx, analysisCtx)
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
}
