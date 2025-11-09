// internal/analysis/auth/ato/analyzer_test.go
package ato

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// Helper function to create a new analyzer instance for testing.
// It now uses the centralized default config constructor.
func newTestAnalyzer(t *testing.T, cfg config.Interface) *ATOAnalyzer {
	t.Helper()
	logger := zaptest.NewLogger(t)
	if cfg == nil {
		// Use the centralized default config constructor.
		// This makes tests more robust to future changes in default values.
		cfg = config.NewDefaultConfig()

		// Get the specific ATO config struct to modify it.
		atoCfg := cfg.Scanners().Active.Auth.ATO
		atoCfg.Enabled = true
		atoCfg.Concurrency = 2
		// Set default keywords needed for various tests.
		atoCfg.SuccessKeywords = []string{"\"success\":true", "welcome"}
		atoCfg.LockoutKeywords = []string{"locked", "too many"}
		atoCfg.PassFailureKeywords = []string{"invalid password", "incorrect password"}
		atoCfg.UserFailureKeywords = []string{"user not found"}
		atoCfg.GenericFailureKeywords = []string{"login failed"}

		// Use the interface's setter to apply the changes.
		cfg.SetATOConfig(atoCfg)
	}

	// Assuming NewATOAnalyzer now accepts the config.Interface.
	analyzer, err := NewATOAnalyzer(cfg, logger)
	require.NoError(t, err)
	return analyzer
}

// -- Test Cases --

func TestNewATOAnalyzer_Initialization(t *testing.T) {
	t.Parallel()
	// Create a default config and modify it using the interface setters.
	// This decouples the test from the concrete config struct implementation.
	cfg := config.NewDefaultConfig()
	atoCfg := cfg.Scanners().Active.Auth.ATO
	atoCfg.Enabled = true
	cfg.SetATOConfig(atoCfg)

	analyzer := newTestAnalyzer(t, cfg)

	assert.NotNil(t, analyzer)
	assert.Equal(t, "Account Takeover", analyzer.Name())
	assert.Equal(t, core.TypeActive, analyzer.Type())
	assert.Len(t, analyzer.credentialSet, 6)
	assert.Equal(t, "admin", analyzer.credentialSet[0].Username)
}

func TestLoadCredentialSet_NotImplemented(t *testing.T) {
	t.Parallel()
	logger := zaptest.NewLogger(t)
	creds, err := loadCredentialSet("/tmp/test_creds.txt", logger)
	assert.Error(t, err)
	assert.Nil(t, creds)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestIdentifyLoginRequest(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)

	testCases := []struct {
		name              string
		request           schemas.Request
		expectSuccess     bool
		expectedUserField string
		expectedPassField string
	}{
		{
			name: "JSON Login - Standard",
			request: schemas.Request{
				Method: http.MethodPost,
				URL:    "https://api.example.com/login",
				PostData: &schemas.PostData{
					MimeType: "application/json",
					Text:     `{"username": "testuser", "password": "testpassword", "extra": 123}`,
				},
			},
			expectSuccess:     true,
			expectedUserField: "username",
			expectedPassField: "password",
		},
		{
			name: "Form URL Encoded Login",
			request: schemas.Request{
				Method: http.MethodPost,
				URL:    "https://example.com/signin",
				PostData: &schemas.PostData{
					MimeType: "application/x-www-form-urlencoded",
					Params: []schemas.NVPair{
						{Name: "login", Value: "user1"},
						{Name: "pass", Value: "pass1"},
					},
				},
			},
			expectSuccess:     true,
			expectedUserField: "login",
			expectedPassField: "pass",
		},
		{
			name: "Case Insensitive Fields",
			request: schemas.Request{
				Method: http.MethodPost,
				PostData: &schemas.PostData{
					MimeType: "application/json",
					Text:     `{"Email": "test@example.com", "PWD": "secret"}`,
				},
			},
			expectSuccess:     true,
			expectedUserField: "Email",
			expectedPassField: "PWD",
		},
		{"Failure: GET request", schemas.Request{Method: http.MethodGet}, false, "", ""},
		{"Failure: POST without Data", schemas.Request{Method: http.MethodPost, PostData: nil}, false, "", ""},
		{"Failure: Unsupported Content Type", schemas.Request{Method: http.MethodPost, PostData: &schemas.PostData{MimeType: "application/xml"}}, false, "", ""},
		{"Failure: Invalid JSON", schemas.Request{Method: http.MethodPost, PostData: &schemas.PostData{MimeType: "application/json", Text: `{"user":`}}, false, "", ""},
		{"Failure: Missing Fields", schemas.Request{Method: http.MethodPost, PostData: &schemas.PostData{MimeType: "application/json", Text: `{}`}}, false, "", ""},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			attempt, err := a.identifyLoginRequest(tc.request)

			if tc.expectSuccess {
				assert.NoError(t, err)
				require.NotNil(t, attempt)
				assert.Equal(t, tc.expectedUserField, attempt.UserField)
				assert.Equal(t, tc.expectedPassField, attempt.PassField)
				assert.NotEmpty(t, attempt.BodyParams)
			} else {
				assert.Error(t, err)
				assert.Nil(t, attempt)
			}
		})
	}
}

func TestIdentifyLoginRequest_HeaderHandling(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)
	req := schemas.Request{
		Method: http.MethodPost,
		URL:    "https://api.example.com/login",
		Headers: []schemas.NVPair{
			{Name: "User-Agent", Value: "TestAgent"},
			{Name: "Content-Type", Value: "application/json"},
			{Name: "Content-Length", Value: "50"},
			{Name: "Cookie", Value: "session=abc"},
			{Name: "cOoKiE", Value: "session=def"},
		},
		PostData: &schemas.PostData{
			MimeType: "application/json",
			Text:     `{"user": "u", "pass": "p"}`,
		},
	}

	attempt, err := a.identifyLoginRequest(req)
	require.NoError(t, err)

	expectedHeaders := map[string]string{
		"User-Agent":   "TestAgent",
		"Content-Type": "application/json",
	}

	assert.Equal(t, expectedHeaders, attempt.Headers)
}

func TestDiscoverLoginEndpoints(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)

	harData := &schemas.HAR{
		Log: schemas.HARLog{
			Entries: []schemas.Entry{
				{Request: schemas.Request{Method: http.MethodPost, URL: "https://api.example.com/login",
					PostData: &schemas.PostData{MimeType: "application/json", Text: `{"user": "u1", "pass": "p1"}`}}},
				{Request: schemas.Request{Method: http.MethodPost, URL: "https://api.example.com/login",
					PostData: &schemas.PostData{MimeType: "application/json", Text: `{"user": "u2", "pass": "p2"}`}}},
				{Request: schemas.Request{Method: http.MethodPost, URL: "https://example.com/signin",
					PostData: &schemas.PostData{MimeType: "application/x-www-form-urlencoded", Params: []schemas.NVPair{{Name: "username", Value: "v"}, {Name: "password", Value: "v"}}}}},
			},
		},
	}

	loginAttempts := a.discoverLoginEndpoints(harData)

	require.Len(t, loginAttempts, 2)
	assert.Contains(t, loginAttempts, "POST-https://api.example.com/login")
	assert.Contains(t, loginAttempts, "POST-https://example.com/signin")
}

func TestAnalyzeLoginResponse(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)

	baselineBody := "Login failed."
	baseline := &baselineFailure{
		Status:   http.StatusUnauthorized,
		Length:   len(baselineBody),
		BodyHash: sha256.Sum256([]byte(baselineBody)),
	}

	testCases := []struct {
		name           string
		response       *fetchResponse
		baseline       *baselineFailure
		expectedResult loginResult
	}{
		{"Success Keyword", &fetchResponse{Status: http.StatusOK, Body: `{"success":true}`}, nil, loginSuccess},
		{"Success Redirect", &fetchResponse{Status: http.StatusFound, Body: ""}, nil, loginSuccess},
		{"Lockout Keyword", &fetchResponse{Status: http.StatusTooManyRequests, Body: "Too many attempts."}, nil, loginFailureLockout},
		{"Invalid Pass Keyword", &fetchResponse{Status: http.StatusUnauthorized, Body: "Invalid password."}, nil, loginFailurePass},
		{"Invalid User Keyword", &fetchResponse{Status: http.StatusUnauthorized, Body: "User not found."}, nil, loginFailureUser},
		{"Matches Baseline", &fetchResponse{Status: baseline.Status, Body: baselineBody}, baseline, loginFailureUser},
		// FIX: Changed the body to "Authentication error." to avoid matching the "login failed" generic keyword.
		// This ensures the differential logic is what gets tested.
		{"Differs - Status", &fetchResponse{Status: http.StatusOK, Body: "Authentication error."}, baseline, loginFailureDifferential},
		{"Differs - Body", &fetchResponse{Status: baseline.Status, Body: "Slightly different failure."}, baseline, loginFailureDifferential},
		{"Differs - Keyword Precedence", &fetchResponse{Status: baseline.Status, Body: "Invalid password."}, baseline, loginFailurePass},
		{"Unknown", &fetchResponse{Status: http.StatusInternalServerError, Body: "Error."}, nil, loginUnknown},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := a.analyzeLoginResponse(tc.response, tc.baseline)
			assert.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestExecuteLoginAttempt_JSON(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)
	mockCtx := mocks.NewMockSessionContext()
	ctx := context.Background()

	attempt := &loginAttempt{
		URL: "https://api.example.com/login", Method: http.MethodPost, ContentType: "application/json",
		UserField: "user", PassField: "pass",
		BodyParams: map[string]interface{}{"user": "old", "pass": "old", "extra": "data"},
		Headers:    map[string]string{"X-Test": "true"},
	}
	creds := schemas.Credential{Username: "new_user", Password: "new_password"}
	token := &csrfToken{Name: "csrf", Value: "token_value"}

	expectedResponse := fetchResponse{Body: `{"success": true}`, Status: http.StatusOK}
	responseJSON, _ := json.Marshal(expectedResponse)

	mockCtx.On("GetHumanoid").Return(nil).Maybe()
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.Anything).
		Return(json.RawMessage(responseJSON), nil).
		Run(func(args mock.Arguments) { // FIX: Corrected the function signature to match the mock's expectations.
			scriptArgs := args.Get(2).([]interface{})
			require.Len(t, scriptArgs, 4)

			assert.Equal(t, attempt.URL, scriptArgs[0])
			assert.Equal(t, attempt.Headers, scriptArgs[2])

			bodyString := scriptArgs[3].(string)
			var bodyData map[string]interface{}
			err := json.Unmarshal([]byte(bodyString), &bodyData)
			require.NoError(t, err)

			assert.Equal(t, creds.Username, bodyData["user"])
			assert.Equal(t, creds.Password, bodyData["pass"])
			assert.Equal(t, token.Value, bodyData["csrf"])
			assert.Equal(t, "data", bodyData["extra"])
		}).Once()

	response, err := a.executeLoginAttempt(ctx, mockCtx, attempt, creds, token)

	require.NoError(t, err)
	assert.Equal(t, expectedResponse.Status, response.Status)
	mockCtx.AssertExpectations(t)
}

func TestExecuteLoginAttempt_FormURLEncoded(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)
	mockCtx := mocks.NewMockSessionContext()
	ctx := context.Background()

	attempt := &loginAttempt{
		URL: "https://example.com/signin", Method: http.MethodPost, ContentType: "application/x-www-form-urlencoded",
		UserField: "username", PassField: "password",
		BodyParams: map[string]interface{}{"username": "a", "password": "b", "redirect": "/home"},
	}
	creds := schemas.Credential{Username: "admin", Password: "pwd"}

	expectedBody := "password=pwd&redirect=%2Fhome&username=admin"

	responseJSON, _ := json.Marshal(fetchResponse{Status: http.StatusFound})

	mockCtx.On("GetHumanoid").Return(nil).Maybe()
	mockCtx.On("ExecuteScript", ctx, mock.Anything, mock.Anything).
		Return(json.RawMessage(responseJSON), nil). // FIX: Corrected the function signature to match the mock's expectations.
		Run(func(args mock.Arguments) {
			scriptArgs := args.Get(2).([]interface{})
			bodyString := scriptArgs[3].(string)
			assert.Equal(t, expectedBody, bodyString)
		}).Once()

	_, err := a.executeLoginAttempt(ctx, mockCtx, attempt, creds, nil)

	require.NoError(t, err)
	mockCtx.AssertExpectations(t)
}

func TestGetFreshCSRFToken_Success(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)
	mockCtx := mocks.NewMockSessionContext()

	ctx := context.Background()
	pageURL := "https://example.com/login"

	expectedToken := csrfToken{Name: "_csrf", Value: "secure_value"}
	tokenJSON, _ := json.Marshal(expectedToken)

	mockCtx.On("GetHumanoid").Return(nil).Maybe()
	mockCtx.On("Navigate", ctx, pageURL).Return(nil).Once()
	mockCtx.On("WaitForAsync", ctx, 0).Return(nil).Once()
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool { // FIX: Corrected the function signature to match the mock's expectations.
		return len(args) == 1 && len(args[0].([]string)) > 0
	})).Return(json.RawMessage(tokenJSON), nil).Once()

	token, err := a.getFreshCSRFToken(ctx, mockCtx, pageURL)

	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, expectedToken.Name, token.Name)
	mockCtx.AssertExpectations(t)
}

func TestExecutePause_TimingAndCancellation(t *testing.T) {
	t.Parallel()

	t.Run("NormalDelay", func(t *testing.T) {
		t.Parallel()
		// Create a specific config for this test case.
		cfg := config.NewDefaultConfig()
		atoCfg := cfg.Scanners().Active.Auth.ATO
		atoCfg.MinRequestDelayMs = 50
		atoCfg.RequestDelayJitterMs = 10
		cfg.SetATOConfig(atoCfg)
		a := newTestAnalyzer(t, cfg)

		start := time.Now()
		// FIX: Pass nil for the humanoid argument.
		err := a.executePause(context.Background(), nil)
		duration := time.Since(start)

		assert.NoError(t, err)
		assert.GreaterOrEqual(t, duration.Milliseconds(), int64(50))
		assert.LessOrEqual(t, duration.Milliseconds(), int64(60)+int64(10)) // Base + Jitter
	})

	t.Run("Cancellation", func(t *testing.T) {
		t.Parallel()
		// Create a new analyzer with a longer delay to test cancellation.
		// This avoids mutating state within a test and keeps test cases isolated.
		cfgWithLongDelay := config.NewDefaultConfig()
		atoCfg := cfgWithLongDelay.Scanners().Active.Auth.ATO
		atoCfg.MinRequestDelayMs = 5000 // A long delay that will surely be interrupted.
		cfgWithLongDelay.SetATOConfig(atoCfg)
		a := newTestAnalyzer(t, cfgWithLongDelay)

		ctx, cancel := context.WithCancel(context.Background())

		start := time.Now()
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()

		// FIX: Pass nil for the humanoid argument.
		err := a.executePause(ctx, nil)
		duration := time.Since(start)

		// We expect the pause to be interrupted, returning a context error.
		assert.ErrorIs(t, err, context.Canceled)
		assert.Less(t, duration.Milliseconds(), int64(500), "Pause should be canceled quickly")
	})
}
func TestAnalyze_Integration(t *testing.T) {
	a := newTestAnalyzer(t, nil)
	mockCtx := mocks.NewMockSessionContext()
	ctx := context.Background()

	// -- Setup HAR and Artifacts --
	harJSON := `
    {
        "log": {
            "entries": [
                {"request": {"method": "POST", "url": "https://api.example.com/login",
                    "postData": {"mimeType": "application/json", "text": "{\"user\": \"u\", \"pass\": \"p\"}"}}},
                {"request": {"method": "POST", "url": "https://example.com/signin",
                    "postData": {"mimeType": "application/json", "text": "{\"email\": \"e\", \"password\": \"pw\"}"}}}
            ]
        }
    }
    `
	rawHAR := json.RawMessage(harJSON)
	artifacts := &schemas.Artifacts{HAR: &rawHAR}
	mockCtx.On("CollectArtifacts", ctx).Return(artifacts, nil).Once()
	mockCtx.On("GetHumanoid").Return(nil).Maybe()

	// -- Setup Finding Collector --
	var findings []schemas.Finding
	var findingsMu sync.Mutex
	mockCtx.On("AddFinding", ctx, mock.Anything).Run(func(args mock.Arguments) {
		findingsMu.Lock()
		defer findingsMu.Unlock()
		findings = append(findings, args.Get(1).(schemas.Finding))
	}).Return(nil)

	// -- Mock CSRF scraping for both endpoints (return no token) --
	mockCtx.On("Navigate", ctx, mock.AnythingOfType("string")).Return(nil)
	mockCtx.On("WaitForAsync", ctx, 0).Return(nil)
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return len(args) == 1 // CSRF scraping script has 1 argument
	})).Return(json.RawMessage("null"), nil)

	// -- Mock login attempts with more specific ordering and responses --

	// Endpoint 1: api.example.com/login (Credential Stuffing)
	// 1a. Baseline attempt (random creds) -> fails
	baselineFailResp, _ := json.Marshal(fetchResponse{Status: http.StatusUnauthorized, Body: "Invalid credentials"})
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		// Match the fetch script for the baseline call
		return len(args) == 4 && args[0] == "https://api.example.com/login" && !strings.Contains(args[3].(string), "admin")
	})).Return(json.RawMessage(baselineFailResp), nil).Once()

	// 1b. Successful attempt (creds: admin/password) -> succeeds
	successResp, _ := json.Marshal(fetchResponse{Status: http.StatusOK, Body: `{"success":true}`})
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		// Match the successful attempt
		return len(args) == 4 && args[0] == "https://api.example.com/login" && strings.Contains(args[3].(string), `"user":"admin"`)
	})).Return(json.RawMessage(successResp), nil).Once()

	// Endpoint 2: example.com/signin (Username Enumeration)
	// 2a. Baseline attempt (random creds) -> fails with generic message
	baselineEnumResp, _ := json.Marshal(fetchResponse{Status: http.StatusUnauthorized, Body: "User not found."})
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		// Match the baseline call for the enumeration endpoint
		return len(args) == 4 && args[0] == "https://example.com/signin" && !strings.Contains(args[3].(string), "admin")
	})).Return(json.RawMessage(baselineEnumResp), nil).Once()

	// 2b. Attempt with valid user, wrong pass -> distinct "incorrect password" message
	enumResp, _ := json.Marshal(fetchResponse{Status: http.StatusUnauthorized, Body: "incorrect password"})
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		// Match the enumeration attempt
		return len(args) == 4 && args[0] == "https://example.com/signin" && strings.Contains(args[3].(string), `"email":"admin"`)
	})).Return(json.RawMessage(enumResp), nil).Once()

	// 2c. Other attempts for this endpoint should fail like the baseline
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return len(args) == 4 && args[0] == "https://example.com/signin"
	})).Return(json.RawMessage(baselineEnumResp), nil)

	// -- Execute and Assert --
	err := a.Analyze(ctx, mockCtx)
	require.NoError(t, err)

	// Use require.Eventually to handle concurrent nature of workers
	require.Eventually(t, func() bool {
		findingsMu.Lock()
		defer findingsMu.Unlock()
		return len(findings) >= 2
	}, 2*time.Second, 50*time.Millisecond, "Expected at least 2 findings")

	hasStuffing := false
	hasEnumeration := false
	for _, f := range findings {
		if f.VulnerabilityName == "Account Takeover (Credential Stuffing)" {
			hasStuffing = true
			assert.Equal(t, schemas.SeverityCritical, f.Severity)
			assert.Equal(t, "https://api.example.com/login", f.Target)
			// Check if the enumeration finding for the OTHER endpoint was correctly noted.
			if strings.Contains(f.Description, "also leaks information") {
				// This description should only appear if enumeration was also found for this target
				// which is not the case in this test setup.
				assert.Fail(t, "Credential stuffing finding incorrectly mentioned enumeration.")
			}
		}
		if f.VulnerabilityName == "Username Enumeration" {
			hasEnumeration = true
			assert.Equal(t, schemas.SeverityMedium, f.Severity)
			assert.Equal(t, "https://example.com/signin", f.Target)
		}
	}

	assert.True(t, hasStuffing, "Missing Credential Stuffing finding")
	assert.True(t, hasEnumeration, "Missing Username Enumeration finding")

	mockCtx.AssertExpectations(t)
}
