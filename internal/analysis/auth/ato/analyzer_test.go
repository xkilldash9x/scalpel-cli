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
		atoCfg.MFAKeywords = []string{"mfa required", "verification code"} // Added MFA keywords
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

// TestNormalizeBody verifies that dynamic content is correctly replaced.
func TestNormalizeBody(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"UUID", `{"id": "123e4567-e89b-12d3-a456-426614174000"}`, `{"id": "DYNAMIC_VALUE"}`},
		{"Timestamp", "Error at 1678886400", "Error at DYNAMIC_VALUE"},
		{"Long Token", `{"csrf": "abcdefghijklmnopqrstuvwxyz1234567890"}`, `{"csrf": "DYNAMIC_VALUE"}`},
		{"Multiple", "ID: 123e4567-e89b-12d3-a456-426614174000 Time: 1678886400", "ID: DYNAMIC_VALUE Time: DYNAMIC_VALUE"},
		{"No Dynamic Content", "Login Failed.", "Login Failed."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeBody(tt.input))
		})
	}
}

func TestIdentifyLoginRequest(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)

	testCases := []struct {
		name               string
		request            schemas.Request
		expectSuccess      bool
		expectedUserField  string
		expectedPassField  string
		expectedEmailBased bool
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
			expectSuccess:      true,
			expectedUserField:  "username",
			expectedPassField:  "password",
			expectedEmailBased: false,
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
			expectSuccess:      true,
			expectedUserField:  "login",
			expectedPassField:  "pass",
			expectedEmailBased: false,
		},
		{
			name: "Case Insensitive Fields (Email)",
			request: schemas.Request{
				Method: http.MethodPost,
				PostData: &schemas.PostData{
					MimeType: "application/json",
					Text:     `{"Email": "test@example.com", "PWD": "secret"}`,
				},
			},
			expectSuccess:      true,
			expectedUserField:  "Email",
			expectedPassField:  "PWD",
			expectedEmailBased: true,
		},
		{"Failure: GET request", schemas.Request{Method: http.MethodGet}, false, "", "", false},
		{"Failure: POST without Data", schemas.Request{Method: http.MethodPost, PostData: nil}, false, "", "", false},
		{"Failure: Unsupported Content Type", schemas.Request{Method: http.MethodPost, PostData: &schemas.PostData{MimeType: "application/xml"}}, false, "", "", false},
		{"Failure: Invalid JSON", schemas.Request{Method: http.MethodPost, PostData: &schemas.PostData{MimeType: "application/json", Text: `{"user":`}}, false, "", "", false},
		{"Failure: Missing Fields", schemas.Request{Method: http.MethodPost, PostData: &schemas.PostData{MimeType: "application/json", Text: `{}`}}, false, "", "", false},
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
				assert.Equal(t, tc.expectedEmailBased, attempt.IsEmailBased)
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
			{Name: "Host", Value: "api.example.com"},
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

	// Updated expectations: Cookies should be preserved, Content-Length/Host excluded.
	expectedHeaders := map[string]string{
		"User-Agent":   "TestAgent",
		"Content-Type": "application/json",
		"Cookie":       "session=abc",
		"cOoKiE":       "session=def",
	}

	assert.Equal(t, expectedHeaders, attempt.Headers)
}

func TestAnalyzeLoginResponse(t *testing.T) {
	t.Parallel()
	a := newTestAnalyzer(t, nil)

	// Setup baseline using normalized data
	baselineBodyRaw := "Login failed. Request ID: 123e4567-e89b-12d3-a456-426614174000"
	baselineBodyNormalized := normalizeBody(baselineBodyRaw)
	baseline := &baselineFailure{
		Status:           http.StatusUnauthorized,
		LengthNormalized: len(baselineBodyNormalized),
		BodyHash:         sha256.Sum256([]byte(baselineBodyNormalized)),
		AvgResponseTime:  100.0,
	}

	testCases := []struct {
		name           string
		response       *fetchResponse
		baseline       *baselineFailure
		expectedResult loginResult
	}{
		{"Success Keyword", &fetchResponse{Status: http.StatusOK, Body: `{"success":true}`}, nil, loginSuccess},
		{"Success Redirect", &fetchResponse{Status: http.StatusFound, Body: ""}, nil, loginSuccess},
		{"MFA Keyword", &fetchResponse{Status: http.StatusOK, Body: `{"status": "MFA required"}`}, nil, loginMFAChallenge},
		{"Lockout Keyword", &fetchResponse{Status: http.StatusTooManyRequests, Body: "Too many attempts."}, nil, loginFailureLockout},
		{"Invalid Pass Keyword", &fetchResponse{Status: http.StatusUnauthorized, Body: "Invalid password."}, nil, loginFailurePass},
		{"Invalid User Keyword", &fetchResponse{Status: http.StatusUnauthorized, Body: "User not found."}, nil, loginFailureUser},

		// Differential Analysis Tests (Updated for normalization)
		// Matches baseline (even with different dynamic ID)
		{"Matches Baseline (Normalized)", &fetchResponse{Status: baseline.Status, Body: "Login failed. Request ID: ffffffff-e89b-12d3-a456-426614174000"}, baseline, loginFailureUser},
		// Differs - Status
		{"Differs - Status", &fetchResponse{Status: http.StatusOK, Body: baselineBodyRaw}, baseline, loginFailureDifferential},
		// Differs - Body content (after normalization)
		{"Differs - Body", &fetchResponse{Status: baseline.Status, Body: "Slightly different failure."}, baseline, loginFailureDifferential},
		// Keyword precedence over differential
		{"Differs - Keyword Precedence", &fetchResponse{Status: baseline.Status, Body: "Invalid password."}, baseline, loginFailurePass},

		// Timing Analysis Tests
		{"Timing Analysis - Significant Delay", &fetchResponse{Status: baseline.Status, Body: baselineBodyRaw, TimeMs: 500.0}, baseline, loginFailureTiming},
		{"Timing Analysis - Insignificant Delay", &fetchResponse{Status: baseline.Status, Body: baselineBodyRaw, TimeMs: 120.0}, baseline, loginFailureUser},

		{"Unknown", &fetchResponse{Status: http.StatusInternalServerError, Body: "Error."}, nil, loginUnknown},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := a.analyzeLoginResponse(tc.response, tc.baseline)
			assert.Equal(t, tc.expectedResult, result, "Result mismatch for %s", tc.name)
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
	credentialsMode := "include"

	expectedResponse := fetchResponse{Body: `{"success": true}`, Status: http.StatusOK, TimeMs: 50.0}
	responseJSON, _ := json.Marshal(expectedResponse)

	mockCtx.On("GetHumanoid").Return(nil).Maybe()
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.Anything).
		Return(json.RawMessage(responseJSON), nil).
		Run(func(args mock.Arguments) {
			scriptArgs := args.Get(2).([]interface{})
			// Updated expected length (URL, Method, Headers, Body, CredentialsMode, MaxSize)
			require.Len(t, scriptArgs, 6)

			assert.Equal(t, attempt.URL, scriptArgs[0])
			assert.Equal(t, attempt.Headers, scriptArgs[2])
			assert.Equal(t, credentialsMode, scriptArgs[4])
			assert.Equal(t, maxResponseSize, scriptArgs[5])

			bodyString := scriptArgs[3].(string)
			var bodyData map[string]interface{}
			err := json.Unmarshal([]byte(bodyString), &bodyData)
			require.NoError(t, err)

			assert.Equal(t, creds.Username, bodyData["user"])
			assert.Equal(t, creds.Password, bodyData["pass"])
			assert.Equal(t, token.Value, bodyData["csrf"])
			assert.Equal(t, "data", bodyData["extra"])
		}).Once()

	response, err := a.executeLoginAttempt(ctx, mockCtx, attempt, creds, token, credentialsMode)

	require.NoError(t, err)
	assert.Equal(t, expectedResponse.Status, response.Status)
	assert.Equal(t, expectedResponse.TimeMs, response.TimeMs)
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
		// Pass nil for the humanoid argument (testing legacy path).
		err := a.executePause(context.Background(), nil)
		duration := time.Since(start)

		assert.NoError(t, err)
		assert.GreaterOrEqual(t, duration.Milliseconds(), int64(50))
		// Allow some leeway for scheduling
		assert.LessOrEqual(t, duration.Milliseconds(), int64(60)+int64(20)) // Base + Jitter + Leeway
	})

	t.Run("Cancellation", func(t *testing.T) {
		t.Parallel()
		// Create a new analyzer with a longer delay to test cancellation.
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

		// Pass nil for the humanoid argument.
		err := a.executePause(ctx, nil)
		duration := time.Since(start)

		// We expect the pause to be interrupted, returning a context error.
		assert.ErrorIs(t, err, context.Canceled)
		assert.Less(t, duration.Milliseconds(), int64(500), "Pause should be canceled quickly")
	})
}

// Mock response helper for integration tests
func mockResponse(t *testing.T, status int, body string, timeMs float64) json.RawMessage {
	t.Helper()
	resp, err := json.Marshal(fetchResponse{Status: status, Body: body, TimeMs: timeMs})
	require.NoError(t, err)
	return resp
}

// Helper to match ExecuteScript calls for the fetch script (6 arguments)
func isFetchScriptCall(args []interface{}, expectedURL string) bool {
	return len(args) == 6 && args[0] == expectedURL
}

// Helper to match ExecuteScript calls for the CSRF script (1 argument)
func isCSRFScriptCall(args []interface{}) bool {
	return len(args) == 1
}

// TestAnalyze_Integration_Comprehensive tests success, MFA, differential, keyword, and timing enumeration concurrently.
func TestAnalyze_Integration_Comprehensive(t *testing.T) {
	a := newTestAnalyzer(t, nil)
	mockCtx := mocks.NewMockSessionContext()
	ctx := context.Background()

	// -- Setup HAR and Artifacts --
	// Testing 3 endpoints: Success/MFA, Keyword Enum, Timing Enum
	harJSON := `
    {
        "log": {
            "entries": [
                {"request": {"method": "POST", "url": "https://app.example.com/success_mfa",
                    "postData": {"mimeType": "application/json", "text": "{\"user\": \"u\", \"pass\": \"p\"}"}}},
                {"request": {"method": "POST", "url": "https://app.example.com/enum_keyword",
                    "postData": {"mimeType": "application/json", "text": "{\"user\": \"u\", \"pass\": \"p\"}"}}},
				{"request": {"method": "POST", "url": "https://app.example.com/enum_timing",
                    "postData": {"mimeType": "application/json", "text": "{\"user\": \"u\", \"pass\": \"p\"}"}}}
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

	// -- Mock Navigation and CSRF (return no token) --
	mockCtx.On("Navigate", ctx, mock.AnythingOfType("string")).Return(nil)
	mockCtx.On("WaitForAsync", ctx, 0).Return(nil)
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(isCSRFScriptCall)).Return(json.RawMessage("null"), nil)

	// -- Mock login attempts --

	// Endpoint 1: Success/MFA
	// Baseline (3 samples)
	baselineSuccessResp := mockResponse(t, http.StatusUnauthorized, "Invalid", 50.0)
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return isFetchScriptCall(args, "https://app.example.com/success_mfa") && !strings.Contains(args[3].(string), "admin")
	})).Return(baselineSuccessResp, nil).Times(baselineSamples)

	// MFA attempt (admin/password is the first credential tested)
	mfaResp := mockResponse(t, http.StatusOK, `{"status":"MFA required"}`, 150.0)
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return isFetchScriptCall(args, "https://app.example.com/success_mfa") && strings.Contains(args[3].(string), `"user":"admin"`)
	})).Return(mfaResp, nil).Once()

	// Endpoint 2: Keyword Enumeration
	// Baseline (3 samples) - Invalid User keyword
	baselineKeywordResp := mockResponse(t, http.StatusUnauthorized, "User not found", 50.0)
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return isFetchScriptCall(args, "https://app.example.com/enum_keyword") && !strings.Contains(args[3].(string), "admin")
	})).Return(baselineKeywordResp, nil).Times(baselineSamples)

	// Keyword response (Invalid Password keyword)
	keywordResp := mockResponse(t, http.StatusUnauthorized, "Incorrect password", 60.0)
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return isFetchScriptCall(args, "https://app.example.com/enum_keyword") && strings.Contains(args[3].(string), `"user":"admin"`)
	})).Return(keywordResp, nil).Once()
	// Other attempts fail like baseline
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return isFetchScriptCall(args, "https://app.example.com/enum_keyword")
	})).Return(baselineKeywordResp, nil)

	// Endpoint 3: Timing Enumeration
	// Baseline (3 samples) - Fast response
	baselineTimingResp := mockResponse(t, http.StatusUnauthorized, "Invalid Credentials", 50.0)
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return isFetchScriptCall(args, "https://app.example.com/enum_timing") && !strings.Contains(args[3].(string), "admin")
	})).Return(baselineTimingResp, nil).Times(baselineSamples)

	// Timing response (Slow response, same body)
	timingResp := mockResponse(t, http.StatusUnauthorized, "Invalid Credentials", 500.0) // Significantly slower
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return isFetchScriptCall(args, "https://app.example.com/enum_timing") && strings.Contains(args[3].(string), `"user":"admin"`)
	})).Return(timingResp, nil).Once()
	// Other attempts fail like baseline
	mockCtx.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.MatchedBy(func(args []interface{}) bool {
		return isFetchScriptCall(args, "https://app.example.com/enum_timing")
	})).Return(baselineTimingResp, nil)

	// -- Execute and Assert --
	err := a.Analyze(ctx, mockCtx)
	require.NoError(t, err)

	require.Eventually(t, func() bool {
		findingsMu.Lock()
		defer findingsMu.Unlock()
		return len(findings) >= 3
	}, 3*time.Second, 50*time.Millisecond, "Expected at least 3 findings")

	foundMFA, foundKeyword, foundTiming := false, false, false
	for _, f := range findings {
		// VULN FIX Check: Ensure password is redacted in the evidence
		assert.NotContains(t, string(f.Evidence), "password 'password'")
		assert.Contains(t, string(f.Evidence), "(password redacted)")

		if f.VulnerabilityName == "Weak Credentials Accepted (MFA Present)" {
			foundMFA = true
			assert.Equal(t, schemas.SeverityHigh, f.Severity)
		}
		if f.VulnerabilityName == "Username Enumeration" {
			if f.Target == "https://app.example.com/enum_keyword" {
				foundKeyword = true
				assert.Contains(t, string(f.Evidence), "Detected via keyword analysis")
			}
			if f.Target == "https://app.example.com/enum_timing" {
				foundTiming = true
				assert.Contains(t, string(f.Evidence), "Detected via timing analysis")
			}
		}
	}

	assert.True(t, foundMFA, "Missing MFA finding")
	assert.True(t, foundKeyword, "Missing Keyword Enumeration finding")
	assert.True(t, foundTiming, "Missing Timing Enumeration finding")

	mockCtx.AssertExpectations(t)
}
