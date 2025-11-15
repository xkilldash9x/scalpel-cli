// internal/agent/signup_executor_test.go
package agent

import (
	"context"
	"errors"

	// "fmt" // Removed fmt import as it's no longer needed for Sprintf script wrappers
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	json "github.com/json-iterator/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// NOTE: go:embed directives and variable declarations are removed here.
// Since we are in the same 'agent' package, we rely on the variables
// (e.g., formAnalysisScript) defined in signup_executor.go.

// --- Mocks and Helpers ---

// Mock for config.Interface
type MockConfig struct {
	mock.Mock
	ScannersData config.ScannersConfig
}

func (m *MockConfig) Scanners() config.ScannersConfig {
	return m.ScannersData
}

// Add stubs for all other methods required by the config.Interface
func (m *MockConfig) Agent() config.AgentConfig                   { return config.AgentConfig{} }
func (m *MockConfig) Autofix() config.AutofixConfig               { return config.AutofixConfig{} }
func (m *MockConfig) Browser() config.BrowserConfig               { return config.BrowserConfig{} }
func (m *MockConfig) Database() config.DatabaseConfig             { return config.DatabaseConfig{} }
func (m *MockConfig) Discovery() config.DiscoveryConfig           { return config.DiscoveryConfig{} }
func (m *MockConfig) Engine() config.EngineConfig                 { return config.EngineConfig{} }
func (m *MockConfig) IAST() config.IASTConfig                     { return config.IASTConfig{} }
func (m *MockConfig) JWT() config.JWTConfig                       { return config.JWTConfig{} }
func (m *MockConfig) Logger() config.LoggerConfig                 { return config.LoggerConfig{} }
func (m *MockConfig) Network() config.NetworkConfig               { return config.NetworkConfig{} }
func (m *MockConfig) Scan() config.ScanConfig                     { return config.ScanConfig{} }
func (m *MockConfig) SetScanConfig(sc config.ScanConfig)          {}
func (m *MockConfig) SetDiscoveryMaxDepth(d int)                  {}
func (m *MockConfig) SetDiscoveryIncludeSubdomains(b bool)        {}
func (m *MockConfig) SetEngineWorkerConcurrency(w int)            {}
func (m *MockConfig) SetBrowserHeadless(b bool)                   {}
func (m *MockConfig) SetBrowserDisableCache(b bool)               {}
func (m *MockConfig) SetBrowserDisableGPU(b bool)                 {}
func (m *MockConfig) SetBrowserIgnoreTLSErrors(b bool)            {}
func (m*MockConfig) SetBrowserDebug(b bool)                       {}
func (m *MockConfig) SetBrowserHumanoidEnabled(b bool)            {}
func (m *MockConfig) SetBrowserHumanoidClickHoldMinMs(ms int)     {}
func (m *MockConfig) SetBrowserHumanoidClickHoldMaxMs(ms int)     {}
func (m *MockConfig) SetBrowserHumanoidKeyHoldMu(ms float64)      {}
func (m *MockConfig) SetNetworkCaptureResponseBodies(b bool)      {}
func (m *MockConfig) SetNetworkNavigationTimeout(d time.Duration) {}
func (m *MockConfig) SetNetworkPostLoadWait(d time.Duration)      {}
func (m *MockConfig) SetNetworkIgnoreTLSErrors(b bool)            {}
func (m *MockConfig) SetIASTEnabled(b bool)                       {}
func (mE *MockConfig) SetJWTEnabled(b bool)                        {}
func (mType *MockConfig) SetJWTBruteForceEnabled(b bool)          {}
func (m *MockConfig) SetATOConfig(atoCfg config.ATOConfig)        {}

// MockSecListsLoader implements the SecListsLoader interface for testing.
type MockSecListsLoader struct {
	Data *seclistsData
	Err  error
}

func (m *MockSecListsLoader) Load(cfg config.Interface) (*seclistsData, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	return m.Data, nil
}

// Default mock data for tests requiring successful initialization.
func defaultMockSecListsData() *seclistsData {
	return &seclistsData{
		Usernames:  []string{"testuser", "admin"},
		FirstNames: []string{"John", "Jane"},
		LastNames:  []string{"Doe", "Smith"},
	}
}

// setupExecutor initializes the executor with specific configuration and loader.
func setupExecutor(t *testing.T, cfg *MockConfig, loader SecListsLoader) (*SignUpExecutor, *mocks.MockHumanoidController, *mocks.MockSessionContext) {
	require.NotNil(t, cfg, "Config should not be nil")

	// Initialize observability with a test logger.
	// Use a debug-level logger for tests
	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))
	// Ensure the logger is reset after the test.
	originalLogger := observability.GetLogger()
	observability.SetLogger(logger)
	t.Cleanup(func() {
		if originalLogger != nil {
			observability.SetLogger(originalLogger)
		}
	})

	mockHumanoid := new(mocks.MockHumanoidController)
	mockSession := new(mocks.MockSessionContext)

	sessionProvider := func() schemas.SessionContext { return mockSession }
	humanoidProvider := func() *humanoid.Humanoid { return humanoid.NewTestHumanoid(mockHumanoid, 1) }

	// Initialize the executor using the provided loader via the constructor.
	executor, err := NewSignUpExecutor(humanoidProvider, sessionProvider, cfg, loader)

	// Assertions based on configuration.
	isEnabled := cfg.Scanners().Active.Auth.SignUp != nil && cfg.Scanners().Active.Auth.SignUp.Enabled

	if !isEnabled && executor != nil {
		// If disabled, it should return nil, nil.
		assert.NoError(t, err, "NewSignUpExecutor should not error when disabled")
		assert.Nil(t, executor, "Executor should be nil when disabled")
	}
	// If enabled, the success/failure depends on the loader; the caller handles specific assertions.

	return executor, mockHumanoid, mockSession
}

// setupExecutorForExecute is a convenience wrapper for tests focusing on the Execute logic.
// It uses a MockSecListsLoader with default data to ensure initialization succeeds.
func setupExecutorForExecute(t *testing.T, cfg *MockConfig) (*SignUpExecutor, *mocks.MockHumanoidController, *mocks.MockSessionContext) {
	loader := &MockSecListsLoader{
		Data: defaultMockSecListsData(),
	}
	executor, mockH, mockS := setupExecutor(t, cfg, loader)

	// For Execute tests, we must ensure the executor is valid before proceeding.
	if cfg.Scanners().Active.Auth.SignUp != nil && cfg.Scanners().Active.Auth.SignUp.Enabled {
		// This addresses the original failures where the executor was nil.
		require.NotNil(t, executor, "Executor must be successfully initialized for Execute tests when enabled")
	}

	return executor, mockH, mockS
}

// Helper to create a default enabled configuration.
func defaultEnabledConfig(secListsPath string) *MockConfig {
	// Path is still needed in the config structure, even if the mock loader ignores it.
	if secListsPath == "" {
		secListsPath = "/dummy/path"
	}
	return &MockConfig{
		ScannersData: config.ScannersConfig{
			Active: config.ActiveScannersConfig{
				Auth: config.AuthConfig{
					SignUp: &config.SignUpConfig{Enabled: true, EmailDomain: "test.com"},
					ATO:    config.ATOConfig{SecListsPath: secListsPath},
				},
			},
		},
	}
}

// Helper to marshal results for mock ExecuteScript responses.
// Updated to be robust: asserts success during test setup.
func marshal(t *testing.T, v interface{}) []byte {
	t.Helper() // Mark this function as a test helper
	b, err := json.Marshal(v)
	require.NoError(t, err, "Test setup failed: Failed to marshal mock data: %+v", v)
	// Ensure the result is not empty, unless we are explicitly marshalling nil (which results in "null").
	if v != nil && len(b) == 0 {
		t.Fatalf("Test setup failed: Marshaling mock data resulted in empty bytes: %+v", v)
	}
	return b
}

// Helper function for matching a script by a unique substring
func scriptContaining(substr string) interface{} {
	return mock.MatchedBy(func(s string) bool {
		return strings.Contains(s, substr)
	})
}

// --- Tests ---

// TestNewSignUpExecutor_Initialization verifies the constructor logic using both mock and real loaders.
func TestNewSignUpExecutor_Initialization(t *testing.T) {
	// Setup providers (mocks are fine here as we are testing initialization)
	hp := func() *humanoid.Humanoid { return nil }
	sp := func() schemas.SessionContext { return nil }

	// Ensure embedded scripts are available (required for initialization check)
	// This relies on the variables defined in signup_executor.go being populated.
	if formAnalysisScript == "" {
		t.Fatal("Embedded scripts (e.g., formAnalysisScript) are empty. Check go:embed configuration in signup_executor.go.")
	}

	// --- Mock Loader Tests ---
	t.Run("MockLoader_Success", func(t *testing.T) {
		cfg := defaultEnabledConfig("")
		loader := &MockSecListsLoader{Data: defaultMockSecListsData()}
		executor, err := NewSignUpExecutor(hp, sp, cfg, loader)
		assert.NoError(t, err)
		assert.NotNil(t, executor)
		assert.Equal(t, "testuser", executor.seclists.Usernames[0])
	})

	t.Run("MockLoader_Failure", func(t *testing.T) {
		cfg := defaultEnabledConfig("")
		expectedError := errors.New("loader error")
		loader := &MockSecListsLoader{Err: expectedError}
		_, err := NewSignUpExecutor(hp, sp, cfg, loader)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), expectedError.Error())
	})

	// --- FileSystem Loader Tests ---
	t.Run("FileSystem_Success", func(t *testing.T) {
		tempDir := t.TempDir()
		setupDummySecLists(t, tempDir)
		cfg := defaultEnabledConfig(tempDir)
		loader := NewFileSystemSecListsLoader()

		executor, err := NewSignUpExecutor(hp, sp, cfg, loader)
		assert.NoError(t, err)
		assert.NotNil(t, executor)
		assert.Contains(t, executor.seclists.Usernames, "dummydata")
	})

	t.Run("FileSystem_InvalidPath", func(t *testing.T) {
		cfg := defaultEnabledConfig("/invalid/path/123")
		loader := NewFileSystemSecListsLoader()
		_, err := NewSignUpExecutor(hp, sp, cfg, loader)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SecLists directory not found")
	})

	// --- Configuration Validation Tests ---
	t.Run("Disabled", func(t *testing.T) {
		cfg := defaultEnabledConfig("")
		cfg.ScannersData.Active.Auth.SignUp.Enabled = false
		loader := &MockSecListsLoader{Data: defaultMockSecListsData()}
		executor, err := NewSignUpExecutor(hp, sp, cfg, loader)
		assert.NoError(t, err)
		assert.Nil(t, executor)
	})

	t.Run("NilInputs", func(t *testing.T) {
		cfg := defaultEnabledConfig("")
		loader := &MockSecListsLoader{Data: defaultMockSecListsData()}
		_, err := NewSignUpExecutor(nil, sp, cfg, loader)
		assert.ErrorIs(t, err, ErrProvidersNil)

		_, err = NewSignUpExecutor(hp, sp, nil, loader)
		assert.ErrorIs(t, err, ErrConfigIsNil)
	})
}

// TestSignUpExecutor_Execute_Success_AuthStateChange verifies the "happy path" execution flow.
// REFACTOR: This test is modified per Tier 1 Recommendation 
// It now tests a direct success path on the first attempt, removing the retry logic
// and avoiding the WaitForAsync panic.
func TestSignUpExecutor_Execute_Success_AuthStateChange(t *testing.T) {
	cfg := defaultEnabledConfig("")
	executor, mockHumanoid, mockSession := setupExecutorForExecute(t, cfg)

	// Ensure the embedded script is loaded before attempting to use it for matching.
	if formAnalysisScript == "" {
		// If go:embed fails during test execution, we cannot construct the exact match.
		t.Fatal("formAnalysisScript is empty during test execution. Check go:embed configuration in signup_executor.go.")
	}

	ctx := context.Background()
	var action Action

	// --- Mock Setup ---

	analysisScriptMatcher := scriptContaining("function analyzeSignUpForm()")
	captchaScriptMatcher := scriptContaining("captchaSelectors")
	storageScriptMatcher := scriptContaining("localStorageKeys")

	// Use mock.Anything for the args list to avoid
	// potential deep-equality issues with `[]interface{}{}` vs `nil`.

	// Expected successful analysis result
	analysisResult := formAnalysisResult{
		ContextSelector: "#form",
		SubmitSelector:  "#submit",
		Fields: map[string]string{
			"email":    "#email",
			"password": "#password",
		},
	}

	// --- MOCKING ATTEMPT 1 (SUCCESS) ---
	// This test now only mocks a single, successful attempt. [cite: 175]

	// 1. Pre-check: Mock CAPTCHA detection
	mockSession.On("ExecuteScript", mock.Anything, captchaScriptMatcher, mock.Anything).Return(marshal(t, nil), nil).Once()

	// 2. Initial State Capture: Mock Initial Auth State
	mockSession.On("ExecuteScript", mock.Anything, storageScriptMatcher, mock.Anything).Return(marshal(t, map[string][]string{}), nil).Once()
	mockSession.On("CollectArtifacts", mock.Anything).Return(&schemas.Artifacts{
		Storage: schemas.StorageState{Cookies: []*schemas.Cookie{}},
	}, nil).Once()
	mockSession.On("ExecuteScript", mock.Anything, "window.location.href", mock.Anything).Return(marshal(t, "http://example.com/signup"), nil).Once()

	// 3. Form Analysis: Mock Form Analysis Script Execution (SUCCESS)
	// This now returns a valid result on the first try. [cite: 174]
	mockSession.On("ExecuteScript", mock.Anything, analysisScriptMatcher, mock.Anything).Return(marshal(t, analysisResult), nil).Once()

	// 4. Fill Form
	mockHumanoid.On("Type", mock.Anything, "#email", mock.AnythingOfType("string"), mock.Anything).Return(nil).Once()
	mockHumanoid.On("Type", mock.Anything, "#password", mock.AnythingOfType("string"), mock.Anything).Return(nil).Once()

	// 6. Form Submission: Mock Strategy 1 (Button Click)
	mockHumanoid.On("IntelligentClick", mock.Anything, "#submit", mock.Anything).Return(nil).Once()

	// 7. Stabilization: Mock WaitForAsync
	mockSession.On("WaitForAsync", mock.Anything, stabilizationWaitMs).Return(nil).Once()

	// 8. Verification: Mock Auth State Change (Success)
	mockSession.On("ExecuteScript", mock.Anything, storageScriptMatcher, mock.Anything).Return(marshal(t, map[string][]string{}), nil).Once()
	mockSession.On("CollectArtifacts", mock.Anything).Return(&schemas.Artifacts{
		Storage: schemas.StorageState{
			// The key indicator of success: a new session token.
			Cookies: []*schemas.Cookie{{Name: "session_token", Value: "abc"}},
		},
	}, nil).Once()

	// --- Execution ---
	// The original panic is avoided as WaitForAsync(retryWaitMs) is no longer called. [cite: 176]
	result, err := executor.Execute(ctx, action)

	// --- Assertions ---
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "success", result.Status)
	assert.Equal(t, ObservedAuthResult, result.ObservationType)

	// Verify the verification method reported.
	resultData := result.Data.(map[string]interface{})
	assert.Equal(t, "auth_state_change", resultData["verification_method"])

	// Verify Knowledge Graph updates were generated for the new account.
	assert.NotNil(t, result.KGUpdates)
	require.Len(t, result.KGUpdates.NodesToAdd, 1)
	assert.Equal(t, schemas.NodeAccount, result.KGUpdates.NodesToAdd[0].Type)

	// Ensure all mocks were called as expected.
	mockHumanoid.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

// TestSignUpExecutor_Execute_Failure_RetriesExhausted verifies the "unhappy path"
// where form analysis fails repeatedly, exhausting all retries.
// REFACTOR: This new test is added per Tier 2 Recommendation. 
// It validates the retry mechanism that was previously breaking the success test.
func TestSignUpExecutor_Execute_Failure_RetriesExhausted(t *testing.T) {
	cfg := defaultEnabledConfig("")
	executor, _, mockSession := setupExecutorForExecute(t, cfg)
	require.NotNil(t, executor)

	ctx := context.Background()
	var action Action

	analysisScriptMatcher := scriptContaining("function analyzeSignUpForm()")
	captchaScriptMatcher := scriptContaining("captchaSelectors")
	storageScriptMatcher := scriptContaining("localStorageKeys")

	// We expect 3 attempts total (1 initial + 2 retries)
	// These constants must match the executor's configuration.
	const totalAttempts = maxSignUpRetries + 1 // 3
	const retryCount = maxSignUpRetries      // 2

	// Mock pre-checks (called 3 times)
	mockSession.On("ExecuteScript", mock.Anything, captchaScriptMatcher, mock.Anything).Return(marshal(t, nil), nil).Times(totalAttempts)
	mockSession.On("ExecuteScript", mock.Anything, storageScriptMatcher, mock.Anything).Return(marshal(t, map[string][]string{}), nil).Times(totalAttempts)
	mockSession.On("CollectArtifacts", mock.Anything).Return(&schemas.Artifacts{Storage: schemas.StorageState{Cookies: []*schemas.Cookie{}}}, nil).Times(totalAttempts)
	mockSession.On("ExecuteScript", mock.Anything, "window.location.href", mock.Anything).Return(marshal(t, "http://example.com/signup"), nil).Times(totalAttempts)

	// Mock form analysis to FAIL every time. [cite: 193]
	// Per the Tier 3 refactor, we return an empty object,
	// not a `null` primitive.
	emptyAnalysisResult := formAnalysisResult{Fields: map[string]string{}}
	mockSession.On("ExecuteScript", mock.Anything, analysisScriptMatcher, mock.Anything).Return(marshal(t, emptyAnalysisResult), nil).Times(totalAttempts)

	// Mock the retry waits (called 2 times). [cite: 194]
	mockSession.On("WaitForAsync", mock.Anything, retryWaitMs).Return(nil).Times(retryCount)

	// --- Execution ---
	result, err := executor.Execute(ctx, action)

	// --- Assertions ---
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "failed", result.Status)
	// It should fail with the error from the last attempt.
	assert.Equal(t, ErrCodeElementNotFound, result.ErrorCode) // This is the error code mapped from the empty analysis result [cite: 79]
	assert.Contains(t, result.ErrorDetails["message"], "Failed to analyze and identify the sign-up form")

	// Ensure all mocks were called the expected number of times
	mockSession.AssertExpectations(t)
}

// TestSignUpExecutor_Execute_Failure_CaptchaDetected verifies that execution stops immediately if a CAPTCHA is detected.
func TestSignUpExecutor_Execute_Failure_CaptchaDetected(t *testing.T) {
	cfg := defaultEnabledConfig("")
	// Use the helper for Execute tests to guarantee initialization success.
	executor, _, mockSession := setupExecutorForExecute(t, cfg)

	ctx := context.Background()
	var action Action

	// **FIX**: Use mock.Anything for the args list for consistency.
	// Use explicit argument matching for robustness.
	// expectedArgs := []interface{}{}

	// Mock CAPTCHA detection (returns the detected selector string)
	mockSession.On("ExecuteScript", mock.Anything, scriptContaining("captchaSelectors"), mock.Anything).Return(marshal(t, ".g-recaptcha"), nil).Once()

	// Execute the action
	result, err := executor.Execute(ctx, action)

	// Assertions
	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "failed", result.Status)
	assert.Equal(t, ErrCodeAuthCaptchaDetected, result.ErrorCode)
	assert.Contains(t, result.ErrorDetails["message"], "CAPTCHA detected")
	assert.Equal(t, ".g-recaptcha", result.ErrorDetails["provider_hint"])

	// Ensure no further interactions occurred.
	mockSession.AssertExpectations(t)
}

// Test specific utility functions

func TestGenerateCompliantPassword(t *testing.T) {
	e := &SignUpExecutor{} // Initialize empty executor just for accessing the method

	for i := 0; i < 100; i++ {
		password, err := e.generateCompliantPassword()
		require.NoError(t, err, "Password generation should not fail (crypto/rand check)")
		// Check against the implementation's minimum length (16).
		assert.GreaterOrEqual(t, len(password), 16, "Password length should be at least 16")

		// Check complexity requirements (using the character sets defined in the implementation)
		lowerChars := "abcdefghijkmnopqrstuvwxyz"
		upperChars := "ABCDEFGHJKLMNPQRSTUVWXYZ"
		numberChars := "23456789"
		symbolChars := "!@#$%^&*()_+-="

		assert.True(t, strings.ContainsAny(password, lowerChars), "Password must contain lowercase")
		assert.True(t, strings.ContainsAny(password, upperChars), "Password must contain uppercase")
		assert.True(t, strings.ContainsAny(password, numberChars), "Password must contain number")
		assert.True(t, strings.ContainsAny(password, symbolChars), "Password must contain symbol")
	}
}

func TestCompareAuthStates(t *testing.T) {
	e := &SignUpExecutor{logger: zaptest.NewLogger(t)}

	state1 := map[string]interface{}{
		"cookies": []string{"cookie1", "cookie2"},
		"storage": map[string][]string{"local": {"key1"}},
	}

	state2 := map[string]interface{}{ // Identical
		"cookies": []string{"cookie1", "cookie2"},
		"storage": map[string][]string{"local": {"key1"}},
	}

	state3 := map[string]interface{}{ // Different cookies
		"cookies": []string{"cookie1", "cookie2", "session"},
		"storage": map[string][]string{"local": {"key1"}},
	}

	assert.False(t, e.compareAuthStates(state1, state2), "Identical states should return false")
	assert.True(t, e.compareAuthStates(state1, state3), "Different cookies should return true")
}

// Helper function to create dummy SecLists files for FileSystem initialization tests.
func setupDummySecLists(t *testing.T, path string) {
	// Create the necessary directory structure expected by FileSystemSecListsLoader.
	namesDir := filepath.Join(path, "Usernames", "Names")
	passwordsDir := filepath.Join(path, "Passwords", "Common-Credentials")
	err := os.MkdirAll(namesDir, 0755)
	require.NoError(t, err)
	err = os.MkdirAll(passwordsDir, 0755)
	require.NoError(t, err)

	// Define the required files.
	files := []string{
		filepath.Join(path, "Usernames", "top-usernames-shortlist.txt"),
		filepath.Join(namesDir, "givennames-usa-top1000.txt"),
		filepath.Join(namesDir, "familynames-usa-top1000.txt"),
		filepath.Join(passwordsDir, "10-million-password-list-top-100.txt"),
	}

	// Write dummy data to the files.
	for _, file := range files {
		err := os.WriteFile(file, []byte("dummydata\n"), 0644)
		require.NoError(t, err, "Failed to write dummy SecLists file: %s", file)
	}
}
