// internal/agent/signup_executor_test.go
package agent

import (
	"context"
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
	"go.uber.org/zap/zaptest"
)


// Mock for config.Interface
type MockConfig struct {
	mock.Mock
	ScannersData config.ScannersConfig
}

func (m *MockConfig) Scanners() config.ScannersConfig {
	return m.ScannersData
}

// Add stubs for all other methods required by the config.Interface
func (m *MockConfig) Agent() config.AgentConfig { return config.AgentConfig{} }
func (m *MockConfig) Autofix() config.AutofixConfig { return config.AutofixConfig{} }
func (m *MockConfig) Browser() config.BrowserConfig { return config.BrowserConfig{} }
func (m *MockConfig) Database() config.DatabaseConfig { return config.DatabaseConfig{} }
func (m *MockConfig) Discovery() config.DiscoveryConfig { return config.DiscoveryConfig{} }
func (m *MockConfig) Engine() config.EngineConfig { return config.EngineConfig{} }
func (m *MockConfig) IAST() config.IASTConfig { return config.IASTConfig{} }
func (m *MockConfig) JWT() config.JWTConfig { return config.JWTConfig{} }
func (m *MockConfig) Logger() config.LoggerConfig { return config.LoggerConfig{} }
func (m *MockConfig) Network() config.NetworkConfig { return config.NetworkConfig{} }
func (m *MockConfig) Scan() config.ScanConfig { return config.ScanConfig{} }
func (m *MockConfig) SetScanConfig(sc config.ScanConfig) {}
func (m *MockConfig) SetDiscoveryMaxDepth(d int) {}
func (m *MockConfig) SetDiscoveryIncludeSubdomains(b bool) {}
func (m *MockConfig) SetEngineWorkerConcurrency(w int) {}
func (m *MockConfig) SetBrowserHeadless(b bool) {}
func (m *MockConfig) SetBrowserDisableCache(b bool) {}
func (m *MockConfig) SetBrowserDisableGPU(b bool) {}
func (m *MockConfig) SetBrowserIgnoreTLSErrors(b bool) {}
func (m *MockConfig) SetBrowserDebug(b bool) {}
func (m *MockConfig) SetBrowserHumanoidEnabled(b bool) {}
func (m *MockConfig) SetBrowserHumanoidClickHoldMinMs(ms int) {}
func (m *MockConfig) SetBrowserHumanoidClickHoldMaxMs(ms int) {}
func (m *MockConfig) SetBrowserHumanoidKeyHoldMu(ms float64) {}
func (m *MockConfig) SetNetworkCaptureResponseBodies(b bool) {}
func (m *MockConfig) SetNetworkNavigationTimeout(d time.Duration) {}
func (m *MockConfig) SetNetworkPostLoadWait(d time.Duration) {}
func (m *MockConfig) SetNetworkIgnoreTLSErrors(b bool) {}
func (m *MockConfig) SetIASTEnabled(b bool) {}
func (m *MockConfig) SetJWTEnabled(b bool) {}
func (m *MockConfig) SetJWTBruteForceEnabled(b bool) {}
func (m *MockConfig) SetATOConfig(atoCfg config.ATOConfig) {}


// Helper function to initialize the executor and mocks for testing
func setupExecutor(t *testing.T, cfg *MockConfig) (*SignUpExecutor, *mocks.MockHumanoidController, *mocks.MockSessionContext) {
	require.NotNil(t, cfg, "Config should not be nil in setupExecutor")
	// Initialize observability with a test logger
	logger := zaptest.NewLogger(t)
	observability.SetLogger(logger)

	mockHumanoid := new(mocks.MockHumanoidController)
	mockSession := new(mocks.MockSessionContext)

	sessionProvider := func() schemas.SessionContext { return mockSession }
	humanoidProvider := func() *humanoid.Humanoid { return humanoid.NewTestHumanoid(mockHumanoid, 1) }

	// Mock SecLists data loading (we bypass the file system loading for unit tests of Execute)
	executor, err := NewSignUpExecutor(humanoidProvider, sessionProvider, cfg)

	if cfg.Scanners().Active.Auth.SignUp != nil && cfg.Scanners().Active.Auth.SignUp.Enabled {
        // If initialization failed (e.g. bad seclists path), we return nil executor, caller handles assertion.
        if err != nil {
            return nil, mockHumanoid, mockSession
        }
		// Manually inject mock seclists data instead of relying on loadSecListsData which hits the FS
        // This is needed if the config path was invalid but we want to test the execution logic anyway.
        if executor != nil && (executor.seclists == nil || len(executor.seclists.Usernames) == 0) {
            executor.seclists = &seclistsData{
                Usernames:  []string{"testuser"},
                FirstNames: []string{"John"},
                LastNames:  []string{"Doe"},
            }
        }
	} else {
		assert.NoError(t, err) // Should return nil, nil if disabled
		assert.Nil(t, executor)
	}

	return executor, mockHumanoid, mockSession
}

// Helper to create a default enabled configuration
func defaultEnabledConfig(dummyPath string) *MockConfig {
    if dummyPath == "" {
        dummyPath = "/tmp/seclists" // Default dummy path if none provided
    }
	return &MockConfig{
		ScannersData: config.ScannersConfig{
			Active: config.ActiveScannersConfig{
				Auth: config.AuthConfig{
					SignUp: &config.SignUpConfig{Enabled: true, EmailDomain: "test.com"},
					ATO:    config.ATOConfig{SecListsPath: dummyPath}, // Needed for NewSignUpExecutor check
				},
			},
		},
	}
}

// Helper to marshal results for mock ExecuteScript responses
func marshal(v interface{}) []byte {
	b, _ := json.Marshal(v)
	return b
}

// --- Tests ---

// TestNewSignUpExecutor_Initialization tests the constructor logic, including SecLists loading.
func TestNewSignUpExecutor_Initialization(t *testing.T) {
    // 1. Setup real temp directory for SecLists
    tempDir := t.TempDir()
    setupDummySecLists(t, tempDir)

    // 2. Test Success Case
    cfg := defaultEnabledConfig(tempDir)
	executor, _, _ := setupExecutor(t, cfg)
    assert.NotNil(t, executor)
    assert.Contains(t, executor.seclists.Usernames, "dummydata")

    // 3. Test Disabled Case
	cfgDisabled := defaultEnabledConfig(tempDir)
	cfgDisabled.ScannersData.Active.Auth.SignUp.Enabled = false
	executor, _, _ = setupExecutor(t, cfgDisabled)
	assert.Nil(t, executor)

    // 4. Test Invalid SecLists Path
    cfgInvalidPath := defaultEnabledConfig("/invalid/path/123")
    // We expect setupExecutor to return nil because NewSignUpExecutor should fail.
    executor, _, _ = setupExecutor(t, cfgInvalidPath)
    assert.Nil(t, executor)

    // To verify the error, we call NewSignUpExecutor directly.
    _, err := NewSignUpExecutor(nil, nil, cfgInvalidPath)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "SecLists directory not found")
}


func TestSignUpExecutor_Execute_Success_AuthStateChange(t *testing.T) {
	cfg := defaultEnabledConfig("")
	require.NotNil(t, cfg)
	executor, mockHumanoid, mockSession := setupExecutor(t, cfg)
	require.NotNil(t, executor, "Executor should not be nil with a valid enabled config")

	ctx := context.Background()
	var action Action // Mock action (nil is fine here)

	// 1. Mock CAPTCHA detection (returns null)
	mockSession.On("ExecuteScript", mock.Anything, mock.MatchedBy(func(s string) bool {
		return strings.Contains(s, "captchaSelectors")
	}), mock.Anything).Return(marshal(nil), nil).Once()

	// 2. Mock Initial Auth State (no cookies/storage)
	mockSession.On("ExecuteScript", mock.Anything, mock.MatchedBy(func(s string) bool {
		return strings.Contains(s, "localStorageKeys")
	}), mock.Anything).Return(marshal(map[string][]string{}), nil).Once()
	mockSession.On("CollectArtifacts", mock.Anything).Return(&schemas.Artifacts{}, nil).Once()

	// 3. Mock Initial URL
	mockSession.On("ExecuteScript", mock.Anything, "window.location.href", mock.Anything).Return(marshal("http://example.com/signup"), nil).Once()

	// 4. Mock Form Analysis Script Execution
	analysisResult := formAnalysisResult{
		ContextSelector: "#form",
		SubmitSelector:  "#submit",
		Fields: map[string]string{
			"email":    "#email",
			"password": "#password",
		},
	}
	// Use the actual embedded script variable for matching
	mockSession.On("ExecuteScript", mock.Anything, formAnalysisScript, mock.Anything).Return(marshal(analysisResult), nil).Once()

	// 5. Mock Form Filling Interactions
	mockHumanoid.On("Type", mock.Anything, "#email", mock.AnythingOfType("string"), mock.Anything).Return(nil).Once()
	mockHumanoid.On("Type", mock.Anything, "#password", mock.AnythingOfType("string"), mock.Anything).Return(nil).Once()

	// 6. Mock Checkbox Handling (Assume none found)

	// 7. Mock Form Submission (Strategy 1: Button Click)
	mockHumanoid.On("IntelligentClick", mock.Anything, "#submit", mock.Anything).Return(nil).Once()

	// 8. Mock WaitForAsync
	mockSession.On("WaitForAsync", mock.Anything, 5000).Return(nil).Once()

	// 9. Mock Verification - Auth State Change (Success)
	// Mock Current Auth State (new cookie added)
	mockSession.On("ExecuteScript", mock.Anything, mock.MatchedBy(func(s string) bool {
		return strings.Contains(s, "localStorageKeys")
	}), mock.Anything).Return(marshal(map[string][]string{}), nil).Once()
	mockSession.On("CollectArtifacts", mock.Anything).Return(&schemas.Artifacts{
		Storage: schemas.StorageState{
			Cookies: []*schemas.Cookie{{Name: "session_token", Value: "abc"}},
		},
	}, nil).Once()

	// Execute the action
	result, err := executor.Execute(ctx, action)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "success", result.Status)
	assert.Equal(t, ObservedAuthResult, result.ObservationType)
	assert.Equal(t, "auth_state_change", result.Data.(map[string]interface{})["verification_method"])
	assert.NotNil(t, result.KGUpdates, "KGUpdates should be generated on success")

	mockHumanoid.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestSignUpExecutor_Execute_Failure_CaptchaDetected(t *testing.T) {
	cfg := defaultEnabledConfig("")
	executor, _, mockSession := setupExecutor(t, cfg)

	ctx := context.Background()
    var action Action

	// Mock CAPTCHA detection (returns the detected selector)
	mockSession.On("ExecuteScript", mock.Anything, mock.MatchedBy(func(s string) bool {
		return strings.Contains(s, "captchaSelectors")
	}), mock.Anything).Return(marshal(".g-recaptcha"), nil).Once()

	// Execute the action
	result, err := executor.Execute(ctx, action)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "failed", result.Status)
	assert.Equal(t, ErrCodeAuthCaptchaDetected, result.ErrorCode)
	assert.Contains(t, result.ErrorDetails["message"], "CAPTCHA detected")

	// Ensure no further interactions occurred
	mockSession.AssertExpectations(t)
}

// Test specific utility functions

func TestGenerateCompliantPassword(t *testing.T) {
	e := &SignUpExecutor{} // Initialize empty executor just for accessing the method

	for i := 0; i < 50; i++ {
		password := e.generateCompliantPassword()
		assert.GreaterOrEqual(t, len(password), 14, "Password length should be at least 14")

		hasLower := strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
		hasUpper := strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
		hasNumber := strings.ContainsAny(password, "0123456789")
		hasSymbol := strings.ContainsAny(password, "!@#$%^&*()_+-=")

		assert.True(t, hasLower, "Password must contain lowercase")
		assert.True(t, hasUpper, "Password must contain uppercase")
		assert.True(t, hasNumber, "Password must contain number")
		assert.True(t, hasSymbol, "Password must contain symbol")
	}
}

func TestCompareAuthStates(t *testing.T) {
	e := &SignUpExecutor{}

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

// Helper function to create dummy SecLists files for initialization tests
func setupDummySecLists(t *testing.T, path string) {
    // Create necessary directories and files
    err := os.MkdirAll(filepath.Join(path, "Usernames", "Names"), 0755)
    assert.NoError(t, err)

    files := []string{
        filepath.Join(path, "Usernames", "top-usernames-shortlist.txt"),
        filepath.Join(path, "Usernames", "Names", "givennames-usa-top1000.txt"),
        filepath.Join(path, "Usernames", "Names", "familynames-usa-top1000.txt"),
    }

    for _, file := range files {
        err := os.WriteFile(file, []byte("dummydata\n"), 0644)
        assert.NoError(t, err)
    }
}
