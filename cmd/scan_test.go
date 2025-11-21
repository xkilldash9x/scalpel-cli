// File: cmd/scan_test.go
package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/service"
	"go.uber.org/zap/zapcore"
)

// FIX: Add a dedicated test for the normalizeTargets function.
func TestNormalizeTargets(t *testing.T) {
	tests := []struct {
		name      string
		input     []string
		expected  []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "Basic normalization (no scheme)",
			input:    []string{"example.com", "sub.domain.org"},
			expected: []string{"https://example.com", "https://sub.domain.org"},
		},
		{
			name:     "Mixed schemes (http and https)",
			input:    []string{"http://example.com", "https://example.com"},
			expected: []string{"http://example.com", "https://example.com"},
		},
		{
			name:     "Whitespace trimming and empty strings",
			input:    []string{"  example.com  ", "", " ", "test.com"},
			expected: []string{"https://example.com", "https://test.com"},
		},
		{
			name:     "URLs with paths and query parameters",
			input:    []string{"example.com/path?q=1"},
			expected: []string{"https://example.com/path?q=1"},
		},
		{
			name:      "Invalid URL format",
			input:     []string{"http://[::1"}, // Missing closing bracket for IPv6
			wantErr:   true,
			errSubstr: "invalid target URL",
		},
		{
			name:      "Missing host",
			input:     []string{"https://"},
			wantErr:   true,
			errSubstr: "malformed target URL after normalization",
		},
		// FIX: Test case for unsupported schemes.
		{
			name:      "Unsupported scheme (FTP)",
			input:     []string{"ftp://example.com"},
			wantErr:   true,
			errSubstr: "unsupported URL scheme in target 'ftp://example.com'",
		},
		{
			name:      "Unsupported scheme mixed with valid",
			input:     []string{"http://good.com", "file:///etc/passwd"},
			wantErr:   true,
			errSubstr: "unsupported URL scheme in target 'file:///etc/passwd'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Act
			actual, err := normalizeTargets(tt.input)

			// Assert
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, actual)
			}
		})
	}
}

func TestApplyScanFlagOverrides(t *testing.T) {
	tests := []struct {
		name                 string
		args                 []string
		initialDepth         int
		initialConcurrency   int
		initialSubdomains    bool
		expectedDepth        int
		expectedConcurrency  int
		expectedSubdomains   bool
		expectedWarning      bool
		warningSubstr        string
		expectSubdomainMatch bool
	}{
		{
			name:         "Depth and Concurrency flags override defaults",
			args:         []string{"--depth", "10", "--concurrency", "20"},
			initialDepth: 5, initialConcurrency: 10, initialSubdomains: false,
			expectedDepth: 10, expectedConcurrency: 20, expectedSubdomains: false,
			expectSubdomainMatch: true,
		},
		{
			name:         "Scope subdomain flag overrides default",
			args:         []string{"--scope", "subdomain"},
			initialDepth: 5, initialConcurrency: 10, initialSubdomains: false,
			expectedDepth: 5, expectedConcurrency: 10, expectedSubdomains: true,
			expectSubdomainMatch: true,
		},
		{
			name:         "Scope strict flag works as expected",
			args:         []string{"--scope", "strict"},
			initialDepth: 5, initialConcurrency: 10, initialSubdomains: true,
			expectedDepth: 5, expectedConcurrency: 10, expectedSubdomains: false,
			expectSubdomainMatch: true,
		},
		{
			// Updated behavior: Invalid scope logs a warning but uses the existing configuration default, it does not force 'strict'.
			name:         "Invalid scope flag logs a warning and uses default",
			args:         []string{"--scope", "invalid-scope"},
			initialDepth: 5, initialConcurrency: 10, initialSubdomains: true,
			expectedDepth: 5, expectedConcurrency: 10, expectedSubdomains: true, // Should remain the initial value
			expectedWarning: true, warningSubstr: "Invalid --scope value",
			expectSubdomainMatch: true,
		},
		{
			// If the user explicitly provides an empty string (though Cobra usually treats this as an error if the flag expects an arg)
			name:         "Empty scope flag uses default",
			args:         []string{"--scope", ""},
			initialDepth: 3, initialConcurrency: 8, initialSubdomains: false,
			expectedDepth: 3, expectedConcurrency: 8, expectedSubdomains: false, // Should remain the initial value
			expectSubdomainMatch: true,
		},
		{
			name:         "No flags uses initial config",
			args:         []string{},
			initialDepth: 3, initialConcurrency: 8, initialSubdomains: true,
			expectedDepth: 3, expectedConcurrency: 8, expectedSubdomains: true,
			expectSubdomainMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			cfg := config.NewDefaultConfig()
			cfg.SetDiscoveryMaxDepth(tt.initialDepth)
			cfg.SetEngineWorkerConcurrency(tt.initialConcurrency)
			cfg.SetDiscoveryIncludeSubdomains(tt.initialSubdomains)

			// Use a test logger that captures output to verify warnings.
			observability.ResetForTest()
			var buffer bytes.Buffer
			writer := zapcore.AddSync(&buffer)
			observability.Initialize(
				config.LoggerConfig{Level: "debug", Format: "console"},
				writer,
			)

			// We must use newPristineRootCmd to ensure the command structure is correct (e.g., persistent flags).
			rootCmd := newPristineRootCmd()
			scanCmd, _, err := rootCmd.Find([]string{"scan"})
			require.NoError(t, err)

			// We need to parse flags against the specific command (scanCmd)
			err = scanCmd.ParseFlags(tt.args)
			require.NoError(t, err)

			// Act
			applyScanFlagOverrides(scanCmd, cfg)

			// Assert
			assert.Equal(t, tt.expectedDepth, cfg.Discovery().MaxDepth)
			assert.Equal(t, tt.expectedConcurrency, cfg.Engine().WorkerConcurrency)

			if tt.expectSubdomainMatch {
				assert.Equal(t, tt.expectedSubdomains, cfg.Discovery().IncludeSubdomains)
			}

			if tt.expectedWarning {
				assert.Contains(t, buffer.String(), tt.warningSubstr, "Expected a warning to be logged")
			} else {
				assert.NotContains(t, buffer.String(), "Invalid --scope value", "Did not expect a scope warning")
			}
		})
	}
}

func TestRunScanLogic(t *testing.T) {
	observability.InitializeLogger(config.LoggerConfig{Level: "fatal"})
	baseCtx := context.Background()
	// Define the expected normalized targets
	defaultTargets := []string{"https://example.com"}

	t.Run("successful scan without report", func(t *testing.T) {
		// Arrange
		mockFactory := new(mocks.MockComponentFactory)
		mockOrchestrator := new(mocks.MockOrchestrator)
		// Use service.Components struct, as runScan asserts this type.
		mockComponents := &service.Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()

		// Expect the normalized targets
		mockFactory.On("Create", mock.Anything, cfg, defaultTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
		mockOrchestrator.On("StartScan", mock.Anything, defaultTargets, mock.AnythingOfType("string")).Return(nil)

		// Act
		// Pass the non-normalized input "example.com"
		err := runScan(baseCtx, cfg, []string{"example.com"}, "", "", mockFactory)

		// Assert
		assert.NoError(t, err)
		mockFactory.AssertExpectations(t)
		mockOrchestrator.AssertExpectations(t)
	})

	t.Run("scan fails when component factory returns an error", func(t *testing.T) {
		// Arrange
		mockFactory := new(mocks.MockComponentFactory)
		cfg := config.NewDefaultConfig()
		factoryErr := errors.New("failed to connect to db")

		// Return nil components when an error occurs. The factory handles cleanup internally now.
		mockFactory.On("Create", mock.Anything, cfg, defaultTargets, mock.AnythingOfType("*zap.Logger")).Return(nil, factoryErr)

		// Act
		err := runScan(baseCtx, cfg, defaultTargets, "", "", mockFactory)

		// Assert
		assert.Error(t, err)
		assert.ErrorIs(t, err, factoryErr)
		assert.Contains(t, err.Error(), "failed to initialize scan components")
		mockFactory.AssertExpectations(t)
	})

	t.Run("scan fails when orchestrator returns an error", func(t *testing.T) {
		// Arrange
		mockFactory := new(mocks.MockComponentFactory)
		mockOrchestrator := new(mocks.MockOrchestrator)
		// Use service.Components struct
		mockComponents := &service.Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()
		orchestratorError := errors.New("orchestrator failed")

		mockFactory.On("Create", mock.Anything, cfg, defaultTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
		mockOrchestrator.On("StartScan", mock.Anything, defaultTargets, mock.AnythingOfType("string")).Return(orchestratorError)

		// Act
		err := runScan(baseCtx, cfg, defaultTargets, "", "", mockFactory)

		// Assert
		assert.Error(t, err)
		assert.ErrorIs(t, err, orchestratorError)
		mockFactory.AssertExpectations(t)
		mockOrchestrator.AssertExpectations(t)
	})

	t.Run("successful scan with report generation", func(t *testing.T) {
		// Arrange
		mockFactory := new(mocks.MockComponentFactory)
		mockOrchestrator := new(mocks.MockOrchestrator)
		mockStore := new(mocks.MockStore)
		// Use service.Components struct
		mockComponents := &service.Components{Orchestrator: mockOrchestrator, Store: mockStore}
		cfg := config.NewDefaultConfig()

		tmpfile, err := os.CreateTemp("", "test-report-*.sarif")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())
		outputFile := tmpfile.Name()
		format := "sarif"

		mockFactory.On("Create", mock.Anything, cfg, defaultTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
		mockOrchestrator.On("StartScan", mock.Anything, defaultTargets, mock.AnythingOfType("string")).Return(nil)
		// Ensure the context passed to GetFindingsByScanID (via the pipeline) respects the report generation timeout.
		mockStore.On("GetFindingsByScanID", mock.Anything, mock.AnythingOfType("string")).Return([]schemas.Finding{}, nil)

		// Act
		err = runScan(baseCtx, cfg, defaultTargets, outputFile, format, mockFactory)

		// Assert
		assert.NoError(t, err)
		mockFactory.AssertExpectations(t)
		mockOrchestrator.AssertExpectations(t)
		mockStore.AssertExpectations(t)

		info, err := os.Stat(outputFile)
		assert.NoError(t, err)
		assert.Greater(t, info.Size(), int64(0), "Report file should not be empty")
	})

	t.Run("normalizes all target URLs without scheme", func(t *testing.T) {
		// Arrange
		mockFactory := new(mocks.MockComponentFactory)
		mockOrchestrator := new(mocks.MockOrchestrator)
		// Use service.Components struct
		mockComponents := &service.Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()
		targetsInput := []string{"example.com", "http://test.com", "another.org"}
		// Expect all targets missing a scheme to default to https.
		expectedTargets := []string{"https://example.com", "http://test.com", "https://another.org"}

		// The factory should be set up with the *expected* normalized targets,
		// as this is what the `Create` method will receive after normalization.
		mockFactory.On("Create", mock.Anything, cfg, expectedTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
		// Assert that the normalized URLs are passed to the orchestrator.
		mockOrchestrator.On("StartScan", mock.Anything, expectedTargets, mock.AnythingOfType("string")).Return(nil)

		// Act
		err := runScan(baseCtx, cfg, targetsInput, "", "", mockFactory)

		// Assert
		assert.NoError(t, err)
		mockOrchestrator.AssertExpectations(t)
	})

	// FIX: Add test case to ensure runScan fails when normalization fails (e.g., unsupported scheme).
	t.Run("fails when target normalization fails (unsupported scheme)", func(t *testing.T) {
		// Arrange
		mockFactory := new(mocks.MockComponentFactory)
		cfg := config.NewDefaultConfig()
		targetsInput := []string{"ftp://example.com"}

		// Act
		err := runScan(baseCtx, cfg, targetsInput, "", "", mockFactory)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to normalize targets")
		assert.Contains(t, err.Error(), "unsupported URL scheme")
		// Crucially, ensure the factory was never called because validation failed first.
		mockFactory.AssertNotCalled(t, "Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})
}

// FIX: TestRunScan_NoGoroutineLeak verifies that runScan cleans up the signal handling goroutine.
func TestRunScan_NoGoroutineLeak(t *testing.T) {
	// This test inspects the global runtime state.
	t.Parallel()

	observability.InitializeLogger(config.LoggerConfig{Level: "fatal"})
	baseCtx := context.Background()
	defaultTargets := []string{"https://example.com"}

	// Arrange
	mockFactory := new(mocks.MockComponentFactory)
	mockOrchestrator := new(mocks.MockOrchestrator)
	mockComponents := &service.Components{Orchestrator: mockOrchestrator}
	cfg := config.NewDefaultConfig()

	mockFactory.On("Create", mock.Anything, cfg, defaultTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
	// Mock the scan to complete immediately and return nil (success).
	mockOrchestrator.On("StartScan", mock.Anything, defaultTargets, mock.AnythingOfType("string")).Return(nil)

	// Capture the number of goroutines before the scan.
	// Give the runtime a moment to settle before capturing the baseline.
	time.Sleep(10 * time.Millisecond)
	initialGoroutines := runtime.NumGoroutine()

	// Act
	err := runScan(baseCtx, cfg, defaultTargets, "", "", mockFactory)
	// runScan returns nil on successful completion in this mock scenario.
	assert.NoError(t, err)

	// Capture the number of goroutines after the scan.
	// We need to wait briefly to allow the cleanup (defer statements and context cancellation) to propagate.
	// This is inherently slightly racy, but necessary for this type of test.
	time.Sleep(50 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()

	// Assert
	// We expect the number of goroutines to return to the initial count.
	// Before the fix, this test reliably shows finalGoroutines == initialGoroutines + 1 because the signal handler leaks.
	// After the fix, the signal handler exits when the context is cancelled.

	// We use LessOrEqual because other parallel tests might finish and reduce the count,
	// or the runtime might clean up background routines. The key is that it shouldn't be consistently higher.
	assert.LessOrEqual(t, finalGoroutines, initialGoroutines,
		"Possible goroutine leak detected. Initial: %d, Final: %d. The signal handler might not be exiting.", initialGoroutines, finalGoroutines)

	mockFactory.AssertExpectations(t)
	mockOrchestrator.AssertExpectations(t)
}

// 'Components' struct and its 'Shutdown' method are no longer part of the
// 'cmd' package. That test should be moved to the 'internal/service' package.
