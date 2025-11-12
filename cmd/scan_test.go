// File: cmd/scan_test.go
package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/service" // FIX: Import the service package
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestApplyScanFlagOverrides(t *testing.T) {
	tests := []struct {
		name                string
		args                []string
		initialDepth        int
		initialConcurrency  int
		initialSubdomains   bool
		expectedDepth       int
		expectedConcurrency int
		expectedSubdomains  bool
		expectedWarning     bool
		warningSubstr       string
	}{
		{
			name:         "Depth and Concurrency flags override defaults",
			args:         []string{"--depth", "10", "--concurrency", "20"},
			initialDepth: 5, initialConcurrency: 10, initialSubdomains: false,
			expectedDepth: 10, expectedConcurrency: 20, expectedSubdomains: false,
		},
		{
			name:         "Scope subdomain flag overrides default",
			args:         []string{"--scope", "subdomain"},
			initialDepth: 5, initialConcurrency: 10, initialSubdomains: false,
			expectedDepth: 5, expectedConcurrency: 10, expectedSubdomains: true,
		},
		{
			name:         "Scope strict flag works as expected",
			args:         []string{"--scope", "strict"},
			initialDepth: 5, initialConcurrency: 10, initialSubdomains: true,
			expectedDepth: 5, expectedConcurrency: 10, expectedSubdomains: false,
		},
		{
			name:         "Invalid scope flag defaults to strict and logs a warning",
			args:         []string{"--scope", "invalid-scope"},
			initialDepth: 5, initialConcurrency: 10, initialSubdomains: true,
			expectedDepth: 5, expectedConcurrency: 10, expectedSubdomains: false,
			expectedWarning: true, warningSubstr: "Invalid --scope value",
		},
		{
			name:         "No flags uses initial config",
			args:         []string{},
			initialDepth: 3, initialConcurrency: 8, initialSubdomains: true,
			expectedDepth: 3, expectedConcurrency: 8, expectedSubdomains: true,
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

			// The factory is not used here, so we pass nil.
			scanCmd := newScanCmd(nil)
			err := scanCmd.ParseFlags(tt.args)
			require.NoError(t, err)

			// Act
			applyScanFlagOverrides(scanCmd, cfg)

			// Assert
			assert.Equal(t, tt.expectedDepth, cfg.Discovery().MaxDepth)
			assert.Equal(t, tt.expectedConcurrency, cfg.Engine().WorkerConcurrency)
			assert.Equal(t, tt.expectedSubdomains, cfg.Discovery().IncludeSubdomains)

			if tt.expectedWarning {
				assert.Contains(t, buffer.String(), tt.warningSubstr, "Expected a warning to be logged")
			} else {
				assert.NotContains(t, buffer.String(), "Invalid --scope value", "Did not expect a scope warning")
			}
		})
	}
}

func TestRunScanLogic(t *testing.T) {
	logger := zap.NewNop()
	baseCtx := context.Background()
	defaultTargets := []string{"https://example.com"}

	t.Run("successful scan without report", func(t *testing.T) {
		// Arrange
		mockFactory := new(mocks.MockComponentFactory)
		mockOrchestrator := new(mocks.MockOrchestrator)
		// FIX: Use service.Components struct, as runScan asserts this type.
		mockComponents := &service.Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()

		mockFactory.On("Create", mock.Anything, cfg, defaultTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
		mockOrchestrator.On("StartScan", mock.Anything, defaultTargets, mock.AnythingOfType("string")).Return(nil)

		// Act
		err := runScan(baseCtx, logger, cfg, defaultTargets, "", "", mockFactory)

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
		err := runScan(baseCtx, logger, cfg, defaultTargets, "", "", mockFactory)

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
		// FIX: Use service.Components struct
		mockComponents := &service.Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()
		orchestratorError := errors.New("orchestrator failed")

		mockFactory.On("Create", mock.Anything, cfg, defaultTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
		mockOrchestrator.On("StartScan", mock.Anything, defaultTargets, mock.AnythingOfType("string")).Return(orchestratorError)

		// Act
		err := runScan(baseCtx, logger, cfg, defaultTargets, "", "", mockFactory)

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
		// FIX: Use service.Components struct
		mockComponents := &service.Components{Orchestrator: mockOrchestrator, Store: mockStore}
		cfg := config.NewDefaultConfig()

		tmpfile, err := os.CreateTemp("", "test-report-*.sarif")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())
		outputFile := tmpfile.Name()
		format := "sarif"

		mockFactory.On("Create", mock.Anything, cfg, defaultTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
		mockOrchestrator.On("StartScan", mock.Anything, defaultTargets, mock.AnythingOfType("string")).Return(nil)
		mockStore.On("GetFindingsByScanID", mock.Anything, mock.AnythingOfType("string")).Return([]schemas.Finding{}, nil)

		// Act
		err = runScan(baseCtx, logger, cfg, defaultTargets, outputFile, format, mockFactory)

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
		// FIX: Use service.Components struct
		mockComponents := &service.Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()
		targetsInput := []string{"example.com", "http://test.com", "another.org"}
		// Expect all targets missing a scheme to default to https.
		expectedTargets := []string{"https://example.com", "http://test.com", "https://another.org"}

		// FIX: The factory should be set up with the *expected* normalized targets,
		// as this is what the `Create` method will receive after normalization.
		mockFactory.On("Create", mock.Anything, cfg, expectedTargets, mock.AnythingOfType("*zap.Logger")).Return(mockComponents, nil)
		// Assert that the normalized URLs are passed to the orchestrator.
		mockOrchestrator.On("StartScan", mock.Anything, expectedTargets, mock.AnythingOfType("string")).Return(nil)

		// Act
		err := runScan(baseCtx, logger, cfg, targetsInput, "", "", mockFactory)

		// Assert
		assert.NoError(t, err)
		mockOrchestrator.AssertExpectations(t)
	})
}

// 'Components' struct and its 'Shutdown' method are no longer part of the
// 'cmd' package. That test should be moved to the 'internal/service' package.
