// File: cmd/scan_test.go
package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestApplyScanFlagOverrides(t *testing.T) {
	// ... (Test cases remain the same as provided in the prompt)
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
		// Return value for the mock must be cast to interface{} to match the signature
		mockComponents := &Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()

		mockFactory.On("Create", mock.Anything, cfg, defaultTargets).Return(mockComponents, nil)
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
		mockFactory.On("Create", mock.Anything, cfg, defaultTargets).Return(nil, factoryErr)

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
		mockComponents := &Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()
		orchestratorError := errors.New("orchestrator failed")

		mockFactory.On("Create", mock.Anything, cfg, defaultTargets).Return(mockComponents, nil)
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
		mockComponents := &Components{Orchestrator: mockOrchestrator, Store: mockStore}
		cfg := config.NewDefaultConfig()

		tmpfile, err := os.CreateTemp("", "test-report-*.sarif")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())
		outputFile := tmpfile.Name()
		format := "sarif"

		mockFactory.On("Create", mock.Anything, cfg, defaultTargets).Return(mockComponents, nil)
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
		mockComponents := &Components{Orchestrator: mockOrchestrator}
		cfg := config.NewDefaultConfig()
		targetsInput := []string{"example.com", "http://test.com", "another.org"}
		// Expect all targets missing a scheme to default to https.
		expectedTargets := []string{"https://example.com", "http://test.com", "https://another.org"}

		// Factory is called with original targets for initialization logic (like scope).
		mockFactory.On("Create", mock.Anything, cfg, targetsInput).Return(mockComponents, nil)
		// Assert that the normalized URLs are passed to the orchestrator.
		mockOrchestrator.On("StartScan", mock.Anything, expectedTargets, mock.AnythingOfType("string")).Return(nil)

		// Act
		err := runScan(baseCtx, logger, cfg, targetsInput, "", "", mockFactory)

		// Assert
		assert.NoError(t, err)
		mockOrchestrator.AssertExpectations(t)
	})
}

func TestComponentsShutdown(t *testing.T) {
	t.Run("shutdown calls all necessary component stop methods and waits for consumer", func(t *testing.T) {
		// Arrange
		observability.ResetForTest()
		var buffer bytes.Buffer
		writer := zapcore.AddSync(&buffer)
		observability.Initialize(
			config.LoggerConfig{Level: "debug", Format: "console"},
			writer,
		)

		mockTaskEngine := new(mocks.MockTaskEngine)
		mockDiscoveryEngine := new(mocks.MockDiscoveryEngine)
		mockBrowserManager := new(mocks.MockBrowserManager)

		// Create a real pool that points to a non existent DB to check that Close is still called.
		pool, err := pgxpool.New(context.Background(), "postgres://user:pass@localhost:1/nonexistentdb")
		require.NoError(t, err) // New doesn't error, connect does.

		findingsChan := make(chan schemas.Finding, 1)
		// This is a pointer to the original WaitGroup, not a copy.
		var consumerWG sync.WaitGroup
		consumerWG.Add(1)

		components := &Components{
			TaskEngine:      mockTaskEngine,
			DiscoveryEngine: mockDiscoveryEngine,
			BrowserManager:  mockBrowserManager,
			DBPool:          pool,
			findingsChan:    findingsChan,
			// Pass the ADDRESS of the waitgroup, not a copy of it.
			consumerWG: &consumerWG,
		}

		mockTaskEngine.On("Stop").Return()
		mockDiscoveryEngine.On("Stop").Return()
		mockBrowserManager.On("Shutdown", mock.Anything).Return(nil)

		// Simulate the consumer running and waiting for the channel to close.
		// This goroutine operates on the original 'consumerWG' variable.
		go func() {
			// Wait for the channel to be closed by Shutdown().
			for range findingsChan {
				// Process findings (drain)
			}
			// Once drained, signal completion on the original WG.
			consumerWG.Done()
		}()

		// Act
		components.Shutdown()

		// Assert
		mockTaskEngine.AssertCalled(t, "Stop")
		mockDiscoveryEngine.AssertCalled(t, "Stop")
		mockBrowserManager.AssertCalled(t, "Shutdown", mock.Anything)

		// Verify log messages confirm the sequence.
		assert.Contains(t, buffer.String(), "Task engine stopped.")
		assert.Contains(t, buffer.String(), "Findings channel closed.")
		assert.Contains(t, buffer.String(), "Findings consumer finished processing.")
		assert.Contains(t, buffer.String(), "Database connection pool closed.")

		// Verify the findings channel was closed.
		select {
		case _, ok := <-findingsChan:
			assert.False(t, ok, "Findings channel should be closed")
		default:
			// Channel already confirmed closed by the goroutine exiting and the WG completing.
		}
	})
}
