// File: cmd/scan_test.go
package cmd

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Mocks for testing --

// MockOrchestrator is a mock for the schemas.Orchestrator interface.
type MockOrchestrator struct {
	mock.Mock
}

func (m *MockOrchestrator) StartScan(ctx context.Context, targets []string, scanID string) error {
	args := m.Called(ctx, targets, scanID)
	return args.Error(0)
}

// MockStore is a mock for the schemas.Store interface.
type MockStore struct {
	mock.Mock
}

func (m *MockStore) GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error) {
	args := m.Called(ctx, scanID)
	if findings, ok := args.Get(0).([]schemas.Finding); ok {
		return findings, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockStore) PersistData(ctx context.Context, envelope *schemas.ResultEnvelope) error {
	args := m.Called(ctx, envelope)
	return args.Error(0)
}

// -- Test Cases --

func TestRunScan(t *testing.T) {
	logger := zap.NewNop()
	baseCtx := context.Background()
	defaultTargets := []string{"https://example.com"}

	t.Run("successful scan without report", func(t *testing.T) {
		// Arrange
		mockOrchestrator := new(MockOrchestrator)
		mockStore := new(MockStore)
		cfg := config.NewDefaultConfig()

		// REFACTOR: Create the components struct and populate it with mocks.
		components := &scanComponents{
			Orchestrator: mockOrchestrator,
			Store:        mockStore,
		}

		mockOrchestrator.On("StartScan", mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil)

		// Act: Call runScan with the new components struct.
		err := runScan(baseCtx, logger, cfg, defaultTargets, "", "", components)

		// Assert
		assert.NoError(t, err)
		mockOrchestrator.AssertExpectations(t)
		mockStore.AssertNotCalled(t, "GetFindingsByScanID")
	})

	t.Run("scan fails when orchestrator returns an error", func(t *testing.T) {
		// Arrange
		mockOrchestrator := new(MockOrchestrator)
		mockStore := new(MockStore)
		cfg := config.NewDefaultConfig()
		orchestratorError := errors.New("orchestrator failed")

		components := &scanComponents{
			Orchestrator: mockOrchestrator,
			Store:        mockStore,
		}

		mockOrchestrator.On("StartScan", mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(orchestratorError)

		// Act
		err := runScan(baseCtx, logger, cfg, defaultTargets, "", "", components)

		// Assert
		assert.Error(t, err)
		assert.ErrorIs(t, err, orchestratorError, "The error from the orchestrator should be propagated")
		mockOrchestrator.AssertExpectations(t)
	})

	t.Run("successful scan with report generation", func(t *testing.T) {
		// Arrange
		mockOrchestrator := new(MockOrchestrator)
		mockStore := new(MockStore)
		cfg := config.NewDefaultConfig()
		tmpfile, err := os.CreateTemp("", "test-report-*.sarif")
		require.NoError(t, err)
		defer os.Remove(tmpfile.Name())
		outputFile := tmpfile.Name()
		format := "sarif"

		components := &scanComponents{
			Orchestrator: mockOrchestrator,
			Store:        mockStore,
		}

		mockOrchestrator.On("StartScan", mock.Anything, mock.Anything, mock.AnythingOfType("string")).Return(nil)
		mockStore.On("GetFindingsByScanID", mock.Anything, mock.AnythingOfType("string")).Return([]schemas.Finding{}, nil)

		// Act
		err = runScan(baseCtx, logger, cfg, defaultTargets, outputFile, format, components)

		// Assert
		assert.NoError(t, err)
		mockOrchestrator.AssertExpectations(t)
		mockStore.AssertExpectations(t)

		info, err := os.Stat(outputFile)
		assert.NoError(t, err)
		assert.Greater(t, info.Size(), int64(0), "The report file should not be empty")
	})
}
