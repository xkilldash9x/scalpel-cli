// File: cmd/evolution_test.go
package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// MockAnalystRunner is a mock implementation of the AnalystRunner interface.
type MockAnalystRunner struct {
	mock.Mock
}

func (m *MockAnalystRunner) Run(ctx context.Context, objective string, files []string) error {
	args := m.Called(ctx, objective, files)
	return args.Error(0)
}

// setupTestConfig is a helper to create a default config for testing.
// It now returns the config interface.
func setupTestConfig(t *testing.T) config.Interface {
	t.Helper()
	return config.NewDefaultConfig()
}

// NOTE: TestInitializeKGClient has been removed from this file, as
// initializeKGClient is no longer part of the 'cmd' package.
// That test should be moved to the 'internal/service' package.

// NOTE: This assumes runEvolve, AnalystRunner, and the initializer function type are defined in the cmd package.
func TestRunEvolve(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx := context.Background()
	cfg := setupTestConfig(t)           // Get a local config instance.
	mockLLM := new(mocks.MockLLMClient) // Create the mock LLM

	// Test Case: Successful Execution
	t.Run("Success", func(t *testing.T) {
		mockRunner := new(MockAnalystRunner)
		expectedObjective := "test objective"
		expectedFiles := []string{"file1.go"}

		// Mock the initializer to return our mock runner.
		// Renamed logger to _ as it is unused in this mock implementation, fixing "declared and not used" error.
		mockInitFn := func(_ *zap.Logger, cfg config.Interface, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (AnalystRunner, error) {
			assert.NotNil(t, llmClient)
			assert.NotNil(t, kgClient)
			return mockRunner, nil
		}

		mockRunner.On("Run", mock.Anything, expectedObjective, expectedFiles).Return(nil)

		// Execute, now passing the mockLLM.
		// We pass useInMemoryKG=true to ensure the external service.InitializeKGClient call succeeds.
		err := runEvolve(ctx, cfg, logger, expectedObjective, expectedFiles, true, mockLLM, mockInitFn)

		// Assertions
		assert.NoError(t, err)
		mockRunner.AssertExpectations(t)
	})

	// Test Case: Validation Failure
	t.Run("Missing Objective", func(t *testing.T) {
		// No LLM client needed since it fails on validation first.
		err := runEvolve(ctx, cfg, logger, "", []string{}, true, nil, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--objective is required")
	})

	// Test Case: Initialization Failure (Analyst)
	t.Run("AnalystInitFailure", func(t *testing.T) {
		expectedErr := errors.New("init failed")
		// Renamed logger to _ as it is unused in this mock implementation.
		mockInitFn := func(_ *zap.Logger, cfg config.Interface, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (AnalystRunner, error) {
			return nil, expectedErr
		}

		// Execute with the mock LLM.
		// We pass useInMemoryKG=true to ensure the external service.InitializeKGClient call succeeds.
		err := runEvolve(ctx, cfg, logger, "some objective", []string{}, true, mockLLM, mockInitFn)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize Improvement Analyst: init failed")
	})
}

func TestEvolveCmd_RunE_LLMInitializationFailure(t *testing.T) {
	// This test specifically checks the RunE function of the cobra command,
	// ensuring that an error during dependency setup (before runEvolve is called)
	// is handled correctly.
	// Arrange
	observability.ResetForTest()

	// Create a config that will cause the LLM client to fail initialization.
	// For example, by having no models configured.
	badCfg := config.NewDefaultConfig()
	badCfg.AgentCfg.LLM.Models = make(map[string]config.LLMModelConfig) // No models

	// Create the command instance.
	evolveCmd := newEvolveCmd()
	ctx := context.WithValue(context.Background(), configKey, badCfg)
	evolveCmd.SetContext(ctx)

	// Set required flags to pass initial cobra validation.
	evolveCmd.SetArgs([]string{"--objective", "this will fail"})

	// Act
	// This will call the 'RunE' function, which in turn calls
	// service.InitializeLLMClient with the bad config.
	err := evolveCmd.Execute()

	// Assert
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no models configured for LLM client")
}
