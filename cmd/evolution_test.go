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

// 1. Unit Testing: initializeKGClient()
func TestInitializeKGClient(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx := context.Background()

	t.Run("In-Memory (Flag)", func(t *testing.T) {
		kgCfg := config.KnowledgeGraphConfig{Type: "postgres"}
		client, cleanup, err := initializeKGClient(ctx, kgCfg, logger, true) // flag overrides to in-memory
		assert.NoError(t, err)
		assert.Nil(t, cleanup)
		assert.NotNil(t, client)
	})

	t.Run("In-Memory (Config)", func(t *testing.T) {
		kgCfg := config.KnowledgeGraphConfig{Type: "in-memory"}
		client, cleanup, err := initializeKGClient(ctx, kgCfg, logger, false)
		assert.NoError(t, err)
		assert.Nil(t, cleanup)
		assert.NotNil(t, client)
	})

	t.Run("Unsupported Type", func(t *testing.T) {
		kgCfg := config.KnowledgeGraphConfig{Type: "unsupported"}
		_, _, err := initializeKGClient(ctx, kgCfg, logger, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported Knowledge Graph type")
	})

	t.Run("Postgres (Config Parsing and Connection Attempt)", func(t *testing.T) {
		// The call to config.Set is no longer needed as the function under test
		// receives all its required configuration via its arguments.

		kgCfg := config.KnowledgeGraphConfig{
			Type: "postgres",
			// Provide invalid credentials to trigger a connection error.
			Postgres: config.PostgresConfig{
				Host: "invalid-host-for-testing",
				Port: 1,
			},
		}
		_, _, err := initializeKGClient(ctx, kgCfg, logger, false)

		assert.Error(t, err)
		// Check for a more generic error that indicates a connection problem.
		assert.Contains(t, err.Error(), "failed to ping PostgreSQL")
	})
}

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
		mockInitFn := func(logger *zap.Logger, cfg config.Interface, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (AnalystRunner, error) {
			assert.NotNil(t, llmClient)
			assert.NotNil(t, kgClient)
			return mockRunner, nil
		}

		mockRunner.On("Run", mock.Anything, expectedObjective, expectedFiles).Return(nil)

		// Execute, now passing the mockLLM.
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
		mockInitFn := func(logger *zap.Logger, cfg config.Interface, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (AnalystRunner, error) {
			return nil, expectedErr
		}

		// Execute with the mock LLM.
		err := runEvolve(ctx, cfg, logger, "some objective", []string{}, true, mockLLM, mockInitFn)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize Improvement Analyst: init failed")
	})
}
