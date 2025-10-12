// File: cmd/self_heal_test.go
package cmd

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// MockMetalystRunner is a mock implementation of the MetalystRunner interface.
type MockMetalystRunner struct {
	mock.Mock
}

// Run provides a mock for the Run method.
func (m *MockMetalystRunner) Run(ctx context.Context, panicLogPath string, originalArgs []string) error {
	args := m.Called(ctx, panicLogPath, originalArgs)
	return args.Error(0)
}

// setupHealTestConfig provides a consistent, default configuration for self-heal tests.
func setupHealTestConfig(t *testing.T) config.Interface {
	t.Helper()
	return config.NewDefaultConfig()
}

func TestRunSelfHeal(t *testing.T) {
	// Common arrange steps for all sub-tests
	logger := zaptest.NewLogger(t)
	ctx := context.Background()
	cfg := setupHealTestConfig(t)
	mockLLM := new(mocks.MockLLMClient)
	panicLog := "crash.log"
	originalArgs := []string{"scan", "https://example.com"}

	t.Run("Success", func(t *testing.T) {
		// Arrange
		mockRunner := new(MockMetalystRunner)
		mockInitFn := func(cfg config.Interface, llm schemas.LLMClient) (MetalystRunner, error) {
			return mockRunner, nil
		}
		mockRunner.On("Run", ctx, panicLog, originalArgs).Return(nil)

		// Act
		err := runSelfHeal(ctx, cfg, logger, panicLog, originalArgs, mockLLM, mockInitFn)

		// Assert
		assert.NoError(t, err)
		mockRunner.AssertExpectations(t)
	})

	t.Run("MetalystInitFailure", func(t *testing.T) {
		// Arrange
		expectedErr := errors.New("init failed")
		mockInitFn := func(cfg config.Interface, llm schemas.LLMClient) (MetalystRunner, error) {
			return nil, expectedErr
		}

		// Act
		err := runSelfHeal(ctx, cfg, logger, panicLog, originalArgs, mockLLM, mockInitFn)

		// Assert
		assert.Error(t, err)
		assert.ErrorIs(t, err, expectedErr, "The original error should be wrapped and returned")
		assert.Contains(t, err.Error(), "failed to initialize Metalyst")
	})

	t.Run("RunnerFailure", func(t *testing.T) {
		// Arrange
		mockRunner := new(MockMetalystRunner)
		expectedErr := errors.New("runner failed during execution")
		mockInitFn := func(cfg config.Interface, llm schemas.LLMClient) (MetalystRunner, error) {
			return mockRunner, nil
		}
		mockRunner.On("Run", ctx, panicLog, originalArgs).Return(expectedErr)

		// Act
		err := runSelfHeal(ctx, cfg, logger, panicLog, originalArgs, mockLLM, mockInitFn)

		// Assert
		assert.Error(t, err)
		assert.ErrorIs(t, err, expectedErr, "The error from the runner should be returned directly")
		mockRunner.AssertExpectations(t)
	})

	t.Run("MissingPanicLogPath", func(t *testing.T) {
		// Arrange
		mockRunner := new(MockMetalystRunner)
		mockInitFn := func(cfg config.Interface, llm schemas.LLMClient) (MetalystRunner, error) {
			return mockRunner, nil
		}

		// Act
		err := runSelfHeal(ctx, cfg, logger, "", originalArgs, mockLLM, mockInitFn)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "--panic-log is required")
		mockRunner.AssertNotCalled(t, "Run")
	})
}
