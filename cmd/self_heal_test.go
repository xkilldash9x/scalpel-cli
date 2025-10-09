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

func (m *MockMetalystRunner) Run(ctx context.Context, panicLogPath string, originalArgs []string) error {
	args := m.Called(ctx, panicLogPath, originalArgs)
	return args.Error(0)
}

func TestRunSelfHeal(t *testing.T) {
	logger := zaptest.NewLogger(t)
	ctx := context.Background()
	cfg := setupTestConfig(t)
	mockLLM := new(mocks.MockLLMClient)

	t.Run("Success", func(t *testing.T) {
		mockRunner := new(MockMetalystRunner)
		mockInitFn := func(cfg *config.Config, llm schemas.LLMClient) (MetalystRunner, error) {
			return mockRunner, nil
		}
		mockRunner.On("Run", mock.Anything, "crash.log", mock.Anything).Return(nil)

		// We now pass the mock LLM client directly into the function under test.
		err := runSelfHeal(ctx, cfg, logger, "crash.log", []string{}, mockLLM, mockInitFn)
		assert.NoError(t, err)
		mockRunner.AssertExpectations(t)
	})

	t.Run("MetalystInitFailure", func(t *testing.T) {
		expectedErr := errors.New("init failed")
		mockInitFn := func(cfg *config.Config, llm schemas.LLMClient) (MetalystRunner, error) {
			return nil, expectedErr
		}

		err := runSelfHeal(ctx, cfg, logger, "crash.log", []string{}, mockLLM, mockInitFn)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize Metalyst: init failed")
	})

	// ... other tests follow the same pattern ...
}
