package llmclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// MockLLMClient is a mock implementation of the LLMClient interface for testing.
type MockLLMClient struct {
	mock.Mock
	Name string
}

// Generate mocks the Generate method.
func (m *MockLLMClient) Generate(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

// setupTestLogger is a helper to create a zap logger for testing with an observer.
func setupTestLogger(t *testing.T) *zap.Logger {
	t.Helper()
	core, _ := observer.New(zap.DebugLevel)
	return zap.New(core)
}

// getValidLLMConfig returns a valid LLMModelConfig for testing purposes.
func getValidLLMConfig() config.LLMModelConfig {
	return config.LLMModelConfig{
		Provider:    config.ProviderGemini,
		APIKey:      "test-api-key",
		Model:       "test-model",
		APITimeout:  5 * time.Second,
		Temperature: 0.7,
		TopP:        0.9,
		TopK:        50,
	}
}
