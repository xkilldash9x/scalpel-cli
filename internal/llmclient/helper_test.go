package llmclient

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// setupTestLogger is a helper to create a zap logger for testing with an observer.
func setupTestLogger(t *testing.T) *zap.Logger {
	t.Helper()
	core, _ := observer.New(zap.DebugLevel)
	return zap.New(core)
}

// getValidLLMConfig returns a valid LLMModelConfig for testing purposes.
func getValidLLMConfig() config.LLMModelConfig {
	return config.LLMModelConfig{
		// Matches config.ProviderGemini ("gemini")
		Provider: "gemini",
		Model:    "gemini-2.5-flash",
		APIKey:   "test-api-key",
		SafetyFilters: map[string]string{
			"HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
		},
		Temperature: 0.5,
		TopP:        0.9,
		TopK:        40,
		MaxTokens:   2048,
		APITimeout:  30 * time.Second,
	}
}
