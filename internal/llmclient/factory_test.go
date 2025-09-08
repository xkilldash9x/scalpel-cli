package llmclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Test Cases: Factory Initialization (NewClient) --

// Verifies that the factory correctly initializes a GeminiClient.
func TestNewClient_Success_Gemini(t *testing.T) {
	logger := setupTestLogger(t)
	llmConfig := getValidLLMConfig()

	// Construct AgentConfig assuming it holds a pointer to LLMModelConfig.
	cfg := config.AgentConfig{
		LLM: &llmConfig,
	}

	// Execute
	client, err := NewClient(cfg, logger)

	// Verification
	require.NoError(t, err, "NewClient should succeed for a valid Gemini configuration")
	require.NotNil(t, client)

	// Type assertion to ensure the correct implementation was instantiated
	geminiClient, ok := client.(*GeminiClient)
	assert.True(t, ok, "The created client should be of type *GeminiClient")

	// White box testing: Verify configuration was passed correctly to the specific client
	if ok {
		assert.Equal(t, llmConfig.APIKey, geminiClient.apiKey)
		assert.Equal(t, llmConfig.Model, geminiClient.config.Model)
	}
}

// Verifies the robustness check against missing LLM configuration.
func TestNewClient_Failure_NilConfigBlock(t *testing.T) {
	logger := setupTestLogger(t)

	// Scenario: LLM block pointer is nil
	cfgNilLLM := config.AgentConfig{
		LLM: nil,
	}

	client, err := NewClient(cfgNilLLM, logger)
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "LLM configuration block is missing in AgentConfig")
}

// Verifies that the factory propagates errors from the specific client's constructor.
func TestNewClient_Failure_ProviderInitializationError(t *testing.T) {
	logger := setupTestLogger(t)

	// Scenario: Configuration is present but required parameters (API Key for Gemini) are missing.
	llmConfig := getValidLLMConfig()
	llmConfig.APIKey = "" // Missing key causes NewGeminiClient failure
	cfgMissingKey := config.AgentConfig{
		LLM: &llmConfig,
	}

	client, err := NewClient(cfgMissingKey, logger)
	assert.Error(t, err)
	assert.Nil(t, client)
	// Verifying the error originates from the GeminiClient constructor
	assert.Contains(t, err.Error(), "Gemini API Key is required")
}

// Verifies the factory returns an error for unknown providers.
func TestNewClient_Failure_UnsupportedProvider(t *testing.T) {
	logger := setupTestLogger(t)
	llmConfig := getValidLLMConfig()
	llmConfig.Provider = "unsupported-provider-xyz"
	cfg := config.AgentConfig{
		LLM: &llmConfig,
	}

	// Execute
	client, err := NewClient(cfg, logger)

	// Verification
	assert.Error(t, err, "NewClient should fail for an unsupported provider")
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "unknown or unsupported LLM provider configured: 'unsupported-provider-xyz'")
	// Ensure the error message guides the user by listing supported options
	assert.Contains(t, err.Error(), config.ProviderGemini, "Error message should list supported providers")
}