package llmclient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import schemas to access ModelTier constants for whitebox testing
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Test Cases: Factory Initialization (NewClient) --

// Verifies that the factory correctly initializes the LLMRouter by looking up configurations from the map.
func TestNewClient_Success_RouterInitialization(t *testing.T) {
	logger := setupTestLogger(t)
	// Use a background context for initialization tests.
	ctx := context.Background()

	// Define configurations for models in the map
	fastConfig := getValidLLMConfig()
	fastConfig.Model = "gemini-flash" // Differentiate models
	fastConfig.APIKey = "key-fast"

	powerfulConfig := getValidLLMConfig()
	powerfulConfig.Model = "gemini-pro"
	powerfulConfig.APIKey = "key-powerful"

	const fastName = "FastAlias"
	const powerfulName = "PowerfulAlias"

	// Construct AgentConfig with the correct LLMRouterConfig structure.
	cfg := config.AgentConfig{
		LLM: config.LLMRouterConfig{
			DefaultFastModel:     fastName,
			DefaultPowerfulModel: powerfulName,
			Models: map[string]config.LLMModelConfig{
				fastName:     fastConfig,
				powerfulName: powerfulConfig,
			},
		},
	}

	// Execute
	// Pass context to the updated NewClient signature.
	client, err := NewClient(ctx, cfg, logger)

	// Verification
	require.NoError(t, err, "NewClient should succeed for a valid configuration")
	require.NotNil(t, client)
	// Ensure the client resources are cleaned up after the test.
	t.Cleanup(func() { client.Close() })

	// Type assertion to ensure the LLMRouter implementation was instantiated
	router, ok := client.(*LLMRouter)
	assert.True(t, ok, "The created client should be of type *LLMRouter")

	// White box testing: Verify the underlying clients were created and configured correctly.
	if ok {
		// Check Fast Client
		fastClient, okFast := router.clients[schemas.TierFast].(*GoogleClient)
		assert.True(t, okFast, "Fast client should be an instance of *GoogleClient")
		if okFast {
			// APIKey is no longer directly accessible on GoogleClient; we verify the model name and config instead.
			assert.Equal(t, "gemini-flash", fastClient.config.Model)
			assert.Equal(t, "key-fast", fastClient.config.APIKey)
			assert.NotNil(t, fastClient.client, "SDK client should be initialized")
		}

		// Check Powerful Client
		powerfulClient, okPowerful := router.clients[schemas.TierPowerful].(*GoogleClient)
		assert.True(t, okPowerful, "Powerful client should be an instance of *GoogleClient")
		if okPowerful {
			assert.Equal(t, "gemini-pro", powerfulClient.config.Model)
			assert.Equal(t, "key-powerful", powerfulClient.config.APIKey)
			assert.NotNil(t, powerfulClient.client, "SDK client should be initialized")
		}
	}
}

// Verifies the robustness check against missing default model names or missing entries in the map.
func TestNewClient_Failure_MissingConfiguration(t *testing.T) {
	logger := setupTestLogger(t)
	ctx := context.Background()
	validConfig := getValidLLMConfig()
	const validName = "ValidModel"

	tests := []struct {
		name          string
		routerConfig  config.LLMRouterConfig
		expectedError string
	}{
		{
			name: "Missing DefaultFastModel Name",
			routerConfig: config.LLMRouterConfig{
				// DefaultFastModel: "",
				DefaultPowerfulModel: validName,
				Models:               map[string]config.LLMModelConfig{validName: validConfig},
			},
			expectedError: "configuration error: DefaultFastModel is not specified in LLMRouterConfig",
		},
		{
			name: "Missing DefaultPowerfulModel Name",
			routerConfig: config.LLMRouterConfig{
				DefaultFastModel: validName,
				// DefaultPowerfulModel: "",
				Models: map[string]config.LLMModelConfig{validName: validConfig},
			},
			expectedError: "configuration error: DefaultPowerfulModel is not specified in LLMRouterConfig",
		},
		{
			name: "DefaultFastModel Not Found in Map",
			routerConfig: config.LLMRouterConfig{
				DefaultFastModel:     "MissingModel",
				DefaultPowerfulModel: validName,
				Models:               map[string]config.LLMModelConfig{validName: validConfig},
			},
			expectedError: "configuration error: DefaultFastModel 'MissingModel' not found in the models map",
		},
		{
			name: "DefaultPowerfulModel Not Found in Map",
			routerConfig: config.LLMRouterConfig{
				DefaultFastModel:     validName,
				DefaultPowerfulModel: "MissingModel",
				Models:               map[string]config.LLMModelConfig{validName: validConfig},
			},
			expectedError: "configuration error: DefaultPowerfulModel 'MissingModel' not found in the models map",
		},
		{
			name:          "Empty Router Config",
			routerConfig:  config.LLMRouterConfig{},
			expectedError: "configuration error: DefaultFastModel is not specified in LLMRouterConfig",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.AgentConfig{LLM: tt.routerConfig}
			// Pass context to the updated NewClient signature.
			client, err := NewClient(ctx, cfg, logger)
			assert.Error(t, err)
			assert.Nil(t, client)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

// Verifies that the factory propagates errors from the specific client's constructor.
func TestNewClient_Failure_ProviderInitializationError(t *testing.T) {
	logger := setupTestLogger(t)
	ctx := context.Background()
	validConfig := getValidLLMConfig()

	// Scenario: Configuration is present but required parameters (API Key for Gemini) are missing.
	invalidConfig := getValidLLMConfig()
	invalidConfig.APIKey = "" // Missing key causes NewGoogleClient failure

	const invalidName = "InvalidConfig"
	const validName = "ValidConfig"

	// Test failure during Fast client initialization
	cfgMissingKey := config.AgentConfig{
		LLM: config.LLMRouterConfig{
			DefaultFastModel:     invalidName,
			DefaultPowerfulModel: validName,
			Models: map[string]config.LLMModelConfig{
				invalidName: invalidConfig,
				validName:   validConfig,
			},
		},
	}

	// Pass context to the updated NewClient signature.
	client, err := NewClient(ctx, cfgMissingKey, logger)
	assert.Error(t, err)
	assert.Nil(t, client)
	// Verifying the error originates from the GoogleClient constructor and is wrapped by the factory
	assert.Contains(t, err.Error(), "failed to initialize Fast tier LLM client (Model: InvalidConfig):")
	assert.Contains(t, err.Error(), "Google/Gemini API Key is required")
}

// Verifies the factory returns an error for unknown providers in any tier.
func TestNewClient_Failure_UnsupportedProvider(t *testing.T) {
	logger := setupTestLogger(t)
	ctx := context.Background()
	validConfig := getValidLLMConfig()

	unsupportedConfig := getValidLLMConfig()
	unsupportedConfig.Provider = "unsupported-provider-xyz"

	const validName = "Valid"
	const unsupportedName = "Unsupported"

	// Test failure during Powerful client initialization
	cfg := config.AgentConfig{
		LLM: config.LLMRouterConfig{
			DefaultFastModel:     validName,
			DefaultPowerfulModel: unsupportedName,
			Models: map[string]config.LLMModelConfig{
				validName:       validConfig,
				unsupportedName: unsupportedConfig,
			},
		},
	}

	// Execute
	// Pass context to the updated NewClient signature.
	client, err := NewClient(ctx, cfg, logger)

	// Verification
	assert.Error(t, err, "NewClient should fail for an unsupported provider")
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to initialize Powerful tier LLM client (Model: Unsupported):")
	assert.Contains(t, err.Error(), "unknown or unsupported LLM provider configured: 'unsupported-provider-xyz'")
	// Ensure the error message guides the user by listing supported options
	assert.Contains(t, err.Error(), config.ProviderGemini, "Error message should list supported providers")
}

// Verifies the factory returns an error if a model is defined but missing the provider field.
func TestNewClient_Failure_MissingProviderField(t *testing.T) {
	logger := setupTestLogger(t)
	ctx := context.Background()
	validConfig := getValidLLMConfig()

	// Config where the Provider field is empty
	missingProviderConfig := getValidLLMConfig()
	missingProviderConfig.Provider = ""

	const missingName = "MissingProvider"
	const validName = "Valid"

	cfg := config.AgentConfig{
		LLM: config.LLMRouterConfig{
			DefaultFastModel:     missingName,
			DefaultPowerfulModel: validName,
			Models: map[string]config.LLMModelConfig{
				validName:   validConfig,
				missingName: missingProviderConfig,
			},
		},
	}

	// Execute
	// Pass context to the updated NewClient signature.
	client, err := NewClient(ctx, cfg, logger)

	// Verification
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "failed to initialize Fast tier LLM client (Model: MissingProvider):")
	assert.Contains(t, err.Error(), "LLM provider is not specified in the model configuration")
}
