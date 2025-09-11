package llmclient

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	// Import the interface from the central interfaces package to break the cycle.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// NewClient is our factory for spitting out the right LLMClient based on the config.
// Assumes config.AgentConfig.LLM is a pointer: *config.LLMModelConfig
func NewClient(cfg config.AgentConfig, logger *zap.Logger) (interfaces.LLMClient, error) {

	// Robustness check, because nil pointers are the bane of our existence.
	if cfg.LLM == nil {
		logger.Error("LLM configuration block is missing in AgentConfig during client initialization")
		return nil, fmt.Errorf("LLM configuration block is missing in AgentConfig")
	}

	// Dereference the pointer to access the configuration values.
	llmConfig := *cfg.LLM
	provider := llmConfig.Provider

	// Using constants defined in config package to avoid magic strings.
	switch provider {
	case config.ProviderGemini:
		// Pass the specific LLMModelConfig (llmConfig) instead of the entire AgentConfig (cfg).
		return NewGeminiClient(llmConfig, logger)
	// case config.ProviderOpenAI:
	//     return NewOpenAIClient(llmConfig, logger)
	default:
		// Assuming config.ProviderGemini is defined in the config package.
		return nil, fmt.Errorf("unknown or unsupported LLM provider configured: '%s'. Supported: [%s]", provider, config.ProviderGemini)
	}
}
