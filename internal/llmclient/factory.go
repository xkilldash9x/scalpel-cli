// -- pkg/llmclient/factory.go --
package llmclient

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	// Import the interface from the central interfaces package to break the cycle.
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
)

// NewClient is a factory function that creates an LLMClient based on the configuration.
func NewClient(cfg config.AgentConfig, logger *zap.Logger) (interfaces.LLMClient, error) {
	provider := cfg.LLM.Provider

	// Using constants defined in config package to avoid magic strings.
	switch provider {
	case config.ProviderGemini:
		return NewGeminiClient(cfg, logger)
	// case config.ProviderOpenAI:
	// 	return NewOpenAIClient(cfg, logger)
	default:
		// Assuming config.ProviderGemini is defined in the config package.
		return nil, fmt.Errorf("unknown or unsupported LLM provider configured: '%s'. Supported: [%s]", provider, config.ProviderGemini)
	}
}