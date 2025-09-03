package llmclient// File:         pkg/llmclient/factory.go
// Description:  The factory now constructs the LLMRouter, instantiating and wiring up
//               all configured models according to their designated tiers.
//
package llmclient

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/agent"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
)

// NewClient is a factory function that now creates an LLMRouter based on the configuration.
// This provides a single, tiered client to the rest of the application.
func NewClient(cfg config.AgentConfig, logger *zap.Logger) (interfaces.LLMClient, error) {
	routerCfg := cfg.LLM
	if len(routerCfg.Models) == 0 {
		return nil, fmt.Errorf("no LLM models configured under agent.llm.models")
	}

	// Create a client instance for each model defined in the configuration.
	instantiatedClients := make(map[string]interfaces.LLMClient)
	for name, modelCfg := range routerCfg.Models {
		var client interfaces.LLMClient
		var err error
		switch modelCfg.Provider {
		case config.ProviderGemini:
			client, err = NewGeminiClient(modelCfg, logger)
		// case config.ProviderOpenAI:
		// 	client, err = NewOpenAIClient(modelCfg, logger)
		default:
			return nil, fmt.Errorf("unknown LLM provider '%s' for model '%s'", modelCfg.Provider, name)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create LLM client for model '%s': %w", name, err)
		}
		instantiatedClients[name] = client
		logger.Info("Instantiated LLM client", zap.String("name", name), zap.String("provider", string(modelCfg.Provider)), zap.String("model", modelCfg.Model))
	}

	// Look up the clients designated for the fast and powerful tiers.
	fastClient, ok := instantiatedClients[routerCfg.DefaultFastModel]
	if !ok {
		return nil, fmt.Errorf("default fast model '%s' not found in defined models", routerCfg.DefaultFastModel)
	}

	powerfulClient, ok := instantiatedClients[routerCfg.DefaultPowerfulModel]
	if !ok {
		return nil, fmt.Errorf("default powerful model '%s' not found in defined models", routerCfg.DefaultPowerfulModel)
	}

	// Create and return the router, which will manage dispatching to the correct client.
	return NewLLMRouter(logger, fastClient, powerfulClient)
}
