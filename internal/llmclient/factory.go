package llmclient

import (
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// initializeProviderClient is a helper factory function to create a specific provider client based on its model config.
func initializeProviderClient(modelConfig config.LLMModelConfig, logger *zap.Logger) (schemas.LLMClient, error) {
	// Using constants defined in config package to avoid magic strings.
	switch modelConfig.Provider {
	case config.ProviderGemini:
		return NewGoogleClient(modelConfig, logger)
	// case config.ProviderOpenAI:
	//     return NewOpenAIClient(modelConfig, logger)
	case "":
		// Handle the case where the configuration block is present but the provider field is empty.
		// This might happen if a model is defined in the map but missing the provider field.
		return nil, fmt.Errorf("LLM provider is not specified in the model configuration")
	default:
		return nil, fmt.Errorf("unknown or unsupported LLM provider configured: '%s'. Supported: [%s]", modelConfig.Provider, config.ProviderGemini)
	}
}

// NewClient is the main factory function. It initializes the LLM Router and its underlying clients based on the configuration.
func NewClient(cfg config.AgentConfig, logger *zap.Logger) (schemas.LLMClient, error) {
	// cfg.LLM is of type LLMRouterConfig.
	routerConfig := cfg.LLM

	// 1. Resolve and Initialize Fast Tier Client
	fastModelName := routerConfig.DefaultFastModel
	if fastModelName == "" {
		return nil, fmt.Errorf("configuration error: DefaultFastModel is not specified in LLMRouterConfig")
	}
	fastConfig, ok := routerConfig.Models[fastModelName]
	if !ok {
		return nil, fmt.Errorf("configuration error: DefaultFastModel '%s' not found in the models map", fastModelName)
	}

	fastClient, err := initializeProviderClient(fastConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Fast tier LLM client (Model: %s): %w", fastModelName, err)
	}

	// 2. Resolve and Initialize Powerful Tier Client
	powerfulModelName := routerConfig.DefaultPowerfulModel
	if powerfulModelName == "" {
		return nil, fmt.Errorf("configuration error: DefaultPowerfulModel is not specified in LLMRouterConfig")
	}
	powerfulConfig, ok := routerConfig.Models[powerfulModelName]
	if !ok {
		return nil, fmt.Errorf("configuration error: DefaultPowerfulModel '%s' not found in the models map", powerfulModelName)
	}

	powerfulClient, err := initializeProviderClient(powerfulConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Powerful tier LLM client (Model: %s): %w", powerfulModelName, err)
	}

	// 3. Initialize the Router
	router, err := NewLLMRouter(logger, fastClient, powerfulClient)
	if err != nil {
		// This error path (e.g., nil clients) should be prevented by the checks above,
		// but included for completeness.
		return nil, fmt.Errorf("failed to initialize LLM Router: %w", err)
	}

	logger.Debug("LLM Router initialized successfully",
		zap.String("fast_model", fastModelName),
		zap.String("powerful_model", powerfulModelName),
	)

	return router, nil
}