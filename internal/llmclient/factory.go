package llmclient

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// initializeProviderClient is a helper factory function to create a specific provider client based on its model config.
// It requires a context for initialization (e.g., for SDK setup).
func initializeProviderClient(ctx context.Context, modelConfig config.LLMModelConfig, logger *zap.Logger) (schemas.LLMClient, error) {
	// Using constants defined in config package to avoid magic strings.
	switch modelConfig.Provider {
	case config.ProviderGemini:
		// Call the updated NewGoogleClient constructor (which uses the new SDK).
		return NewGoogleClient(ctx, modelConfig, logger)
	// case config.ProviderOpenAI:
	//     return NewOpenAIClient(ctx, modelConfig, logger)
	case "":
		// Handle the case where the configuration block is present but the provider field is empty.
		// This might happen if a model is defined in the map but missing the provider field.
		return nil, fmt.Errorf("LLM provider is not specified in the model configuration")
	default:
		return nil, fmt.Errorf("unknown or unsupported LLM provider configured: '%s'. Supported: [%s]", modelConfig.Provider, config.ProviderGemini)
	}
}

// NewClient is the main factory function. It initializes the LLM Router and its underlying clients based on the configuration.
// It requires a context, typically the application's startup context.
func NewClient(ctx context.Context, cfg config.AgentConfig, logger *zap.Logger) (schemas.LLMClient, error) {
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

	// Pass context during initialization
	fastClient, err := initializeProviderClient(ctx, fastConfig, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Fast tier LLM client (Model: %s): %w", fastModelName, err)
	}

	// 2. Resolve and Initialize Powerful Tier Client
	// CRITICAL: If subsequent initializations fail, we must close the clients initialized so far.
	powerfulModelName := routerConfig.DefaultPowerfulModel
	if powerfulModelName == "" {
		// If initialization fails, ensure we close the previously initialized client.
		if closeErr := fastClient.Close(); closeErr != nil {
			logger.Warn("Failed to close Fast tier client during error handling", zap.Error(closeErr))
		}
		return nil, fmt.Errorf("configuration error: DefaultPowerfulModel is not specified in LLMRouterConfig")
	}
	powerfulConfig, ok := routerConfig.Models[powerfulModelName]
	if !ok {
		if closeErr := fastClient.Close(); closeErr != nil {
			logger.Warn("Failed to close Fast tier client during error handling", zap.Error(closeErr))
		}
		return nil, fmt.Errorf("configuration error: DefaultPowerfulModel '%s' not found in the models map", powerfulModelName)
	}

	// Pass context during initialization
	powerfulClient, err := initializeProviderClient(ctx, powerfulConfig, logger)
	if err != nil {
		// Ensure fastClient is closed if powerfulClient initialization fails.
		if closeErr := fastClient.Close(); closeErr != nil {
			logger.Warn("Failed to close Fast tier client during error handling", zap.Error(closeErr))
		}
		return nil, fmt.Errorf("failed to initialize Powerful tier LLM client (Model: %s): %w", powerfulModelName, err)
	}

	// 3. Initialize the Router
	// The LLMRouter takes ownership of the clients and is responsible for closing them.
	router, err := NewLLMRouter(logger, fastClient, powerfulClient)
	if err != nil {
		// This error path (e.g., nil clients) should be prevented by the checks above,
		// but included for completeness. Ensure both clients are closed if router init fails.
		fastClient.Close()
		powerfulClient.Close()
		return nil, fmt.Errorf("failed to initialize LLM Router: %w", err)
	}

	logger.Debug("LLM Router initialized successfully",
		zap.String("fast_model", fastModelName),
		zap.String("powerful_model", powerfulModelName),
	)

	return router, nil
}
