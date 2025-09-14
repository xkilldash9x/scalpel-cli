package llmclient

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// LLMRouter implements the LLMClient interface and routes requests.
type LLMRouter struct {
	logger  *zap.Logger
	clients map[schemas.ModelTier]schemas.LLMClient
}

// NewLLMRouter creates a new router with the specified clients for each tier.
func NewLLMRouter(logger *zap.Logger, fastClient, powerfulClient schemas.LLMClient) (*LLMRouter, error) {
	if fastClient == nil || powerfulClient == nil {
		return nil, fmt.Errorf("both fast and powerful tier clients must be provided")
	}

	return &LLMRouter{
		logger: logger.Named("llm_router"),
		clients: map[schemas.ModelTier]schemas.LLMClient{
			schemas.TierFast:     fastClient,
			schemas.TierPowerful: powerfulClient,
		},
	}, nil
}

// GenerateResponse selects the appropriate client based on the request's Tier.
func (r *LLMRouter) GenerateResponse(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	tier := req.Tier
	if tier == "" {
		tier = schemas.TierPowerful // Default to the powerful tier if unspecified.
	}

	client, ok := r.clients[tier]
	if !ok {
		return "", fmt.Errorf("no LLM client configured for tier: %s", tier)
	}

	r.logger.Debug("Routing LLM request", zap.String("tier", string(tier)))
	return client.Generate(ctx, req)
}

// Generate is now the public-facing method that satisfies the LLMClient interface.
func (r *LLMRouter) Generate(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	return r.GenerateResponse(ctx, req)
}
