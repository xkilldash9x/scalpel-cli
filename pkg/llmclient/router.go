/ File:         pkg/llmclient/router.go
// Description:  This file introduces the LLMRouter, which intelligently dispatches
//               requests to different LLM clients based on the requested capability tier.
//
package llmclient

import (
	"context"
	"fmt"

	"github.com/xkilldash9x/scalpel-cli/pkg/agent"
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
	"go.uber.org/zap"
)

// LLMRouter implements the LLMClient interface and routes requests to different
// underlying clients based on the requested agent.ModelTier.
type LLMRouter struct {
	logger  *zap.Logger
	clients map[agent.ModelTier]interfaces.LLMClient
}

// NewLLMRouter creates a new router with the specified clients for each tier.
func NewLLMRouter(logger *zap.Logger, fastClient, powerfulClient interfaces.LLMClient) (*LLMRouter, error) {
	if fastClient == nil {
		return nil, fmt.Errorf("fast tier client cannot be nil")
	}
	if powerfulClient == nil {
		return nil, fmt.Errorf("powerful tier client cannot be nil")
	}

	return &LLMRouter{
		logger: logger.Named("llm_router"),
		clients: map[agent.ModelTier]interfaces.LLMClient{
			agent.TierFast:     fastClient,
			agent.TierPowerful: powerfulClient,
		},
	}, nil
}

// GenerateResponse selects the appropriate client based on the request's Tier and forwards the request.
func (r *LLMRouter) GenerateResponse(ctx context.Context, req agent.GenerationRequest) (string, error) {
	// Default to the powerful tier if the tier is not specified.
	tier := req.Tier
	if tier == "" {
		tier = agent.TierPowerful
	}

	client, ok := r.clients[tier]
	if !ok {
		return "", fmt.Errorf("no LLM client configured for tier: %s", tier)
	}

	r.logger.Debug("Routing LLM request", zap.String("tier", string(tier)))

	// The request is passed directly to the selected underlying client.
	return client.GenerateResponse(ctx, req)
}