// File:         pkg/agent/interfaces.go
// Description:  This file defines the updated, more robust interfaces for the agent's LLM client.
//
package agent

import (
	"context"
)

// ModelTier represents the desired capability level of the LLM for a given task.
// This allows the agent to request a cheaper, faster model for simple tasks,
// and a more powerful, expensive model for complex reasoning.
type ModelTier string

const (
	// TierFast is for simple, low-cost operations (e.g., text summarization, formatting).
	TierFast ModelTier = "fast"
	// TierPowerful is for complex reasoning, analysis, and decision-making.
	TierPowerful ModelTier = "powerful"
)

// GenerationOptions holds parameters for controlling LLM generation.
type GenerationOptions struct {
	// Temperature controls the creativity of the response. Lower is more deterministic.
	Temperature float32
	// MaxTokens sets the maximum length of the generated response.
	MaxTokens int
	// ForceJSONFormat indicates to the LLM provider to enforce JSON output mode if available.
	ForceJSONFormat bool
}

// GenerationRequest encapsulates all inputs for a single LLM API call.
// This provides a structured and extensible way to make requests.
type GenerationRequest struct {
	SystemPrompt string
	UserPrompt   string
	Tier         ModelTier // The requested capability tier for this specific request.
	Options      GenerationOptions
}

// LLMClient defines the interface for interacting with a Large Language Model.
// It abstracts the specific provider (e.g., Gemini, OpenAI) and the routing logic.
type LLMClient interface {
	// GenerateResponse sends a structured request to the LLM and returns the text content.
	GenerateResponse(ctx context.Context, req GenerationRequest) (string, error)
}