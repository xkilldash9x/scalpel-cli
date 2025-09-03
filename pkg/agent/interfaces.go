// -- pkg/agent/interfaces.go --
package agent

import (
	"context"
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
type GenerationRequest struct {
	SystemPrompt string
	UserPrompt   string
	Options      GenerationOptions
}

// LLMClient defines the interface for interacting with a Large Language Model.
// It abstracts the specific provider (e.g., Gemini, OpenAI) away from the agent logic.
type LLMClient interface {
	// GenerateResponse sends a structured request to the LLM and returns the text content.
	GenerateResponse(ctx context.Context, req GenerationRequest) (string, error)
}
