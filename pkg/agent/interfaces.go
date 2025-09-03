package agent

import (
	"context"
)

// LLMClient defines the interface for interacting with a Large Language Model.
// It abstracts the specific provider (e.g., Gemini, OpenAI) away from the agent logic.
type LLMClient interface {
	// GenerateResponse sends a system and user prompt to the LLM and returns
	// the generated text content.
	GenerateResponse(ctx context.Context, systemPrompt string, userPrompt string) (string, error)
}

