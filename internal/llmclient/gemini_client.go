// internal/llmclient/gemini_client.go
package llmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// GeminiClient implements the interfaces.LLMClient interface for Google Gemini APIs.
type GeminiClient struct {
	apiKey     string
	endpoint   string
	httpClient *http.Client
	logger     *zap.Logger
	config     config.LLMModelConfig
}

// -- Gemini API Request/Response Structures (Internal to this file) --
type GeminiContent struct {
	Parts []GeminiPart `json:"parts"`
	Role  string       `json:"role,omitempty"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiSystemInstruction struct {
	Parts []GeminiPart `json:"parts"`
}

type GeminiSafetySetting struct {
	Category  string `json:"category"`
	Threshold string `json:"threshold"`
}

type GeminiGenerationConfig struct {
	Temperature      float64 `json:"temperature"`
	ResponseMimeType string  `json:"response_mime_type,omitempty"`
	TopP             float32 `json:"topP,omitempty"`
	TopK             int     `json:"topK,omitempty"`
	MaxOutputTokens  int     `json:"maxOutputTokens,omitempty"`
}

type GeminiRequestPayload struct {
	Contents          []GeminiContent          `json:"contents"`
	SystemInstruction *GeminiSystemInstruction `json:"system_instruction,omitempty"`
	SafetySettings    []GeminiSafetySetting    `json:"safetySettings,omitempty"`
	GenerationConfig  GeminiGenerationConfig   `json:"generationConfig,omitempty"`
}

type GeminiResponsePayload struct {
	Candidates []struct {
		Content      GeminiContent `json:"content"`
		FinishReason string        `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
}


// NewGeminiClient initializes the client.
func NewGeminiClient(cfg config.LLMModelConfig, logger *zap.Logger) (*GeminiClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("Gemini API Key is required")
	}

	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", cfg.Model)
	}

	return &GeminiClient{
		apiKey:   cfg.APIKey,
		endpoint: endpoint,
		config:   cfg,
		httpClient: &http.Client{
			Timeout: cfg.APITimeout,
		},
		logger: logger.Named("llm_client.gemini"),
	}, nil
}


// GenerateResponse sends the prompts to the Gemini API and returns the generated content with retries.
func (c *GeminiClient) GenerateResponse(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	payload := c.buildRequestPayload(req)

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request payload: %w", err)
	}

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = 2 * time.Minute
	b.MaxInterval = 30 * time.Second

	var responseContent string

	operation := func() error {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewBuffer(body))
		if err != nil {
			return backoff.Permanent(fmt.Errorf("failed to create HTTP request: %w", err))
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("x-goog-api-key", c.apiKey)

		startTime := time.Now()
		resp, err := c.httpClient.Do(httpReq)
		duration := time.Since(startTime)

		if err != nil {
			c.logger.Warn("Network error during LLM request, retrying...", zap.Error(err))
			return fmt.Errorf("failed to execute HTTP request: %w", err)
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return c.handleAPIError(resp.StatusCode, respBody)
		}

		var responsePayload GeminiResponsePayload
		if err := json.Unmarshal(respBody, &responsePayload); err != nil {
			return backoff.Permanent(fmt.Errorf("failed to decode response payload: %w", err))
		}

		if len(responsePayload.Candidates) == 0 {
			return backoff.Permanent(fmt.Errorf("gemini API returned no candidates"))
		}

		candidate := responsePayload.Candidates[0]
		if len(candidate.Content.Parts) == 0 {
			if candidate.FinishReason == "SAFETY" || candidate.FinishReason == "BLOCKLIST" {
				return backoff.Permanent(fmt.Errorf("gemini API blocked the request (Reason: %s)", candidate.FinishReason))
			}
			return fmt.Errorf("gemini API returned empty content parts (Reason: %s)", candidate.FinishReason)
		}

		c.logger.Info("LLM generation complete (Gemini)",
			zap.Duration("duration", duration),
			zap.Int("prompt_tokens", responsePayload.UsageMetadata.PromptTokenCount),
			zap.Int("completion_tokens", responsePayload.UsageMetadata.CandidatesTokenCount),
			zap.Int("total_tokens", responsePayload.UsageMetadata.TotalTokenCount),
		)

		responseContent = candidate.Content.Parts[0].Text
		return nil
	}

	if err = backoff.Retry(operation, backoff.WithContext(b, ctx)); err != nil {
		return "", err
	}

	return responseContent, nil
}

func (c *GeminiClient) buildRequestPayload(req schemas.GenerationRequest) GeminiRequestPayload {
	genConfig := GeminiGenerationConfig{
		Temperature:     float64(req.Options.Temperature),
		TopP:            c.config.TopP,
		TopK:            c.config.TopK,
		MaxOutputTokens: c.config.MaxTokens,
	}

	if req.Options.ForceJSONFormat {
		genConfig.ResponseMimeType = "application/json"
	}

	payload := GeminiRequestPayload{
		Contents: []GeminiContent{
			{
				Role: "user",
				Parts: []GeminiPart{
					{Text: req.UserPrompt},
				},
			},
		},
		SystemInstruction: &GeminiSystemInstruction{
			Parts: []GeminiPart{
				{Text: req.SystemPrompt},
			},
		},
		GenerationConfig: genConfig,
		SafetySettings:   c.getSafetySettings(),
	}
	return payload
}

func (c *GeminiClient) handleAPIError(statusCode int, body []byte) error {
	c.logger.Error("Gemini API returned error status", zap.Int("status", statusCode), zap.String("response", string(body)))
	err := fmt.Errorf("gemini API error: status %d, body: %s", statusCode, string(body))

	switch statusCode {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusInternalServerError:
		return err // Transient errors, retry.
	default:
		return backoff.Permanent(err) // Permanent errors.
	}
}

func (c *GeminiClient) getSafetySettings() []GeminiSafetySetting {
	settings := make([]GeminiSafetySetting, 0, len(c.config.SafetyFilters))
	for category, threshold := range c.config.SafetyFilters {
		settings = append(settings, GeminiSafetySetting{
			Category:  category,
			Threshold: threshold,
		})
	}
	return settings
}
