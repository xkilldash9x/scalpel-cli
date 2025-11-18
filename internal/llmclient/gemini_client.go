package llmclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/genai"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// GoogleClient implements the schemas.LLMClient interface for Google Gemini APIs
// using the unified SDK (google.golang.org/genai).
type GoogleClient struct {
	client *genai.Client
	logger *zap.Logger
	config config.LLMModelConfig
}

// Ensures GoogleClient implements the LLMClient interface.
var _ schemas.LLMClient = (*GoogleClient)(nil)

// endpointTransport is a custom RoundTripper that rewrites the request URL
// to point to a specific endpoint (e.g., a mock server for testing) while
// preserving the original path and body.
type endpointTransport struct {
	transport http.RoundTripper
	endpoint  string
}

// RoundTrip executes a single HTTP transaction, overriding the destination.
func (t *endpointTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.endpoint == "" {
		return t.transport.RoundTrip(req)
	}

	targetURL, err := url.Parse(t.endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL: %w", err)
	}

	// Clone the request to avoid modifying the original shared state.
	newReq := req.Clone(req.Context())
	newReq.URL.Scheme = targetURL.Scheme
	newReq.URL.Host = targetURL.Host

	// We return the response from the underlying transport (usually http.DefaultTransport)
	// but with the modified request pointing to our custom endpoint.
	return t.transport.RoundTrip(newReq)
}

// NewGoogleClient initializes the client for the Gemini API using the new unified Go SDK.
func NewGoogleClient(ctx context.Context, cfg config.LLMModelConfig, logger *zap.Logger) (*GoogleClient, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("Google/Gemini API Key is required but not configured")
	}

	namedLogger := logger.Named("llm_client.google_sdk")

	// Configure the client.
	// FIX: Use "v1beta" to support system instructions and responseSchema (JSON mode).
	// "v1" does not yet support these fields in the format sent by the SDK, leading to 400 errors.
	clientCfg := &genai.ClientConfig{
		APIKey:  cfg.APIKey,
		Backend: genai.BackendGeminiAPI, // Explicitly select the Gemini backend (optional but good practice)
		HTTPOptions: genai.HTTPOptions{
			APIVersion: "v1beta",
		},
	}

	// Handle custom endpoints (e.g., for testing or Vertex AI proxies).
	// Since ClientConfig might not expose a BaseURL field in this version,
	// we use a custom HTTPClient with a Transport that rewrites the host.
	if cfg.Endpoint != "" {
		namedLogger.Debug("Configuring custom endpoint via HTTP Client Transport", zap.String("endpoint", cfg.Endpoint))

		clientCfg.HTTPClient = &http.Client{
			// Use the custom transport to route requests to the configured endpoint.
			Transport: &endpointTransport{
				transport: http.DefaultTransport,
				endpoint:  cfg.Endpoint,
			},
			// Inherit the timeout from the config if desirable, though the SDK
			// often handles timeouts via Context.
			Timeout: cfg.APITimeout,
		}
	}

	// Initialize the client.
	client, err := genai.NewClient(ctx, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Google AI client: %w", err)
	}

	gc := &GoogleClient{
		client: client,
		config: cfg,
		logger: namedLogger,
	}

	return gc, nil
}

// Generate sends a structured request to the Gemini API using the SDK and returns the generated content.
func (c *GoogleClient) Generate(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	// Enforce an overall timeout using the context if configured.
	if c.config.APITimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.APITimeout)
		defer cancel()
	}

	// build the generation config (Temperature, TopP, etc.)
	genConfig := c.buildGenerationConfig(req)

	// Prepare the content payload.
	// The new SDK expects a list of *genai.Content.
	contents := []*genai.Content{
		{
			Role: "user",
			Parts: []*genai.Part{
				{Text: req.UserPrompt},
			},
		},
	}

	// Prepare the system instruction if present.
	if req.SystemPrompt != "" {
		genConfig.SystemInstruction = &genai.Content{
			Parts: []*genai.Part{
				{Text: req.SystemPrompt},
			},
		}
	}

	// Apply safety settings.
	genConfig.SafetySettings = c.getSafetySettings()

	startTime := time.Now()

	// Execute the request.
	// API Signature: client.Models.GenerateContent(ctx, modelName, contents, config)
	resp, err := c.client.Models.GenerateContent(ctx, c.config.Model, contents, genConfig)
	duration := time.Since(startTime)

	if err != nil {
		c.logger.Error("Gemini API generation failed", zap.Error(err), zap.Duration("duration", duration))
		return "", fmt.Errorf("failed to generate content via Gemini API: %w", err)
	}

	return c.processResponse(resp, duration)
}

// buildGenerationConfig creates the generation configuration struct.
func (c *GoogleClient) buildGenerationConfig(req schemas.GenerationRequest) *genai.GenerateContentConfig {
	// Initialize with nil to allow the SDK/API defaults to take over if we don't set them.
	cfg := &genai.GenerateContentConfig{}

	// --- Apply Defaults from Config ---
	// Note: The SDK uses *float32 for temperature/topP and *int32 (or int32) for tokens.
	// We must cast explicitly.

	if c.config.Temperature > 0 {
		t := float32(c.config.Temperature)
		cfg.Temperature = &t
	}
	if c.config.TopP > 0 {
		p := float32(c.config.TopP)
		cfg.TopP = &p
	}
	if c.config.TopK > 0 {
		// Error indicated target is *float32 (unusual for TopK, but following compiler error).
		k := float32(c.config.TopK)
		cfg.TopK = &k
	}
	if c.config.MaxTokens > 0 {
		// Error "cannot use &m (value of type *int64) as int32 value" implies the field is int32 (not pointer).
		// If the SDK changes to *int32 later, this will need &m.
		m := int32(c.config.MaxTokens)
		cfg.MaxOutputTokens = m
	}

	// --- Apply Request Overrides ---

	// Override temperature if specified in the request options.
	requestTemp := req.Options.Temperature
	if requestTemp >= 0 {
		t := float32(requestTemp)
		cfg.Temperature = &t
	}

	// Force JSON format.
	if req.Options.ForceJSONFormat {
		cfg.ResponseMIMEType = "application/json"
	}

	return cfg
}

// processResponse handles the response from the SDK.
func (c *GoogleClient) processResponse(resp *genai.GenerateContentResponse, duration time.Duration) (string, error) {
	if resp == nil {
		return "", fmt.Errorf("received nil response from Gemini API")
	}

	// Log usage metadata if available.
	// Fields are int32, so we cast to int64 for Zap compatibility.
	if resp.UsageMetadata != nil {
		c.logger.Info("LLM generation complete (Gemini)",
			zap.Duration("duration", duration),
			zap.String("model", c.config.Model),
			zap.Int64("prompt_tokens", int64(resp.UsageMetadata.PromptTokenCount)),
			zap.Int64("completion_tokens", int64(resp.UsageMetadata.CandidatesTokenCount)),
			zap.Int64("total_tokens", int64(resp.UsageMetadata.TotalTokenCount)),
		)
	}

	// Check for prompt feedback (blocking).
	if resp.PromptFeedback != nil && resp.PromptFeedback.BlockReason != "" {
		c.logger.Warn("Gemini prompt blocked",
			zap.String("reason", string(resp.PromptFeedback.BlockReason)),
		)
		return "", fmt.Errorf("Gemini prompt blocked (Reason: %s)", resp.PromptFeedback.BlockReason)
	}

	if len(resp.Candidates) == 0 {
		return "", fmt.Errorf("Gemini API returned no candidates")
	}

	candidate := resp.Candidates[0]

	// Check finish reason.
	if candidate.FinishReason != "" && candidate.FinishReason != "STOP" {
		c.logger.Warn("Gemini generation finished unexpectedly",
			zap.String("reason", string(candidate.FinishReason)),
		)
		if candidate.FinishReason == "SAFETY" {
			return "", fmt.Errorf("Gemini response blocked due to SAFETY reasons")
		}
	}

	return extractResponseText(candidate), nil
}

// extractResponseText combines the text parts from a candidate.
func extractResponseText(cand *genai.Candidate) string {
	if cand.Content == nil {
		return ""
	}
	var builder strings.Builder
	for _, part := range cand.Content.Parts {
		if part.Text != "" {
			builder.WriteString(part.Text)
		}
	}
	return builder.String()
}

// Mappings for Safety Settings.
var harmCategoryMap = map[string]string{
	"HARM_CATEGORY_HARASSMENT":        "HARM_CATEGORY_HARASSMENT",
	"HARM_CATEGORY_HATE_SPEECH":       "HARM_CATEGORY_HATE_SPEECH",
	"HARM_CATEGORY_SEXUALLY_EXPLICIT": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
	"HARM_CATEGORY_DANGEROUS_CONTENT": "HARM_CATEGORY_DANGEROUS_CONTENT",
	"HARM_CATEGORY_CIVIC_INTEGRITY":   "HARM_CATEGORY_CIVIC_INTEGRITY",
}

// blockThresholdMap defines the mappings from config strings to SDK constants.
var blockThresholdMap = map[string]string{
	"BLOCK_LOW_AND_ABOVE":              "BLOCK_LOW_AND_ABOVE",
	"BLOCK_MEDIUM_AND_ABOVE":           "BLOCK_MEDIUM_AND_ABOVE",
	"BLOCK_ONLY_HIGH":                  "BLOCK_ONLY_HIGH",
	"BLOCK_NONE":                       "BLOCK_NONE",
	"HARM_BLOCK_THRESHOLD_UNSPECIFIED": "HARM_BLOCK_THRESHOLD_UNSPECIFIED",
}

func (c *GoogleClient) getSafetySettings() []*genai.SafetySetting {
	settings := make([]*genai.SafetySetting, 0, len(c.config.SafetyFilters))

	for categoryStr, thresholdStr := range c.config.SafetyFilters {
		category, ok := harmCategoryMap[categoryStr]
		if !ok {
			category = categoryStr
		}

		threshold, ok := blockThresholdMap[thresholdStr]
		if !ok {
			c.logger.Warn("Unknown safety threshold in config, using default (UNSPECIFIED)", zap.String("threshold", thresholdStr))
			threshold = "HARM_BLOCK_THRESHOLD_UNSPECIFIED"
		}

		// Explicit casting to SDK types is required here.
		settings = append(settings, &genai.SafetySetting{
			Category:  genai.HarmCategory(category),
			Threshold: genai.HarmBlockThreshold(threshold),
		})
	}
	return settings
}

// Close cleans up the underlying client resources.
func (c *GoogleClient) Close() error {
	return nil
}
