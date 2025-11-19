package llmclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Test Setup Helpers --

// setupGeminiClient initializes a GoogleClient pointing at a mock HTTP server.
// Since the new SDK is REST based, we can use httptest.Server!
func setupGeminiClient(t *testing.T, handler http.HandlerFunc) (*GoogleClient, *httptest.Server, config.LLMModelConfig, *observer.ObservedLogs) {
	t.Helper()

	// Initialize mock server
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			t.Logf("Warning: Unexpected HTTP request in test: %s %s", r.Method, r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}
	server := httptest.NewServer(handler)

	// Initialize logger with observer
	loggerCore, observedLogs := observer.New(zap.InfoLevel)
	logger := zap.New(loggerCore)

	// Configuration
	cfg := getValidLLMConfig()
	cfg.APITimeout = 2 * time.Second
	// CRITICAL: Point the SDK to our mock server.
	cfg.Endpoint = server.URL

	// Initialize the client using our constructor.
	// This ensures the internal HTTP client logic inside NewGoogleClient is exercised.
	client, err := NewGoogleClient(context.Background(), cfg, logger)
	require.NoError(t, err, "NewGoogleClient initialization failed")

	t.Cleanup(server.Close)
	t.Cleanup(func() { client.Close() })

	return client, server, cfg, observedLogs
}

func createTestRequest() schemas.GenerationRequest {
	temp := 0.7
	return schemas.GenerationRequest{
		SystemPrompt: "System prompt instructions.",
		UserPrompt:   "User query.",
		Options: schemas.GenerationOptions{
			Temperature: &temp,
		},
	}
}

// -- Test Cases: Initialization --

func TestNewGoogleClient_Success(t *testing.T) {
	logger := setupTestLogger(t)
	cfg := getValidLLMConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := NewGoogleClient(ctx, cfg, logger)

	require.NoError(t, err)
	require.NotNil(t, client)
	defer client.Close()

	assert.NotNil(t, client.client, "SDK client should be initialized")
	assert.Equal(t, cfg.Model, client.config.Model)
}

func TestNewGoogleClient_Failure_MissingAPIKey(t *testing.T) {
	logger := setupTestLogger(t)
	cfg := getValidLLMConfig()
	cfg.APIKey = ""

	client, err := NewGoogleClient(context.Background(), cfg, logger)

	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "Google/Gemini API Key is required but not configured")
}

// -- Test Cases: Response Generation (Generate) --

func TestGenerate_Success(t *testing.T) {
	expectedResponseText := "This is the generated content."
	// Note: UsageMetadata in new SDK often uses larger ints or different field names in JSON.
	// We mock the JSON response expected by the new SDK.
	expectedPromptTokens := int64(100)
	expectedCompletionTokens := int64(50)
	testReq := createTestRequest()

	handler := func(w http.ResponseWriter, r *http.Request) {
		// 1. Verify Request
		assert.Equal(t, "POST", r.Method)
		// The new SDK constructs the URL: /v1beta/models/{model}:generateContent
		// NOTE: With APIVersion="v1", the path might be /v1/models/... but we check for "generateContent" presence.
		assert.Contains(t, r.URL.Path, "generateContent")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		// New SDK sends key in query param or header. Usually header x-goog-api-key.
		assert.NotEmpty(t, r.Header.Get("x-goog-api-key"))

		// 2. Verify Body
		body, _ := io.ReadAll(r.Body)
		// We can define a struct or map to verify incoming JSON.
		var payload map[string]interface{}
		err := json.Unmarshal(body, &payload)
		require.NoError(t, err)

		// Verify contents
		contents, ok := payload["contents"].([]interface{})
		require.True(t, ok)
		require.NotEmpty(t, contents)

		// Verify System Instruction
		sysInst, ok := payload["systemInstruction"].(map[string]interface{})
		require.True(t, ok)
		parts := sysInst["parts"].([]interface{})
		part := parts[0].(map[string]interface{})
		assert.Equal(t, testReq.SystemPrompt, part["text"])

		// 3. Send Success Response
		// The new SDK expects snake_case JSON or matching the JSON tags in genai structs.
		responseJSON := map[string]interface{}{
			"candidates": []map[string]interface{}{
				{
					"finishReason": "STOP",
					"content": map[string]interface{}{
						"parts": []map[string]interface{}{
							{"text": expectedResponseText},
						},
					},
				},
			},
			"usageMetadata": map[string]interface{}{
				"promptTokenCount":     expectedPromptTokens,
				"candidatesTokenCount": expectedCompletionTokens,
				"totalTokenCount":      expectedPromptTokens + expectedCompletionTokens,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responseJSON)
	}

	client, _, _, observedLogs := setupGeminiClient(t, handler)

	// Execute
	response, err := client.Generate(context.Background(), testReq)

	// Verification
	assert.NoError(t, err)
	assert.Equal(t, expectedResponseText, response)

	// Verify Logging
	require.Equal(t, 1, observedLogs.Len())
	logEntry := observedLogs.All()[0]
	assert.Equal(t, "LLM generation complete (Gemini)", logEntry.Message)
	assert.Equal(t, expectedPromptTokens, logEntry.ContextMap()["prompt_tokens"])
}

func TestGenerate_Success_JSONMode(t *testing.T) {
	req := createTestRequest()
	req.Options.ForceJSONFormat = true
	expectedResponseText := `{"status":"ok"}`

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		json.Unmarshal(body, &payload)

		// Verify Config Override
		genConfig, ok := payload["generationConfig"].(map[string]interface{})
		require.True(t, ok)

		// FIX: The API JSON key is "responseMimeType" (camelCase, lower 'ime'), not "responseMIMEType"
		assert.Equal(t, "application/json", genConfig["responseMimeType"])

		responseJSON := map[string]interface{}{
			"candidates": []map[string]interface{}{
				{
					"finishReason": "STOP",
					"content": map[string]interface{}{
						"parts": []map[string]interface{}{
							{"text": expectedResponseText},
						},
					},
				},
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responseJSON)
	}

	client, _, _, _ := setupGeminiClient(t, handler)

	response, err := client.Generate(context.Background(), req)
	assert.NoError(t, err)
	assert.Equal(t, expectedResponseText, response)
}

func TestGenerate_SDK_ErrorHandling(t *testing.T) {
	// Simulate a 400 Bad Request (Permanent Error)
	errorJSON := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    400,
			"message": "Invalid Argument",
			"status":  "INVALID_ARGUMENT",
		},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(errorJSON)
	}

	client, _, _, observedLogs := setupGeminiClient(t, handler)

	response, err := client.Generate(context.Background(), createTestRequest())

	assert.Error(t, err)
	assert.Empty(t, response)
	// The new SDK wraps errors well, we expect the message to bubble up
	assert.Contains(t, err.Error(), "Invalid Argument")
	assert.Equal(t, 1, observedLogs.FilterLevelExact(zap.ErrorLevel).Len())
}

func TestGenerate_Failure_PromptSafetyBlock(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		responseJSON := map[string]interface{}{
			"promptFeedback": map[string]interface{}{
				"blockReason": "SAFETY",
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responseJSON)
	}

	client, _, _, observedLogs := setupGeminiClient(t, handler)

	response, err := client.Generate(context.Background(), createTestRequest())

	assert.Error(t, err)
	assert.Empty(t, response)
	assert.Contains(t, err.Error(), "Gemini prompt blocked")
	assert.Equal(t, 1, observedLogs.FilterLevelExact(zap.WarnLevel).Len())
}

func TestGenerate_WithZeroTemperature(t *testing.T) {
	req := createTestRequest()
	zeroTemp := 0.0
	req.Options.Temperature = &zeroTemp

	handler := func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]interface{}
		json.Unmarshal(body, &payload)

		genConfig, ok := payload["generationConfig"].(map[string]interface{})
		require.True(t, ok, "generationConfig should be present in the payload")

		temp, ok := genConfig["temperature"].(float64)
		require.True(t, ok, "temperature should be present in generationConfig")
		assert.Equal(t, zeroTemp, temp, "temperature value should be 0")

		responseJSON := map[string]interface{}{"candidates": []map[string]interface{}{{"finishReason": "STOP", "content": map[string]interface{}{"parts": []map[string]interface{}{{"text": "ok"}}}}}}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responseJSON)
	}

	client, _, _, _ := setupGeminiClient(t, handler)

	_, err := client.Generate(context.Background(), req)
	assert.NoError(t, err)
}
