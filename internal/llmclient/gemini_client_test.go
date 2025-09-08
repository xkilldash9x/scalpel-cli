package llmclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Test Setup Helpers --

// setupGeminiClient rigs up a GeminiClient pointed at a mock HTTP server for our testing pleasure.
// It returns the client, the mock server, the configuration used, and a log observer.
func setupGeminiClient(t *testing.T, handler http.HandlerFunc) (*GeminiClient, *httptest.Server, config.LLMModelConfig, *observer.ObservedLogs) {
	t.Helper()
	// Initialize mock server
	if handler == nil {
		// Default handler for tests that don't require HTTP interactions
		handler = func(w http.ResponseWriter, r *http.Request) {
			t.Log("Warning: Unexpected HTTP request in test.")
			w.WriteHeader(http.StatusNotFound)
		}
	}
	server := httptest.NewServer(handler)

	// Initialize logger with observer to capture Info/Error/Warn level logs
	loggerCore, observedLogs := observer.New(zap.InfoLevel)
	logger := zap.New(loggerCore)

	// Configuration pointing to the mock server
	cfg := getValidLLMConfig()
	cfg.Endpoint = server.URL

	client, err := NewGeminiClient(cfg, logger)
	require.NoError(t, err, "NewGeminiClient initialization failed")

	// Ensure tests fail fast on unexpected hangs
	client.httpClient.Timeout = 5 * time.Second

	t.Cleanup(server.Close)
	return client, server, cfg, observedLogs
}

// createTestRequest provides a standard generation request structure.
func createTestRequest() schemas.GenerationRequest {
	return schemas.GenerationRequest{
		SystemPrompt: "System prompt instructions.",
		UserPrompt:   "User query.",
		Options: schemas.GenerationOptions{
			Temperature: 0.7,
		},
	}
}

// -- Test Cases: Initialization (NewGeminiClient) --

// Verifies successful initialization and default endpoint configuration.
func TestNewGeminiClient_Success(t *testing.T) {
	logger := setupTestLogger(t)
	cfg := getValidLLMConfig()
	// Ensure endpoint is empty to test the default assignment logic
	cfg.Endpoint = ""

	client, err := NewGeminiClient(cfg, logger)

	// Verification
	require.NoError(t, err)
	require.NotNil(t, client)

	// White box verification of internal state
	assert.Equal(t, cfg.APIKey, client.apiKey)
	assert.Equal(t, cfg.APITimeout, client.httpClient.Timeout)
	// Verify the default endpoint format
	expectedEndpoint := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", cfg.Model)
	assert.Equal(t, expectedEndpoint, client.endpoint)
}

// Verifies the requirement for an API key.
func TestNewGeminiClient_Failure_MissingAPIKey(t *testing.T) {
	logger := setupTestLogger(t)
	cfg := getValidLLMConfig()
	cfg.APIKey = ""

	client, err := NewGeminiClient(cfg, logger)

	// Verification
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "Gemini API Key is required")
}

// -- Test Cases: Request Payload Generation (buildRequestPayload) --
// White box testing. We're going straight for the unexported goods to check the payload generation.

// Verifies the structure and content of the generated payload.
func TestBuildRequestPayload_Standard(t *testing.T) {
	// Setup client with specific configuration to test parameter mapping
	client, _, _, _ := setupGeminiClient(t, nil)

	// Modify client config for this specific test
	client.config.TopP = 0.9
	client.config.TopK = 50
	client.config.MaxTokens = 2048
	client.config.SafetyFilters = map[string]string{"CAT_A": "BLOCK_LOW", "CAT_B": "BLOCK_HIGH"}

	req := createTestRequest()
	req.Options.Temperature = 0.5 // Specific temperature override

	// Execute
	payload := client.buildRequestPayload(req)

	// Verification: Structure
	require.NotNil(t, payload.SystemInstruction)
	require.Len(t, payload.Contents, 1)

	// Verification: Content
	assert.Equal(t, req.SystemPrompt, payload.SystemInstruction.Parts[0].Text)
	assert.Equal(t, "user", payload.Contents[0].Role)
	assert.Equal(t, req.UserPrompt, payload.Contents[0].Parts[0].Text)

	// Verification: Generation Config Mapping
	assert.Equal(t, 0.5, payload.GenerationConfig.Temperature)
	assert.Equal(t, float32(0.9), payload.GenerationConfig.TopP)
	assert.Equal(t, 50, payload.GenerationConfig.TopK)
	assert.Equal(t, 2048, payload.GenerationConfig.MaxOutputTokens)
	assert.Empty(t, payload.GenerationConfig.ResponseMimeType)

	// Verification: Safety Settings (order independent check)
	require.Len(t, payload.SafetySettings, 2)
	actualSafety := make(map[string]string)
	for _, setting := range payload.SafetySettings {
		actualSafety[setting.Category] = setting.Threshold
	}
	assert.Equal(t, client.config.SafetyFilters, actualSafety)
}

// Verifies the ResponseMimeType is set correctly when requested.
func TestBuildRequestPayload_ForceJSON(t *testing.T) {
	client, _, _, _ := setupGeminiClient(t, nil)

	req := createTestRequest()
	req.Options.ForceJSONFormat = true

	// Execute
	payload := client.buildRequestPayload(req)

	// Verification
	assert.Equal(t, "application/json", payload.GenerationConfig.ResponseMimeType)
}

// -- Test Cases: Response Generation (GenerateResponse) - Success Scenarios --

// Verifies a standard successful API call, including request validation, response parsing, and logging.
func TestGenerateResponse_Success(t *testing.T) {
	expectedResponseText := "This is the generated content."
	expectedPromptTokens := 100
	expectedCompletionTokens := 50

	// Define the mock server handler
	handler := func(w http.ResponseWriter, r *http.Request) {
		// 1. Verify Request Integrity
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		// Verify Authentication
		assert.Equal(t, TestAPIKey, r.Header.Get("x-goog-api-key"))

		// 2. Verify Request Body Structure
		body, _ := io.ReadAll(r.Body)
		var payload GeminiRequestPayload
		err := json.Unmarshal(body, &payload)
		require.NoError(t, err, "Server received invalid JSON payload")
		assert.Equal(t, createTestRequest().UserPrompt, payload.Contents[0].Parts[0].Text)

		// 3. Send Mock Success Response
		responsePayload := GeminiResponsePayload{
			Candidates: []struct {
				Content      GeminiContent `json:"content"`
				FinishReason string        `json:"finishReason"`
			}{
				{
					Content: GeminiContent{
						Parts: []GeminiPart{{Text: expectedResponseText}},
					},
					FinishReason: "STOP",
				},
			},
			UsageMetadata: struct {
				PromptTokenCount     int `json:"promptTokenCount"`
				CandidatesTokenCount int `json:"candidatesTokenCount"`
				TotalTokenCount      int `json:"totalTokenCount"`
			}{
				PromptTokenCount:     expectedPromptTokens,
				CandidatesTokenCount: expectedCompletionTokens,
				TotalTokenCount:      expectedPromptTokens + expectedCompletionTokens,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responsePayload)
	}

	client, _, _, observedLogs := setupGeminiClient(t, handler)
	req := createTestRequest()

	// Execute
	response, err := client.GenerateResponse(context.Background(), req)

	// Verification
	assert.NoError(t, err)
	assert.Equal(t, expectedResponseText, response)

	// Verify Logging Details (Token usage and duration)
	require.Equal(t, 1, observedLogs.Len(), "Expected one log entry for successful generation")
	logEntry := observedLogs.All()[0]
	assert.Equal(t, "LLM generation complete (Gemini)", logEntry.Message)
	assert.Equal(t, int64(expectedPromptTokens), logEntry.ContextMap()["prompt_tokens"])
	assert.Equal(t, int64(expectedCompletionTokens), logEntry.ContextMap()["completion_tokens"])
	assert.NotNil(t, logEntry.ContextMap()["duration"])
}

// -- Test Cases: Response Generation (GenerateResponse) - Error Handling & Retries --
// because networks are flaky

// Verifies the exponential backoff mechanism works for transient API errors (5xx).
func TestGenerateResponse_RetryOnTransientErrors(t *testing.T) {
	var attemptCounter int32
	expectedAttempts := 3

	handler := func(w http.ResponseWriter, r *http.Request) {
		attempt := atomic.AddInt32(&attemptCounter, 1)

		if int(attempt) < expectedAttempts {
			// Simulate a transient error (e.g., 503 Service Unavailable)
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Service temporarily unavailable."))
		} else {
			// Success on the final attempt
			responsePayload := GeminiResponsePayload{
				Candidates: []struct {
					Content      GeminiContent `json:"content"`
					FinishReason string        `json:"finishReason"`
				}{
					{Content: GeminiContent{Parts: []GeminiPart{{Text: "Success after retry"}}}},
				},
			}
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(responsePayload)
		}
	}

	client, _, _, observedLogs := setupGeminiClient(t, handler)
	req := createTestRequest()

	// Execute
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := client.GenerateResponse(ctx, req)

	// Verification
	assert.NoError(t, err)
	assert.Equal(t, "Success after retry", response)
	assert.Equal(t, int32(expectedAttempts), atomic.LoadInt32(&attemptCounter), "The request should have been retried the expected number of times")

	// Verify Error logging occurred during retries
	errorLogs := observedLogs.FilterLevelExact(zap.ErrorLevel)
	assert.Equal(t, expectedAttempts-1, errorLogs.Len(), "Expected ERROR logs for the failed attempts")
}

// Verifies that network level errors are retried and logged as warnings.
func TestGenerateResponse_RetryOnNetworkError(t *testing.T) {
	// Setup the client first.
	client, server, _, observedLogs := setupGeminiClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler reached despite server being closed.")
	})

	// Immediately close the server to simulate a network error (connection refused).
	server.Close()

	// Execute with a short timeout to ensure the test finishes quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, err := client.GenerateResponse(ctx, createTestRequest())

	// Verification
	assert.Error(t, err)

	// Network errors must be recognized as transient (not PermanentError).
	var permanentErr *backoff.PermanentError
	assert.False(t, errors.As(err, &permanentErr), "Network errors should be treated as transient and retried")

	// Verify Warning logs for network errors during retries
	warnLogs := observedLogs.FilterLevelExact(zap.WarnLevel)
	assert.Greater(t, warnLogs.Len(), 0, "Expected WARN logs for network errors")
	assert.Contains(t, warnLogs.All()[0].Message, "Network error during LLM request, retrying...")
}

// Verifies that permanent errors (e.g., 400/403) fail immediately.
func TestGenerateResponse_NoRetryOnPermanentErrors(t *testing.T) {
	var attemptCounter int32
	errorBody := "API Key Invalid"

	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attemptCounter, 1)
		// Simulate a permanent error (e.g., Invalid API Key - often 403 or 400)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(errorBody))
	}

	client, _, _, observedLogs := setupGeminiClient(t, handler)
	req := createTestRequest()

	// Execute
	response, err := client.GenerateResponse(context.Background(), req)

	// Verification
	assert.Error(t, err)
	assert.Empty(t, response)
	assert.Contains(t, err.Error(), "gemini API error: status 403")

	// Crucially, verify only one attempt was made (backoff.Permanent was used)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attemptCounter), "Permanent errors must not trigger retries")

	// Verify it is wrapped as a permanent error
	var permanentErr *backoff.PermanentError
	assert.ErrorAs(t, err, &permanentErr)

	// Verify Error Logging
	errorLogs := observedLogs.FilterLevelExact(zap.ErrorLevel)
	require.Equal(t, 1, errorLogs.Len())
	logEntry := errorLogs.All()[0]
	assert.Equal(t, "Gemini API returned error status", logEntry.Message)
	assert.Equal(t, int64(403), logEntry.ContextMap()["status"])
	assert.Contains(t, logEntry.ContextMap()["response"], errorBody)
}

// Verifies handling of responses blocked by safety filters (Permanent Error).
func TestGenerateResponse_Failure_SafetyBlock(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Simulate a response where generation finished due to safety reasons (HTTP 200, but FinishReason=SAFETY).
		responsePayload := GeminiResponsePayload{
			Candidates: []struct {
				Content      GeminiContent `json:"content"`
				FinishReason string        `json:"finishReason"`
			}{
				{
					Content:      GeminiContent{Parts: []GeminiPart{}},
					FinishReason: "SAFETY",
				},
			},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responsePayload)
	}

	client, _, _, _ := setupGeminiClient(t, handler)
	req := createTestRequest()

	// Execute
	response, err := client.GenerateResponse(context.Background(), req)

	// Verification
	assert.Error(t, err)
	assert.Empty(t, response)
	assert.Contains(t, err.Error(), "gemini API blocked the request (Reason: SAFETY)")
	// Verify it is treated as a permanent error
	var permanentErr *backoff.PermanentError
	assert.ErrorAs(t, err, &permanentErr)
}

// Verifies handling of empty content for non blocking reasons (Transient Error).
func TestGenerateResponse_Failure_EmptyContent_NonBlockReason(t *testing.T) {
	var attemptCounter int32
	// Simulate empty content but a non-blocking reason (e.g., OTHER or MAX_TOKENS)
	responsePayload := GeminiResponsePayload{
		Candidates: []struct {
			Content      GeminiContent `json:"content"`
			FinishReason string        `json:"finishReason"`
		}{{Content: GeminiContent{Parts: []GeminiPart{}}, FinishReason: "OTHER"}},
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attemptCounter, 1)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responsePayload)
	}

	client, _, _, _ := setupGeminiClient(t, handler)

	// Execute with a short timeout to limit the retries during the test.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err := client.GenerateResponse(ctx, createTestRequest())

	// Verification
	assert.Error(t, err)

	// This specific scenario is treated as transient (retryable) by the implementation.
	var permanentErr *backoff.PermanentError
	assert.False(t, errors.As(err, &permanentErr), "Empty content with non-blocking reason should be transient")

	// Verify that retries occurred.
	assert.Greater(t, atomic.LoadInt32(&attemptCounter), int32(1))
}

// Verifies robustness against empty response lists (Permanent Error).
func TestGenerateResponse_Failure_NoCandidates(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Simulate a valid JSON response with an empty candidates array.
		responsePayload := GeminiResponsePayload{
			Candidates: []struct {
				Content      GeminiContent `json:"content"`
				FinishReason string        `json:"finishReason"`
			}{},
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(responsePayload)
	}

	client, _, _, _ := setupGeminiClient(t, handler)
	req := createTestRequest()

	// Execute
	response, err := client.GenerateResponse(context.Background(), req)

	// Verification
	assert.Error(t, err)
	assert.Empty(t, response)
	assert.Contains(t, err.Error(), "gemini API returned no candidates")
	// Verify it is treated as a permanent error
	var permanentErr *backoff.PermanentError
	assert.ErrorAs(t, err, &permanentErr)
}

// Verifies handling of corrupted API responses (Permanent Error).
func TestGenerateResponse_Failure_InvalidJSONResponse(t *testing.T) {
	var attemptCounter int32
	handler := func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attemptCounter, 1)
		w.WriteHeader(http.StatusOK)
		// Send corrupted JSON
		w.Write([]byte("{invalid json:"))
	}

	client, _, _, _ := setupGeminiClient(t, handler)
	req := createTestRequest()

	// Execute
	response, err := client.GenerateResponse(context.Background(), req)

	// Verification
	assert.Error(t, err)
	assert.Empty(t, response)
	assert.Contains(t, err.Error(), "failed to decode response payload")
	// JSON decoding errors should be treated as permanent failures (no retry)
	assert.Equal(t, int32(1), atomic.LoadInt32(&attemptCounter))
	var permanentErr *backoff.PermanentError
	assert.ErrorAs(t, err, &permanentErr)
}

// Verifies that the operation respects context cancellation during backoff waits.
func TestGenerateResponse_ContextCancellation(t *testing.T) {
	// Handler that always returns a transient error, forcing continuous retries.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests) // Transient error
	}

	client, _, _, _ := setupGeminiClient(t, handler)
	req := createTestRequest()

	// Create a context and cancel it almost immediately
	ctx, cancel := context.WithCancel(context.Background())
	// Allow a brief moment for the first request to potentially start before cancelling
	time.AfterFunc(20*time.Millisecond, cancel)

	// Execute
	startTime := time.Now()
	response, err := client.GenerateResponse(ctx, req)
	duration := time.Since(startTime)

	// Verification
	assert.Error(t, err)
	assert.Empty(t, response)
	// The error must indicate the context was cancelled (propagated by HTTP client or backoff library)
	assert.True(t, errors.Is(err, context.Canceled), "Error should be context.Canceled, but got: %v", err)
	// Ensure the operation aborted quickly
	assert.Less(t, duration, 1*time.Second, "Operation should abort quickly upon cancellation")
}
