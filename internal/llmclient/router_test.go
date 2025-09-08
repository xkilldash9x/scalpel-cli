package llmclient

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
)

// -- Test Setup Helper --

// setupRouter creates a standard LLMRouter instance for testing, along with its mocks and a log observer.
func setupRouter(t *testing.T) (*LLMRouter, *MockLLMClient, *MockLLMClient, *observer.ObservedLogs) {
	t.Helper()
	// Set up logger with observer to inspect log outputs (e.g., routing decisions)
	loggerCore, observedLogs := observer.New(zap.DebugLevel)
	logger := zap.New(loggerCore)

	fastClient := &MockLLMClient{Name: "FastClient"}
	powerfulClient := &MockLLMClient{Name: "PowerfulClient"}

	router, err := NewLLMRouter(logger, fastClient, powerfulClient)
	require.NoError(t, err, "NewLLMRouter should initialize successfully")

	return router, fastClient, powerfulClient, observedLogs
}

// -- Test Cases: Initialization (NewLLMRouter) --

// Verifies successful initialization.
func TestNewLLMRouter_Success(t *testing.T) {
	router, fastClient, powerfulClient, _ := setupRouter(t)

	// Verification
	require.NotNil(t, router)

	// White box verification of internal map structure
	assert.Equal(t, fastClient, router.clients[schemas.TierFast])
	assert.Equal(t, powerfulClient, router.clients[schemas.TierPowerful])
}

// Verifies error handling when required clients are nil.
func TestNewLLMRouter_Failure_MissingClients(t *testing.T) {
	logger := setupTestLogger(t)
	validClient := new(MockLLMClient)
	expectedError := "both fast and powerful tier clients must be provided"

	tests := []struct {
		name       string
		fast       interfaces.LLMClient
		powerful   interfaces.LLMClient
	}{
		{"Missing Fast Client", nil, validClient},
		{"Missing Powerful Client", validClient, nil},
		{"Missing Both Clients", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, err := NewLLMRouter(logger, tt.fast, tt.powerful)
			assert.Error(t, err)
			assert.Nil(t, router)
			assert.Contains(t, err.Error(), expectedError)
		})
	}
}

// -- Test Cases: Routing Logic (GenerateResponse) --

// Verifies requests are routed to the fast client.
func TestGenerateResponse_Routing_TierFast(t *testing.T) {
	router, fastClient, powerfulClient, observedLogs := setupRouter(t)
	ctx := context.Background()
	req := schemas.GenerationRequest{
		Tier:       schemas.TierFast,
		UserPrompt: "test fast prompt",
	}
	expectedResponse := "response from fast client"

	// Mock expectation: The fast client must be called with the exact request.
	fastClient.On("GenerateResponse", ctx, req).Return(expectedResponse, nil).Once()

	// Execute
	response, err := router.GenerateResponse(ctx, req)

	// Verification
	assert.NoError(t, err)
	assert.Equal(t, expectedResponse, response)
	fastClient.AssertExpectations(t)
	// Ensure the powerful client was NOT involved
	powerfulClient.AssertNotCalled(t, "GenerateResponse", mock.Anything, mock.Anything)

	// Verify logging details
	require.Equal(t, 1, observedLogs.Len(), "Expected one log entry for routing")
	logEntry := observedLogs.All()[0]
	assert.Equal(t, "Routing LLM request", logEntry.Message)
	assert.Equal(t, string(schemas.TierFast), logEntry.ContextMap()["tier"])
}

// Verifies requests are routed to the powerful client.
func TestGenerateResponse_Routing_TierPowerful(t *testing.T) {
	router, fastClient, powerfulClient, _ := setupRouter(t)
	ctx := context.Background()
	req := schemas.GenerationRequest{
		Tier:       schemas.TierPowerful,
		UserPrompt: "test powerful prompt",
	}
	expectedResponse := "response from powerful client"

	// Mock expectation
	powerfulClient.On("GenerateResponse", ctx, req).Return(expectedResponse, nil).Once()

	// Execute
	response, err := router.GenerateResponse(ctx, req)

	// Verification
	assert.NoError(t, err)
	assert.Equal(t, expectedResponse, response)
	powerfulClient.AssertExpectations(t)
	fastClient.AssertNotCalled(t, "GenerateResponse", mock.Anything, mock.Anything)
}

// Verifies requests with an empty tier default to powerful.
func TestGenerateResponse_Routing_Default(t *testing.T) {
	router, fastClient, powerfulClient, observedLogs := setupRouter(t)
	ctx := context.Background()
	// Request with empty Tier
	req := schemas.GenerationRequest{
		Tier:       "",
		UserPrompt: "test default prompt",
	}
	expectedResponse := "response from default (powerful) client"

	// Mock expectation: Powerful client handles the default case.
	// Crucially, the router implementation passes the original request object (req) to the client,
	// the tier is only determined locally for routing and logging.
	powerfulClient.On("GenerateResponse", ctx, req).Return(expectedResponse, nil).Once()

	// Execute
	response, err := router.GenerateResponse(ctx, req)

	// Verification
	assert.NoError(t, err)
	assert.Equal(t, expectedResponse, response)
	powerfulClient.AssertExpectations(t)
	fastClient.AssertNotCalled(t, "GenerateResponse", mock.Anything, mock.Anything)

	// Verify logging reflects the defaulted tier used for routing
	logEntry := observedLogs.All()[0]
	assert.Equal(t, string(schemas.TierPowerful), logEntry.ContextMap()["tier"])
}

// Verifies that errors from the underlying client are returned.
func TestGenerateResponse_Error_Propagation(t *testing.T) {
	router, fastClient, _, _ := setupRouter(t)
	ctx := context.Background()
	req := schemas.GenerationRequest{Tier: schemas.TierFast}
	expectedError := errors.New("underlying client API failure")

	// Mock failure
	fastClient.On("GenerateResponse", ctx, req).Return("", expectedError).Once()

	// Execute
	response, err := router.GenerateResponse(ctx, req)

	// Verification
	assert.Error(t, err)
	assert.Equal(t, "", response)
	assert.ErrorIs(t, err, expectedError, "The exact error from the client should be propagated")
}

// Verifies behavior when an unknown tier is requested.
func TestGenerateResponse_Error_InvalidTier(t *testing.T) {
	router, fastClient, powerfulClient, _ := setupRouter(t)
	ctx := context.Background()
	invalidTier := schemas.ModelTier("invalid-tier-xyz")
	req := schemas.GenerationRequest{Tier: invalidTier}

	// Execute
	response, err := router.GenerateResponse(ctx, req)

	// Verification
	assert.Error(t, err)
	assert.Equal(t, "", response)
	assert.Contains(t, err.Error(), "no LLM client configured for tier: invalid-tier-xyz")

	// Ensure no clients were called
	fastClient.AssertNotCalled(t, "GenerateResponse", mock.Anything, mock.Anything)
	powerfulClient.AssertNotCalled(t, "GenerateResponse", mock.Anything, mock.Anything)
}
