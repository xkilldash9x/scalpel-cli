package protopollution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	// Assuming these imports based on the provided context
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
)

// -- Mock Definitions --
// Comprehensive mocks for isolating the Analyzer logic from browser dependencies.
// Adheres to the standard of robust mocks capable of simulating asynchronous callbacks.

// MockSessionManager mocks the browser.SessionManager interface.
type MockSessionManager struct {
	mock.Mock
}

func (m *MockSessionManager) InitializeSession(ctx context.Context) (browser.SessionContext, error) {
	args := m.Called(ctx)
	// Robustness: Handle nil session return for error scenarios, as required by the standard.
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(browser.SessionContext), args.Error(1)
}

// MockSessionContext mocks the browser.SessionContext interface (a browser tab).
type MockSessionContext struct {
	mock.Mock
	// Stores exposed Go functions to simulate callbacks from the browser (JS Shim -> Go).
	exposedFunctions map[string]interface{}
	mutex            sync.Mutex
}

func NewMockSessionContext() *MockSessionContext {
	return &MockSessionContext{
		exposedFunctions: make(map[string]interface{}),
	}
}

// Stores the function provided by the analyzer for later simulation.
// The signature matches the usage in the analyzer (no context parameter).
func (m *MockSessionContext) ExposeFunction(name string, function interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	args := m.Called(name, function)
	// Store the function only if exposure succeeded
	if args.Error(0) == nil {
		m.exposedFunctions[name] = function
	}
	return args.Error(0)
}

// Allows tests to invoke the exposed Go functions, just like the JS shim would.
// This is crucial for testing the asynchronous communication path.
func (m *MockSessionContext) SimulateCallback(t *testing.T, name string, payload interface{}) {
	t.Helper()
	m.mutex.Lock()
	fn, exists := m.exposedFunctions[name]
	m.mutex.Unlock()

	if !exists {
		t.Fatalf("function %s not exposed by analyzer", name)
	}

	// Use type assertion based on the expected callback signature (handlePollutionProof).
	// This ensures the contract between Go and JS is maintained.
	switch name {
	case jsCallbackName:
		callback, ok := fn.(func(PollutionProofEvent))
		require.True(t, ok, "PollutionProofEvent callback signature mismatch. Got: %T", fn)
		event, ok := payload.(PollutionProofEvent)
		require.True(t, ok, "PollutionProofEvent payload type mismatch. Got: %T", payload)
		// Execute the callback asynchronously to mimic real browser behavior and avoid deadlocks.
		go callback(event)

	default:
		t.Fatalf("Unknown callback name simulated: %s", name)
	}
}

// Standard SessionContext methods (mocks based on analyzer usage)
func (m *MockSessionContext) InjectScriptPersistently(script string) error {
	args := m.Called(script)
	return args.Error(0)
}

func (m *MockSessionContext) Navigate(url string) error {
	args := m.Called(url)
	return args.Error(0)
}

// The signature matches the usage in the analyzer (includes context parameter).
func (m *MockSessionContext) Close(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// -- Test Setup Helper --

// Creates a standard Analyzer instance for testing, complete with its mocks.
// It allows customization of the configuration for optimized testing.
func setupAnalyzer(t *testing.T, configMod func(*Config)) (*Analyzer, *MockSessionManager) {
	t.Helper()
	logger := zaptest.NewLogger(t)

	// Default configuration optimized for testing speed
	config := Config{
		// Set a very short duration for the monitoring phase in tests.
		WaitDuration: 50 * time.Millisecond,
	}

	// Apply custom modifications
	if configMod != nil {
		configMod(&config)
	}

	mockBrowserManager := new(MockSessionManager)

	// We are in the same package (protopollution), allowing white box testing.
	// Using the refactored NewAnalyzer signature.
	analyzer := NewAnalyzer(logger, mockBrowserManager, &config)
	require.NotNil(t, analyzer, "NewAnalyzer should return a valid analyzer")

	return analyzer, mockBrowserManager
}

// -- Test Cases: Initialization and Configuration --

// Verifies that the analyzer correctly sets default values if a nil config is provided.
func TestNewAnalyzer_Defaults(t *testing.T) {
	logger := zaptest.NewLogger(t)
	// Provide nil config to test defaults
	analyzer := NewAnalyzer(logger, nil, nil)
	require.NotNil(t, analyzer)

	// Verify defaults (white box access to unexported 'config' field)
	assert.Equal(t, defaultWaitDuration, analyzer.config.WaitDuration, "Default WaitDuration mismatch")
	assert.NotEmpty(t, analyzer.canary, "Canary should be generated on initialization")
	assert.Len(t, analyzer.canary, 8, "Canary should be 8 characters (UUID prefix)")
	assert.NotNil(t, analyzer.findingChan, "Finding channel should be initialized")
	// Check channel buffer size (Capacity)
	assert.Equal(t, 5, cap(analyzer.findingChan))
}

// Verifies that configuration overrides work correctly, including input validation.
func TestNewAnalyzer_ConfigOverride(t *testing.T) {
	// Test specific override
	analyzer, _ := setupAnalyzer(t, func(c *Config) {
		c.WaitDuration = 1 * time.Hour
	})
	assert.Equal(t, 1*time.Hour, analyzer.config.WaitDuration)

	// Test invalid override (should revert to default)
	logger := zaptest.NewLogger(t)
	invalidConfig := Config{WaitDuration: -5 * time.Second}
	// Call NewAnalyzer directly to test the validation logic for invalid inputs.
	analyzerInvalid := NewAnalyzer(logger, nil, &invalidConfig)

	// The logic inside NewAnalyzer ensures it defaults if the provided value <= 0.
	assert.Equal(t, defaultWaitDuration, analyzerInvalid.config.WaitDuration, "Invalid WaitDuration should revert to default")
}

// -- Test Cases: Shim Generation and Instrumentation --

// Verifies the JavaScript instrumentation code is generated correctly with its dynamic values.
func TestGenerateShim(t *testing.T) {
	analyzer, _ := setupAnalyzer(t, nil)

	// Set a specific canary for predictable output
	testCanary := "T3STC4NRY"
	analyzer.canary = testCanary

	// Test the unexported generateShim method (White box testing)
	shim, err := analyzer.generateShim()
	require.NoError(t, err)
	require.NotEmpty(t, shim)

	// Verify key components and dynamic values are present in the generated JS template.
	// These checks must match the exact structure defined in the ProtoPollutionShim constant.
	assert.Contains(t, shim, fmt.Sprintf("let pollutionCanary = '%s';", testCanary), "Canary value not correctly injected into shim")
	assert.Contains(t, shim, fmt.Sprintf("let detectionCallbackName = '%s';", jsCallbackName), "Callback name not correctly injected into shim")

	// Verify structural integrity of the JS shim (check for key functions/logic)
	assert.Contains(t, shim, "setupPrototypeTrap", "Shim missing core trap logic")
	assert.Contains(t, shim, "monitorDOMClobbering", "Shim missing DOM Clobbering detection")
}

// -- Test Cases: Event Handling (Callback Logic) --
// These tests focus solely on the logic within the handlePollutionProof callback.

// Uses a table driven test to verify the detection and classification of different pollution events.
func TestHandlePollutionProof_ValidFlows(t *testing.T) {
	tests := []struct {
		name             string
		sourceVector     string
		expectedVuln     string
		expectedSeverity schemas.Severity
		expectedCWE      string
	}{
		{"Standard PP", "Object.prototype_access", "Client-Side Prototype Pollution", schemas.SeverityHigh, "CWE-1321"},
		{"PP via Fetch", "Fetch_Response_json_proto_key", "Client-Side Prototype Pollution", schemas.SeverityHigh, "CWE-1321"},
		{"DOM Clobbering", "DOM_Clobbering", "DOM Clobbering", schemas.SeverityMedium, "CWE-1339"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer, _ := setupAnalyzer(t, nil)
			analyzer.taskID = "task-flow-123"
			canary := analyzer.canary

			event := PollutionProofEvent{
				Source: tt.sourceVector,
				Canary: canary,
			}

			// Execute the handler (White box testing)
			analyzer.handlePollutionProof(event)

			// Verify Finding
			require.Len(t, analyzer.findingChan, 1, "Should have reported exactly one finding")
			finding := <-analyzer.findingChan

			assert.Equal(t, "task-flow-123", finding.TaskID)
			assert.Equal(t, tt.expectedVuln, finding.Vulnerability)
			assert.Equal(t, tt.expectedSeverity, finding.Severity)
			assert.Equal(t, tt.expectedCWE, finding.CWE)
			assert.Contains(t, finding.Description, tt.sourceVector)

			// Verify evidence structure using JSON unmarshalling for robustness
			var evidenceData PollutionProofEvent
			err := json.Unmarshal(finding.Evidence, &evidenceData)
			require.NoError(t, err)
			assert.Equal(t, canary, evidenceData.Canary)
			assert.Equal(t, tt.sourceVector, evidenceData.Source)
		})
	}
}

// Verifies that events with an incorrect canary are ignored to reduce false positives.
func TestHandlePollutionProof_MismatchedCanary(t *testing.T) {
	analyzer, _ := setupAnalyzer(t, nil)
	analyzer.canary = "EXPECTED"

	event := PollutionProofEvent{
		Source: "Object.prototype_access",
		Canary: "STALE_OR_INVALID", // Incorrect canary
	}

	// Execute
	analyzer.handlePollutionProof(event)

	// Verify no findings were generated
	assert.Empty(t, analyzer.findingChan, "Mismatched canary should not generate a finding")
}

// Verifies the analyzer remains robust when the finding channel is full, ensuring a non blocking send.
func TestHandlePollutionProof_ChannelFull(t *testing.T) {
	analyzer, _ := setupAnalyzer(t, nil)
	canary := analyzer.canary

	// The channel buffer size is 5 (defined in NewAnalyzer).
	bufferSize := 5

	// Fill the buffer
	for i := 0; i < bufferSize; i++ {
		// We can call the handler directly to fill the buffer quickly
		analyzer.handlePollutionProof(PollutionProofEvent{Canary: canary, Source: "Flood"})
	}
	require.Len(t, analyzer.findingChan, bufferSize)

	// Attempt to add one more. This should NOT block or panic.
	// Use a timeout mechanism to verify non blocking behavior.
	done := make(chan struct{})
	go func() {
		// This call uses a select-default block internally.
		analyzer.handlePollutionProof(PollutionProofEvent{Canary: canary, Source: "DroppedEvent"})
		close(done)
	}()

	select {
	case <-done:
	// Success: The handler returned without blocking.
	case <-time.After(1 * time.Second):
		t.Fatal("handlePollutionProof blocked when the channel was full; it should be non-blocking.")
	}

	// Verify channel state remains at capacity
	assert.Len(t, analyzer.findingChan, bufferSize)
}

// -- Test Cases: Overall Analysis Flow (Analyze Method Integration) --
// These tests verify the orchestration of the analysis process.

// Verifies the full analysis flow for the happy path where a vulnerability is detected.
func TestAnalyze_HappyPath_Detection(t *testing.T) {
	// Setup analyzer with a slightly longer wait duration to allow the async callback simulation to process.
	analyzer, mockBrowserManager := setupAnalyzer(t, func(c *Config) {
		c.WaitDuration = 200 * time.Millisecond
	})

	ctx := context.Background()
	targetURL := "http://example.com/vulnerable_app"
	mockSession := NewMockSessionContext()
	taskID := "task-success-1"

	// --- Mock Expectations (Defined in order of execution) ---

	// 1. Initialize (Use mock.Anything for context as the exact object might change, though here it's the root ctx)
	mockBrowserManager.On("InitializeSession", ctx).Return(mockSession, nil).Once()

	// 2. Instrument
	// Technical Detail: Ensure the correct Go function type (handlePollutionProof) is exposed.
	mockSession.On("ExposeFunction", jsCallbackName, mock.AnythingOfType("func(protopollution.PollutionProofEvent)")).Return(nil).Once()
	// Technical Detail: Ensure the shim containing the unique canary is injected.
	mockSession.On("InjectScriptPersistently", mock.MatchedBy(func(script string) bool {
		return strings.Contains(script, analyzer.canary)
	})).Return(nil).Once()

	// 3. Navigation and Monitoring
	mockSession.On("Navigate", targetURL).Return(nil).Once().Run(func(args mock.Arguments) {
		// --- SIMULATE CONCURRENT FINDING DETECTION ---
		// During the wait period, simulate the callback.
		// This tests the asynchronous nature of the detection.
		go func() {
			// Small delay to ensure the Analyze method has entered the select{} block.
			time.Sleep(10 * time.Millisecond)
			mockSession.SimulateCallback(t, jsCallbackName, PollutionProofEvent{
				Source: "Simulated_Vulnerability",
				Canary: analyzer.canary,
			})
		}()
	})

	// 4. Cleanup (Deferred call)
	mockSession.On("Close", ctx).Return(nil).Once()

	// --- Execute Analysis ---
	findings, err := analyzer.Analyze(ctx, taskID, targetURL)

	// --- Verification ---
	assert.NoError(t, err)
	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)

	// Verify the finding was correctly captured and returned
	require.Len(t, findings, 1)
	assert.Contains(t, string(findings[0].Evidence), "Simulated_Vulnerability")
	assert.Equal(t, targetURL, findings[0].Target)
	assert.Equal(t, taskID, findings[0].TaskID)
}

// Verifies the flow when analysis completes without detecting any vulnerabilities.
func TestAnalyze_HappyPath_NoFindings(t *testing.T) {
	// Use the default fast WaitDuration (50ms)
	analyzer, mockBrowserManager := setupAnalyzer(t, nil)
	configuredWait := analyzer.config.WaitDuration

	ctx := context.Background()
	targetURL := "http://example.com/secure_app"
	mockSession := NewMockSessionContext()

	// Setup standard expectations without simulating any callbacks.
	mockBrowserManager.On("InitializeSession", ctx).Return(mockSession, nil)
	mockSession.On("ExposeFunction", jsCallbackName, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything).Return(nil)
	mockSession.On("Navigate", targetURL).Return(nil)
	mockSession.On("Close", ctx).Return(nil)

	// Execute Analysis
	startTime := time.Now()
	findings, err := analyzer.Analyze(ctx, "task-none", targetURL)
	duration := time.Since(startTime)

	// Verification
	assert.NoError(t, err)
	assert.Empty(t, findings)
	mockSession.AssertExpectations(t)

	// Verify timing: Should take slightly longer than the configured WaitDuration.
	assert.GreaterOrEqual(t, duration, configuredWait)
	assert.Less(t, duration, configuredWait+500*time.Millisecond) // Ensure it finishes quickly.
}

// -- Test Cases: Robustness and Error Handling --

// Verifies proper error handling if the browser session fails to start.
func TestAnalyze_InitializationFailure(t *testing.T) {
	analyzer, mockBrowserManager := setupAnalyzer(t, nil)
	ctx := context.Background()

	// Mock failure
	expectedError := errors.New("browser driver crashed")
	// Crucial: Return nil SessionContext on failure.
	mockBrowserManager.On("InitializeSession", ctx).Return(nil, expectedError).Once()

	// Execute Analysis
	findings, err := analyzer.Analyze(ctx, "task-fail-init", "http://example.com")

	// Verify error propagation. No cleanup (Close) is expected as session is nil.
	assert.Error(t, err)
	assert.Nil(t, findings)
	assert.Contains(t, err.Error(), "could not initialize browser session")
	assert.ErrorIs(t, err, expectedError)
	mockBrowserManager.AssertExpectations(t)
}

// Verifies error handling during function exposure and makes sure cleanup still happens.
func TestAnalyze_InstrumentationFailure_Expose(t *testing.T) {
	analyzer, mockBrowserManager := setupAnalyzer(t, nil)
	ctx := context.Background()
	mockSession := NewMockSessionContext()

	// Setup initialization success
	mockBrowserManager.On("InitializeSession", ctx).Return(mockSession, nil)

	// Mock failure during ExposeFunction
	expectedError := errors.New("JS context destroyed")
	mockSession.On("ExposeFunction", jsCallbackName, mock.Anything).Return(expectedError).Once()

	// Robustness: Ensure session is closed even on failure (defer session.Close() check)
	mockSession.On("Close", ctx).Return(nil).Once()

	// Execute Analysis
	_, err := analyzer.Analyze(ctx, "task-fail-expose", "http://example.com")

	// Verify error propagation and cleanup
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to expose proof function")
	mockSession.AssertExpectations(t)
	// Ensure subsequent steps were skipped
	mockSession.AssertNotCalled(t, "InjectScriptPersistently", mock.Anything)
}

// Verifies that navigation errors are handled gracefully and don't crash the analysis.
func TestAnalyze_NavigationFailure_GracefulHandling(t *testing.T) {
	// The analyzer should proceed to monitoring even if navigation fails, as the shim is already injected.
	analyzer, mockBrowserManager := setupAnalyzer(t, nil)
	ctx := context.Background()
	mockSession := NewMockSessionContext()
	targetURL := "http://offline.example.com"

	// Setup standard success until navigation
	mockBrowserManager.On("InitializeSession", ctx).Return(mockSession, nil)
	mockSession.On("ExposeFunction", jsCallbackName, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything).Return(nil)

	// Mock navigation failure (e.g., timeout, DNS error)
	navigationError := errors.New("net::ERR_NAME_NOT_RESOLVED")
	mockSession.On("Navigate", targetURL).Return(navigationError).Once()

	// Ensure session is closed
	mockSession.On("Close", ctx).Return(nil).Once()

	// Execute Analysis
	findings, err := analyzer.Analyze(ctx, "task-nav-fail", targetURL)

	// Verify successful analysis completion (no error returned) despite navigation error
	assert.NoError(t, err)
	assert.Empty(t, findings)
	mockSession.AssertExpectations(t)
}

// Verifies that the analysis stops promptly when the context is canceled,
// and that any findings detected before cancellation are still returned.
func TestAnalyze_ContextCancellation(t *testing.T) {
	// Setup analyzer with a long wait duration to ensure cancellation occurs during the wait.
	analyzer, mockBrowserManager := setupAnalyzer(t, func(c *Config) {
		c.WaitDuration = 10 * time.Second
	})

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	mockSession := NewMockSessionContext()

	// Setup standard expectations
	mockBrowserManager.On("InitializeSession", ctx).Return(mockSession, nil)
	mockSession.On("ExposeFunction", jsCallbackName, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything).Return(nil)
	mockSession.On("Navigate", mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		// --- ROBUSTNESS TEST ---
		// Simulate a finding immediately before cancellation.
		mockSession.SimulateCallback(t, jsCallbackName, PollutionProofEvent{
			Source: "Detected_Before_Cancel",
			Canary: analyzer.canary,
		})
	})
	// The context passed to Close will be the cancelled one.
	mockSession.On("Close", mock.Anything).Return(nil)

	// Execute Analysis in a goroutine
	type result struct {
		findings []schemas.Finding
		err      error
	}
	done := make(chan result)
	go func() {
		f, e := analyzer.Analyze(ctx, "task-cancel", "http://example.com")
		done <- result{f, e}
	}()

	// Wait briefly and then cancel the context
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Wait for the analysis to complete or timeout
	select {
	case res := <-done:
		// Verify that the error is due to context cancellation
		assert.Error(t, res.err)
		assert.ErrorIs(t, res.err, context.Canceled)

		// Verify that the finding detected before cancellation was still returned.
		require.Len(t, res.findings, 1, "Findings detected before cancellation should still be returned")
		assert.Contains(t, string(res.findings[0].Evidence), "Detected_Before_Cancel")

	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for analysis to cancel. It did not stop promptly.")
	}

	// Ensure cleanup occurred
	mockSession.AssertExpectations(t)
}
