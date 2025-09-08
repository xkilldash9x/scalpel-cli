package taint

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// -- Mock Definitions --
// Time to build our little puppet theater. These are some serious mocks,
// we're talking thread safe and sticking to the contract like glue.

// MockBrowserInteractor mocks the BrowserInteractor interface.
type MockBrowserInteractor struct {
	mock.Mock
}

func (m *MockBrowserInteractor) InitializeSession(ctx context.Context) (SessionContext, error) {
	args := m.Called(ctx)
	// Handle nil session return for error scenarios
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(SessionContext), args.Error(1)
}

// MockSessionContext mocks the SessionContext interface (a browser tab).
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

func (m *MockSessionContext) InjectScriptPersistently(ctx context.Context, script string) error {
	args := m.Called(ctx, script)
	return args.Error(0)
}

func (m *MockSessionContext) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	args := m.Called(ctx, name, function)
	// Store the function only if exposure succeeded
	if args.Error(0) == nil {
		m.exposedFunctions[name] = function
	}
	return args.Error(0)
}

// SimulateCallback is our way of pretending to be the browser, asynchronously calling back to Go.
func (m *MockSessionContext) SimulateCallback(t *testing.T, name string, payload interface{}) {
	t.Helper()
	m.mutex.Lock()
	fn, exists := m.exposedFunctions[name]
	m.mutex.Unlock()

	if !exists {
		t.Fatalf("function %s not exposed by analyzer", name)
	}

	// Strictly enforce the contract (signatures) between Go and JS.
	switch name {
	case JSCallbackSinkEvent:
		callback, ok := fn.(func(SinkEvent))
		require.True(t, ok, "SinkEvent callback signature mismatch. Got: %T", fn)
		event, ok := payload.(SinkEvent)
		require.True(t, ok, "SinkEvent payload type mismatch. Got: %T", payload)
		// Execute in a goroutine to simulate true asynchronous behavior.
		go callback(event)

	case JSCallbackExecutionProof:
		callback, ok := fn.(func(ExecutionProofEvent))
		require.True(t, ok, "ExecutionProof callback signature mismatch. Got: %T", fn)
		event, ok := payload.(ExecutionProofEvent)
		require.True(t, ok, "ExecutionProof payload type mismatch. Got: %T", payload)
		go callback(event)

	case JSCallbackShimError:
		callback, ok := fn.(func(ShimErrorEvent))
		require.True(t, ok, "ShimError callback signature mismatch. Got: %T", fn)
		event, ok := payload.(ShimErrorEvent)
		require.True(t, ok, "ShimError payload type mismatch. Got: %T", payload)
		go callback(event)
	default:
		t.Fatalf("Unknown callback name simulated: %s", name)
	}
}

func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string) error {
	args := m.Called(ctx, script)
	return args.Error(0)
}

func (m *MockSessionContext) Navigate(ctx context.Context, url string) error {
	args := m.Called(ctx, url)
	// Allow simulating context cancellation during navigation
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return args.Error(0)
	}
}

func (m *MockSessionContext) WaitForAsync(ctx context.Context, milliseconds int) error {
	args := m.Called(ctx, milliseconds)
	return args.Error(0)
}

func (m *MockSessionContext) Interact(ctx context.Context, config InteractionConfig) error {
	args := m.Called(ctx, config)
	// Allow simulating context cancellation during interaction.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return args.Error(0)
	}
}

// Close adheres to the interface contract required by the Analyzer (takes context).
func (m *MockSessionContext) Close(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockResultsReporter mocks the ResultsReporter interface (Thread-safe).
type MockResultsReporter struct {
	mock.Mock
	Findings []CorrelatedFinding
	mutex    sync.Mutex
}

func (m *MockResultsReporter) Report(finding CorrelatedFinding) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.Called(finding)
	m.Findings = append(m.Findings, finding)
}

// GetFindings safely retrieves a copy of the recorded findings.
func (m *MockResultsReporter) GetFindings() []CorrelatedFinding {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	// Return a copy to prevent race conditions
	findings := make([]CorrelatedFinding, len(m.Findings))
	copy(findings, m.Findings)
	return findings
}

// MockOASTProvider mocks the OASTProvider interface.
type MockOASTProvider struct {
	mock.Mock
}

func (m *MockOASTProvider) GetInteractions(ctx context.Context, canaries []string) ([]OASTInteraction, error) {
	args := m.Called(ctx, canaries)
	// Handle nil return for error scenarios
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]OASTInteraction), args.Error(1)
}

func (m *MockOASTProvider) GetServerURL() string {
	args := m.Called()
	return args.String(0)
}

// -- Test Setup Helper --

// setupAnalyzer creates a standard Analyzer instance for testing, along with its mocks and a log observer.
func setupAnalyzer(t *testing.T, configMod func(*Config), oastEnabled bool) (*Analyzer, *MockBrowserInteractor, *MockResultsReporter, *MockOASTProvider, *observer.ObservedLogs) {
	t.Helper()

	// Setup logging observer to allow tests to inspect logs.
	observedCore, observedLogs := observer.New(zapcore.DebugLevel)
	logger := zap.New(observedCore)

	targetURL, _ := url.Parse("http://example.com/app")

	// Default configuration optimized for testing speed and reliability
	config := Config{
		TaskID:                  "test-task-123",
		Target:                  targetURL,
		Probes:                  DefaultProbes(),
		Sinks:                   DefaultSinks(),
		AnalysisTimeout:         5 * time.Second,
		// Speed up background tasks and finalization for faster tests
		CleanupInterval:         10 * time.Millisecond,
		OASTPollingInterval:     20 * time.Millisecond,
		FinalizationGracePeriod: 50 * time.Millisecond,
		ProbeExpirationDuration: 500 * time.Millisecond,
		EventChannelBuffer:      10,
	}

	// Apply custom modifications
	if configMod != nil {
		configMod(&config)
	}

	browser := new(MockBrowserInteractor)
	reporter := new(MockResultsReporter)
	var oastProvider *MockOASTProvider
	var oastProviderIface OASTProvider
	if oastEnabled {
		oastProvider = new(MockOASTProvider)
		// Default OAST server URL mock.
		oastProvider.On("GetServerURL").Return("oast.example.com").Maybe()
		oastProviderIface = oastProvider
	}

	// White box testing.
	analyzer, err := NewAnalyzer(config, browser, reporter, oastProviderIface, logger)
	require.NoError(t, err, "NewAnalyzer should not return an error")
	return analyzer, browser, reporter, oastProvider, observedLogs
}

// -- Test Cases: Event Handling and Correlation (The Core Logic) --

// setup/teardown helpers for correlation tests manage the lifecycle of the 'correlate' goroutine.
func setupCorrelationTest(t *testing.T) (*Analyzer, *MockResultsReporter, *observer.ObservedLogs) {
	t.Helper()
	// Setup analyzer (disable OAST/Cleanup background workers for isolation)
	analyzer, _, reporter, _, observedLogs := setupAnalyzer(t, func(c *Config) {
		c.CleanupInterval = time.Hour
		c.OASTPollingInterval = time.Hour
	}, false)

	// Initialize context and start the correlation engine manually (the consumer)
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.wg.Add(1)
	go analyzer.correlate()
	return analyzer, reporter, observedLogs
}

// finalizeCorrelationTest ensures the correlation engine finishes processing the event queue gracefully.
func finalizeCorrelationTest(t *testing.T, analyzer *Analyzer) {
	t.Helper()
	// Signal shutdown to producers.
	if analyzer.backgroundCancel != nil {
		analyzer.backgroundCancel()
	}
	analyzer.producersWG.Wait()

	// Close the channel to signal the consumer (correlate) to finish.
	close(analyzer.eventsChan)

	// Wait for the consumer to finalize, with a timeout to detect deadlocks.
	done := make(chan struct{})
	go func() {
		analyzer.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	// Clean shutdown
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for correlation engine to shut down (potential deadlock)")
	}
}

// TestProcessSinkEvent_ValidFlow verifies a standard, valid taint flow detection.
func TestProcessSinkEvent_ValidFlow(t *testing.T) {
	analyzer, reporter, _ := setupCorrelationTest(t)

	// Setup: Register a probe
	canary := analyzer.generateCanary("T", ProbeTypeXSS)
	payload := fmt.Sprintf("<img src=x onerror=%s>", canary)
	probe := ActiveProbe{Type: ProbeTypeXSS, Canary: canary, Value: payload, Source: SourceURLParam}
	analyzer.registerProbe(probe)

	// Simulate event: Payload reaches a valid sink (InnerHTML) intact.
	sinkValue := fmt.Sprintf("<div>%s</div>", payload)
	sinkEvent := SinkEvent{Type: SinkInnerHTML, Value: sinkValue, Detail: "Element.innerHTML", StackTrace: "at app.js:42"}

	reporter.On("Report", mock.Anything).Return().Once()

	analyzer.eventsChan <- sinkEvent
	finalizeCorrelationTest(t, analyzer)

	// Verify Finding
	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]

	assert.Equal(t, canary, finding.Canary)
	assert.Equal(t, SinkInnerHTML, finding.Sink)
}

// -- Test Cases: False Positive Reduction Logic (Unit Tests) --

// TestCheckSanitization tests the heuristics for detecting payload modification.
func TestCheckSanitization(t *testing.T) {
	analyzer, _, _, _, _ := setupAnalyzer(t, nil, false)
	canary := "CANARY123"

	tests := []struct {
		name            string
		probeType       ProbeType
		originalPayload string
		sinkValue       string
		wantLevel       SanitizationLevel
		wantDetail      string
	}{
		// No Sanitization
		{
			"Intact (XSS)", ProbeTypeXSS,
			`<img src=x>` + canary,
			`<div><img src=x>` + canary + `</div>`,
			SanitizationNone, "",
		},
		// HTML Sanitization
		{
			"HTML Stripped (XSS)", ProbeTypeXSS,
			`<img src=x>` + canary,
			`img src=x` + canary, // < > removed
			SanitizationPartial, "HTML tags modified or stripped",
		},
		// Quote Escaping
		{
			"Quotes Escaped (Backslash)", ProbeTypeXSS,
			`" autofocus onfocus=` + canary,
			// `\\"` is needed to produce a literal backslash followed by a quote.
			`\" autofocus onfocus=` + canary, // Quotes escaped with backslash
			SanitizationPartial, "Quotes escaped",
		},
		// SSTI Specific Sanitization
		{
			"SSTI (Braces Encoded)", ProbeTypeSSTI,
			`{{` + canary + `}}`,
			`&#123;&#123;` + canary + `&#125;&#125;`, // Braces HTML encoded
			SanitizationPartial, "SSTI delimiters modified",
		},
		// Generic Modification
		{
			"Modified (Generic)", ProbeTypeGeneric,
			`START_` + canary + `_END`,
			`START_` + canary, // _END stripped
			SanitizationPartial, "Payload modified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := ActiveProbe{Type: tt.probeType, Value: tt.originalPayload}
			// Test the unexported sanitization check function
			level, detail := analyzer.checkSanitization(tt.sinkValue, probe)
			assert.Equal(t, tt.wantLevel, level)
			if tt.wantDetail != "" {
				assert.Contains(t, detail, tt.wantDetail)
			}
		})
	}
}

// -- Test Cases: Background Workers (State Management) --

// TestPollOASTInteractions_ProviderError verifies robustness when the OAST provider fails and ensures logging.
func TestPollOASTInteractions_ProviderError(t *testing.T) {
	analyzer, _, _, mockOAST, observedLogs := setupAnalyzer(t, func(c *Config) {
		c.OASTPollingInterval = 10 * time.Millisecond
	}, true)

	// Register a relevant probe
	analyzer.registerProbe(ActiveProbe{Canary: "OAST_1", Type: ProbeTypeOAST})

	expectedError := errors.New("transient network failure")

	// Configure the mock to return an error.
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return(nil, expectedError).Maybe()

	// Start the poller (Producer)
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.producersWG.Add(1)
	go analyzer.pollOASTInteractions()

	// Wait for a few cycles and stop
	time.Sleep(35 * time.Millisecond)
	analyzer.backgroundCancel()
	analyzer.producersWG.Wait()

	// Verify mock calls occurred
	mockOAST.AssertCalled(t, "GetInteractions", mock.Anything, mock.Anything)

	// Verify that the error was logged correctly
	logs := observedLogs.FilterLevelExact(zapcore.ErrorLevel).FilterMessage("Failed to poll OAST provider")
	require.GreaterOrEqual(t, logs.Len(), 1, "Should have logged the OAST provider error")
	// Check that the error context is included in the log entry.
	assert.Contains(t, logs.All()[0].ContextMap()["error"].(error).Error(), expectedError.Error())
}

// -- Test Cases: Robustness and Error Handling --

//  verifies that events are dropped if the buffer is full and that this action is logged.
func TestHandleEvent_ChannelFull(t *testing.T) {
	// Setup analyzer with a very small buffer
	analyzer, _, _, _, observedLogs := setupAnalyzer(t, func(c *Config) {
		c.EventChannelBuffer = 1
	}, false)

	// Initialize context
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	defer analyzer.backgroundCancel()

	// Do NOT start the consumer (correlate).

	// Fill the buffer
	analyzer.handleSinkEvent(SinkEvent{Detail: "Event1"})

	// This should be dropped
	analyzer.handleSinkEvent(SinkEvent{Detail: "Event2_Dropped"})

	// Verify channel state
	assert.Len(t, analyzer.eventsChan, 1)

	// Verify that the dropped event was logged
	logs := observedLogs.FilterLevelExact(zapcore.WarnLevel).FilterMessage("Event channel buffer full, dropping event")
	require.Equal(t, 1, logs.Len(), "Should have logged the dropped event warning")
}

//  verifies that errors reported by the JS shim are logged correctly.
func TestHandleShimError(t *testing.T) {
	analyzer, _, _, _, observedLogs := setupAnalyzer(t, nil, false)

	// Initialize context
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	defer analyzer.backgroundCancel()

	// Simulate a detailed error from the JS instrumentation
	shimError := ShimErrorEvent{
		Message:    "CSP violation",
		StackTrace: "at taint_shim.js:150",
	}

	// Execute the handler directly
	analyzer.handleShimError(shimError)

	// Verify the error was logged with high fidelity
	logs := observedLogs.FilterLevelExact(zapcore.ErrorLevel).FilterMessage("Runtime error reported by JavaScript instrumentation shim")
	require.Equal(t, 1, logs.Len())

	logContext := logs.All()[0].ContextMap()
	assert.Equal(t, shimError.Message, logContext["message"])
	assert.Equal(t, shimError.StackTrace, logContext["stack_trace"])
}

// -- Test Cases: Overall Analysis Flow (Analyze Method Integration) --

//  verifies the full orchestration of the analysis process.
func TestAnalyze_HappyPath(t *testing.T) {
	analyzer, mockBrowser, reporter, mockOAST, _ := setupAnalyzer(t, func(c *Config) {
		c.Probes = []ProbeDefinition{{Type: ProbeTypeOAST, Payload: "http://{{.OASTServer}}/{{.Canary}}"}}
	}, true)

	ctx := context.Background()
	mockSession := NewMockSessionContext()

	// -- Mock Expectations (Overview) --

	// 1. Initialize
	mockBrowser.On("InitializeSession", mock.Anything).Return(mockSession, nil).Once()

	// 2. Instrument
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(3)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil).Once()

	// 3. Execute Probes (Simplified)
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything).Return(nil).Once()
	mockSession.On("Navigate", mock.Anything, mock.AnythingOfType("string")).Return(nil).Times(4)

	// 4. Interaction Phase
	mockSession.On("Interact", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
		// Simulate concurrent finding detection
		analyzer.probesMutex.RLock()
		var activeCanary string
		for canary := range analyzer.activeProbes {
			activeCanary = canary
			break
		}
		analyzer.probesMutex.RUnlock()

		// Simulate the callback (Asynchronously)
		mockSession.SimulateCallback(t, JSCallbackSinkEvent, SinkEvent{Type: SinkFetch_URL, Value: "http://oast.example.com/" + activeCanary})

		reporter.On("Report", mock.Anything).Once()

		// Brief sleep to allow async processing
		time.Sleep(20 * time.Millisecond)
	})

	// 5. Background Workers
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]OASTInteraction{}, nil).Maybe()

	// 6. Cleanup
	mockSession.On("Close", mock.Anything).Return(nil).Once()

	// -- Execute Analysis --
	err := analyzer.Analyze(ctx)
	assert.NoError(t, err)

	// -- Verification --
	mockBrowser.AssertExpectations(t)
	mockSession.AssertExpectations(t)
	reporter.AssertExpectations(t)
}

//  verifies graceful shutdown when the context is cancelled mid-analysis.
func TestAnalyze_CancellationDuringInteraction(t *testing.T) {
	analyzer, mockBrowser, _, _, _ := setupAnalyzer(t, func(c *Config) {
		c.Probes = []ProbeDefinition{} // No probes to speed up
	}, false)

	ctx, cancel := context.WithCancel(context.Background())
	mockSession := NewMockSessionContext()

	// Setup standard mocks.
	mockBrowser.On("InitializeSession", mock.Anything).Return(mockSession, nil)
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(3)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Mock the Interaction phase. The mock implementation respects ctx.Done().
	mockSession.On("Interact", mock.Anything, mock.Anything).Return(context.Canceled).Once()

	// Crucial: Ensure the session is closed upon cancellation.
	mockSession.On("Close", mock.Anything).Return(nil).Once()

	// Run analysis in a separate goroutine.
	analyzeErrChan := make(chan error, 1)
	go func() {
		analyzeErrChan <- analyzer.Analyze(ctx)
	}()

	// Wait briefly then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Wait for the result.
	select {
	case err := <-analyzeErrChan:
		// Cancellation should result in context.Canceled error or nil.
		if err != nil {
			assert.ErrorIs(t, err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Analysis did not stop after context cancellation (deadlock)")
	}

	// Verify cleanup occurred.
	mockSession.AssertExpectations(t)
}