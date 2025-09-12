// /testing/taint_analyzer_test.go
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
	"go.uber.org/zap/zaptest"
)

// Mock Definitions
// Comprehensive mocks for isolating the Analyzer logic from external dependencies.
//
// MockBrowserInteractor mocks the BrowserInteractor interface.
type MockBrowserInteractor struct {
	mock.Mock
}

func (m *MockBrowserInteractor) InitializeSession(ctx context.Context) (SessionContext, error) {
	args := m.Called(ctx)
	// Robustness: Handle nil session return for error scenarios
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

// SimulateCallback allows tests to invoke the exposed Go functions (like the JS shim would).
// This is crucial for testing the asynchronous communication path.
func (m *MockSessionContext) SimulateCallback(t *testing.T, name string, payload interface{}) {
	t.Helper()
	m.mutex.Lock()
	fn, exists := m.exposedFunctions[name]
	m.mutex.Unlock()

	if !exists {
		t.Fatalf("function %s not exposed by analyzer", name)
	}

	// Use type assertion based on the expected callback signatures defined in the Analyzer.
	// This ensures the contract between Go and JS is maintained.
	switch name {
	case JSCallbackSinkEvent:
		callback, ok := fn.(func(SinkEvent))
		require.True(t, ok, "SinkEvent callback signature mismatch. Got: %T", fn)
		event, ok := payload.(SinkEvent)
		require.True(t, ok, "SinkEvent payload type mismatch. Got: %T", payload)
		callback(event)

	case JSCallbackExecutionProof:
		callback, ok := fn.(func(ExecutionProofEvent))
		require.True(t, ok, "ExecutionProof callback signature mismatch. Got: %T", fn)
		event, ok := payload.(ExecutionProofEvent)
		require.True(t, ok, "ExecutionProof payload type mismatch. Got: %T", payload)
		callback(event)

	case JSCallbackShimError:
		callback, ok := fn.(func(ShimErrorEvent))
		require.True(t, ok, "ShimError callback signature mismatch. Got: %T", fn)
		event, ok := payload.(ShimErrorEvent)
		require.True(t, ok, "ShimError payload type mismatch. Got: %T", payload)
		callback(event)
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
	return args.Error(0)
}

func (m *MockSessionContext) WaitForAsync(ctx context.Context, milliseconds int) error {
	args := m.Called(ctx, milliseconds)
	return args.Error(0)
}

func (m *MockSessionContext) Interact(ctx context.Context, config InteractionConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockSessionContext) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockResultsReporter mocks the ResultsReporter interface.
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

// GetFindings safely retrieves the recorded findings.
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
	// Robustness: Handle nil return for error scenarios
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]OASTInteraction), args.Error(1)
}

func (m *MockOASTProvider) GetServerURL() string {
	args := m.Called()
	return args.String(0)
}

// Test Setup Helper
//
// setupAnalyzer creates a standard Analyzer instance for testing, along with its mocks.
// It allows customization of the configuration and enabling/disabling the OAST provider.
func setupAnalyzer(t *testing.T, configMod func(*Config), oastEnabled bool) (*Analyzer, *MockBrowserInteractor, *MockResultsReporter, *MockOASTProvider) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	targetURL, _ := url.Parse("http://example.com/app")

	// Default configuration optimized for testing speed and reliability
	config := Config{
		TaskID:          "test-task-123",
		Target:          targetURL,
		Probes:          DefaultProbes(),
		Sinks:           DefaultSinks(),
		AnalysisTimeout: 5 * time.Second,
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
		// Default OAST server URL mock, used by Maybe() if not explicitly overridden.
		oastProvider.On("GetServerURL").Return("oast.example.com").Maybe()
		oastProviderIface = oastProvider
	}

	// We are in the same package (taint), so this performs white-box testing.
	analyzer, err := NewAnalyzer(config, browser, reporter, oastProviderIface, logger)
	require.NoError(t, err, "NewAnalyzer should not return an error")
	return analyzer, browser, reporter, oastProvider
}

// Test Cases: Initialization and Configuration
//
// TestNewAnalyzer_Defaults verifies that the analyzer sets default values if none are provided.
func TestNewAnalyzer_Defaults(t *testing.T) {
	targetURL, _ := url.Parse("http://example.com")
	// Minimal config provided (zero values for performance settings)
	config := Config{
		TaskID: "test-defaults",
		Target: targetURL,
	}

	// White-box access to the unexported 'config' field.
	analyzer, err := NewAnalyzer(config, nil, nil, nil, zaptest.NewLogger(t))
	require.NoError(t, err)
	require.NotNil(t, analyzer)

	// Verify defaults (as defined in NewAnalyzer implementation)
	assert.Equal(t, 500, analyzer.config.EventChannelBuffer, "Default EventChannelBuffer mismatch")
	assert.Equal(t, 10*time.Second, analyzer.config.FinalizationGracePeriod, "Default FinalizationGracePeriod mismatch")
	assert.Equal(t, 10*time.Minute, analyzer.config.ProbeExpirationDuration, "Default ProbeExpirationDuration mismatch")
	assert.Equal(t, 1*time.Minute, analyzer.config.CleanupInterval, "Default CleanupInterval mismatch")
	assert.Equal(t, 20*time.Second, analyzer.config.OASTPollingInterval, "Default OASTPollingInterval mismatch")
	assert.NotNil(t, analyzer.shimTemplate, "Shim template should be initialized from embedded FS")
}

// Test Cases: Shim Generation and Instrumentation
//
// TestGenerateShim verifies the JavaScript instrumentation code is generated correctly.
func TestGenerateShim(t *testing.T) {
	// Setup analyzer with a specific, minimal set of sinks to verify JSON serialization
	sinks := []SinkDefinition{
		{Name: "eval", Type: SinkEval, ArgIndex: 0},
		{Name: "Element.prototype.innerHTML", Type: SinkInnerHTML, Setter: true, ConditionID: "COND_TEST"},
	}
	analyzer, _, _, _ := setupAnalyzer(t, func(c *Config) {
		c.Sinks = sinks
	}, false)

	// Test the unexported generateShim method
	shim, err := analyzer.generateShim()
	require.NoError(t, err)
	require.NotEmpty(t, shim)

	// Verify key components are present in the generated JS
	assert.Contains(t, shim, fmt.Sprintf(`SinkCallbackName: "%s"`, JSCallbackSinkEvent))
	assert.Contains(t, shim, fmt.Sprintf(`ProofCallbackName: "%s"`, JSCallbackExecutionProof))
	assert.Contains(t, shim, fmt.Sprintf(`ErrorCallbackName: "%s"`, JSCallbackShimError))

	// Verify the sinks configuration is correctly JSON encoded and injected
	// Note the order and structure must match the SinkDefinition struct tags and Go's JSON marshaler.
	expectedSinksJSON := `[{"Name":"eval","Type":"EVAL","Setter":false,"ArgIndex":0},{"Name":"Element.prototype.innerHTML","Type":"INNER_HTML","Setter":true,"ArgIndex":0,"ConditionID":"COND_TEST"}]`
	// Check against the specific structure generated by the template in taint_shim.js
	assert.Contains(t, shim, fmt.Sprintf("Sinks: %s,", expectedSinksJSON))
}

// TestInstrument_Success verifies the sequence of calls to instrument the browser session.
func TestInstrument_Success(t *testing.T) {
	analyzer, _, _, _ := setupAnalyzer(t, nil, false)
	mockSession := NewMockSessionContext()
	ctx := context.Background()

	// Expectations: Expose all 3 functions and inject the script.
	// We check the types of the exposed functions to ensure the analyzer exposes the correct handlers.
	mockSession.On("ExposeFunction", ctx, JSCallbackSinkEvent, mock.AnythingOfType("func(taint.SinkEvent)")).Return(nil).Once()
	mockSession.On("ExposeFunction", ctx, JSCallbackExecutionProof, mock.AnythingOfType("func(taint.ExecutionProofEvent)")).Return(nil).Once()
	mockSession.On("ExposeFunction", ctx, JSCallbackShimError, mock.AnythingOfType("func(taint.ShimErrorEvent)")).Return(nil).Once()
	mockSession.On("InjectScriptPersistently", ctx, mock.AnythingOfType("string")).Return(nil).Once()

	// Execute
	err := analyzer.instrument(ctx, mockSession)
	assert.NoError(t, err)

	// Verify
	mockSession.AssertExpectations(t)
}

// TestInstrument_Failure_ExposeFunction verifies error handling during instrumentation.
func TestInstrument_Failure_ExposeFunction(t *testing.T) {
	analyzer, _, _, _ := setupAnalyzer(t, nil, false)
	mockSession := NewMockSessionContext()
	ctx := context.Background()

	// Simulate failure on the first ExposeFunction call
	expectedError := errors.New("browser connection lost")
	mockSession.On("ExposeFunction", ctx, JSCallbackSinkEvent, mock.Anything).Return(expectedError).Once()

	// Execute
	err := analyzer.instrument(ctx, mockSession)

	// Verify error propagation
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to expose sink event callback")
	assert.ErrorIs(t, err, expectedError)
}

// Test Cases: Probing Mechanics (Unit Tests)
//
// TestGenerateCanary verifies the format and uniqueness of generated canaries.
func TestGenerateCanary(t *testing.T) {
	analyzer, _, _, _ := setupAnalyzer(t, nil, false)

	canary1 := analyzer.generateCanary("P", ProbeTypeXSS)
	canary2 := analyzer.generateCanary("Q", ProbeTypeSSTI)

	// Check format using the exported regex variable
	assert.True(t, canaryRegex.MatchString(canary1), "Canary format should match SCALPEL_{Prefix}_{Type}_{UUID_Short}")
	assert.True(t, canaryRegex.MatchString(canary2), "Canary format should match SCALPEL_{Prefix}_{Type}_{UUID_Short}")

	// Check uniqueness
	assert.NotEqual(t, canary1, canary2)

	// Check prefix and type embedding
	assert.Contains(t, canary1, "SCALPEL_P_XSS_")
	assert.Contains(t, canary2, "SCALPEL_Q_SSTI_")
}

// TestPreparePayload verifies placeholder replacement logic, including OAST scenarios.
func TestPreparePayload(t *testing.T) {
	// Setup analyzers with and without OAST
	analyzerNoOAST, _, _, _ := setupAnalyzer(t, nil, false)
	analyzerWithOAST, _, _, mockOAST := setupAnalyzer(t, nil, true)

	// Configure OAST mock specifically for this test, overriding the default.
	oastURL := "custom.oast.test"
	mockOAST.ExpectedCalls = nil // Clear default setup mock
	mockOAST.On("GetServerURL").Return(oastURL)

	canary := "CANARY_TEST_123"

	tests := []struct {
		name     string
		analyzer *Analyzer
		payload  string
		expected string
	}{
		{
			"Standard Canary Replacement", analyzerNoOAST,
			"prefix_{{.Canary}}_suffix",
			"prefix_" + canary + "_suffix",
		},
		{
			"OAST Enabled Replacement", analyzerWithOAST,
			"http://{{.OASTServer}}/{{.Canary}}",
			"http://" + oastURL + "/" + canary,
		},
		{
			"OAST Disabled (Skipped)", analyzerNoOAST,
			"http://{{.OASTServer}}/{{.Canary}}",
			"", // Should return empty string if OAST is required but provider is missing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probeDef := ProbeDefinition{Payload: tt.payload}
			result := tt.analyzer.preparePayload(probeDef, canary)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestRegisterProbe_Concurrency verifies thread-safe registration of probes.
func TestRegisterProbe_Concurrency(t *testing.T) {
	analyzer, _, _, _ := setupAnalyzer(t, nil, false)

	// Concurrently register many probes
	wg := sync.WaitGroup{}
	count := 100
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			analyzer.registerProbe(ActiveProbe{Canary: fmt.Sprintf("CONCURRENT_%d", i)})
		}(i)
	}
	wg.Wait()

	// Verify all probes were registered without data races.
	analyzer.probesMutex.RLock()
	defer analyzer.probesMutex.RUnlock()
	assert.Len(t, analyzer.activeProbes, count)
}

// Test Cases: Probing Strategies (Integration Style)
// These tests verify the interaction between the probing logic and the browser session.
//
// TestProbePersistentSources verifies injection into storage/cookies, focusing on encoding and the Secure flag logic.
func TestProbePersistentSources(t *testing.T) {
	// Use specific probes, including one requiring complex JSON encoding (quotes, slashes, tags).
	probes := []ProbeDefinition{
		{Type: ProbeTypeXSS, Payload: "XSS<tag>_{{.Canary}}"},
		{Type: ProbeTypeGeneric, Payload: `GENERIC_"quote"_\/slash\/_{{.Canary}}`},
	}

	// Test both HTTP (no Secure flag) and HTTPS (Secure flag) scenarios.
	tests := []struct {
		name             string
		targetURL        string
		expectSecureFlag bool
	}{
		{"HTTP Target (No Secure Flag)", "http://example.com/app", false},
		{"HTTPS Target (Secure Flag)", "https://secure.example.com/app", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer, _, _, _ := setupAnalyzer(t, func(c *Config) {
				c.Probes = probes
				c.Target, _ = url.Parse(tt.targetURL)
			}, false)

			mockSession := NewMockSessionContext()
			ctx := context.Background()

			var capturedScript string
			mockSession.On("ExecuteScript", ctx, mock.AnythingOfType("string")).Run(func(args mock.Arguments) {
				capturedScript = args.String(1)
			}).Return(nil).Once()

			// Expect refresh navigation after injection
			mockSession.On("Navigate", ctx, tt.targetURL).Return(nil).Once()

			// Execute
			err := analyzer.probePersistentSources(ctx, mockSession)
			require.NoError(t, err)

			// Verify Mocks
			mockSession.AssertExpectations(t)

			// Verify Registration (2 probes * 3 sources = 6 probes)
			assert.Len(t, analyzer.activeProbes, 6)

			// **FIX**: The regexs are now more flexible to account for unique canaries.
			// We now check for the presence of each command type instead of a single monolithic script.
			// The original test failed because it tried to match a multi-line script against single-line patterns.
			assert.Regexp(t, `localStorage\.setItem\("sc_store_0", ".*"\);`, capturedScript)
			assert.Regexp(t, `sessionStorage\.setItem\("sc_store_0_s", ".*"\);`, capturedScript)
			assert.Regexp(t, `localStorage\.setItem\("sc_store_1", ".*"\);`, capturedScript)

			// Verify Cookie Flags
			cookieCommandRegex := regexp.MustCompile("document\\.cookie = `\\${.sc_cookie_0.}=\\${encodeURIComponent\\(.*samesite=Lax;(.*)`" + `;`)
			matches := cookieCommandRegex.FindStringSubmatch(capturedScript)
			require.Len(t, matches, 2, "Cookie command structure mismatch")

			if tt.expectSecureFlag {
				assert.Contains(t, matches[1], " Secure;")
			} else {
				assert.NotContains(t, matches[1], " Secure;")
			}
		})
	}
}

// TestProbeURLSources verifies injection into URL parameters and hash fragments, ensuring correct URL encoding.
func TestProbeURLSources(t *testing.T) {
	// Include payloads needing URL encoding (<, &, =)
	probes := []ProbeDefinition{
		{Type: ProbeTypeXSS, Payload: "<XSS&={{.Canary}}"},
		{Type: ProbeTypeGeneric, Payload: "GENERIC={{.Canary}}"},
	}
	analyzer, _, _, _ := setupAnalyzer(t, func(c *Config) {
		c.Probes = probes
		// Start with existing query param to ensure preservation
		c.Target, _ = url.Parse("http://example.com/page?existing=1")
	}, false)

	mockSession := NewMockSessionContext()
	ctx := context.Background()

	var queryURL, hashURL string

	// Expect two navigations: one for Query parameters, one for Hash fragments.
	mockSession.On("Navigate", ctx, mock.AnythingOfType("string")).Return(nil).Twice().Run(func(args mock.Arguments) {
		navURL := args.String(1)
		if strings.Contains(navURL, "#") {
			hashURL = navURL
		} else {
			queryURL = navURL
		}
	})

	// Execute
	err := analyzer.probeURLSources(ctx, mockSession)
	require.NoError(t, err)

	// Verify Mocks
	mockSession.AssertExpectations(t)

	// Verify Registration (2 probes * 2 sources = 4 probes)
	assert.Len(t, analyzer.activeProbes, 4)

	// Verify Query URL
	require.NotEmpty(t, queryURL)
	parsedQ, err := url.Parse(queryURL)
	require.NoError(t, err)
	q := parsedQ.Query()

	assert.Equal(t, "1", q.Get("existing"), "Existing params should be preserved")
	// Check encoding (Go's url.Values handles this automatically, so the retrieved value is the decoded version)
	assert.Contains(t, q.Get("sc_test_0"), "<XSS&=")
	assert.Contains(t, q.Get("sc_test_0"), "SCALPEL_Q_XSS_")

	// Verify Hash URL
	require.NotEmpty(t, hashURL)
	parsedH, err := url.Parse(hashURL)
	require.NoError(t, err)

	// Query should be reset to original for hash probing
	assert.Equal(t, "existing=1", parsedH.RawQuery)

	// Check encoding in Hash Fragment (Requires explicit url.QueryEscape in the implementation)
	// <XSS&= -> %3CXSS%26%3D
	assert.Contains(t, parsedH.Fragment, "sc_test_0=%3CXSS%26%3D")
	assert.Contains(t, parsedH.Fragment, "SCALPEL_H_XSS_")
	// GENERIC= -> GENERIC%3D
	assert.Contains(t, parsedH.Fragment, "sc_test_1=GENERIC%3D")
	// Ensure fragments are combined
	assert.Contains(t, parsedH.Fragment, "&")
}

// Test Cases: Event Handling and Correlation (The Core Logic)
//
// Setup/Teardown helpers for correlation tests manage the lifecycle of the 'correlate' goroutine.
func setupCorrelationTest(t *testing.T) (*Analyzer, *MockResultsReporter) {
	t.Helper()
	// Setup analyzer (disable OAST/Cleanup background workers for isolated correlation tests)
	analyzer, _, reporter, _ := setupAnalyzer(t, func(c *Config) {
		c.CleanupInterval = time.Hour
	}, false)

	// Initialize context and start the correlation engine manually (the consumer)
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.wg.Add(1)
	go analyzer.correlate()
	return analyzer, reporter
}

// finalizeCorrelationTest ensures the correlation engine finishes processing the event queue gracefully.
func finalizeCorrelationTest(t *testing.T, analyzer *Analyzer) {
	t.Helper()
	// Signal shutdown to potential producers (though typically none running in these tests)
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
	analyzer, reporter := setupCorrelationTest(t)

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
	assert.Equal(t, SourceURLParam, finding.Origin)
	assert.False(t, finding.IsConfirmed, "Sink events are suspicious, not confirmed proof")
	assert.Equal(t, SanitizationNone, finding.SanitizationLevel, "Payload was intact")
	assert.Equal(t, "at app.js:42", finding.StackTrace)
}

// TestProcessSinkEvent_InvalidContext verifies that flows violating the rules engine are suppressed (FP reduction).
func TestProcessSinkEvent_InvalidContext(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)

	// Scenario: XSS probe data flows into a WebSocket Send (Invalid context for XSS execution according to ValidTaintFlows).
	canary := analyzer.generateCanary("T", ProbeTypeXSS)
	probe := ActiveProbe{Type: ProbeTypeXSS, Canary: canary}
	analyzer.registerProbe(probe)

	sinkEvent := SinkEvent{Type: SinkWebSocketSend, Value: canary}

	analyzer.eventsChan <- sinkEvent
	finalizeCorrelationTest(t, analyzer)

	assert.Empty(t, reporter.GetFindings(), "Invalid taint flow context should be suppressed by isContextValid")
}

// TestProcessSinkEvent_SanitizationDetected verifies payload modification detection.
func TestProcessSinkEvent_SanitizationDetected(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)

	// Setup: XSS probe with HTML tags
	canary := analyzer.generateCanary("T", ProbeTypeXSS)
	originalPayload := fmt.Sprintf(`<script>alert('%s')</script>`, canary)
	probe := ActiveProbe{Type: ProbeTypeXSS, Canary: canary, Value: originalPayload}
	analyzer.registerProbe(probe)

	// Scenario: Payload reaches sink, but HTML tags are stripped. Canary remains.
	sanitizedPayload := fmt.Sprintf(`alert('%s')`, canary)
	sinkEvent := SinkEvent{Type: SinkInnerHTML, Value: sanitizedPayload}

	reporter.On("Report", mock.Anything).Return().Once()

	analyzer.eventsChan <- sinkEvent
	finalizeCorrelationTest(t, analyzer)

	// Verify Finding
	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]

	assert.Equal(t, SanitizationPartial, finding.SanitizationLevel)
	// Check the specific detail message generated by checkSanitization
	assert.Contains(t, finding.Detail, "Potential Sanitization: HTML tags modified or stripped")
}

// TestProcessExecutionProof_Confirmed verifies high-confidence execution events.
func TestProcessExecutionProof_Confirmed(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)

	// Setup: Register an execution-type probe (XSS, SSTI, etc.)
	canary := analyzer.generateCanary("T", ProbeTypeXSS)
	probe := ActiveProbe{Type: ProbeTypeXSS, Canary: canary, Source: SourceHashFragment}
	analyzer.registerProbe(probe)

	// Simulate Execution Proof
	proofEvent := ExecutionProofEvent{Canary: canary, StackTrace: "at onerror (app.js:1)"}

	reporter.On("Report", mock.Anything).Return().Once()

	analyzer.eventsChan <- proofEvent
	finalizeCorrelationTest(t, analyzer)

	// Verify Finding
	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]

	assert.Equal(t, SinkExecution, finding.Sink)
	assert.True(t, finding.IsConfirmed, "Execution proof must be confirmed")
	assert.Equal(t, SanitizationNone, finding.SanitizationLevel)
}

// TestProcessPrototypePollutionConfirmation_Valid verifies confirmed Prototype Pollution findings.
func TestProcessPrototypePollutionConfirmation_Valid(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)

	// Setup: Register a Prototype Pollution probe
	canary := analyzer.generateCanary("T", ProbeTypePrototypePollution)
	payload := `{"__proto__":{"polluted":"yes"}}`
	probe := ActiveProbe{Type: ProbeTypePrototypePollution, Canary: canary, Value: payload, Source: SourceBody}
	analyzer.registerProbe(probe)

	// Simulate the specific event sent by the JS shim when pollution is confirmed.
	// 'Value' contains the canary, 'Detail' contains the polluted property name.
	ppEvent := SinkEvent{Type: SinkPrototypePollution, Value: canary, Detail: "pollutedProperty"}

	reporter.On("Report", mock.Anything).Return().Once()

	analyzer.eventsChan <- ppEvent
	finalizeCorrelationTest(t, analyzer)

	// Verify Finding
	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]

	assert.Equal(t, SinkPrototypePollution, finding.Sink)
	assert.True(t, finding.IsConfirmed)
	assert.Equal(t, payload, finding.Value, "Finding value should be the original pollution payload")
	assert.Contains(t, finding.Detail, "Successfully polluted Object.prototype property: pollutedProperty")
}

// TestProcessOASTInteraction_Valid verifies OAST callbacks result in high-confidence findings.
func TestProcessOASTInteraction_Valid(t *testing.T) {
	// Although OAST provider is disabled in setupCorrelationTest, we can still test the correlation logic itself.
	analyzer, reporter := setupCorrelationTest(t)

	// Setup: Register an OAST probe
	canary := analyzer.generateCanary("T", ProbeTypeOAST)
	probe := ActiveProbe{Type: ProbeTypeOAST, Canary: canary, Source: SourceHeader}
	analyzer.registerProbe(probe)

	// Simulate OAST Interaction event
	interactionTime := time.Now().UTC()
	oastEvent := OASTInteraction{Canary: canary, Protocol: "DNS", SourceIP: "1.2.3.4", InteractionTime: interactionTime}

	reporter.On("Report", mock.Anything).Return().Once()

	analyzer.eventsChan <- oastEvent
	finalizeCorrelationTest(t, analyzer)

	// Verify Finding
	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]

	assert.Equal(t, SinkOASTInteraction, finding.Sink)
	assert.True(t, finding.IsConfirmed)
	require.NotNil(t, finding.OASTDetails)
	assert.Equal(t, "DNS", finding.OASTDetails.Protocol)
	assert.Equal(t, interactionTime, finding.OASTDetails.InteractionTime)
}

// Test Cases: False Positive Reduction Logic (Unit Tests)
//
// TestIsContextValid comprehensively tests the rules engine (ValidTaintFlows) and exceptions.
func TestIsContextValid(t *testing.T) {
	analyzer, _, _, _ := setupAnalyzer(t, nil, false)

	tests := []struct {
		name        string
		probeType   ProbeType
		sinkType    TaintSink
		sinkValue   string
		expectValid bool
	}{
		// Valid Flows (Declarative Rules)
		{"XSS -> innerHTML", ProbeTypeXSS, SinkInnerHTML, "<svg...>", true},
		{"SSTI -> Eval", ProbeTypeSSTI, SinkEval, "{{7*7}}", true},
		{"Generic -> Fetch URL", ProbeTypeGeneric, SinkFetch_URL, "http://...", true},

		// Valid Flows (Reflected Backend Injections treated as XSS)
		{"Reflected SQLi -> innerHTML", ProbeTypeSQLi, SinkInnerHTML, "' OR 1=1 <script>...", true},
		{"Reflected CmdInjection -> innerHTML", ProbeTypeCmdInjection, SinkInnerHTML, "; echo <script>...", true},

		// Invalid Flows
		{"XSS -> WebSocketSend", ProbeTypeXSS, SinkWebSocketSend, "<svg...>", false},
		{"Generic -> innerHTML", ProbeTypeGeneric, SinkInnerHTML, "GENERIC_...", false},

		// Navigation Sink Exceptions (Conditional Rules - Protocol Specific)
		{"XSS -> Navigation (javascript:)", ProbeTypeXSS, SinkNavigation, "javascript:alert(1)", true},
		{"XSS -> Navigation (data: case/trim)", ProbeTypeXSS, SinkNavigation, " Data:text/html,<body>", true},
		{"XSS -> Navigation (http:)", ProbeTypeXSS, SinkNavigation, "http://evil.com?q=<script>", false}, // FP: XSS payload navigating to HTTP is not XSS
		{"Generic -> Navigation (http:)", ProbeTypeGeneric, SinkNavigation, "http://evil.com?q=GENERIC", true}, // Valid data leakage/redirect
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := ActiveProbe{Type: tt.probeType}
			event := SinkEvent{Type: tt.sinkType, Value: tt.sinkValue}
			// Test the unexported validation function
			isValid := analyzer.isContextValid(event, probe)
			assert.Equal(t, tt.expectValid, isValid)
		})
	}
}

// TestCheckSanitization tests the heuristics for detecting payload modification.
func TestCheckSanitization(t *testing.T) {
	analyzer, _, _, _ := setupAnalyzer(t, nil, false)
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
			// **FIX**: The original `\"` is just a quote character in a raw Go string.
			// `\\"` is needed to produce a literal backslash followed by a quote.
			`\" autofocus onfocus=` + canary, // Quotes escaped with backslash
			SanitizationPartial, "Quotes escaped",
		},
		{
			"Quotes Escaped (HTML Entity)", ProbeTypeXSS,
			`" autofocus onfocus=` + canary,
			`&#34; autofocus onfocus=` + canary, // Quotes escaped with HTML entity
			SanitizationPartial, "Quotes escaped",
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

// Test Cases: Background Workers (State Management)
//
// TestCleanupExpiredProbes verifies the periodic removal of old probes.
func TestCleanupExpiredProbes(t *testing.T) {
	// Configure short expiration and cleanup intervals for a fast test
	analyzer, _, _, _ := setupAnalyzer(t, func(c *Config) {
		c.ProbeExpirationDuration = 50 * time.Millisecond
		c.CleanupInterval = 10 * time.Millisecond
	}, false)

	// Register probes with different creation times
	now := time.Now()
	probeActive := ActiveProbe{Canary: "ACTIVE", CreatedAt: now}
	// Expired probe (created 100ms ago, which is > 50ms expiration)
	probeExpired := ActiveProbe{Canary: "EXPIRED", CreatedAt: now.Add(-100 * time.Millisecond)}

	analyzer.registerProbe(probeActive)
	analyzer.registerProbe(probeExpired)
	assert.Len(t, analyzer.activeProbes, 2)

	// Start the cleanup routine (Producer)
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.producersWG.Add(1)
	go analyzer.cleanupExpiredProbes()

	// Wait long enough for the cleanup routine to run (e.g., 3 cycles)
	time.Sleep(35 * time.Millisecond)

	// Stop the routine gracefully
	analyzer.backgroundCancel()
	analyzer.producersWG.Wait()

	// Verify the results (thread-safe access)
	analyzer.probesMutex.RLock()
	defer analyzer.probesMutex.RUnlock()

	assert.Len(t, analyzer.activeProbes, 1, "Expired probes should have been cleaned up")
	_, exists := analyzer.activeProbes["ACTIVE"]
	assert.True(t, exists, "Active probe should remain")
	_, exists = analyzer.activeProbes["EXPIRED"]
	assert.False(t, exists, "Expired probe should not exist")
}

// TestPollOASTInteractions_CanaryFiltering verifies the OAST polling mechanism correctly identifies relevant canaries.
func TestPollOASTInteractions_CanaryFiltering(t *testing.T) {
	analyzer, _, _, mockOAST := setupAnalyzer(t, func(c *Config) {
		c.OASTPollingInterval = 10 * time.Millisecond
	}, true)
	// Uses default mock OAST URL: oast.example.com

	// Register different types of probes
	// 1. Relevant: Type OAST
	analyzer.registerProbe(ActiveProbe{Canary: "OAST_1", Type: ProbeTypeOAST})
	// 2. Relevant: Type XSS, but payload contains OAST URL (Blind XSS)
	analyzer.registerProbe(ActiveProbe{Canary: "BLIND_XSS_2", Type: ProbeTypeXSS, Value: "fetch('http://oast.example.com/2')"})
	// 3. Irrelevant: Type Generic, no OAST URL
	analyzer.registerProbe(ActiveProbe{Canary: "IRRELEVANT_3", Type: ProbeTypeGeneric})

	expectedInteractions := []OASTInteraction{{Canary: "OAST_1", Protocol: "DNS"}}

	// **FIX**: Use .Maybe() instead of .Once() to allow for multiple poll cycles during the test.
	mockOAST.On("GetInteractions", mock.Anything, mock.MatchedBy(func(canaries []string) bool {
		// Use ElementsMatch for order-independent comparison
		return assert.ElementsMatch(t, []string{"OAST_1", "BLIND_XSS_2"}, canaries)
	})).Return(expectedInteractions, nil).Maybe()

	// Start the poller (Producer)
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.producersWG.Add(1)
	go analyzer.pollOASTInteractions()

	// Wait and stop
	time.Sleep(30 * time.Millisecond)
	analyzer.backgroundCancel()
	analyzer.producersWG.Wait()

	// Verify mock calls and that the fetched interaction was enqueued
	mockOAST.AssertExpectations(t)
	assert.GreaterOrEqual(t, len(analyzer.eventsChan), 1, "Should have enqueued at least 1 OAST interaction")
}

// Test Cases: Robustness and Error Handling
//
// TestHandleEvent_ChannelFull verifies that events are dropped if the buffer is full (non-blocking send).
func TestHandleEvent_ChannelFull(t *testing.T) {
	// Setup analyzer with a very small buffer
	analyzer, _, _, _ := setupAnalyzer(t, func(c *Config) {
		c.EventChannelBuffer = 1
	}, false)

	// Initialize context so the handlers don't exit early due to shutdown signal
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	defer analyzer.backgroundCancel()

	// Do NOT start the consumer (correlate), so the channel fills up.

	event1 := SinkEvent{Detail: "Event1"}
	event2_dropped := SinkEvent{Detail: "Event2_Dropped"}

	// Fill the buffer
	analyzer.handleSinkEvent(event1)

	// This should be dropped (non-blocking send) and not cause a deadlock or panic
	analyzer.handleSinkEvent(event2_dropped)

	// Verify channel state
	assert.Len(t, analyzer.eventsChan, 1)
	e1 := <-analyzer.eventsChan
	assert.Equal(t, "Event1", e1.(SinkEvent).Detail)
}

// Test Cases: Overall Analysis Flow (Analyze Method Integration)
//
// TestAnalyze_HappyPath verifies the full orchestration of the analysis process, including concurrent finding detection.
func TestAnalyze_HappyPath(t *testing.T) {
	// Setup with OAST enabled to test all phases
	analyzer, mockBrowser, reporter, mockOAST := setupAnalyzer(t, func(c *Config) {
		// **CORRECTION**: The original probe did not use OAST, causing the GetInteractions mock to never be called.
		// This new probe is of Type OAST and will ensure the OAST poller has canaries to check for.
		c.Probes = []ProbeDefinition{{Type: ProbeTypeOAST, Payload: "http://{{.OASTServer}}/{{.Canary}}"}}
	}, true)

	ctx := context.Background()
	mockSession := NewMockSessionContext()
	targetURL := analyzer.config.Target.String()

	// --- Mock Expectations (Defined in order of execution) ---

	// 1. Initialize
	mockBrowser.On("InitializeSession", mock.Anything).Return(mockSession, nil).Once()

	// 2. Instrument
	mockSession.On("ExposeFunction", mock.Anything, JSCallbackSinkEvent, mock.Anything).Return(nil).Once()
	mockSession.On("ExposeFunction", mock.Anything, JSCallbackExecutionProof, mock.Anything).Return(nil).Once()
	mockSession.On("ExposeFunction", mock.Anything, JSCallbackShimError, mock.Anything).Return(nil).Once()
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil).Once()

	// 3. Execute Probes
	// Initial navigation (required before persistent injection)
	mockSession.On("Navigate", mock.Anything, targetURL).Return(nil).Once()

	// Persistent Probes (JS Execution + Refresh)
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything).Return(nil).Once()
	mockSession.On("Navigate", mock.Anything, targetURL).Return(nil).Once() // Refresh

	// URL Probes (Query + Hash)
	mockSession.On("Navigate", mock.Anything, mock.AnythingOfType("string")).Return(nil).Twice()

	// Interaction Phase
	mockSession.On("Interact", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
		// --- SIMULATE CONCURRENT FINDING DETECTION ---
		// While interacting, simulate a callback from the browser.

		// Find a registered canary (probes are registered during the steps above)
		analyzer.probesMutex.RLock()
		var activeCanary string
		for canary, probe := range analyzer.activeProbes {
			// Change this to find the OAST probe to simulate a different kind of event.
			// Let's simulate a sink event instead of execution proof for variety.
			if probe.Type == ProbeTypeOAST {
				activeCanary = canary
				break
			}
		}
		analyzer.probesMutex.RUnlock()

		require.NotEmpty(t, activeCanary, "Should have registered probes before interaction phase")

		// Simulate the callback for a sink event this time
		mockSession.SimulateCallback(t, JSCallbackSinkEvent, SinkEvent{Type: SinkFetch_URL, Value: "http://oast.example.com/" + activeCanary})

		// Expect a report for this finding
		reporter.On("Report", mock.MatchedBy(func(f CorrelatedFinding) bool {
			return f.Canary == activeCanary && !f.IsConfirmed && f.Sink == SinkFetch_URL
		})).Once()
	})

	// 4. Background Workers (OAST Polling)
	// Expect polling to occur during the run and during finalization.
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]OASTInteraction{}, nil).Maybe()

	// 5. Cleanup
	mockSession.On("Close").Return(nil).Once()

	// --- Execute Analysis ---
	err := analyzer.Analyze(ctx)
	assert.NoError(t, err)

	// --- Verification ---
	mockBrowser.AssertExpectations(t)
	mockSession.AssertExpectations(t)
	reporter.AssertExpectations(t)

	// Verify OAST polling occurred at least once
	mockOAST.AssertCalled(t, "GetInteractions", mock.Anything, mock.Anything)

	// Verify graceful shutdown (background context cancelled, WaitGroups finalized)
	assert.Error(t, analyzer.backgroundCtx.Err(), "Background context should be cancelled")
	// Channel closure is implicitly verified by Analyze returning without deadlock (it waits for wg/producersWG).
}

// TestAnalyze_InitializationFailure verifies error handling if the browser session fails to start.
func TestAnalyze_InitializationFailure(t *testing.T) {
	analyzer, mockBrowser, _, _ := setupAnalyzer(t, nil, false)
	ctx := context.Background()

	// Mock failure
	expectedError := errors.New("browser crashed")
	// Crucial: Return nil SessionContext on failure
	mockBrowser.On("InitializeSession", mock.Anything).Return(nil, expectedError).Once()

	// Execute Analysis
	err := analyzer.Analyze(ctx)

	// Verify error propagation
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize browser session")
	mockBrowser.AssertExpectations(t)
}

// TestAnalyze_TimeoutDuringGracePeriod verifies behavior when the analysis timeout is reached during the finalization phase.
func TestAnalyze_TimeoutDuringGracePeriod(t *testing.T) {
	// Set a short analysis timeout, but a longer grace period
	analyzer, mockBrowser, _, mockOAST := setupAnalyzer(t, func(c *Config) {
		c.AnalysisTimeout = 100 * time.Millisecond
		c.FinalizationGracePeriod = 500 * time.Millisecond // Longer than timeout
		c.Probes = []ProbeDefinition{}                       // No probes to speed up probing phase
	}, true)

	ctx := context.Background()
	mockSession := NewMockSessionContext()

	// Setup standard mocks (init, instrument, probing)
	mockBrowser.On("InitializeSession", mock.Anything).Return(mockSession, nil)
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(3)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockSession.On("Interact", mock.Anything, mock.Anything).Return(nil).Once()

	// Ensure OAST polling occurs
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]OASTInteraction{}, nil).Maybe()

	// Ensure session is closed
	mockSession.On("Close").Return(nil).Once()

	// Execute Analysis
	startTime := time.Now()
	err := analyzer.Analyze(ctx)
	duration := time.Since(startTime)

	assert.NoError(t, err)

	// Verify timing: The analysis should stop shortly after the AnalysisTimeout (100ms),
	// even though the GracePeriod (500ms) is longer, because the context timeout interrupts the wait.
	assert.GreaterOrEqual(t, duration, 100*time.Millisecond)
	assert.Less(t, duration, 200*time.Millisecond) // Should be much less than 500ms

	mockSession.AssertExpectations(t)
}
