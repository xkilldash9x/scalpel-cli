package taint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"go.uber.org/zap/zaptest/observer"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/static/javascript"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// Mock Definitions

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

func (m *MockResultsReporter) GetFindings() []CorrelatedFinding {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	findings := make([]CorrelatedFinding, len(m.Findings))
	copy(findings, m.Findings)
	return findings
}

// Test Setup Helper

func setupAnalyzer(t *testing.T, configMod func(*Config), oastEnabled bool) (*Analyzer, *MockResultsReporter, *mocks.MockOASTProvider) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	targetURL, _ := url.Parse("http://example.com/app")

	// Default configuration optimized for testing
	config := Config{
		TaskID:                  "test-task-123",
		Target:                  targetURL,
		Probes:                  DefaultProbes(),
		Sinks:                   DefaultSinks(),
		AnalysisTimeout:         5 * time.Second,
		CleanupInterval:         10 * time.Millisecond,
		OASTPollingInterval:     20 * time.Millisecond,
		FinalizationGracePeriod: 50 * time.Millisecond,
		ProbeExpirationDuration: 500 * time.Millisecond,
		EventChannelBuffer:      10,
	}

	if configMod != nil {
		configMod(&config)
	}

	reporter := new(MockResultsReporter)
	var oastProvider *mocks.MockOASTProvider
	var oastProviderIface OASTProvider
	if oastEnabled {
		oastProvider = new(mocks.MockOASTProvider)
		oastProvider.On("GetServerURL").Return("oast.example.com").Maybe()
		oastProviderIface = oastProvider
	}

	analyzer, err := NewAnalyzer(config, reporter, oastProviderIface, logger)
	require.NoError(t, err, "NewAnalyzer should not return an error")
	return analyzer, reporter, oastProvider
}

// --- NEW SUITE: Hybrid IAST (Smart Probing & Correlation) ---

func TestHybrid_SmartProbing_GeneratesProbes(t *testing.T) {
	// 1. Setup Analyzer with standard probes
	probes := []ProbeDefinition{
		{Type: schemas.ProbeTypeXSS, Payload: "XSS_{{.Canary}}"},
	}
	analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
		c.Probes = probes
		c.Target, _ = url.Parse("http://example.com/app")
	}, false)

	// 2. Inject Fake Static Findings (Simulating SAST results)
	// Finding 1: Vulnerability using a query parameter "q"
	// Finding 2: Vulnerability using a hash parameter "state"
	analyzer.findingsMutex.Lock()
	analyzer.staticFindings["app.js"] = []javascript.StaticFinding{
		{
			Source:        "param:query:q", // Unified source format
			CanonicalType: schemas.SinkInnerHTML,
			Location:      javascript.LocationInfo{Line: 10},
		},
		{
			Source:        "param:hash:state",
			CanonicalType: schemas.SinkEval,
			Location:      javascript.LocationInfo{Line: 20},
		},
	}
	analyzer.findingsMutex.Unlock()

	// 3. Mock Session to capture Navigation
	mockSession := mocks.NewMockSessionContext()
	ctx := context.Background()

	// We expect Navigations.
	// One for Query Params logic, one for Hash Params logic.
	// The order depends on map iteration, so we use Matchers.

	var visitedURLs []string
	mockSession.On("Navigate", ctx, mock.MatchedBy(func(u string) bool {
		visitedURLs = append(visitedURLs, u)
		return true
	})).Return(nil)

	// Mock Humanoid pause (return nil)
	// We need to check if analyzer implements HumanoidProvider or handles nil.
	// The code checks `if h == nil { return nil }`, so we don't need to mock Humanoid if we don't provide it.

	// 4. Execute Smart Probes
	analyzer.generateAndExecuteSmartProbes(ctx, mockSession, nil)

	// 5. Verify Results
	assert.GreaterOrEqual(t, len(visitedURLs), 2, "Should navigate at least twice (once for q, once for state)")

	// Check for Query Param Injection
	foundQueryInjection := false
	for _, u := range visitedURLs {
		parsed, _ := url.Parse(u)
		if parsed.Query().Get("q") != "" && strings.Contains(parsed.Query().Get("q"), "SCALPEL_SMART_Q_XSS_") {
			foundQueryInjection = true
		}
	}
	assert.True(t, foundQueryInjection, "Smart Probe failed to inject into discovered query param 'q'")

	// Check for Hash Param Injection
	foundHashInjection := false
	for _, u := range visitedURLs {
		parsed, _ := url.Parse(u)
		// Hash might be encoded, e.g. state=...
		if strings.Contains(parsed.Fragment, "state=") && strings.Contains(parsed.Fragment, "SCALPEL_SMART_H_XSS_") {
			foundHashInjection = true
		}
	}
	assert.True(t, foundHashInjection, "Smart Probe failed to inject into discovered hash param 'state'")
}

func TestHybrid_Correlation_LinksStaticAndDynamic(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)

	// 1. Setup Static Finding (SAST)
	sastLocation := javascript.LocationInfo{Line: 50, Column: 10, File: "main.js"}
	staticFinding := javascript.StaticFinding{
		CanonicalType: schemas.SinkInnerHTML,
		Source:        core.SourceLocationSearch, // Corresponds to schemas.SourceURLParam
		Location:      sastLocation,
		Confidence:    "High",
	}

	analyzer.findingsMutex.Lock()
	// Map keys usually match the file path or URL
	analyzer.staticFindings["http://example.com/main.js"] = []javascript.StaticFinding{staticFinding}
	analyzer.findingsMutex.Unlock()

	// 2. Create a Dynamic Finding (IAST) that matches
	// - Same Sink (InnerHTML)
	// - Same Source (URLParam)
	// - Nearby Location (Line 50 vs Line 52)
	canary := "TEST_CANARY"
	probe := ActiveProbe{Type: schemas.ProbeTypeXSS, Source: schemas.SourceURLParam, Canary: canary}

	dynamicFinding := CorrelatedFinding{
		Sink:             schemas.SinkInnerHTML,
		Probe:            probe,
		Canary:           canary,
		StackTrace:       "at func (http://example.com/main.js:52:15)", // Within 3 lines of 50
		ConfirmedDynamic: true,
		ConfirmedStatic:  false, // Initially false
	}

	// 3. Run Correlation
	analyzer.correlateWithStaticFindings(&dynamicFinding)

	// 4. Verify Linking
	assert.True(t, dynamicFinding.ConfirmedStatic, "Should be confirmed by SAST")
	assert.True(t, dynamicFinding.IsConfirmed, "IsConfirmed should be set to true due to SAST verification")
	assert.NotNil(t, dynamicFinding.StaticFinding, "StaticFinding struct should be linked")
	assert.Equal(t, sastLocation, dynamicFinding.StaticFinding.Location)
}

func TestHybrid_Correlation_NoMatch(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)

	// 1. Static Finding (Source: Cookie)
	staticFinding := javascript.StaticFinding{
		CanonicalType: schemas.SinkInnerHTML,
		Source:        core.SourceDocumentCookie,
		Location:      javascript.LocationInfo{Line: 50},
	}
	analyzer.findingsMutex.Lock()
	analyzer.staticFindings["http://example.com/main.js"] = []javascript.StaticFinding{staticFinding}
	analyzer.findingsMutex.Unlock()

	// 2. Dynamic Finding (Source: URL Param) - Mismatch!
	dynamicFinding := CorrelatedFinding{
		Sink:             schemas.SinkInnerHTML,
		Probe:            ActiveProbe{Source: schemas.SourceURLParam}, // Mismatch
		StackTrace:       "at func (http://example.com/main.js:50:10)",
	}

	// 3. Run Correlation
	analyzer.correlateWithStaticFindings(&dynamicFinding)

	// 4. Verify NO Linking
	assert.False(t, dynamicFinding.ConfirmedStatic)
	assert.Nil(t, dynamicFinding.StaticFinding)
}

// --- NEW: Robustness for External Interactions ---

func TestAnalyze_HandlesNavigationFailure(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	mockSession := mocks.NewMockSessionContext()
	ctx := context.Background()

	// Mock Instrumentation Success
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)

	// Mock Navigation FAILURE
	navErr := fmt.Errorf("network unreachable")
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(navErr).Once()

	// Probing phases follow...
	// Persistent Source Probing calls ExecuteScript
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage("null"), nil).Maybe()
	// And Navigates to refresh
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil).Maybe()
	// Interaction phase
	mockSession.On("Interact", mock.Anything, mock.Anything).Return(nil).Maybe()

	// Execute
	err := analyzer.Analyze(ctx, mockSession)

	// We expect NO error returned from Analyze, it should log the warning and continue
	assert.NoError(t, err)
	mockSession.AssertCalled(t, "Navigate", mock.Anything, mock.Anything)
}

// Test Cases: Initialization and Configuration

func TestNewAnalyzer_Defaults(t *testing.T) {
	targetURL, _ := url.Parse("http://example.com")
	config := Config{
		TaskID: "test-defaults",
		Target: targetURL,
	}

	analyzer, err := NewAnalyzer(config, nil, nil, zaptest.NewLogger(t))
	require.NoError(t, err)
	require.NotNil(t, analyzer)

	assert.Equal(t, 1000, analyzer.config.EventChannelBuffer)
	assert.Equal(t, 10*time.Second, analyzer.config.FinalizationGracePeriod)
	assert.Equal(t, 10*time.Minute, analyzer.config.ProbeExpirationDuration)
	assert.Equal(t, 1*time.Minute, analyzer.config.CleanupInterval)
	assert.Equal(t, 20*time.Second, analyzer.config.OASTPollingInterval)
	assert.NotNil(t, analyzer.shimTemplate)
}

// Test Cases: Shim Generation and Instrumentation

func TestGenerateShim(t *testing.T) {
	sinks := []SinkDefinition{
		{Name: "eval", Type: schemas.SinkEval, ArgIndex: 0},
		{Name: "Element.prototype.innerHTML", Type: schemas.SinkInnerHTML, Setter: true, ConditionID: "COND_TEST"},
	}
	analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
		c.Sinks = sinks
	}, false)

	shim, err := analyzer.generateShim()
	require.NoError(t, err)
	require.NotEmpty(t, shim)

	// VULN-FIX: Assert that the shim contains the session-specific randomized names, not the static constants.
	assert.Contains(t, shim, fmt.Sprintf(`SinkCallbackName: "%s"`, analyzer.jsCallbackSinkEventName))
	assert.Contains(t, shim, fmt.Sprintf(`ProofCallbackName: "%s"`, analyzer.jsCallbackExecutionProofName))
	assert.Contains(t, shim, fmt.Sprintf(`ErrorCallbackName: "%s"`, analyzer.jsCallbackShimErrorName))
	assert.NotContains(t, shim, fmt.Sprintf(`SinkCallbackName: "%s"`, JSCallbackSinkEvent))

	expectedSinksJSON := `[{"Name":"eval","Type":"EVAL","Setter":false,"ArgIndex":0},{"Name":"Element.prototype.innerHTML","Type":"INNER_HTML","Setter":true,"ArgIndex":0,"ConditionID":"COND_TEST"}]`
	assert.Contains(t, shim, "Sinks: "+expectedSinksJSON+",")
}

func TestInstrument_Success(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	mockSession := mocks.NewMockSessionContext()
	ctx := context.Background()

	// VULN-FIX: The callback names are now randomized. The mock should expect any string that
	// matches the base prefix, rather than a hardcoded static value. This makes the test robust.
	mockSession.On("ExposeFunction", ctx, mock.MatchedBy(func(name string) bool {
		return strings.HasPrefix(name, JSCallbackSinkEvent)
	}), mock.AnythingOfType("func(taint.SinkEvent)")).Return(nil).Once()
	mockSession.On("ExposeFunction", ctx, mock.MatchedBy(func(name string) bool {
		return strings.HasPrefix(name, JSCallbackExecutionProof)
	}), mock.AnythingOfType("func(taint.ExecutionProofEvent)")).Return(nil).Once()
	mockSession.On("ExposeFunction", ctx, mock.MatchedBy(func(name string) bool {
		return strings.HasPrefix(name, JSCallbackShimError)
	}), mock.AnythingOfType("func(taint.ShimErrorEvent)")).Return(nil).Once()
	mockSession.On("InjectScriptPersistently", ctx, mock.AnythingOfType("string")).Return(nil).Once()

	err := analyzer.instrument(ctx, mockSession)
	assert.NoError(t, err)

	mockSession.AssertExpectations(t)
}

func TestInstrument_Failure_ExposeFunction(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	mockSession := mocks.NewMockSessionContext()
	ctx := context.Background()

	expectedError := errors.New("browser connection lost")
	// VULN-FIX: Match against the randomized prefix, not the static constant.
	mockSession.On("ExposeFunction", ctx, mock.MatchedBy(func(name string) bool {
		return strings.HasPrefix(name, JSCallbackSinkEvent)
	}), mock.Anything).Return(expectedError).Once()

	err := analyzer.instrument(ctx, mockSession)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to expose sink event callback")
	assert.ErrorIs(t, err, expectedError)
}

// Test Cases: Probing Mechanics (Unit Tests)

func TestGenerateCanary(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	canary1 := analyzer.generateCanary("P", schemas.ProbeTypeXSS)
	canary2 := analyzer.generateCanary("Q", schemas.ProbeTypeSSTI)
	assert.True(t, canaryRegex.MatchString(canary1))
	assert.True(t, canaryRegex.MatchString(canary2))
	assert.NotEqual(t, canary1, canary2)
	assert.Contains(t, canary1, "SCALPEL_P_XSS_")
	assert.Contains(t, canary2, "SCALPEL_Q_SSTI_")
}

func TestPreparePayload(t *testing.T) {
	analyzerNoOAST, _, _ := setupAnalyzer(t, nil, false)
	analyzerWithOAST, _, mockOAST := setupAnalyzer(t, nil, true)
	oastURL := "custom.oast.test"
	mockOAST.ExpectedCalls = nil
	mockOAST.On("GetServerURL").Return(oastURL)
	canary := "CANARY_TEST_123"
	tests := []struct {
		name     string
		analyzer *Analyzer
		payload  string
		expected string
	}{
		{"Standard Canary Replacement", analyzerNoOAST, "prefix_{{.Canary}}_suffix", "prefix_" + canary + "_suffix"},
		{"OAST Enabled Replacement", analyzerWithOAST, "http://{{.OASTServer}}/{{.Canary}}", "http://" + oastURL + "/" + canary},
		{"OAST Disabled (Skipped)", analyzerNoOAST, "http://{{.OASTServer}}/{{.Canary}}", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probeDef := ProbeDefinition{Payload: tt.payload}
			result := tt.analyzer.preparePayload(probeDef, canary)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRegisterProbe_Concurrency(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
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
	analyzer.probesMutex.RLock()
	defer analyzer.probesMutex.RUnlock()
	assert.Len(t, analyzer.activeProbes, count)
}

// Test Cases: Probing Strategies (Integration Style)

func TestProbePersistentSources(t *testing.T) {
	probes := []ProbeDefinition{
		{Type: schemas.ProbeTypeXSS, Payload: "XSS<tag>_{{.Canary}}"},
		{Type: schemas.ProbeTypeGeneric, Payload: `GENERIC_"quote"_\/slash\/_{{.Canary}}`},
	}
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
			analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
				c.Probes = probes
				c.Target, _ = url.Parse(tt.targetURL)
			}, false)
			mockSession := mocks.NewMockSessionContext()
			ctx := context.Background()
			var capturedScript string
			mockSession.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.Anything).Run(func(args mock.Arguments) {
				capturedScript = args.String(1)
			}).Return(json.RawMessage("null"), nil).Once()

			mockSession.On("Navigate", ctx, tt.targetURL).Return(nil).Once()
			err := analyzer.probePersistentSources(ctx, mockSession, nil)
			require.NoError(t, err)

			mockSession.AssertExpectations(t)

			assert.Len(t, analyzer.activeProbes, len(probes)*3)
			assert.Regexp(t, `localStorage\.setItem\("sc_store_0", ".*"\);`, capturedScript)
			assert.Regexp(t, `sessionStorage\.setItem\("sc_store_0_s", ".*"\);`, capturedScript)
			assert.Regexp(t, `localStorage\.setItem\("sc_store_1", ".*"\);`, capturedScript)

			if tt.expectSecureFlag {
				assert.Contains(t, capturedScript, " Secure;")
			} else {
				assert.NotContains(t, capturedScript, " Secure;")
			}
		})
	}
}

func TestProbeURLSources(t *testing.T) {
	probes := []ProbeDefinition{
		{Type: schemas.ProbeTypeXSS, Payload: "<XSS&={{.Canary}}"},
		{Type: schemas.ProbeTypeGeneric, Payload: "GENERIC={{.Canary}}"},
	}
	analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
		c.Probes = probes
		c.Target, _ = url.Parse("http://example.com/page?existing=1")
	}, false)
	mockSession := mocks.NewMockSessionContext()
	ctx := context.Background()
	var queryURL, hashURL string
	mockSession.On("Navigate", ctx, mock.AnythingOfType("string")).Return(nil).Twice().Run(func(args mock.Arguments) {
		navURL := args.String(1)
		if strings.Contains(navURL, "#") {
			hashURL = navURL
		} else {
			queryURL = navURL
		}
	})
	err := analyzer.probeURLSources(ctx, mockSession, nil)
	require.NoError(t, err)
	mockSession.AssertExpectations(t)
	assert.Len(t, analyzer.activeProbes, len(probes)*2)
	require.NotEmpty(t, queryURL)
	parsedQ, err := url.Parse(queryURL)
	require.NoError(t, err)
	q := parsedQ.Query()
	assert.Equal(t, "1", q.Get("existing"))
	assert.Contains(t, q.Get("sc_test_0"), "<XSS&=")
	assert.Contains(t, q.Get("sc_test_0"), "SCALPEL_Q_XSS_")
	require.NotEmpty(t, hashURL)
	parsedH, err := url.Parse(hashURL)
	require.NoError(t, err)
	assert.Equal(t, "existing=1", parsedH.RawQuery)
	assert.Contains(t, parsedH.Fragment, "sc_test_0=%3CXSS%26%3D")
	assert.Contains(t, parsedH.Fragment, "SCALPEL_H_XSS_")
	assert.Contains(t, parsedH.Fragment, "sc_test_1=GENERIC%3D")
	assert.Contains(t, parsedH.Fragment, "&")
}

// Test Cases: Event Handling and Correlation (The Core Logic)

func setupCorrelationTest(t *testing.T) (*Analyzer, *MockResultsReporter) {
	t.Helper()
	analyzer, reporter, _ := setupAnalyzer(t, func(c *Config) {
		c.CleanupInterval = time.Hour
	}, false)
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	return analyzer, reporter
}

func TestHandleShimError(t *testing.T) {
	// This test primarily checks that the analyzer receives the event and logs it.
	// We use a logger observer to verify this.
	core, hook := observer.New(zaptest.NewLogger(t).Core())
	logger := zaptest.NewLogger(t).WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core { return core }))

	analyzer, _, _ := setupAnalyzer(t, nil, false)
	analyzer.logger = logger // Replace default logger with observed logger

	errorEvent := ShimErrorEvent{
		Error:      "TypeError: null is not an object",
		Location:   "instrumentFunction(fetch)",
		StackTrace: "at wrapper (shim.js:100)",
	}

	// Call the handler directly (this is what the browser session does)
	analyzer.handleShimError(errorEvent)

	// Verify that an error log was produced
	require.Equal(t, 1, hook.Len(), "Expected one error log entry")
	entry := hook.All()[0]
	assert.Equal(t, "JavaScript Instrumentation Shim Error reported.", entry.Message)
	fields := entry.ContextMap()
	assert.Equal(t, errorEvent.Error, fields["error_message"])
	assert.Equal(t, errorEvent.Location, fields["location"])
}

func finalizeCorrelationTest(t *testing.T, analyzer *Analyzer) {
	t.Helper()
	if analyzer.backgroundCancel != nil {
		analyzer.backgroundCancel()
	}
	analyzer.producersWG.Wait()
	if analyzer.eventsChan != nil {
		defer func() { recover() }()
		close(analyzer.eventsChan)
	}
	done := make(chan struct{})
	go func() {
		analyzer.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for correlation engine to shut down (potential deadlock)")
	}
}

func TestProcessSinkEvent_ValidFlow(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)
	canary := analyzer.generateCanary("T", schemas.ProbeTypeXSS)
	payload := fmt.Sprintf("<img src=x onerror=%s>", canary)
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	probe := ActiveProbe{Type: schemas.ProbeTypeXSS, Canary: canary, Value: payload, Source: schemas.SourceURLParam}
	analyzer.registerProbe(probe)
	sinkValue := fmt.Sprintf("<div>%s</div>", payload)
	sinkEvent := SinkEvent{Type: schemas.SinkInnerHTML, Value: sinkValue, Detail: "Element.innerHTML", StackTrace: "at app.js:42"}
	reporter.On("Report", mock.Anything).Return().Once()
	analyzer.eventsChan <- sinkEvent
	finalizeCorrelationTest(t, analyzer)
	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]
	assert.Equal(t, canary, finding.Canary)
	assert.Equal(t, schemas.SinkInnerHTML, finding.Sink)
	assert.Equal(t, schemas.SourceURLParam, finding.Origin)
	assert.False(t, finding.IsConfirmed)
	assert.Equal(t, SanitizationNone, finding.SanitizationLevel)
	assert.Equal(t, "at app.js:42", finding.StackTrace)
}

func TestProcessSinkEvent_InvalidFlow_Suppressed(t *testing.T) {
	// Setup analyzer and observer to check logs for suppression reason
	core, hook := observer.New(zaptest.NewLogger(t).Core())
	logger := zaptest.NewLogger(t).WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core { return core }))

	analyzer, reporter := setupCorrelationTest(t)
	analyzer.logger = logger

	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	// XSS probe flowing into a WebSocketSend sink is invalid according to ValidTaintFlows (FP)
	canary := analyzer.generateCanary("T", schemas.ProbeTypeXSS)
	payload := fmt.Sprintf("<svg onload=%s>", canary)
	probe := ActiveProbe{Type: schemas.ProbeTypeXSS, Canary: canary, Value: payload}
	analyzer.registerProbe(probe)

	sinkEvent := SinkEvent{Type: schemas.SinkWebSocketSend, Value: payload}

	// Expect no report
	analyzer.eventsChan <- sinkEvent
	finalizeCorrelationTest(t, analyzer)

	assert.Empty(t, reporter.GetFindings())
	// Verify suppression log
	assert.Equal(t, 1, hook.FilterMessage("Context mismatch: Taint flow suppressed (False Positive).").Len())
}

func TestProcessSinkEvent_SanitizationDetected(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)
	canary := analyzer.generateCanary("T", schemas.ProbeTypeXSS)
	originalPayload := fmt.Sprintf("<img src=x onerror=%s>", canary)
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	probe := ActiveProbe{Type: schemas.ProbeTypeXSS, Canary: canary, Value: originalPayload}
	analyzer.registerProbe(probe)

	// Payload at sink has tags stripped, but canary remains
	sanitizedValue := fmt.Sprintf("img src=x onerror=%s", canary)
	sinkEvent := SinkEvent{Type: schemas.SinkInnerHTML, Value: sanitizedValue}

	reporter.On("Report", mock.Anything).Return().Once()

	analyzer.eventsChan <- sinkEvent
	finalizeCorrelationTest(t, analyzer)

	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]
	assert.Equal(t, SanitizationPartial, finding.SanitizationLevel)
	assert.Contains(t, finding.Detail, "HTML tags modified or stripped")
}

func TestProcessSinkEvent_MultipleCanaries(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)
	canary1 := analyzer.generateCanary("M1", schemas.ProbeTypeXSS)
	canary2 := analyzer.generateCanary("M2", schemas.ProbeTypeSSTI)

	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	analyzer.registerProbe(ActiveProbe{Type: schemas.ProbeTypeXSS, Canary: canary1, Value: canary1})
	analyzer.registerProbe(ActiveProbe{Type: schemas.ProbeTypeSSTI, Canary: canary2, Value: canary2})

	// Value contains both canaries
	sinkValue := fmt.Sprintf("<div>%s and %s</div>", canary1, canary2)
	sinkEvent := SinkEvent{Type: schemas.SinkInnerHTML, Value: sinkValue}

	reporter.On("Report", mock.Anything).Return().Twice()

	analyzer.eventsChan <- sinkEvent
	finalizeCorrelationTest(t, analyzer)

	require.Len(t, reporter.GetFindings(), 2)
	findings := reporter.GetFindings()
	canariesFound := []string{findings[0].Canary, findings[1].Canary}
	assert.ElementsMatch(t, []string{canary1, canary2}, canariesFound)
}

func TestProcessOASTInteraction_Valid(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)
	canary := analyzer.generateCanary("T", schemas.ProbeTypeOAST)
	probe := ActiveProbe{Type: schemas.ProbeTypeOAST, Canary: canary, Source: schemas.SourceHeader}
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	analyzer.registerProbe(probe)
	interactionTime := time.Now().UTC()

	// FIX: Initialize using the embedded schema struct because OASTInteraction uses struct embedding.
	oastEvent := OASTInteraction{
		OASTInteraction: schemas.OASTInteraction{
			Canary:          canary,
			Protocol:        "DNS",
			SourceIP:        "1.2.3.4",
			InteractionTime: interactionTime,
		},
	}

	reporter.On("Report", mock.Anything).Return().Once()
	analyzer.eventsChan <- oastEvent
	finalizeCorrelationTest(t, analyzer)
	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]
	assert.Equal(t, schemas.SinkOASTInteraction, finding.Sink)
	assert.True(t, finding.IsConfirmed)
	require.NotNil(t, finding.OASTDetails)
	assert.Equal(t, "DNS", finding.OASTDetails.Protocol)
	assert.Equal(t, interactionTime, finding.OASTDetails.InteractionTime)
}

func TestProcessExecutionProof_Valid(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)
	canary := analyzer.generateCanary("XSS", schemas.ProbeTypeXSS)
	probe := ActiveProbe{Type: schemas.ProbeTypeXSS, Canary: canary, Source: schemas.SourceCookie}
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	analyzer.registerProbe(probe)

	proofEvent := ExecutionProofEvent{
		Canary:     canary,
		StackTrace: "at <anonymous>:1:1 (via img onerror)",
	}

	reporter.On("Report", mock.Anything).Return().Once()

	analyzer.eventsChan <- proofEvent

	finalizeCorrelationTest(t, analyzer)

	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]
	assert.Equal(t, schemas.SinkExecution, finding.Sink)
	assert.True(t, finding.IsConfirmed)
	assert.Equal(t, "Payload execution confirmed via JS callback.", finding.Detail)
	assert.Equal(t, canary, finding.Canary)
	assert.Equal(t, "at <anonymous>:1:1 (via img onerror)", finding.StackTrace)
}

func TestProcessPrototypePollutionConfirmation_Valid(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)
	canary := analyzer.generateCanary("PP", schemas.ProbeTypePrototypePollution)
	payload := fmt.Sprintf(`{"__proto__":{"scalpelPolluted":"%s"}}`, canary)
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	probe := ActiveProbe{Type: schemas.ProbeTypePrototypePollution, Canary: canary, Value: payload, Source: schemas.SourceLocalStorage}
	analyzer.registerProbe(probe)

	// The SinkEvent structure for PP confirmation
	confirmationEvent := SinkEvent{Type: schemas.SinkPrototypePollution, Value: canary, Detail: "scalpelPolluted"}

	reporter.On("Report", mock.Anything).Return().Once()
	analyzer.eventsChan <- confirmationEvent
	finalizeCorrelationTest(t, analyzer)

	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]
	assert.Equal(t, schemas.SinkPrototypePollution, finding.Sink)
	assert.True(t, finding.IsConfirmed)
	assert.Equal(t, "Successfully polluted Object.prototype property: scalpelPolluted", finding.Detail)
}

// Test Cases: False Positive Reduction Logic (Unit Tests)

func TestIsErrorPageContext_URLPathHeuristics(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	tests := []struct {
		name      string
		pageURL   string
		pageTitle string
		isError   bool
	}{
		// Existing logic checks
		{"Suffix Match 404", "http://example.com/page/404", "", true},
		{"Suffix Match 500", "http://example.com/page/500", "", true},
		{"Path Contains error.", "http://example.com/error.html", "", true},
		{"Path Contains /errors/", "http://example.com/errors/", "", true},
		{"Normal Page", "http://example.com/normal/page", "", false},
		{"Title Match 404", "http://example.com/normal", "404 Not Found", true},
		{"Title Match Server Error", "http://example.com/normal", "Internal Server Error", true},
		{"Normal Title", "http://example.com/normal", "Welcome!", false},

		// BUG: New failing tests for more flexible path matching
		{"Contains /404/", "http://example.com/error/404/details", "", true},
		{"Contains /500/", "http://example.com/a/500/b", "", true},
		{"Path ends with /404/", "http://example.com/error/404/", "", true},
		{"Path with query params", "http://example.com/path/404?a=1", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.isErrorPageContext(tt.pageURL, tt.pageTitle)
			assert.Equal(t, tt.isError, result, "URL: %s", tt.pageURL)
		})
	}
}

func TestIsContextValid(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	tests := []struct {
		name        string
		probeType   schemas.ProbeType
		sinkType    schemas.TaintSink
		sinkValue   string
		expectValid bool
	}{
		{"XSS -> innerHTML", schemas.ProbeTypeXSS, schemas.SinkInnerHTML, "<svg...>", true},
		{"SSTI -> Eval", schemas.ProbeTypeSSTI, schemas.SinkEval, "{{7*7}}", true},
		{"Generic -> Fetch URL", schemas.ProbeTypeGeneric, schemas.SinkFetchURL, "http://...", true},
		{"XSS -> Navigation (javascript:)", schemas.ProbeTypeXSS, schemas.SinkNavigation, "javascript:alert(1)", true},
		{"XSS -> WebSocketSend", schemas.ProbeTypeXSS, schemas.SinkWebSocketSend, "<svg...>", false},
		{"Generic -> innerHTML", schemas.ProbeTypeGeneric, schemas.SinkInnerHTML, "GENERIC_...", false},
		{"XSS -> Navigation (http)", schemas.ProbeTypeXSS, schemas.SinkNavigation, "http://example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := ActiveProbe{Type: tt.probeType}
			event := SinkEvent{Type: tt.sinkType, Value: tt.sinkValue}
			isValid := analyzer.isContextValid(event, probe)
			assert.Equal(t, tt.expectValid, isValid)
		})
	}
}

func TestCheckSanitization(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	canary := "CANARY123"
	tests := []struct {
		name            string
		probeType       schemas.ProbeType
		originalPayload string
		sinkValue       string
		wantLevel       SanitizationLevel
		wantDetail      string
	}{
		{"Intact (XSS)", schemas.ProbeTypeXSS, `<img src=x>` + canary, `<div><img src=x>` + canary + `</div>`, SanitizationNone, ""},
		{"HTML Stripped (XSS)", schemas.ProbeTypeXSS, `<img src=x>` + canary, `img src=x` + canary, SanitizationPartial, "HTML tags modified or stripped"},
		{"Quotes Escaped (XSS)", schemas.ProbeTypeXSS, `"onclick="` + canary, `\"onclick=\"` + canary, SanitizationPartial, "Quotes escaped"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := ActiveProbe{Type: tt.probeType, Value: tt.originalPayload}
			level, detail := analyzer.checkSanitization(tt.sinkValue, probe)
			assert.Equal(t, tt.wantLevel, level)
			if tt.wantDetail != "" {
				assert.Contains(t, detail, tt.wantDetail)
			}
		})
	}
}

// Test Cases: Background Workers (State Management)

func TestCleanupExpiredProbes(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
		// Configure very fast expiration and cleanup
		c.ProbeExpirationDuration = 20 * time.Millisecond
		c.CleanupInterval = 5 * time.Millisecond
	}, false)

	// Register probes
	analyzer.registerProbe(ActiveProbe{Canary: "ACTIVE_1", CreatedAt: time.Now()})
	analyzer.registerProbe(ActiveProbe{Canary: "EXPIRED_1", CreatedAt: time.Now().Add(-time.Minute)})

	analyzer.probesMutex.RLock()
	assert.Len(t, analyzer.activeProbes, 2)
	analyzer.probesMutex.RUnlock()

	// Start the background worker
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.producersWG.Add(1)
	go analyzer.cleanupExpiredProbes()

	// Wait for cleanup to occur
	assert.Eventually(t, func() bool {
		analyzer.probesMutex.RLock()
		defer analyzer.probesMutex.RUnlock()
		// Check if EXPIRED_1 is gone.
		_, exists := analyzer.activeProbes["EXPIRED_1"]
		return !exists
	}, 100*time.Millisecond, 5*time.Millisecond, "Expired probe was not cleaned up")

	// Stop the worker
	analyzer.backgroundCancel()
	analyzer.producersWG.Wait()
}

func TestEnqueueEvent_Backpressure_Logging(t *testing.T) {
	// Setup analyzer with a minimal buffer and observe logs
	core, hook := observer.New(zaptest.NewLogger(t).Core())
	logger := zaptest.NewLogger(t).WithOptions(zap.WrapCore(func(c zapcore.Core) zapcore.Core { return core }))

	analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
		c.EventChannelBuffer = 1
	}, false)
	analyzer.logger = logger
	analyzer.backgroundCtx = context.Background() // Mock active context

	// Fill the buffer and trigger backpressure
	analyzer.enqueueEvent(SinkEvent{Detail: "Event 1"}, "Test")
	analyzer.enqueueEvent(SinkEvent{Detail: "Event 2 (Dropped)"}, "Test")

	assert.Len(t, analyzer.eventsChan, 1)
	// Verify the warning log for backpressure
	assert.Equal(t, 1, hook.FilterMessage("Event channel full, dropping event. Consider increasing CorrelationWorkers or EventChannelBuffer.").Len())
}

func TestPollOASTInteractions_CanaryFiltering(t *testing.T) {
	analyzer, _, mockOAST := setupAnalyzer(t, func(c *Config) {
		c.OASTPollingInterval = 10 * time.Millisecond
	}, true)
	analyzer.registerProbe(ActiveProbe{Canary: "OAST_1", Type: schemas.ProbeTypeOAST})
	analyzer.registerProbe(ActiveProbe{Canary: "BLIND_XSS_2", Type: schemas.ProbeTypeXSS, Value: "fetch('http://oast.example.com/2')"})
	analyzer.registerProbe(ActiveProbe{Canary: "IRRELEVANT_3", Type: schemas.ProbeTypeGeneric})
	expectedInteractions := []schemas.OASTInteraction{{Canary: "OAST_1", Protocol: "DNS"}}
	mockOAST.On("GetInteractions", mock.Anything, mock.MatchedBy(func(canaries []string) bool {
		return assert.ElementsMatch(t, []string{"OAST_1", "BLIND_XSS_2"}, canaries)
	})).Return(expectedInteractions, nil).Maybe()
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.producersWG.Add(1)
	go analyzer.pollOASTInteractions()
	assert.Eventually(t, func() bool {
		return len(analyzer.eventsChan) >= 1
	}, 100*time.Millisecond, 5*time.Millisecond, "Expected OAST event to be enqueued")
	analyzer.backgroundCancel()
	analyzer.producersWG.Wait()
	mockOAST.AssertExpectations(t)
}

// Test Cases: Overall Analysis Flow (Analyze Method Integration)

func simulateCallback(t *testing.T, mockSession *mocks.MockSessionContext, callbackName string, event interface{}) {
	t.Helper()
	fn, ok := mockSession.GetExposedFunction(callbackName)
	if !ok {
		t.Fatalf("Callback function '%s' was not exposed on the mock session.", callbackName)
	}
	switch e := event.(type) {
	case SinkEvent:
		callback, ok := fn.(func(SinkEvent))
		if !ok {
			t.Fatalf("Exposed function '%s' has the wrong signature. Expected func(SinkEvent), got %T", callbackName, fn)
		}
		callback(e)
	case ExecutionProofEvent:
		callback, ok := fn.(func(ExecutionProofEvent))
		if !ok {
			t.Fatalf("Exposed function '%s' has the wrong signature. Expected func(ExecutionProofEvent), got %T", callbackName, fn)
		}
		callback(e)
	case ShimErrorEvent:
		callback, ok := fn.(func(ShimErrorEvent))
		if !ok {
			t.Fatalf("Exposed function '%s' has the wrong signature. Expected func(ShimErrorEvent), got %T", callbackName, fn)
		}
		callback(e)
	default:
		t.Fatalf("Unsupported event type (%T) passed to simulateCallback.", event)
	}
}

func TestAnalyze_HappyPath(t *testing.T) {
	analyzer, reporter, mockOAST := setupAnalyzer(t, func(c *Config) {
		c.Probes = []ProbeDefinition{{Type: schemas.ProbeTypeOAST, Payload: "http://{{.OASTServer}}/{{.Canary}}"}}
	}, true)
	ctx := context.Background()
	mockSession := mocks.NewMockSessionContext()
	mockSession.On("ID").Return("mock-session-id").Maybe()
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(3)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil).Once()
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil).Times(4)
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage("null"), nil).Once()
	mockSession.On("CollectArtifacts", mock.Anything).Return(&schemas.Artifacts{}, nil).Maybe()
	mockSession.On("Interact", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
		analyzer.probesMutex.RLock()
		var activeCanary string
		for canary, probe := range analyzer.activeProbes {
			if probe.Type == schemas.ProbeTypeOAST {
				activeCanary = canary
				break
			}
		}
		analyzer.probesMutex.RUnlock()
		require.NotEmpty(t, activeCanary)
		// VULN-FIX: Use the dynamic callback name from the analyzer instance.
		simulateCallback(t, mockSession, analyzer.jsCallbackSinkEventName, SinkEvent{Type: schemas.SinkFetchURL, Value: "http://oast.example.com/" + activeCanary})
		reporter.On("Report", mock.MatchedBy(func(f CorrelatedFinding) bool {
			return f.Canary == activeCanary && f.Sink == schemas.SinkFetchURL
		})).Once()
	})
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]schemas.OASTInteraction{}, nil).Maybe()
	err := analyzer.Analyze(ctx, mockSession)
	assert.NoError(t, err)
	mockSession.AssertExpectations(t)
	reporter.AssertExpectations(t)
	mockOAST.AssertCalled(t, "GetInteractions", mock.Anything, mock.Anything)
	assert.Error(t, analyzer.backgroundCtx.Err(), "Background context should be cancelled upon completion")
}

func TestAnalyze_Timeout(t *testing.T) {
	// Setup analyzer with a very short timeout
	analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
		c.AnalysisTimeout = 50 * time.Millisecond
	}, false)

	ctx := context.Background()
	mockSession := mocks.NewMockSessionContext()

	// Mock necessary calls for instrumentation and probing
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage("null"), nil).Maybe()

	// Mock interaction to block until the context is cancelled (simulating long interaction)
	mockSession.On("Interact", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		interactCtx := args.Get(0).(context.Context)
		<-interactCtx.Done() // Wait for cancellation (timeout)
	}).Return(context.Canceled).Once()

	startTime := time.Now()
	err := analyzer.Analyze(ctx, mockSession)
	duration := time.Since(startTime)

	// The error returned by Analyze itself might be nil if the timeout happens gracefully during probing/finalization
	assert.NoError(t, err)
	assert.Less(t, duration, 500*time.Millisecond, "Analysis should terminate shortly after timeout")

	// Ensure shutdown was called (background context should be done)
	assert.Error(t, analyzer.backgroundCtx.Err())

	mockSession.AssertExpectations(t)
}