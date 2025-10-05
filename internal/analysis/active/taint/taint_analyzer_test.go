// File: internal/analysis/active/taint/taint_analyzer_test.go
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
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
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

// MockOASTProvider mocks the OASTProvider interface.
type MockOASTProvider struct {
	mock.Mock
}

func (m *MockOASTProvider) GetInteractions(ctx context.Context, canaries []string) ([]schemas.OASTInteraction, error) {
	args := m.Called(ctx, canaries)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]schemas.OASTInteraction), args.Error(1)
}

func (m *MockOASTProvider) GetServerURL() string {
	args := m.Called()
	return args.String(0)
}

// Test Setup Helper

func setupAnalyzer(t *testing.T, configMod func(*Config), oastEnabled bool) (*Analyzer, *MockResultsReporter, *MockOASTProvider) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	targetURL, _ := url.Parse("http://example.com/app")

	// Default configuration optimized for testing
	config := Config{
		TaskID:          "test-task-123",
		Target:          targetURL,
		Probes:          DefaultProbes(),
		Sinks:           DefaultSinks(),
		AnalysisTimeout: 5 * time.Second,
		// Speed up background tasks
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
	var oastProvider *MockOASTProvider
	var oastProviderIface OASTProvider
	if oastEnabled {
		oastProvider = new(MockOASTProvider)
		oastProvider.On("GetServerURL").Return("oast.example.com").Maybe()
		oastProviderIface = oastProvider
	}

	analyzer, err := NewAnalyzer(config, reporter, oastProviderIface, logger)
	require.NoError(t, err, "NewAnalyzer should not return an error")
	return analyzer, reporter, oastProvider
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

	// Verify defaults
	assert.Equal(t, 1000, analyzer.config.EventChannelBuffer)
	assert.Equal(t, 10*time.Second, analyzer.config.FinalizationGracePeriod)
	assert.Equal(t, 10*time.Minute, analyzer.config.ProbeExpirationDuration)
	assert.Equal(t, 1*time.Minute, analyzer.config.CleanupInterval)
	assert.Equal(t, 20*time.Second, analyzer.config.OASTPollingInterval)
	assert.NotNil(t, analyzer.shimTemplate)
}

// Test Cases: Shim Generation and Instrumentation

func TestGenerateShim(t *testing.T) {
	// Setup analyzer with a specific, minimal set of sinks
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

	assert.Contains(t, shim, fmt.Sprintf(`SinkCallbackName: "%s"`, JSCallbackSinkEvent))
	assert.Contains(t, shim, fmt.Sprintf(`ProofCallbackName: "%s"`, JSCallbackExecutionProof))
	assert.Contains(t, shim, fmt.Sprintf(`ErrorCallbackName: "%s"`, JSCallbackShimError))

	// Verify the sinks configuration is correctly JSON encoded and injected
	expectedSinksJSON := `[{"Name":"eval","Type":"EVAL","Setter":false,"ArgIndex":0},{"Name":"Element.prototype.innerHTML","Type":"INNER_HTML","Setter":true,"ArgIndex":0,"ConditionID":"COND_TEST"}]`
	// Check against the format used in the JS template.
	assert.Contains(t, shim, "Sinks: "+expectedSinksJSON+",")
}

// TestInstrument_Success verifies the sequence of calls to instrument the browser session.
func TestInstrument_Success(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	mockSession := agent.NewMockSessionContext()
	ctx := context.Background()

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
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	// Use the agent package mock context as required by the interface definition.
	mockSession := agent.NewMockSessionContext()
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

// TestPreparePayload verifies placeholder replacement logic, including OAST scenarios.
func TestPreparePayload(t *testing.T) {
	// Setup analyzers with and without OAST
	analyzerNoOAST, _, _ := setupAnalyzer(t, nil, false)
	analyzerWithOAST, _, mockOAST := setupAnalyzer(t, nil, true)

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
	analyzer, _, _ := setupAnalyzer(t, nil, false)

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

			mockSession := agent.NewMockSessionContext()
			ctx := context.Background()

			var capturedScript string
			mockSession.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.Anything).Run(func(args mock.Arguments) {
				capturedScript = args.String(1)
			}).Return(json.RawMessage("null"), nil).Once()

			mockSession.On("Navigate", ctx, tt.targetURL).Return(nil).Once()

			// REFACTOR: Updated call signature (removed browserCtx)
			err := analyzer.probePersistentSources(ctx, mockSession, nil)
			require.NoError(t, err)

			mockSession.AssertExpectations(t)
			// Each probe creates 3 persistent sources (LocalStorage, SessionStorage, Cookie)
			assert.Len(t, analyzer.activeProbes, len(probes)*3)

			// Verify script content using flexible regex.
			assert.Regexp(t, `localStorage\.setItem\("sc_store_0", ".*"\);`, capturedScript)
			assert.Regexp(t, `sessionStorage\.setItem\("sc_store_0_s", ".*"\);`, capturedScript)
			assert.Regexp(t, `localStorage\.setItem\("sc_store_1", ".*"\);`, capturedScript)

			// Verify Cookie Flags (Simplified check)
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

	mockSession := agent.NewMockSessionContext()
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

	// REFACTOR: Updated call signature (removed browserCtx)
	err := analyzer.probeURLSources(ctx, mockSession, nil)
	require.NoError(t, err)

	mockSession.AssertExpectations(t)
	// Each probe creates 2 URL sources (Query, Hash)
	assert.Len(t, analyzer.activeProbes, len(probes)*2)

	// Verify Query URL
	require.NotEmpty(t, queryURL)
	parsedQ, err := url.Parse(queryURL)
	require.NoError(t, err)
	q := parsedQ.Query()

	assert.Equal(t, "1", q.Get("existing"))
	assert.Contains(t, q.Get("sc_test_0"), "<XSS&=")
	assert.Contains(t, q.Get("sc_test_0"), "SCALPEL_Q_XSS_")

	// Verify Hash URL
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

// Setup/Teardown helpers for correlation tests.
func setupCorrelationTest(t *testing.T) (*Analyzer, *MockResultsReporter) {
	t.Helper()
	analyzer, reporter, _ := setupAnalyzer(t, func(c *Config) {
		c.CleanupInterval = time.Hour
	}, false)

	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)
	return analyzer, reporter
}

func finalizeCorrelationTest(t *testing.T, analyzer *Analyzer) {
	t.Helper()
	if analyzer.backgroundCancel != nil {
		analyzer.backgroundCancel()
	}
	analyzer.producersWG.Wait()

	// In these unit tests, we manually close the channel as the full Analyze lifecycle isn't run.
	if analyzer.eventsChan != nil {
		// Use a defer/recover to prevent panic if the channel is somehow already closed (e.g. by Analyze finalizing early).
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

func TestProcessOASTInteraction_Valid(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)

	// Setup: Register an OAST probe
	canary := analyzer.generateCanary("T", schemas.ProbeTypeOAST)
	probe := ActiveProbe{Type: schemas.ProbeTypeOAST, Canary: canary, Source: schemas.SourceHeader}
	analyzer.registerProbe(probe)

	// Simulate OAST Interaction event
	interactionTime := time.Now().UTC()

	oastEvent := OASTInteraction{
		Canary:          canary,
		Protocol:        "DNS",
		SourceIP:        "1.2.3.4",
		InteractionTime: interactionTime,
	}

	reporter.On("Report", mock.Anything).Return().Once()

	analyzer.eventsChan <- oastEvent
	finalizeCorrelationTest(t, analyzer)

	// Verify Finding
	require.Len(t, reporter.GetFindings(), 1)
	finding := reporter.GetFindings()[0]

	assert.Equal(t, schemas.SinkOASTInteraction, finding.Sink)
	assert.True(t, finding.IsConfirmed)
	require.NotNil(t, finding.OASTDetails)
	assert.Equal(t, "DNS", finding.OASTDetails.Protocol)
	assert.Equal(t, interactionTime, finding.OASTDetails.InteractionTime)
}

// Test Cases: False Positive Reduction Logic (Unit Tests)

func TestIsContextValid(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, nil, false)

	tests := []struct {
		name        string
		probeType   schemas.ProbeType
		sinkType    schemas.TaintSink
		sinkValue   string
		expectValid bool
	}{
		// Valid Flows
		{"XSS -> innerHTML", schemas.ProbeTypeXSS, schemas.SinkInnerHTML, "<svg...>", true},
		{"SSTI -> Eval", schemas.ProbeTypeSSTI, schemas.SinkEval, "{{7*7}}", true},
		{"Generic -> Fetch URL", schemas.ProbeTypeGeneric, schemas.SinkFetchURL, "http://...", true},
		{"XSS -> Navigation (javascript:)", schemas.ProbeTypeXSS, schemas.SinkNavigation, "javascript:alert(1)", true},

		// Invalid Flows
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

// TestCheckSanitization tests the heuristics for detecting payload modification.
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
		// No Sanitization
		{
			"Intact (XSS)", schemas.ProbeTypeXSS,
			`<img src=x>` + canary,
			`<div><img src=x>` + canary + `</div>`,
			SanitizationNone, "",
		},
		// HTML Sanitization
		{
			"HTML Stripped (XSS)", schemas.ProbeTypeXSS,
			`<img src=x>` + canary,
			`img src=x` + canary,
			SanitizationPartial, "HTML tags modified or stripped",
		},
		// Quote escaping
		{
			"Quotes Escaped (XSS)", schemas.ProbeTypeXSS,
			`"onclick="` + canary,
			`\"onclick=\"` + canary,
			SanitizationPartial, "Quotes escaped",
		},
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

func TestPollOASTInteractions_CanaryFiltering(t *testing.T) {
	analyzer, _, mockOAST := setupAnalyzer(t, func(c *Config) {
		c.OASTPollingInterval = 10 * time.Millisecond
	}, true)

	// Register different types of probes
	analyzer.registerProbe(ActiveProbe{Canary: "OAST_1", Type: schemas.ProbeTypeOAST})
	analyzer.registerProbe(ActiveProbe{Canary: "BLIND_XSS_2", Type: schemas.ProbeTypeXSS, Value: "fetch('http://oast.example.com/2')"})
	analyzer.registerProbe(ActiveProbe{Canary: "IRRELEVANT_3", Type: schemas.ProbeTypeGeneric})

	expectedInteractions := []schemas.OASTInteraction{{Canary: "OAST_1", Protocol: "DNS"}}

	// Use .Maybe() to allow for multiple poll cycles.
	mockOAST.On("GetInteractions", mock.Anything, mock.MatchedBy(func(canaries []string) bool {
		return assert.ElementsMatch(t, []string{"OAST_1", "BLIND_XSS_2"}, canaries)
	})).Return(expectedInteractions, nil).Maybe()

	// Start the poller
	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.producersWG.Add(1)
	go analyzer.pollOASTInteractions()

	// Wait for events to be processed
	assert.Eventually(t, func() bool {
		return len(analyzer.eventsChan) >= 1
	}, 100*time.Millisecond, 5*time.Millisecond, "Expected OAST event to be enqueued")

	analyzer.backgroundCancel()
	analyzer.producersWG.Wait()

	mockOAST.AssertExpectations(t)
}

// Test Cases: Overall Analysis Flow (Analyze Method Integration)

// Helper function to simulate a callback invocation in tests.
// This is necessary because the mock framework (testify/mock) doesn't natively support invoking captured function arguments.
func simulateCallback(t *testing.T, mockSession *agent.MockSessionContext, callbackName string, event interface{}) {
	t.Helper()
	fn, ok := mockSession.GetExposedFunction(callbackName)
	if !ok {
		t.Fatalf("Callback function '%s' was not exposed on the mock session.", callbackName)
	}

	// Perform type assertion based on the expected event type.
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
		// Ensure an OAST probe is present.
		c.Probes = []ProbeDefinition{{Type: schemas.ProbeTypeOAST, Payload: "http://{{.OASTServer}}/{{.Canary}}"}}
	}, true)

	ctx := context.Background()
	mockSession := agent.NewMockSessionContext()

	// --- Mock Expectations (Simplified for brevity) ---
	mockSession.On("ID").Return("mock-session-id").Maybe()
	// Ensure callbacks are exposed so we can retrieve them later.
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(3)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil).Once()
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil).Times(4) // Initial, Refresh, Query, Hash
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage("null"), nil).Once()
	mockSession.On("CollectArtifacts", mock.Anything).Return(&schemas.Artifacts{}, nil).Maybe()

	// Interaction Phase
	mockSession.On("Interact", mock.Anything, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
		// Simulate concurrent finding detection
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

		// Use the helper to invoke the callback captured by ExposeFunction.
		simulateCallback(t, mockSession, JSCallbackSinkEvent, SinkEvent{Type: schemas.SinkFetchURL, Value: "http://oast.example.com/" + activeCanary})

		reporter.On("Report", mock.MatchedBy(func(f CorrelatedFinding) bool {
			return f.Canary == activeCanary && f.Sink == schemas.SinkFetchURL
		})).Once()
	})

	// Background Workers (OAST Polling)
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]schemas.OASTInteraction{}, nil).Maybe()

	// --- Execute Analysis ---
	err := analyzer.Analyze(ctx, mockSession)
	assert.NoError(t, err)

	// --- Verification ---
	mockSession.AssertExpectations(t)
	reporter.AssertExpectations(t)
	mockOAST.AssertCalled(t, "GetInteractions", mock.Anything, mock.Anything)
	assert.Error(t, analyzer.backgroundCtx.Err())
}