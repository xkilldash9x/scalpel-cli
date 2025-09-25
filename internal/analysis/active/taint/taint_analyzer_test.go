// File: internal/analysis/active/taint/taint_analyzer_test.go
package taint

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	// "regexp" // Removed unused import
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Mock Definitions

// MockBrowserInteractor is removed as it's no longer used in these tests.

// MockSessionContext mocks the SessionContext interface (must match schemas.SessionContext).
type MockSessionContext struct {
	mock.Mock
	exposedFunctions map[string]interface{}
	mutex            sync.Mutex
}

func NewMockSessionContext() *MockSessionContext {
	return &MockSessionContext{
		exposedFunctions: make(map[string]interface{}),
	}
}

// FIX: Added the missing ID method to satisfy the SessionContext interface.
func (m *MockSessionContext) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockSessionContext) InjectScriptPersistently(ctx context.Context, script string) error {
	args := m.Called(ctx, script)
	return args.Error(0)
}

func (m *MockSessionContext) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	args := m.Called(ctx, name, function)
	if args.Error(0) == nil {
		m.exposedFunctions[name] = function
	}
	return args.Error(0)
}

// SimulateCallback allows tests to invoke the exposed Go functions.
func (m *MockSessionContext) SimulateCallback(t *testing.T, name string, payload interface{}) {
	t.Helper()
	m.mutex.Lock()
	fn, exists := m.exposedFunctions[name]
	m.mutex.Unlock()

	if !exists {
		t.Fatalf("function %s not exposed by analyzer", name)
	}

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

// FIX: Signature updated to match the interface, which now includes an 'options' parameter.
func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string, options interface{}) error {
	args := m.Called(ctx, script, options)
	return args.Error(0)
}

func (m *MockSessionContext) Navigate(ctx context.Context, url string) error {
	args := m.Called(ctx, url)
	return args.Error(0)
}

// FIX: Signature updated to match the interface (removed context.Context).
func (m *MockSessionContext) WaitForAsync(milliseconds int) error {
	args := m.Called(milliseconds)
	return args.Error(0)
}

func (m *MockSessionContext) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

// FIX: Signature updated to match schemas.SessionContext (Close(context.Context) error).
func (m *MockSessionContext) Close(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// FIX: Implement all missing methods required by schemas.SessionContext.
func (m *MockSessionContext) Click(selector string) error {
	args := m.Called(selector)
	return args.Error(0)
}

func (m *MockSessionContext) Type(selector string, text string) error {
	args := m.Called(selector, text)
	return args.Error(0)
}

func (m *MockSessionContext) Submit(selector string) error {
	args := m.Called(selector)
	return args.Error(0)
}

func (m *MockSessionContext) ScrollPage(direction string) error {
	args := m.Called(direction)
	return args.Error(0)
}

func (m *MockSessionContext) GetContext() context.Context {
	args := m.Called()
	if args.Get(0) == nil {
		return nil // Return nil if not mocked, to avoid panicking on type assertion
	}
	return args.Get(0).(context.Context)
}


// FIX: Updated the AddFinding signature to return an error, matching the interface.
func (m *MockSessionContext) AddFinding(finding schemas.Finding) error {
	args := m.Called(finding)
	return args.Error(0)
}

// FIX: Corrected the signature to match the interface: no arguments, returns a pointer.
func (m *MockSessionContext) CollectArtifacts() (*schemas.Artifacts, error) {
	args := m.Called()
	var artifacts *schemas.Artifacts
	if args.Get(0) != nil {
		artifacts = args.Get(0).(*schemas.Artifacts)
	}
	return artifacts, args.Error(1)
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

// FIX: Updated return signature, removed BrowserInteractor management.
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

	// FIX: Updated NewAnalyzer call signature (removed browser argument).
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

	// FIX: Updated NewAnalyzer call signature.
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
	// FIX: Updated setupAnalyzer usage
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
	// FIX: Updated setupAnalyzer usage
	analyzer, _, _ := setupAnalyzer(t, nil, false)
	mockSession := NewMockSessionContext()
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
	// FIX: Updated setupAnalyzer usage
	analyzer, _, _ := setupAnalyzer(t, nil, false)
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

func TestGenerateCanary(t *testing.T) {
	// FIX: Updated setupAnalyzer usage
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
	// FIX: Updated setupAnalyzer usage
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
	// FIX: Updated setupAnalyzer usage
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
			// FIX: Updated setupAnalyzer usage
			analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
				c.Probes = probes
				c.Target, _ = url.Parse(tt.targetURL)
			}, false)

			mockSession := NewMockSessionContext()
			ctx := context.Background()

			var capturedScript string
			// FIX: Updated mock for ExecuteScript to include the third 'options' argument.
			mockSession.On("ExecuteScript", ctx, mock.AnythingOfType("string"), mock.Anything).Run(func(args mock.Arguments) {
				capturedScript = args.String(1)
			}).Return(nil).Once()

			mockSession.On("Navigate", ctx, tt.targetURL).Return(nil).Once()

			// FIX: Pass nil for the new humanoid and browserCtx arguments.
			err := analyzer.probePersistentSources(ctx, mockSession, nil, nil)
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
	// FIX: Updated setupAnalyzer usage
	analyzer, _, _ := setupAnalyzer(t, func(c *Config) {
		c.Probes = probes
		c.Target, _ = url.Parse("http://example.com/page?existing=1")
	}, false)

	mockSession := NewMockSessionContext()
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

	// FIX: Pass nil for the new humanoid and browserCtx arguments.
	err := analyzer.probeURLSources(ctx, mockSession, nil, nil)
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
	// FIX: Updated setupAnalyzer usage
	analyzer, reporter, _ := setupAnalyzer(t, func(c *Config) {
		c.CleanupInterval = time.Hour
	}, false)

	analyzer.backgroundCtx, analyzer.backgroundCancel = context.WithCancel(context.Background())
	analyzer.wg.Add(1)
	// FIX: Call the correct worker method instead of the non-existent 'correlate'.
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
	// FIX: Use schemas.SourceURLParam
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
	// FIX: Use schemas.SourceURLParam
	assert.Equal(t, schemas.SourceURLParam, finding.Origin)
	assert.False(t, finding.IsConfirmed)
	assert.Equal(t, SanitizationNone, finding.SanitizationLevel)
	assert.Equal(t, "at app.js:42", finding.StackTrace)
}

func TestProcessOASTInteraction_Valid(t *testing.T) {
	analyzer, reporter := setupCorrelationTest(t)

	// Setup: Register an OAST probe
	canary := analyzer.generateCanary("T", schemas.ProbeTypeOAST)
	// FIX: Use schemas.SourceHeader
	probe := ActiveProbe{Type: schemas.ProbeTypeOAST, Canary: canary, Source: schemas.SourceHeader}
	analyzer.registerProbe(probe)

	// Simulate OAST Interaction event
	interactionTime := time.Now().UTC()

	// FIX: Use the local taint.OASTInteraction type which implements Event interface.
	oastEvent := OASTInteraction{
		Canary:          canary,
		Protocol:        "DNS",
		SourceIP:        "1.2.3.4",
		InteractionTime: interactionTime,
	}

	reporter.On("Report", mock.Anything).Return().Once()

	// FIX: Send the local type which implements Event interface.
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
	// FIX: Updated setupAnalyzer usage
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
		// FIX: Use SinkFetchURL (no underscore)
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
	// FIX: Updated setupAnalyzer usage
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
	// FIX: Updated setupAnalyzer usage
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

func TestAnalyze_HappyPath(t *testing.T) {
	// FIX: Updated setupAnalyzer usage (removed mockBrowser)
	analyzer, reporter, mockOAST := setupAnalyzer(t, func(c *Config) {
		// Ensure an OAST probe is present.
		c.Probes = []ProbeDefinition{{Type: schemas.ProbeTypeOAST, Payload: "http://{{.OASTServer}}/{{.Canary}}"}}
	}, true)

	ctx := context.Background()
	mockSession := NewMockSessionContext()

	// --- Mock Expectations (Simplified for brevity) ---
	mockSession.On("ID").Return("mock-session-id").Maybe()
	// FIX: Add the missing expectation for the GetContext() call.
	mockSession.On("GetContext").Return(nil).Maybe()
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil).Times(3)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil).Once()
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(nil).Times(4) // Initial, Refresh, Query, Hash
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(nil).Once()
	mockSession.On("CollectArtifacts").Return(&schemas.Artifacts{}, nil).Maybe()


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

		// FIX: Use SinkFetchURL
		mockSession.SimulateCallback(t, JSCallbackSinkEvent, SinkEvent{Type: schemas.SinkFetchURL, Value: "http://oast.example.com/" + activeCanary})

		reporter.On("Report", mock.MatchedBy(func(f CorrelatedFinding) bool {
			// FIX: Use SinkFetchURL
			return f.Canary == activeCanary && f.Sink == schemas.SinkFetchURL
		})).Once()
	})

	// Background Workers (OAST Polling)
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]schemas.OASTInteraction{}, nil).Maybe()

	// --- Execute Analysis ---
	// FIX: Pass the session context to Analyze.
	err := analyzer.Analyze(ctx, mockSession)
	assert.NoError(t, err)

	// --- Verification ---
	mockSession.AssertExpectations(t)
	reporter.AssertExpectations(t)
	mockOAST.AssertCalled(t, "GetInteractions", mock.Anything, mock.Anything)
	assert.Error(t, analyzer.backgroundCtx.Err())
}