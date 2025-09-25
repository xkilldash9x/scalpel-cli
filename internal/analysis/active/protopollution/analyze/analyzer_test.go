package analyze

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Mock Definitions --

// MockBrowserManager mocks the schemas.BrowserManager interface.
type MockBrowserManager struct {
	mock.Mock
}

// FIX: Updated the function signature to include the new `findingsChan` parameter.
func (m *MockBrowserManager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
	findingsChan chan<- schemas.Finding,
) (schemas.SessionContext, error) {
	// FIX: Added the new channel to the list of arguments passed to the mock framework.
	args := m.Called(sessionCtx, cfg, persona, taintTemplate, taintConfig, findingsChan)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(schemas.SessionContext), args.Error(1)
}

func (m *MockBrowserManager) Shutdown(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockSessionContext mocks the schemas.SessionContext interface.
// NOTE: This mock has been made complete by implementing all methods from the interface.
type MockSessionContext struct {
	mock.Mock
	callbackFunc func(payload PollutionProofEvent)
	mu           sync.Mutex
}

// --- Start of schemas.SessionContext interface implementation ---

func (m *MockSessionContext) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockSessionContext) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cb, ok := function.(func(PollutionProofEvent)); ok {
		m.callbackFunc = cb
	}
	args := m.Called(ctx, name, function)
	return args.Error(0)
}

func (m *MockSessionContext) InjectScriptPersistently(ctx context.Context, script string) error {
	args := m.Called(ctx, script)
	return args.Error(0)
}

func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string, res interface{}) error {
	args := m.Called(ctx, script, res)
	return args.Error(0)
}

func (m *MockSessionContext) Navigate(ctx context.Context, url string) error {
	args := m.Called(ctx, url)
	return args.Error(0)
}

func (m *MockSessionContext) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockSessionContext) Close(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockSessionContext) Click(selector string) error {
	return m.Called(selector).Error(0)
}

func (m *MockSessionContext) Type(selector string, text string) error {
	return m.Called(selector, text).Error(0)
}

func (m *MockSessionContext) Submit(selector string) error {
	return m.Called(selector).Error(0)
}

func (m *MockSessionContext) ScrollPage(direction string) error {
	return m.Called(direction).Error(0)
}

func (m *MockSessionContext) WaitForAsync(milliseconds int) error {
	return m.Called(milliseconds).Error(0)
}

func (m *MockSessionContext) GetContext() context.Context {
	args := m.Called()
	if ctx, ok := args.Get(0).(context.Context); ok {
		return ctx
	}
	return context.Background()
}

func (m *MockSessionContext) CollectArtifacts() (*schemas.Artifacts, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*schemas.Artifacts), args.Error(1)
}

func (m *MockSessionContext) AddFinding(finding schemas.Finding) error {
	args := m.Called(finding)
	return args.Error(0)
}

// --- End of interface implementation ---

// SimulateCallback is a test helper to invoke the registered callback function.
func (m *MockSessionContext) SimulateCallback(t *testing.T, functionName string, event PollutionProofEvent) {
	t.Helper()
	m.mu.Lock()
	cb := m.callbackFunc
	m.mu.Unlock()
	require.NotNil(t, cb, "Callback function was not set via ExposeFunction")
	// Simulate the asynchronous nature of the browser callback.
	go cb(event)
}
func generateCanary() string {
	return uuid.NewString()[:8]
}

// -- Test Cases --

func TestNewAnalyzer(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(MockBrowserManager)
	cfg := config.ProtoPollutionConfig{
		Enabled: true,
		// WaitDuration is 0 (invalid)
	}

	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)

	assert.NotNil(t, analyzer)
	assert.Equal(t, logger.Named("pp_analyzer"), analyzer.logger)
	assert.Equal(t, mockBrowserManager, analyzer.browser)
	// Check that the default wait duration is applied.
	expectedCfg := cfg
	expectedCfg.WaitDuration = 8 * time.Second
	assert.Equal(t, expectedCfg, analyzer.config)
}

func TestAnalyze_FindingFound(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(MockBrowserManager)
	mockSession := new(MockSessionContext)
	cfg := config.ProtoPollutionConfig{
		WaitDuration: 150 * time.Millisecond,
	}
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)

	ctx := context.Background()
	testURL := "http://example.com/test"
	var capturedCanary string

	// --- Mocks ---
	// FIX: Added mock.Anything to match the new findings channel argument.
	mockBrowserManager.On("NewAnalysisContext", ctx, mock.Anything, schemas.Persona{}, "", "", mock.Anything).Return(mockSession, nil).Once()

	// CRITICAL: Updated the type signature to reflect the new package name 'analyze'.
	mockSession.On("ExposeFunction", ctx, jsCallbackName, mock.AnythingOfType("func(analyze.PollutionProofEvent)")).Return(nil).Once()

	mockSession.On("InjectScriptPersistently", ctx, mock.AnythingOfType("string")).Return(nil).Once().Run(func(args mock.Arguments) {
		script := args.String(1)
		// Extract the canary from the injected script.
		re := regexp.MustCompile(`let pollutionCanary = '([^']+)';`)
		matches := re.FindStringSubmatch(script)

		if len(matches) < 2 {
			// Robustness check for go:embed issues or shim changes.
			t.Logf("Injected script content:\n%s", script)
			require.FailNow(t, "Could not find canary in injected script. Check if go:embed is working in the test environment.")
		}

		capturedCanary = matches[1]
		assert.True(t, strings.HasPrefix(capturedCanary, "sclp_"), "Canary should have the 'sclp_' prefix")
	})

	mockSession.On("Navigate", ctx, testURL).Return(nil).Once().Run(func(args mock.Arguments) {
		// Simulate the browser finding a vulnerability after a short delay.
		go func() {
			time.Sleep(20 * time.Millisecond)
			require.NotEmpty(t, capturedCanary, "Canary was not captured from injected script before navigation simulation")
			mockSession.SimulateCallback(t, jsCallbackName, PollutionProofEvent{
				Source:     "URL_SearchParams",
				Canary:     capturedCanary,
				Vector:     "__proto__[polluted]=true",
				StackTrace: "at trigger (app.js:10)",
			})
		}()
	})
	mockSession.On("Close", ctx).Return(nil).Once()

	// --- Execute ---
	findings, err := analyzer.Analyze(ctx, "task-1", testURL)

	// --- Assertions ---
	require.NoError(t, err)
	require.Len(t, findings, 1, "Expected exactly one finding")

	finding := findings[0]
	assert.Equal(t, "Client-Side Prototype Pollution", finding.Vulnerability.Name)
	assert.Equal(t, schemas.SeverityHigh, finding.Severity)
	assert.Equal(t, "task-1", finding.TaskID)
	assert.Equal(t, testURL, finding.Target)

	// Validate the evidence structure.
	var evidenceData PollutionProofEvent
	err = json.Unmarshal([]byte(finding.Evidence), &evidenceData)
	require.NoError(t, err)
	assert.Equal(t, capturedCanary, evidenceData.Canary)
	assert.Equal(t, "at trigger (app.js:10)", evidenceData.StackTrace)

	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestAnalyze_NoFinding(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(MockBrowserManager)
	mockSession := new(MockSessionContext)
	cfg := config.ProtoPollutionConfig{
		WaitDuration: 50 * time.Millisecond,
	}
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)
	ctx := context.Background()

	// FIX: Added mock.Anything for the new channel parameter.
	mockBrowserManager.On("NewAnalysisContext", ctx, mock.Anything, schemas.Persona{}, "", "", mock.Anything).Return(mockSession, nil)
	// Updated the type signature.
	mockSession.On("ExposeFunction", ctx, jsCallbackName, mock.AnythingOfType("func(analyze.PollutionProofEvent)")).Return(nil)
	mockSession.On("InjectScriptPersistently", ctx, mock.AnythingOfType("string")).Return(nil)
	mockSession.On("Navigate", ctx, "http://clean.example.com").Return(nil)
	mockSession.On("Close", ctx).Return(nil)

	findings, err := analyzer.Analyze(ctx, "task-clean", "http://clean.example.com")

	assert.NoError(t, err)
	assert.Empty(t, findings)
	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestAnalyze_BrowserError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(MockBrowserManager)
	cfg := config.ProtoPollutionConfig{}
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)
	ctx := context.Background()
	expectedErr := errors.New("failed to launch browser")

	// FIX: Added mock.Anything for the new channel parameter.
	mockBrowserManager.On("NewAnalysisContext", ctx, mock.Anything, schemas.Persona{}, "", "", mock.Anything).Return(nil, expectedErr)

	findings, err := analyzer.Analyze(ctx, "task-fail", "http://example.com")

	assert.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
	assert.Contains(t, err.Error(), "could not initialize browser analysis context")
	assert.Nil(t, findings)
	mockBrowserManager.AssertExpectations(t)
}

// --- Production Quality Enhancements: Additional Tests ---

// TestAnalyze_ContextCancellation verifies that the analysis stops promptly if the context is cancelled during the wait period.
func TestAnalyze_ContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(MockBrowserManager)
	mockSession := new(MockSessionContext)
	// Set a long wait duration to ensure cancellation happens during the wait phase.
	cfg := config.ProtoPollutionConfig{WaitDuration: 5 * time.Second}
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)

	ctx, cancel := context.WithCancel(context.Background())

	// Use mock.Anything for context arguments as the context object might be wrapped or cancelled.
	// FIX: Added mock.Anything for the new channel parameter.
	mockBrowserManager.On("NewAnalysisContext", mock.Anything, mock.Anything, schemas.Persona{}, "", "", mock.Anything).Return(mockSession, nil)
	// Updated the type signature.
	mockSession.On("ExposeFunction", mock.Anything, jsCallbackName, mock.AnythingOfType("func(analyze.PollutionProofEvent)")).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.AnythingOfType("string")).Return(nil)
	mockSession.On("Navigate", mock.Anything, "http://slow.example.com").Return(nil).Run(func(args mock.Arguments) {
		// Cancel the context shortly after navigation starts.
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()
	})
	// Close expectation must handle the potentially cancelled context passed via defer.
	mockSession.On("Close", mock.Anything).Return(nil)

	startTime := time.Now()
	findings, err := analyzer.Analyze(ctx, "task-cancel", "http://slow.example.com")
	duration := time.Since(startTime)

	assert.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled, "Analysis should return a context canceled error")
	assert.Empty(t, findings)
	assert.Less(t, duration, 1*time.Second, "Analysis should stop quickly after cancellation")

	// Give a moment for the deferred Close() to be called.
	time.Sleep(20 * time.Millisecond)
	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

// TestAnalyze_InstrumentationError verifies failures during session setup are handled correctly.
func TestAnalyze_InstrumentationError(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(MockBrowserManager)
	mockSession := new(MockSessionContext)
	cfg := config.ProtoPollutionConfig{}
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)
	ctx := context.Background()
	expectedErr := errors.New("browser disconnected")

	// FIX: Added mock.Anything for the new channel parameter.
	mockBrowserManager.On("NewAnalysisContext", ctx, mock.Anything, schemas.Persona{}, "", "", mock.Anything).Return(mockSession, nil)
	// Fail during ExposeFunction
	mockSession.On("ExposeFunction", ctx, jsCallbackName, mock.Anything).Return(expectedErr)
	mockSession.On("Close", ctx).Return(nil) // Ensure Close is still called due to defer

	findings, err := analyzer.Analyze(ctx, "task-instrument-fail", "http://example.com")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to instrument browser session")
	assert.ErrorIs(t, err, expectedErr)
	assert.Nil(t, findings)
	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

// TestAnalyze_MismatchedCanary verifies that stray callbacks with incorrect canaries are ignored (ensuring isolation).
func TestAnalyze_MismatchedCanary(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockBrowserManager := new(MockBrowserManager)
	mockSession := new(MockSessionContext)
	cfg := config.ProtoPollutionConfig{WaitDuration: 100 * time.Millisecond}
	analyzer := NewAnalyzer(logger, mockBrowserManager, cfg)
	ctx := context.Background()

	// FIX: Added mock.Anything for the new channel parameter.
	mockBrowserManager.On("NewAnalysisContext", ctx, mock.Anything, schemas.Persona{}, "", "", mock.Anything).Return(mockSession, nil)
	// Updated the type signature.
	mockSession.On("ExposeFunction", ctx, jsCallbackName, mock.AnythingOfType("func(analyze.PollutionProofEvent)")).Return(nil)
	mockSession.On("InjectScriptPersistently", ctx, mock.AnythingOfType("string")).Return(nil)
	mockSession.On("Navigate", ctx, "http://example.com").Return(nil).Run(func(args mock.Arguments) {
		go func() {
			time.Sleep(10 * time.Millisecond)
			// Simulate a callback with an incorrect canary.
			mockSession.SimulateCallback(t, jsCallbackName, PollutionProofEvent{
				Source: "StrayEvent",
				Canary: "wrong_canary",
				Vector: "N/A",
			})
		}()
	})
	mockSession.On("Close", ctx).Return(nil)

	findings, err := analyzer.Analyze(ctx, "task-mismatch", "http://example.com")

	assert.NoError(t, err)
	assert.Empty(t, findings, "Should not generate findings for mismatched canaries")
	mockBrowserManager.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

// TestHandlePollutionProof_ChannelFull verifies the non-blocking send mechanism to prevent deadlocks.
func TestHandlePollutionProof_ChannelFull(t *testing.T) {
	logger := zaptest.NewLogger(t)
	// Create a context where the channel is already full (buffer size 0).
	aCtx := &analysisContext{
		taskID:    "task-full",
		targetURL: "http://example.com",
		canary:    "canary123",
		// Create a channel with buffer 0 to simulate fullness immediately.
		findingChan: make(chan schemas.Finding, 0),
		logger:      logger,
	}

	event := PollutionProofEvent{
		Source: "Test",
		Canary: aCtx.canary, // Correct canary
		Vector: "vector",
	}

	// This call should execute without blocking due to the select-default pattern.
	done := make(chan bool)
	go func() {
		aCtx.handlePollutionProof(event)
		done <- true
	}()

	select {
	case <-done:
		// Success: the function returned without blocking.
	case <-time.After(1 * time.Second):
		t.Fatal("handlePollutionProof blocked when the channel was full, potential deadlock risk.")
	}

	// Verify that the finding was dropped (channel is still empty).
	assert.Len(t, aCtx.findingChan, 0, "Finding should have been dropped as the channel was full.")
}

func TestDetermineVulnerability(t *testing.T) {
	tests := []struct {
		source           string
		expectedName     string
		expectedSeverity schemas.Severity
	}{
		{"URL_SearchParams", "Client-Side Prototype Pollution", schemas.SeverityHigh},
		{"Fetch_Response_JSON_payload", "Client-Side Prototype Pollution", schemas.SeverityHigh},
		{"DOM_Clobbering", "DOM Clobbering", schemas.SeverityMedium},
		{"Something_DOM_Clobbering_Related", "DOM Clobbering", schemas.SeverityMedium},
		{"Unknown_Source", "Client-Side Prototype Pollution", schemas.SeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			name, _, severity := determineVulnerability(tt.source)
			assert.Equal(t, tt.expectedName, name)
			assert.Equal(t, tt.expectedSeverity, severity)
		})
	}
}

func TestGetRecommendation(t *testing.T) {
	ppRec := getRecommendation("Client-Side Prototype Pollution")
	assert.Contains(t, ppRec, "Object.freeze(Object.prototype)")

	dcRec := getRecommendation("DOM Clobbering")
	assert.Contains(t, dcRec, "Avoid using `id` attributes")

	unknownRec := getRecommendation("Some Other Vulnerability")
	assert.Contains(t, unknownRec, "Object.freeze(Object.prototype)", "Should default to Prototype Pollution recommendation")
}
