// internal/worker/adapters/taint_adapter_test.go
package adapters_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/zap/zaptest"

	// Assuming these import paths based on the provided files
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	// Assuming a config package exists and is needed for context setup
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// --- Mocks (Defined locally for the test suite based on schemas.go interfaces) ---

type MockBrowserManager struct {
	mock.Mock
}

func (m *MockBrowserManager) NewAnalysisContext(sessionCtx context.Context, cfg interface{}, persona schemas.Persona, taintTemplate string, taintConfig string, findingsChan chan<- schemas.Finding) (schemas.SessionContext, error) {
    // Ensure the adapter passes the Task object, as required by the implementation
    if _, ok := cfg.(schemas.Task); !ok {
         if _, ok := cfg.(*schemas.Task); !ok {
            panic("BrowserManager.NewAnalysisContext must be called with a schemas.Task object")
         }
    }

	args := m.Called(sessionCtx, cfg, persona, taintTemplate, taintConfig, findingsChan)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(schemas.SessionContext), args.Error(1)
}

func (m *MockBrowserManager) Shutdown(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

type MockOASTProvider struct {
	mock.Mock
}

func (m *MockOASTProvider) GetInteractions(ctx context.Context, canaries []string) ([]schemas.OASTInteraction, error) {
	args := m.Called(ctx, canaries)
	return args.Get(0).([]schemas.OASTInteraction), args.Error(1)
}

func (m *MockOASTProvider) GetServerURL() string {
	return m.Called().String(0)
}

// MockSessionContext must implement the full schemas.SessionContext interface.
type MockSessionContext struct {
	mock.Mock
}

// Implement all methods required by schemas.SessionContext, delegating to mock.Mock
func (m *MockSessionContext) ID() string { return m.Called().String(0) }
func (m *MockSessionContext) Close(ctx context.Context) error { return m.Called(ctx).Error(0) }
func (m *MockSessionContext) Navigate(ctx context.Context, url string) error { return m.Called(ctx, url).Error(0) }
func (m *MockSessionContext) Click(ctx context.Context, selector string) error { return m.Called(ctx, selector).Error(0) }
func (m *MockSessionContext) Type(ctx context.Context, selector string, text string) error { return m.Called(ctx, selector, text).Error(0) }
func (m *MockSessionContext) Submit(ctx context.Context, selector string) error { return m.Called(ctx, selector).Error(0) }
func (m *MockSessionContext) ScrollPage(ctx context.Context, direction string) error { return m.Called(ctx, direction).Error(0) }
func (m *MockSessionContext) WaitForAsync(ctx context.Context, milliseconds int) error { return m.Called(ctx, milliseconds).Error(0) }
func (m *MockSessionContext) ExposeFunction(ctx context.Context, name string, function interface{}) error { return m.Called(ctx, name, function).Error(0) }
func (m *MockSessionContext) InjectScriptPersistently(ctx context.Context, script string) error { return m.Called(ctx, script).Error(0) }
func (m *MockSessionContext) Interact(ctx context.Context, config schemas.InteractionConfig) error { return m.Called(ctx, config).Error(0) }
func (m *MockSessionContext) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) { 
	args := m.Called(ctx)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
	return args.Get(0).(*schemas.Artifacts), args.Error(1)
}
func (m *MockSessionContext) AddFinding(ctx context.Context, finding schemas.Finding) error { return m.Called(ctx, finding).Error(0) }
func (m *MockSessionContext) Sleep(ctx context.Context, d time.Duration) error { return m.Called(ctx, d).Error(0) }
func (m *MockSessionContext) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error { return m.Called(ctx, data).Error(0) }
func (m *MockSessionContext) SendKeys(ctx context.Context, keys string) error { return m.Called(ctx, keys).Error(0) }
func (m *MockSessionContext) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	args := m.Called(ctx, selector)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
	return args.Get(0).(*schemas.ElementGeometry), args.Error(1)
}
func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	retArgs := m.Called(ctx, script, args)
	return retArgs.Get(0).(json.RawMessage), retArgs.Error(1)
}

// --- Test Setup ---

func setupTaintAdapterTest(t *testing.T) (*adapters.TaintAdapter, *core.AnalysisContext, *MockBrowserManager, *MockSessionContext, *MockOASTProvider) {
	adapter := adapters.NewTaintAdapter()
	logger := zaptest.NewLogger(t)
	mockBM := new(MockBrowserManager)
	mockSession := new(MockSessionContext)
	mockOAST := new(MockOASTProvider)
	findingsChan := make(chan schemas.Finding, 10)

	// Setup a minimal configuration required by the adapter initialization logic
	cfg := &config.Config{
		Engine: config.EngineConfig{DefaultTaskTimeout: 5 * time.Minute},
		Scanners: config.ScannersConfig{Active: config.ActiveScannersConfig{Taint: config.TaintConfig{Depth: 2}}},
	}

	targetURL, _ := url.Parse("http://example.com")
	task := schemas.Task{
		TaskID:    "task-taint-1",
		TargetURL: targetURL.String(),
	}

	analysisCtx := &core.AnalysisContext{
		Task:      task,
		TargetURL: targetURL,
		Logger:    logger,
		Global: &core.GlobalContext{
			BrowserManager: mockBM,
			OASTProvider:   mockOAST,
			Config:         cfg,
			FindingsChan:   findingsChan,
		},
	}
	return adapter, analysisCtx, mockBM, mockSession, mockOAST
}

// TestTaintAdapter_Analyze_SuccessOrchestration verifies the adapter calls the BM, runs the analysis, and closes the session.
func TestTaintAdapter_Analyze_SuccessOrchestration(t *testing.T) {
	adapter, ctx, mockBM, mockSession, mockOAST := setupTaintAdapterTest(t)
	
	// 1. Expect NewAnalysisContext to be called correctly (Verifying the fix: passing Task and FindingsChan)
	mockBM.On("NewAnalysisContext",
		mock.Anything, // context.Context
		ctx.Task,      // The specific task object
		schemas.DefaultPersona,
		"", "",
		ctx.Global.FindingsChan,
	).Return(mockSession, nil)

	// 2. The adapter instantiates the real taint.Analyzer. We must mock the calls the Analyzer makes on the Session/OAST.
    // These are necessary mocks for the analyzer's initialization and execution loop.
	mockOAST.On("GetServerURL").Return("http://oast.com")
    mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]schemas.OASTInteraction{}, nil)
    
    // Mock initialization calls the analyzer makes on the session
    mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
    mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
    
    // Mock execution calls
	mockSession.On("Navigate", mock.Anything, ctx.TargetURL.String()).Return(nil)
    // Verify the InteractionConfig depth is correctly read from the config
    expectedInteractionConfig := schemas.InteractionConfig{MaxDepth: 2}
	mockSession.On("Interact", mock.Anything, expectedInteractionConfig).Return(nil)

	// 3. Expect the session to be closed at the end (defer)
	mockSession.On("Close", mock.Anything).Return(nil)

	err := adapter.Analyze(context.Background(), ctx)

	assert.NoError(t, err)
	mockBM.AssertExpectations(t)
	mockSession.AssertExpectations(t)
    mockOAST.AssertExpectations(t)
}

func TestTaintAdapter_Analyze_NilBrowserManager(t *testing.T) {
	adapter, ctx, _, _, _ := setupTaintAdapterTest(t)
	ctx.Global.BrowserManager = nil // Simulate missing dependency

	err := adapter.Analyze(context.Background(), ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "critical error: browser manager not initialized")
}

func TestTaintAdapter_Analyze_SessionCreationError(t *testing.T) {
	adapter, ctx, mockBM, _, _ := setupTaintAdapterTest(t)

	expectedError := errors.New("failed to launch browser")

	// Expect NewAnalysisContext to return an error
	mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, expectedError)

	err := adapter.Analyze(context.Background(), ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create browser session")
	mockBM.AssertExpectations(t)
}

// TestTaintAdapter_Analyze_TimeoutHandling verifies the adapter handles context cancellation gracefully during execution.
func TestTaintAdapter_Analyze_TimeoutHandling(t *testing.T) {
	adapter, analysisCtx, mockBM, mockSession, mockOAST := setupTaintAdapterTest(t)

	// Setup the context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSession, nil)
	mockSession.On("Close", mock.Anything).Return(nil)

    // Setup necessary mocks for the analyzer initialization
    mockOAST.On("GetServerURL").Return("http://oast.com")
    mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
    mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)

	// Simulate the analyzer taking a long time (blocking until context timeout)
	mockSession.On("Navigate", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		// Wait for the context passed to Analyze (which is passed down to Navigate) to time out
		<-args.Get(0).(context.Context).Done()
	}).Return(context.DeadlineExceeded) // The analyzer should return the context error

	err := adapter.Analyze(ctx, analysisCtx)
    
	// The adapter should catch the timeout/cancellation during execution and return nil (interruption, not failure).
	assert.NoError(t, err)

	mockSession.AssertExpectations(t)
}