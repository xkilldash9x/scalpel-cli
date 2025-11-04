// File: internal/worker/adapters/taint_adapter_test.go
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

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

// Helper function to set up the test environment for TaintAdapter.
func setupTaintAdapterTest(t *testing.T) (*adapters.TaintAdapter, *core.AnalysisContext, *mocks.MockBrowserManager, *mocks.MockSessionContext, *mocks.MockOASTProvider, *mocks.MockConfig) {
	adapter := adapters.NewTaintAdapter()
	logger := zaptest.NewLogger(t)
	mockBM := new(mocks.MockBrowserManager)
	mockSession := mocks.NewMockSessionContext()
	mockOAST := new(mocks.MockOASTProvider)
	mockCfg := new(mocks.MockConfig)
	findingsChan := make(chan schemas.Finding, 10)

	// Default configuration expectations.
	engineCfg := config.EngineConfig{DefaultTaskTimeout: 5 * time.Minute}
	scannersCfg := config.ScannersConfig{Active: config.ActiveScannersConfig{Taint: config.TaintConfig{Depth: 2}}}

	mockCfg.On("Engine").Return(engineCfg)
	mockCfg.On("Scanners").Return(scannersCfg)

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
			Config:         mockCfg,
			FindingsChan:   findingsChan,
		},
	}
	return adapter, analysisCtx, mockBM, mockSession, mockOAST, mockCfg
}

func TestTaintAdapter_Analyze_SuccessOrchestration(t *testing.T) {
	adapter, ctx, mockBM, mockSession, mockOAST, _ := setupTaintAdapterTest(t)

	// Mock resource acquisition (Browser Session)
	mockBM.On("NewAnalysisContext", mock.Anything, ctx.Task, schemas.DefaultPersona, "", "", ctx.Global.FindingsChan).Return(mockSession, nil)
	// Ensure Close is called with context.Background()
	mockSession.On("Close", mock.MatchedBy(func(ctx context.Context) bool {
		return ctx == context.Background()
	})).Return(nil)

	// Mock OAST provider interactions (required by the underlying analyzer)
	mockOAST.On("GetServerURL").Return("http://oast.com")
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]schemas.OASTInteraction{}, nil)

	// Mock browser interactions (required by the underlying analyzer)
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage("null"), nil)
	mockSession.On("Navigate", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	// Mock the interaction phase
	expectedInteractionConfig := schemas.InteractionConfig{MaxDepth: ctx.Global.Config.Scanners().Active.Taint.Depth}
	mockSession.On("Interact", mock.Anything, expectedInteractionConfig).Return(nil)

	// Execute analysis
	err := adapter.Analyze(context.Background(), ctx)

	// Assertions
	assert.NoError(t, err)
	mockBM.AssertExpectations(t)
	mockSession.AssertExpectations(t)
	mockOAST.AssertExpectations(t)
}

func TestTaintAdapter_Analyze_ResourceAndConfigValidation(t *testing.T) {
	t.Run("Nil BrowserManager", func(t *testing.T) {
		adapter, ctx, _, _, _, _ := setupTaintAdapterTest(t)
		ctx.Global.BrowserManager = nil

		err := adapter.Analyze(context.Background(), ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "browser manager not initialized")
	})

	t.Run("Nil Global Config", func(t *testing.T) {
		adapter, ctx, _, _, _, _ := setupTaintAdapterTest(t)
		ctx.Global.Config = nil // Set config to nil

		err := adapter.Analyze(context.Background(), ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to setup taint configuration: global configuration is missing")
	})

	t.Run("Nil TargetURL", func(t *testing.T) {
		adapter, ctx, _, _, _, _ := setupTaintAdapterTest(t)
		ctx.TargetURL = nil

		err := adapter.Analyze(context.Background(), ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "TargetURL is missing")
	})

	t.Run("Session Creation Error", func(t *testing.T) {
		adapter, ctx, mockBM, _, _, _ := setupTaintAdapterTest(t)
		expectedError := errors.New("failed to launch browser")
		mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, expectedError)

		err := adapter.Analyze(context.Background(), ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create browser session")
		mockBM.AssertExpectations(t)
	})
}

// Test case added: Ensure Taint Analyzer runs even if OASTProvider is nil (OAST is optional).
func TestTaintAdapter_Analyze_NilOASTProvider(t *testing.T) {
	adapter, ctx, mockBM, mockSession, _, _ := setupTaintAdapterTest(t)
	ctx.Global.OASTProvider = nil

	// Setup mocks for the successful path, as the taint analyzer should still run.
	mockBM.On("NewAnalysisContext", mock.Anything, ctx.Task, schemas.DefaultPersona, "", "", ctx.Global.FindingsChan).Return(mockSession, nil)
	// Note: OASTProvider mocks (GetServerURL, GetInteractions) are not needed as it's nil.

	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage("null"), nil)
	mockSession.On("Navigate", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	expectedInteractionConfig := schemas.InteractionConfig{MaxDepth: ctx.Global.Config.Scanners().Active.Taint.Depth}
	mockSession.On("Interact", mock.Anything, expectedInteractionConfig).Return(nil)
	mockSession.On("Close", mock.Anything).Return(nil)

	// The analyzer should initialize and run successfully without OAST.
	err := adapter.Analyze(context.Background(), ctx)

	assert.NoError(t, err)
	mockBM.AssertExpectations(t)
	mockSession.AssertExpectations(t)
}

func TestTaintAdapter_Analyze_TimeoutHandling(t *testing.T) {
	adapter, analysisCtx, mockBM, mockSession, mockOAST, _ := setupTaintAdapterTest(t)
	// Create a context with a very short timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Setup mocks for successful initialization
	mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSession, nil)
	// Expect Close to be called with context.Background() even during timeout.
	mockSession.On("Close", mock.Anything).Return(nil)
	mockOAST.On("GetServerURL").Return("http://oast.com")
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)

	// Mock Navigate (the first major blocking operation) to wait until the context times out.
	mockSession.On("Navigate", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		// Wait for the context passed to Navigate (the short-timeout context) to be done.
		<-args.Get(0).(context.Context).Done()
	}).Return(context.DeadlineExceeded)

	// Execute analysis
	err := adapter.Analyze(ctx, analysisCtx)

	// Assertions: The adapter should return the context error gracefully.
	assert.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	mockSession.AssertExpectations(t)
}

// Test case added to increase coverage: Handling analyzer execution failure (non-timeout).
func TestTaintAdapter_Analyze_ExecutionFailure(t *testing.T) {
	adapter, ctx, mockBM, mockSession, mockOAST, _ := setupTaintAdapterTest(t)

	// Setup mocks for successful initialization
	mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSession, nil)
	mockSession.On("Close", mock.Anything).Return(nil)
	mockOAST.On("GetServerURL").Return("http://oast.com")
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)

	// Simulate a failure during the first navigation attempt that is NOT a context error.
	expectedError := errors.New("browser navigation failed unexpectedly")
	mockSession.On("Navigate", mock.Anything, mock.Anything).Return(expectedError)

	// Execute analysis
	err := adapter.Analyze(context.Background(), ctx)

	// Assertions: The adapter should report the specific execution failure.
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "taint analysis failed during execution")
	assert.ErrorIs(t, err, expectedError)
	mockSession.AssertExpectations(t)
}
