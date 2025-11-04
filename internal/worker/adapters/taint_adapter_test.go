// internal/worker/adapters/taint_adapter_test.go
package adapters_test

import ( // This is a comment to force a change
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

func setupTaintAdapterTest(t *testing.T) (*adapters.TaintAdapter, *core.AnalysisContext, *mocks.MockBrowserManager, *mocks.MockSessionContext, *mocks.MockOASTProvider) {
	adapter := adapters.NewTaintAdapter()
	logger := zaptest.NewLogger(t)
	mockBM := new(mocks.MockBrowserManager)
	mockSession := mocks.NewMockSessionContext()
	mockOAST := new(mocks.MockOASTProvider)
	findingsChan := make(chan schemas.Finding, 10)

	// Use the mock config and set up expectations for the methods called by the adapter.
	mockCfg := new(mocks.MockConfig)
	mockCfg.On("Engine").Return(config.EngineConfig{DefaultTaskTimeout: 5 * time.Minute})
	mockCfg.On("Scanners").Return(config.ScannersConfig{Active: config.ActiveScannersConfig{Taint: config.TaintConfig{Depth: 2}}})

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
			Config:         mockCfg, // This will work once Global.Config is an interface
			FindingsChan:   findingsChan,
		},
	}
	return adapter, analysisCtx, mockBM, mockSession, mockOAST
}

func TestTaintAdapter_Analyze_SuccessOrchestration(t *testing.T) {
	adapter, ctx, mockBM, mockSession, mockOAST := setupTaintAdapterTest(t)

	mockBM.On("NewAnalysisContext", mock.Anything, ctx.Task, schemas.DefaultPersona, "", "", ctx.Global.FindingsChan).Return(mockSession, nil)
	mockOAST.On("GetServerURL").Return("http://oast.com")
	mockOAST.On("GetInteractions", mock.Anything, mock.Anything).Return([]schemas.OASTInteraction{}, nil)
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)
	mockSession.On("ExecuteScript", mock.Anything, mock.Anything, mock.Anything).Return(json.RawMessage("null"), nil)

	// The analyzer calls Navigate multiple times with different URLs (containing probes).
	mockSession.On("Navigate", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	// This now correctly reads the 'Depth' from the mocked Scanners() config
	expectedInteractionConfig := schemas.InteractionConfig{MaxDepth: ctx.Global.Config.Scanners().Active.Taint.Depth}
	mockSession.On("Interact", mock.Anything, expectedInteractionConfig).Return(nil)
	mockSession.On("Close", mock.Anything).Return(nil)

	err := adapter.Analyze(context.Background(), ctx)

	assert.NoError(t, err)
	mockBM.AssertExpectations(t)
	mockSession.AssertExpectations(t)
	mockOAST.AssertExpectations(t)
}

func TestTaintAdapter_Analyze_NilBrowserManager(t *testing.T) {
	adapter, ctx, _, _, _ := setupTaintAdapterTest(t)
	ctx.Global.BrowserManager = nil

	err := adapter.Analyze(context.Background(), ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "critical error: browser manager not initialized")
}

func TestTaintAdapter_Analyze_SessionCreationError(t *testing.T) {
	adapter, ctx, mockBM, _, _ := setupTaintAdapterTest(t)
	expectedError := errors.New("failed to launch browser")
	mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, expectedError)

	err := adapter.Analyze(context.Background(), ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create browser session")
	mockBM.AssertExpectations(t)
}

func TestTaintAdapter_Analyze_TimeoutHandling(t *testing.T) {
	adapter, analysisCtx, mockBM, mockSession, mockOAST := setupTaintAdapterTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	mockBM.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSession, nil)
	mockSession.On("Close", mock.Anything).Return(nil)
	mockOAST.On("GetServerURL").Return("http://oast.com")
	mockSession.On("ExposeFunction", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockSession.On("InjectScriptPersistently", mock.Anything, mock.Anything).Return(nil)

	mockSession.On("Navigate", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		<-args.Get(0).(context.Context).Done()
	}).Return(context.DeadlineExceeded)

	err := adapter.Analyze(ctx, analysisCtx)
	assert.NoError(t, err)
	mockSession.AssertExpectations(t)
}
