// internal/worker/worker_extended_test.go
package worker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
)

// setupTestEnvironment prepares the basic components needed for worker tests.
func setupTestEnvironment(t testing.TB) (*config.Config, *zap.Logger, *core.GlobalContext) {
	t.Helper()

	cfg := config.NewDefaultConfig()
	logger := zap.NewNop()
	globalCtx := &core.GlobalContext{Config: cfg}

	return cfg, logger, globalCtx
}

func TestNewMonolithicWorker_WithAnalyzers(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	mockAnalyzer := new(mocks.MockAnalyzer)
	mockAnalyzer.On("Name").Return("MockAnalyzer")
	analyzers := core.AdapterRegistry{
		schemas.TaskType("MOCK_TASK"): mockAnalyzer,
	}

	w, err := NewMonolithicWorker(cfg, logger, globalCtx, WithAnalyzers(analyzers))
	require.NoError(t, err)
	assert.NotNil(t, w)

	// Verification (Bug 1): Ensure that when using WithAnalyzers, the GlobalContext is also updated (they point to the same map)
	assert.Equal(t, analyzers, globalCtx.Adapters)

	analysisCtx := &core.AnalysisContext{
		Task:   schemas.Task{Type: "MOCK_TASK"},
		Logger: logger,
	}

	mockAnalyzer.On("Analyze", mock.Anything, mock.Anything).Return(nil)

	err = w.ProcessTask(context.Background(), analysisCtx)
	assert.NoError(t, err)

	mockAnalyzer.AssertExpectations(t)
}

func TestNewMonolithicWorker_GlobalContextUpdate(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)
	// globalCtx.Adapters is nil here

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)
	assert.NotNil(t, w)

	assert.Equal(t, w.adapterRegistry, globalCtx.Adapters)
	assert.NotEmpty(t, globalCtx.Adapters)
}

// TestNewMonolithicWorker_GlobalContextUpdate_NonNilEmptyMap verifies the fix (Bug 1)
// for the synchronization bug. If GlobalContext.Adapters is initialized as an
// empty map, the worker must still update it to use the actual registry.
func TestNewMonolithicWorker_GlobalContextUpdate_NonNilEmptyMap(t *testing.T) {
	cfg, logger, _ := setupTestEnvironment(t)

	// Initialize GlobalContext with a non-nil, empty Adapters map
	globalCtx := &core.GlobalContext{
		Config:   cfg,
		Adapters: make(core.AdapterRegistry),
	}
	require.Empty(t, globalCtx.Adapters)

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)
	assert.NotNil(t, w)

	// Verify that globalCtx.Adapters is now populated and matches the worker's registry
	assert.NotEmpty(t, globalCtx.Adapters, "GlobalContext Adapters should be populated with defaults")
	assert.Equal(t, w.adapterRegistry, globalCtx.Adapters)
}

func Test_remarshalParams(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		type testStruct struct {
			Name  string `json:"name"`
			Value int    `json:"value"`
		}

		params := map[string]interface{}{
			"name":  "test",
			"value": 123,
		}

		var result testStruct
		err := remarshalParams(params, &result)

		require.NoError(t, err)
		assert.Equal(t, "test", result.Name)
		assert.Equal(t, 123, result.Value)
	})

	t.Run("nil params", func(t *testing.T) {
		var result struct{}
		err := remarshalParams(nil, &result)
		require.NoError(t, err)
	})

	t.Run("unmarshal error", func(t *testing.T) {
		params := map[string]interface{}{
			"name": 123, // Invalid type
		}

		var result struct {
			Name string `json:"name"`
		}
		err := remarshalParams(params, &result)
		require.Error(t, err)
	})
}

// TestMonolithicWorker_ProcessTask_HumanoidSequence_TaintConfigPropagation verifies (Bug 3)
// that the TaintTemplate and TaintConfig parameters are correctly passed to the
// BrowserManager when creating a new analysis context.
func TestMonolithicWorker_ProcessTask_HumanoidSequence_TaintConfigPropagation(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSessionContext := new(mocks.MockSessionContext)
	globalCtx.BrowserManager = mockBrowserManager

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)

	expectedTaintTemplate := "custom_template"
	expectedTaintConfig := "custom_config"
	testURL := "http://example.com/taint"

	task := schemas.Task{
		Type:      schemas.TaskHumanoidSequence,
		TargetURL: testURL, // Required due to Bug 2 fix
		Parameters: schemas.HumanoidSequenceParams{
			TaintTemplate: expectedTaintTemplate,
			TaintConfig:   expectedTaintConfig,
			Steps: []schemas.HumanoidStep{
				// Use a simple PAUSE step to minimize required mocks for execution
				{Action: schemas.HumanoidPause, MeanScale: 0.001, StdDevScale: 0.001},
			},
		},
	}

	analysisCtx := &core.AnalysisContext{
		Task:   task,
		Logger: logger,
	}

	// Set expectations on the BrowserManager
	// We specifically check if the expected TaintTemplate and TaintConfig are passed.
	mockBrowserManager.On(
		"NewAnalysisContext",
		mock.Anything,         // ctx
		mock.Anything,         // cfg
		mock.Anything,         // persona
		expectedTaintTemplate, // taintTemplate
		expectedTaintConfig,   // taintConfig
		mock.Anything,         // findingsChan
	).Return(mockSessionContext, nil).Once()

	// Mocks required for the session context lifecycle and execution
	mockSessionContext.On("Navigate", mock.Anything, testURL).Return(nil) // Required due to Bug 2 fix
	mockSessionContext.On("Sleep", mock.Anything, mock.AnythingOfType("time.Duration")).Return(nil)
	mockSessionContext.On("Close", mock.Anything).Return(nil)

	err = w.ProcessTask(context.Background(), analysisCtx)
	assert.NoError(t, err)

	// Verify that NewAnalysisContext was called with the correct parameters.
	mockBrowserManager.AssertExpectations(t)
	mockSessionContext.AssertExpectations(t)
}

func TestMonolithicWorker_ProcessTask_HumanoidSequence_Success(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSessionContext := new(mocks.MockSessionContext)
	globalCtx.BrowserManager = mockBrowserManager

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)

	// Updated task definition (Bug 2): Include TargetURL for the success case
	testURL := "http://example.com/testpage"
	task := schemas.Task{
		Type:      schemas.TaskHumanoidSequence,
		TargetURL: testURL,
		Parameters: schemas.HumanoidSequenceParams{
			Steps: []schemas.HumanoidStep{
				{Action: schemas.HumanoidMove, Selector: "#test"},
			},
		},
	}

	analysisCtx := &core.AnalysisContext{
		Task:   task,
		Logger: logger,
	}

	// Updated expectation (Bug 3): Ensure NewAnalysisContext is called with empty strings when TaintConfig is not provided.
	mockBrowserManager.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, "", "", mock.Anything).Return(mockSessionContext, nil)

	// Updated expectation (Bug 2): Must mock the Navigate call now that it's unconditional
	mockSessionContext.On("Navigate", mock.Anything, testURL).Return(nil)

	mockSessionContext.On("GetElementGeometry", mock.Anything, "#test").Return(&schemas.ElementGeometry{
		Vertices: []float64{0, 0, 10, 0, 10, 10, 0, 10},
		Width:    10,
		Height:   10,
	}, nil)
	mockSessionContext.On("DispatchMouseEvent", mock.Anything, mock.AnythingOfType("schemas.MouseEventData")).Return(nil)
	mockSessionContext.On("Sleep", mock.Anything, mock.AnythingOfType("time.Duration")).Return(nil)
	mockSessionContext.On("ExecuteScript", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(map[string]interface{}{
		"isIntersecting": true,
	}, nil)
	mockSessionContext.On("Close", mock.Anything).Return(nil)

	// Verification (Bug 4): Check that the analysisCtx.Session is initially nil.
	assert.Nil(t, analysisCtx.Session, "Session should be nil before processing")

	err = w.ProcessTask(context.Background(), analysisCtx)
	assert.NoError(t, err)

	// Verification (Bug 4): Check that the analysisCtx.Session is updated after processing.
	assert.Equal(t, mockSessionContext, analysisCtx.Session, "Session should be updated after processing")

	mockBrowserManager.AssertExpectations(t)
	mockSessionContext.AssertExpectations(t)
}

// TestMonolithicWorker_ProcessTask_HumanoidSequence_MissingTargetURL verifies (Bug 2) that
// a HUMANOID_SEQUENCE task fails validation if TargetURL is missing but steps are present.
func TestMonolithicWorker_ProcessTask_HumanoidSequence_MissingTargetURL(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	// Setup mocks. We expect validation to fail before the browser manager is used.
	mockBrowserManager := new(mocks.MockBrowserManager)
	// We must set BrowserManager otherwise the worker will error later that it's missing,
	// but we assert here it's not used due to early validation.
	globalCtx.BrowserManager = mockBrowserManager

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)

	task := schemas.Task{
		Type:      schemas.TaskHumanoidSequence,
		TargetURL: "", // Explicitly empty TargetURL
		Parameters: schemas.HumanoidSequenceParams{
			Steps: []schemas.HumanoidStep{
				// Steps require a page to operate on
				{Action: schemas.HumanoidClick, Selector: "#should-exist-on-target"},
			},
		},
	}

	analysisCtx := &core.AnalysisContext{
		Task:   task,
		Logger: logger,
	}

	// Execute the task
	err = w.ProcessTask(context.Background(), analysisCtx)

	// Assert that the correct validation error is returned
	assert.Error(t, err)
	// Check against the error message implemented in the fix
	assert.Contains(t, err.Error(), "TargetURL is required for HUMANOID_SEQUENCE when steps are provided")

	// Crucially, assert that the expensive operation (creating a browser context) did NOT happen.
	mockBrowserManager.AssertNotCalled(t, "NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestMonolithicWorker_executeHumanoidSteps(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)
	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)

	t.Run("move success", func(t *testing.T) {
		mockHumanoid := &MockHumanoid{}
		steps := []schemas.HumanoidStep{
			{Action: schemas.HumanoidMove, Selector: "#test"},
		}
		mockHumanoid.On("MoveTo", mock.Anything, "#test", mock.Anything).Return(nil).Once()
		err := w.executeHumanoidSteps(context.Background(), mockHumanoid, steps)
		assert.NoError(t, err)
		mockHumanoid.AssertExpectations(t)
	})

	t.Run("unknown action", func(t *testing.T) {
		mockHumanoid := &MockHumanoid{}
		steps := []schemas.HumanoidStep{
			{Action: "UNKNOWN_ACTION"},
		}
		err := w.executeHumanoidSteps(context.Background(), mockHumanoid, steps)
		assert.Error(t, err)
		mockHumanoid.AssertExpectations(t)
	})
}

func Test_convertHumanoidOptions(t *testing.T) {
	t.Run("nil options", func(t *testing.T) {
		opts, err := convertHumanoidOptions(nil)
		assert.NoError(t, err)
		assert.Nil(t, opts)
	})

	t.Run("with field sources", func(t *testing.T) {
		schemaOpts := &schemas.HumanoidInteractionOptions{
			FieldSources: []schemas.HumanoidForceSource{
				{PositionX: 1, PositionY: 2, Strength: 3, Falloff: 4},
			},
		}
		opts, err := convertHumanoidOptions(schemaOpts)
		assert.NoError(t, err)
		assert.NotNil(t, opts)
		assert.NotNil(t, opts.Field)
	})
}

// MockHumanoid is a mock type for the Humanoid type
type MockHumanoid struct {
	mock.Mock
}

func (m *MockHumanoid) MoveTo(ctx context.Context, selector string, opts *humanoid.InteractionOptions) error {
	args := m.Called(ctx, selector, opts)
	return args.Error(0)
}

func (m *MockHumanoid) IntelligentClick(ctx context.Context, selector string, opts *humanoid.InteractionOptions) error {
	args := m.Called(ctx, selector, opts)
	return args.Error(0)
}

func (m *MockHumanoid) Type(ctx context.Context, selector, text string, opts *humanoid.InteractionOptions) error {
	args := m.Called(ctx, selector, text, opts)
	return args.Error(0)
}

func (m *MockHumanoid) DragAndDrop(ctx context.Context, startSelector, endSelector string, opts *humanoid.InteractionOptions) error {
	args := m.Called(ctx, startSelector, endSelector, opts)
	return args.Error(0)
}

func (m *MockHumanoid) CognitivePause(ctx context.Context, meanScale, stdDevScale float64) error {
	args := m.Called(ctx, meanScale, stdDevScale)
	return args.Error(0)
}

var _ HumanoidInterface = (*MockHumanoid)(nil)
