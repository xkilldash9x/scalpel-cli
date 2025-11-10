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

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)
	assert.NotNil(t, w)

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

func TestMonolithicWorker_ProcessTask_HumanoidSequence_Success(t *testing.T) {
	cfg, logger, globalCtx := setupTestEnvironment(t)

	mockBrowserManager := new(mocks.MockBrowserManager)
	mockSessionContext := new(mocks.MockSessionContext)
	globalCtx.BrowserManager = mockBrowserManager

	w, err := NewMonolithicWorker(cfg, logger, globalCtx)
	require.NoError(t, err)

	task := schemas.Task{
		Type: schemas.TaskHumanoidSequence,
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

	mockBrowserManager.On("NewAnalysisContext", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(mockSessionContext, nil)
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

	err = w.ProcessTask(context.Background(), analysisCtx)
	assert.NoError(t, err)

	mockBrowserManager.AssertExpectations(t)
	mockSessionContext.AssertExpectations(t)
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
