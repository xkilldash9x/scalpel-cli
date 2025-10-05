// internal/mocks/mocks.go
package mocks

import (
	"context"
	"encoding/json"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// MockBrowserManager is a mock implementation of schemas.BrowserManager.
type MockBrowserManager struct {
	mock.Mock
}

// Note: The implementation in agent_adapter.go seems to use a slightly different signature
// (passing Task as cfg, and using initialURL/initialData instead of taintTemplate/taintConfig).
// We will mock the interface as defined in schemas.go, but tests must account for how the adapter calls it.
func (m *MockBrowserManager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
	findingsChan chan<- schemas.Finding,
) (schemas.SessionContext, error) {
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

// MockSessionContext is a mock implementation of schemas.SessionContext.
type MockSessionContext struct {
	mock.Mock
}

// Implement all required methods of schemas.SessionContext (Stubs)
func (m *MockSessionContext) ID() string                                     { return "mock-session" }
func (m *MockSessionContext) Navigate(ctx context.Context, url string) error { return m.Called(ctx, url).Error(0) }
func (m *MockSessionContext) Click(ctx context.Context, selector string) error {
	return m.Called(ctx, selector).Error(0)
}
func (m *MockSessionContext) Type(ctx context.Context, selector string, text string) error {
	return m.Called(ctx, selector, text).Error(0)
}
func (m *MockSessionContext) Submit(ctx context.Context, selector string) error {
	return m.Called(ctx, selector).Error(0)
}
func (m *MockSessionContext) ScrollPage(ctx context.Context, direction string) error {
	return m.Called(ctx, direction).Error(0)
}
func (m *MockSessionContext) WaitForAsync(ctx context.Context, milliseconds int) error {
	return m.Called(ctx, milliseconds).Error(0)
}
func (m *MockSessionContext) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	return m.Called(ctx, name, function).Error(0)
}
func (m *MockSessionContext) InjectScriptPersistently(ctx context.Context, script string) error {
	return m.Called(ctx, script).Error(0)
}
func (m *MockSessionContext) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	return m.Called(ctx, config).Error(0)
}

// Crucial for testing resource management (defer Close())
func (m *MockSessionContext) Close(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}

func (m *MockSessionContext) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*schemas.Artifacts), args.Error(1)
}
func (m *MockSessionContext) AddFinding(ctx context.Context, finding schemas.Finding) error {
	return m.Called(ctx, finding).Error(0)
}
func (m *MockSessionContext) Sleep(ctx context.Context, d time.Duration) error {
	return m.Called(ctx, d).Error(0)
}
func (m *MockSessionContext) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	return m.Called(ctx, data).Error(0)
}
func (m *MockSessionContext) SendKeys(ctx context.Context, keys string) error {
	return m.Called(ctx, keys).Error(0)
}

func (m *MockSessionContext) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	args := m.Called(ctx, selector)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*schemas.ElementGeometry), args.Error(1)
}
func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string, args_ []interface{}) (json.RawMessage, error) {
	args := m.Called(ctx, script, args_)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(json.RawMessage), args.Error(1)
}

// MockAnalyzer is a mock implementation of the core.Analyzer interface for isolated testing.
type MockAnalyzer struct {
	mock.Mock
}

// Analyze is the mock's implementation of the Analyze method.
func (m *MockAnalyzer) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	args := m.Called(ctx, analysisCtx)
	return args.Error(0)
}

// Name is the mock's implementation of the Name method.
func (m *MockAnalyzer) Name() string {
	args := m.Called()
	return args.String(0)
}

// Description is the mock's implementation of the Description method.
func (m *MockAnalyzer) Description() string {
	args := m.Called()
	return args.String(0)
}

// Type is the mock's implementation of the Type method.
// It now returns a core.AnalyzerType to match the updated interface.
func (m *MockAnalyzer) Type() core.AnalyzerType {
	args := m.Called()
	// We get the first argument and assert its type to core.AnalyzerType.
	return args.Get(0).(core.AnalyzerType)
}

