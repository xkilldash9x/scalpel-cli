package service

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

func TestMain(m *testing.M) {
	// Initialize logger
	cfg := config.NewDefaultConfig()
	observability.InitializeLogger(cfg.Logger())

	// Run tests
	exitCode := m.Run()

	// Sync logger
	observability.Sync()

	// Exit
	os.Exit(exitCode)
}

// MockTaskEngine is a mock implementation of schemas.TaskEngine
type MockTaskEngine struct {
	mock.Mock
}

func (m *MockTaskEngine) Start(ctx context.Context, taskChan <-chan schemas.Task) {
	m.Called(ctx, taskChan)
}

func (m *MockTaskEngine) Stop() {
	m.Called()
}

// MockScopeManager is a mock for discovery.ScopeManager (defined implicitly via interface in factory usage, but explicitly in discovery package)
// We will define a local interface here matching what's needed or use the one from discovery if available.
// Looking at factory.go, it uses discovery.ScopeManager.
type MockScopeManager struct {
	mock.Mock
}

func (m *MockScopeManager) IsInScope(u *url.URL) bool {
	args := m.Called(u)
	return args.Bool(0)
}

func (m *MockScopeManager) GetRootDomain() string {
	args := m.Called()
	return args.String(0)
}

// MockDiscoveryEngine is a mock implementation of schemas.DiscoveryEngine
type MockDiscoveryEngine struct {
	mock.Mock
}

func (m *MockDiscoveryEngine) Start(ctx context.Context, targets []string) (<-chan schemas.Task, error) {
	args := m.Called(ctx, targets)
	var ch <-chan schemas.Task
	if args.Get(0) != nil {
		ch = args.Get(0).(<-chan schemas.Task)
	}
	return ch, args.Error(1)
}

func (m *MockDiscoveryEngine) Stop() {
	m.Called()
}

// MockBrowserManager is a mock implementation of schemas.BrowserManager
type MockBrowserManager struct {
	mock.Mock
}

func (m *MockBrowserManager) Shutdown(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

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

// MockStore is a mock implementation of schemas.Store
type MockStore struct {
	mock.Mock
}

func (m *MockStore) PersistData(ctx context.Context, data *schemas.ResultEnvelope) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockStore) GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error) {
	args := m.Called(ctx, scanID)
	return args.Get(0).([]schemas.Finding), args.Error(1)
}

// MockSessionContext is a mock for schemas.SessionContext (needed for return of NewAnalysisContext if tested)
type MockSessionContext struct {
	mock.Mock
}

func (m *MockSessionContext) ID() string {
	return m.Called().String(0)
}
func (m *MockSessionContext) Navigate(ctx context.Context, url string) error {
	return m.Called(ctx, url).Error(0)
}
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
func (m *MockSessionContext) Close(ctx context.Context) error {
	return m.Called(ctx).Error(0)
}
func (m *MockSessionContext) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	args := m.Called(ctx)
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
func (m *MockSessionContext) DispatchStructuredKey(ctx context.Context, data schemas.KeyEventData) error {
	return m.Called(ctx, data).Error(0)
}
func (m *MockSessionContext) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	args := m.Called(ctx, selector)
	return args.Get(0).(*schemas.ElementGeometry), args.Error(1)
}
func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	ret := m.Called(ctx, script, args)
	return ret.Get(0).(json.RawMessage), ret.Error(1)
}