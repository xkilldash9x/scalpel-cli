// File: internal/mocks/mocks.go
package mocks

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Config Mock --

// MockConfig mocks the config.Interface.
type MockConfig struct {
	mock.Mock
}

func (m *MockConfig) SetBrowserHumanoidKeyHoldMu(ms float64) {
	m.Called(ms)
}

func (m *MockConfig) SetATOConfig(atoCfg config.ATOConfig) {
	m.Called(atoCfg)
}

// --- Getters ---

// Helper function to safely retrieve mock return values or return a default zero value.
func safeGet[T any](args mock.Arguments, index int) T {
	val := args.Get(index)
	if val == nil {
		var zero T
		return zero
	}
	if casted, ok := val.(T); ok {
		return casted
	}
	// Fallback if type assertion fails unexpectedly.
	var zero T
	return zero
}

func (m *MockConfig) Logger() config.LoggerConfig {
	return safeGet[config.LoggerConfig](m.Called(), 0)
}

func (m *MockConfig) Database() config.DatabaseConfig {
	return safeGet[config.DatabaseConfig](m.Called(), 0)
}

func (m *MockConfig) Engine() config.EngineConfig {
	return safeGet[config.EngineConfig](m.Called(), 0)
}

func (m *MockConfig) Browser() config.BrowserConfig {
	return safeGet[config.BrowserConfig](m.Called(), 0)
}

func (m *MockConfig) Network() config.NetworkConfig {
	return safeGet[config.NetworkConfig](m.Called(), 0)
}

func (m *MockConfig) IAST() config.IASTConfig {
	return safeGet[config.IASTConfig](m.Called(), 0)
}

func (m *MockConfig) Scanners() config.ScannersConfig {
	return safeGet[config.ScannersConfig](m.Called(), 0)
}

func (m *MockConfig) JWT() config.JWTConfig {
	return safeGet[config.JWTConfig](m.Called(), 0)
}

func (m *MockConfig) Agent() config.AgentConfig {
	return safeGet[config.AgentConfig](m.Called(), 0)
}

func (m *MockConfig) Discovery() config.DiscoveryConfig {
	// Special handling for DiscoveryConfig because it contains a pointer (*bool).
	args := m.Called()
	if args.Get(0) == nil {
		// Provide a safe default for the pointer field PassiveEnabled
		defaultBool := false
		return config.DiscoveryConfig{PassiveEnabled: &defaultBool}
	}
	// Ensure type safety if a non-nil value is returned.
	if cfg, ok := args.Get(0).(config.DiscoveryConfig); ok {
		return cfg
	}
	return config.DiscoveryConfig{}
}

func (m *MockConfig) Autofix() config.AutofixConfig {
	return safeGet[config.AutofixConfig](m.Called(), 0)
}

func (m *MockConfig) Scan() config.ScanConfig {
	return safeGet[config.ScanConfig](m.Called(), 0)
}

// --- Setters ---

func (m *MockConfig) SetScanConfig(sc config.ScanConfig) {
	m.Called(sc)
}

func (m *MockConfig) SetDiscoveryMaxDepth(d int) {
	m.Called(d)
}

func (m *MockConfig) SetDiscoveryIncludeSubdomains(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetEngineWorkerConcurrency(w int) {
	m.Called(w)
}

func (m *MockConfig) SetBrowserHeadless(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetBrowserDisableCache(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetBrowserIgnoreTLSErrors(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetBrowserDebug(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetBrowserHumanoidEnabled(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetBrowserHumanoidClickHoldMinMs(ms int) {
	m.Called(ms)
}

func (m *MockConfig) SetBrowserHumanoidClickHoldMaxMs(ms int) {
	m.Called(ms)
}

func (m *MockConfig) SetNetworkCaptureResponseBodies(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetNetworkNavigationTimeout(d time.Duration) {
	m.Called(d)
}

func (m *MockConfig) SetNetworkPostLoadWait(d time.Duration) {
	m.Called(d)
}

func (m *MockConfig) SetNetworkIgnoreTLSErrors(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetIASTEnabled(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetJWTEnabled(b bool) {
	m.Called(b)
}

func (m *MockConfig) SetJWTBruteForceEnabled(b bool) {
	m.Called(b)
}

// -- LLM Client Mock --

type MockLLMClient struct {
	mock.Mock
}

func (m *MockLLMClient) Generate(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	// Respect context cancellation.
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

// -- Knowledge Graph Client Mock --

type MockKGClient struct {
	mock.Mock
}

func (m *MockKGClient) AddNode(ctx context.Context, node schemas.Node) error {
	return m.Called(ctx, node).Error(0)
}
func (m *MockKGClient) AddEdge(ctx context.Context, edge schemas.Edge) error {
	return m.Called(ctx, edge).Error(0)
}
func (m *MockKGClient) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	args := m.Called(ctx, id)
	if node, ok := args.Get(0).(schemas.Node); ok {
		return node, args.Error(1)
	}
	return schemas.Node{}, args.Error(1)
}
func (m *MockKGClient) GetEdges(ctx context.Context, nodeID string) ([]schemas.Edge, error) {
	args := m.Called(ctx, nodeID)
	if edges, ok := args.Get(0).([]schemas.Edge); ok {
		return edges, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockKGClient) GetNeighbors(ctx context.Context, nodeID string) ([]schemas.Node, error) {
	args := m.Called(ctx, nodeID)
	if nodes, ok := args.Get(0).([]schemas.Node); ok {
		return nodes, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockKGClient) QueryImprovementHistory(ctx context.Context, goal string, limit int) ([]schemas.Node, error) {
	args := m.Called(ctx, goal, limit)
	if nodes, ok := args.Get(0).([]schemas.Node); ok {
		return nodes, args.Error(1)
	}
	return nil, args.Error(1)
}

// -- LTM Mock --

// MockLTM mocks the long-term memory interface.
type MockLTM struct {
	mock.Mock
}

// ProcessAndFlagObservation mocks the processing of an observation.
// It uses interface{} for the observation payload to avoid a circular dependency
// between the agent and mocks packages.
func (m *MockLTM) ProcessAndFlagObservation(ctx context.Context, obs interface{}) error {
	args := m.Called(ctx, obs)
	return args.Error(0)
}

// Stop mocks the cleanup/shutdown process.
func (m *MockLTM) Stop() {
	m.Called()
}

// -- Session Context Mock --

type MockSessionContext struct {
	mock.Mock
	exposedFunctions map[string]interface{}
	mutex            sync.Mutex
}

// DispatchStructuredKey implements schemas.SessionContext.
func (m *MockSessionContext) DispatchStructuredKey(ctx context.Context, data schemas.KeyEventData) error {
	panic("unimplemented")
}

func NewMockSessionContext() *MockSessionContext {
	return &MockSessionContext{exposedFunctions: make(map[string]interface{})}
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
func (m *MockSessionContext) GetExposedFunction(name string) (interface{}, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	fn, ok := m.exposedFunctions[name]
	return fn, ok
}
func (m *MockSessionContext) ID() string                      { return m.Called().String(0) }
func (m *MockSessionContext) Close(ctx context.Context) error { return m.Called(ctx).Error(0) }
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
func (m *MockSessionContext) InjectScriptPersistently(ctx context.Context, script string) error {
	return m.Called(ctx, script).Error(0)
}
func (m *MockSessionContext) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	return m.Called(ctx, config).Error(0)
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
func (m *MockSessionContext) AddFinding(ctx context.Context, finding schemas.Finding) error {
	return m.Called(ctx, finding).Error(0)
}
func (m *MockSessionContext) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	args := m.Called(ctx)
	if artifacts, ok := args.Get(0).(*schemas.Artifacts); ok {
		return artifacts, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockSessionContext) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	args := m.Called(ctx, selector)
	if geom, ok := args.Get(0).(*schemas.ElementGeometry); ok {
		return geom, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string, scriptArgs []interface{}) (json.RawMessage, error) {
	args := m.Called(ctx, script, scriptArgs)
	if msg, ok := args.Get(0).(json.RawMessage); ok {
		return msg, args.Error(1)
	}
	return nil, args.Error(1)
}

// -- Browser Manager Mock --

type MockBrowserManager struct {
	mock.Mock
}

func (m *MockBrowserManager) NewAnalysisContext(sessionCtx context.Context, cfg interface{}, persona schemas.Persona, taintTemplate, taintConfig string, findingsChan chan<- schemas.Finding) (schemas.SessionContext, error) {
	args := m.Called(sessionCtx, cfg, persona, taintTemplate, taintConfig, findingsChan)
	if ctx, ok := args.Get(0).(schemas.SessionContext); ok {
		return ctx, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockBrowserManager) Shutdown(ctx context.Context) error { return m.Called(ctx).Error(0) }

// -- OAST Provider Mock --

type MockOASTProvider struct {
	mock.Mock
}

func (m *MockOASTProvider) GetInteractions(ctx context.Context, canaries []string) ([]schemas.OASTInteraction, error) {
	args := m.Called(ctx, canaries)
	if interactions, ok := args.Get(0).([]schemas.OASTInteraction); ok {
		return interactions, args.Error(1)
	}
	return nil, args.Error(1)
}
func (m *MockOASTProvider) GetServerURL() string { return m.Called().String(0) }

// -- Analyzer Mock --

type MockAnalyzer struct {
	mock.Mock
}

// NewMockAnalyzer creates a new mock instance.
func NewMockAnalyzer() *MockAnalyzer {
	return &MockAnalyzer{}
}

func (m *MockAnalyzer) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	return m.Called(ctx, analysisCtx).Error(0)
}
func (m *MockAnalyzer) Name() string        { return m.Called().String(0) }
func (m *MockAnalyzer) Description() string { return m.Called().String(0) }
func (m *MockAnalyzer) Type() core.AnalyzerType {
	args := m.Called()
	if t, ok := args.Get(0).(core.AnalyzerType); ok {
		return t
	}
	return core.AnalyzerType(core.TypeUnknown)
}

// -- Store Mock --

type MockStore struct {
	mock.Mock
}

func (m *MockStore) PersistData(ctx context.Context, data *schemas.ResultEnvelope) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockStore) GetFindingsByScanID(ctx context.Context, scanID string) ([]schemas.Finding, error) {
	args := m.Called(ctx, scanID)
	if findings, ok := args.Get(0).([]schemas.Finding); ok {
		return findings, args.Error(1)
	}
	return nil, args.Error(1)
}

// -- IDOR Session Mock --

type MockIdorSession struct {
	mock.Mock
}

func (m *MockIdorSession) ApplyToRequest(r *http.Request) {
	m.Called(r)
}
func (m *MockIdorSession) WithAuthToken(token string) *MockIdorSession {
	m.On("ApplyToRequest", mock.Anything).Run(func(args mock.Arguments) {
		req := args.Get(0).(*http.Request)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	})
	return m
}

// -- Orchestrator Mock --

type MockOrchestrator struct {
	mock.Mock
}

func (m *MockOrchestrator) StartScan(ctx context.Context, targets []string, scanID string) error {
	args := m.Called(ctx, targets, scanID)
	return args.Error(0)
}

// -- Component Factory Mock (for testing cmd/scan.go) --

// MockComponentFactory mocks the ComponentFactory interface.
type MockComponentFactory struct {
	mock.Mock
}

// Create provides a mock function for component creation.
// It returns interface{} to avoid a direct dependency on the cmd package (where Components is defined),
// preventing an import cycle. The calling test code will perform a type assertion.
func (m *MockComponentFactory) Create(ctx context.Context, cfg config.Interface, targets []string) (interface{}, error) {
	args := m.Called(ctx, cfg, targets)
	return args.Get(0), args.Error(1)
}

// -- Engine Mocks --

// MockTaskEngine mocks the schemas.TaskEngine interface.
type MockTaskEngine struct {
	mock.Mock
}

func (m *MockTaskEngine) Start(ctx context.Context, taskChan <-chan schemas.Task) {
	m.Called(ctx, taskChan)
}
func (m *MockTaskEngine) Stop() {
	m.Called()
}

// MockDiscoveryEngine mocks the schemas.DiscoveryEngine interface.
type MockDiscoveryEngine struct {
	mock.Mock
}

func (m *MockDiscoveryEngine) Start(ctx context.Context, targets []string) (<-chan schemas.Task, error) {
	args := m.Called(ctx, targets)
	if ch, ok := args.Get(0).(<-chan schemas.Task); ok {
		return ch, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockDiscoveryEngine) Stop() {
	m.Called()
}

// -- Humanoid Controller Mock --

// MockHumanoidController mocks the humanoid.Controller interface.
type MockHumanoidController struct {
	mock.Mock
}

func (m *MockHumanoidController) MoveTo(ctx context.Context, selector string, opts *humanoid.InteractionOptions) error {
	return m.Called(ctx, selector, opts).Error(0)
}

func (m *MockHumanoidController) IntelligentClick(ctx context.Context, selector string, opts *humanoid.InteractionOptions) error {
	return m.Called(ctx, selector, opts).Error(0)
}

func (m *MockHumanoidController) DragAndDrop(ctx context.Context, startSelector, endSelector string, opts *humanoid.InteractionOptions) error {
	return m.Called(ctx, startSelector, endSelector, opts).Error(0)
}

func (m *MockHumanoidController) Type(ctx context.Context, selector string, text string, opts *humanoid.InteractionOptions) error {
	return m.Called(ctx, selector, text, opts).Error(0)
}

func (m *MockHumanoidController) CognitivePause(ctx context.Context, meanScale, stdDevScale float64) error {
	return m.Called(ctx, meanScale, stdDevScale).Error(0)
}

// Shortcut provides a mock function with given fields: ctx, keysExpression
func (m *MockHumanoidController) Shortcut(ctx context.Context, keysExpression string) error {
	return m.Called(ctx, keysExpression).Error(0)
}
