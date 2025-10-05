package agent

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- LLM Client Mock --

// MockLLMClient mocks the schemas.LLMClient interface used by LLMMind.
type MockLLMClient struct {
	mock.Mock
}

// Generate mocks the LLM generation call.
func (m *MockLLMClient) Generate(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

// -- Knowledge Graph Store Mock --

// MockGraphStore mocks the knowledgegraph.GraphStore interface.
type MockGraphStore struct {
	mock.Mock
	mu sync.RWMutex
}

// AddNode mocks the corresponding method in the graph store.
func (m *MockGraphStore) AddNode(ctx context.Context, node schemas.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(ctx, node)
	return args.Error(0)
}

// AddEdge mocks the corresponding method in the graph store.
func (m *MockGraphStore) AddEdge(ctx context.Context, edge schemas.Edge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(ctx, edge)
	return args.Error(0)
}

// GetNode mocks the corresponding method in the graph store.
func (m *MockGraphStore) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return schemas.Node{}, args.Error(1)
	}
	return args.Get(0).(schemas.Node), args.Error(1)
}

// GetNeighbors mocks the corresponding method in the graph store.
func (m *MockGraphStore) GetNeighbors(ctx context.Context, id string) ([]schemas.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]schemas.Node), args.Error(1)
}

// GetEdges mocks the corresponding method in the graph store.
func (m *MockGraphStore) GetEdges(ctx context.Context, id string) ([]schemas.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]schemas.Edge), args.Error(1)
}

// -- Session Context Mock --

// MockSessionContext implements the schemas.SessionContext interface for testing.
type MockSessionContext struct {
	mock.Mock
	exposedFunctions map[string]interface{}
	mutex            sync.Mutex
}

// NewMockSessionContext creates a new mock with initialized fields.
func NewMockSessionContext() *MockSessionContext {
	return &MockSessionContext{
		exposedFunctions: make(map[string]interface{}),
	}
}

// ExposeFunction mocks the real method and stores the callback for later retrieval.
func (m *MockSessionContext) ExposeFunction(ctx context.Context, name string, function interface{}) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	args := m.Called(ctx, name, function)
	if args.Error(0) == nil {
		m.exposedFunctions[name] = function
	}
	return args.Error(0)
}

// GetExposedFunction is a test helper to retrieve a function captured by ExposeFunction.
func (m *MockSessionContext) GetExposedFunction(name string) (interface{}, bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	fn, ok := m.exposedFunctions[name]
	return fn, ok
}

// -- High Level Interaction Methods --

func (m *MockSessionContext) ID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockSessionContext) Navigate(ctx context.Context, url string) error {
	args := m.Called(ctx, url)
	return args.Error(0)
}

func (m *MockSessionContext) Click(ctx context.Context, selector string) error {
	args := m.Called(ctx, selector)
	return args.Error(0)
}

func (m *MockSessionContext) Type(ctx context.Context, selector string, text string) error {
	args := m.Called(ctx, selector, text)
	return args.Error(0)
}

func (m *MockSessionContext) Submit(ctx context.Context, selector string) error {
	args := m.Called(ctx, selector)
	return args.Error(0)
}

func (m *MockSessionContext) ScrollPage(ctx context.Context, direction string) error {
	args := m.Called(ctx, direction)
	return args.Error(0)
}

func (m *MockSessionContext) WaitForAsync(ctx context.Context, milliseconds int) error {
	args := m.Called(ctx, milliseconds)
	return args.Error(0)
}

func (m *MockSessionContext) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

// -- Session State & Control --

// REFACTOR: Removed GetContext() implementation.

func (m *MockSessionContext) Close(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// -- Scripting and Callbacks --

func (m *MockSessionContext) InjectScriptPersistently(ctx context.Context, script string) error {
	args := m.Called(ctx, script)
	return args.Error(0)
}

// -- Data Collection --

func (m *MockSessionContext) CollectArtifacts(ctx context.Context) (*schemas.Artifacts, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*schemas.Artifacts), args.Error(1)
}

func (m *MockSessionContext) AddFinding(ctx context.Context, finding schemas.Finding) error {
	args := m.Called(ctx, finding)
	return args.Error(0)
}

// -- humanoid.Executor Methods --

func (m *MockSessionContext) Sleep(ctx context.Context, d time.Duration) error {
	args := m.Called(ctx, d)
	return args.Error(0)
}

func (m *MockSessionContext) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockSessionContext) SendKeys(ctx context.Context, keys string) error {
	args := m.Called(ctx, keys)
	return args.Error(0)
}

func (m *MockSessionContext) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	args := m.Called(ctx, selector)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*schemas.ElementGeometry), args.Error(1)
}

func (m *MockSessionContext) ExecuteScript(ctx context.Context, script string, scriptArgs []interface{}) (json.RawMessage, error) {
	args := m.Called(ctx, script, scriptArgs)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(json.RawMessage), args.Error(1)
}