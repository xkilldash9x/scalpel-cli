package agent

import (
	"context"
	"sync"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	// Removed imports related to internal interfaces that are no longer mocked directly here.
)

// Mocks the schemas.LLMClient interface used by LLMMind.
type MockLLMClient struct {
	mock.Mock
}

// Generate mocks the LLM generation call (matching schemas.LLMClient.Generate).
func (m *MockLLMClient) Generate(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

// Mocks the knowledgegraph.GraphStore interface based on usage in llm_mind.go (BFS Traversal).
type MockGraphStore struct {
	mock.Mock
	mu sync.RWMutex
}

// Implement methods used by LLMMind (AddNode, AddEdge, GetNode, GetNeighbors, GetEdges)

// Mocks AddNode (using schemas.Node).
func (m *MockGraphStore) AddNode(ctx context.Context, node schemas.Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(ctx, node)
	return args.Error(0)
}

// Mocks AddEdge (using schemas.Edge).
func (m *MockGraphStore) AddEdge(ctx context.Context, edge schemas.Edge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(ctx, edge)
	return args.Error(0)
}

// Mocks GetNode (required for BFS traversal).
func (m *MockGraphStore) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return schemas.Node{}, args.Error(1)
	}
	return args.Get(0).(schemas.Node), args.Error(1)
}

// Mocks GetNeighbors (required for BFS traversal).
func (m *MockGraphStore) GetNeighbors(ctx context.Context, id string) ([]schemas.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]schemas.Node), args.Error(1)
}

// Mocks GetEdges (required for BFS traversal).
func (m *MockGraphStore) GetEdges(ctx context.Context, id string) ([]schemas.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]schemas.Edge), args.Error(1)
}

// MockSessionContext implements schemas.SessionContext for testing.
// Consolidated here to prevent redeclaration errors across test files.
type MockSessionContext struct {
	mock.Mock
}

// Implement all methods required by schemas.SessionContext interface.

func (m *MockSessionContext) Navigate(ctx context.Context, url string) error {
	// Ensure Called arguments match the signature (ctx, url).
	args := m.Called(ctx, url)
	return args.Error(0)
}

// Note: Based on the contracts used in executors.go, these methods do not take context when called by the handlers.
func (m *MockSessionContext) Click(selector string) error {
	args := m.Called(selector)
	return args.Error(0)
}

func (m *MockSessionContext) Type(selector string, text string) error {
	args := m.Called(selector, text)
	return args.Error(0)
}

func (m *MockSessionContext) Submit(selector string) error {
	args := m.Called(selector)
	return args.Error(0)
}

func (m *MockSessionContext) ScrollPage(direction string) error {
	args := m.Called(direction)
	return args.Error(0)
}

func (m *MockSessionContext) WaitForAsync(milliseconds int) error {
	args := m.Called(milliseconds)
	return args.Error(0)
}

func (m *MockSessionContext) GetContext() context.Context {
	args := m.Called()
	if args.Get(0) == nil {
		return context.Background() // Default fallback
	}
	return args.Get(0).(context.Context)
}

func (m *MockSessionContext) ExposeFunction(ctx context.Context, name string, function interface{}) error {
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

func (m *MockSessionContext) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockSessionContext) Close(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockSessionContext) AddFinding(finding schemas.Finding) error {
	args := m.Called(finding)
	return args.Error(0)
}

func (m *MockSessionContext) CollectArtifacts() (*schemas.Artifacts, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*schemas.Artifacts), args.Error(1)
}

func (m *MockSessionContext) ID() string {
	args := m.Called()
	return args.String(0)
}

