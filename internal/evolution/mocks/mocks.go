// File: internal/mocks/mocks.go
package mocks

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- LLM Client Mock --

// MockLLMClient mocks the schemas.LLMClient interface.
type MockLLMClient struct {
	mock.Mock
}

// Generate provides a mock function for LLM calls.
// R3 FIX: Redesigned Generate to respect context even when m.Called() blocks (e.g., due to a blocking Run func in tests).
func (m *MockLLMClient) Generate(ctx context.Context, req schemas.GenerationRequest) (string, error) {
	// Use a channel to receive the result of the mock call.
	type result struct {
		s   string
		err error
	}
	doneChan := make(chan result, 1)

	go func() {
		// Execute the mock logic (which might block if the test setup uses a blocking Run func).
		// The Run func itself should also respect the context for prompt cleanup.
		args := m.Called(ctx, req)
		doneChan <- result{args.String(0), args.Error(1)}
	}()

	// Wait for the mock call to complete or the context to be cancelled.
	select {
	case <-ctx.Done():
		// Context cancelled. Return the context error promptly.
		return "", ctx.Err()
	case res := <-doneChan:
		// Mock call completed.
		return res.s, res.err
	}
}

// -- Knowledge Graph Client Mock --

// MockKGClient mocks the schemas.KnowledgeGraphClient interface.
// This single mock replaces the various hand-written versions and wrappers.
type MockKGClient struct {
	mock.Mock
}

func (m *MockKGClient) AddNode(ctx context.Context, node schemas.Node) error {
	args := m.Called(ctx, node)
	return args.Error(0)
}

func (m *MockKGClient) AddEdge(ctx context.Context, edge schemas.Edge) error {
	args := m.Called(ctx, edge)
	return args.Error(0)
}

func (m *MockKGClient) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	args := m.Called(ctx, id)
	var r0 schemas.Node
	if args.Get(0) != nil {
		r0 = args.Get(0).(schemas.Node)
	}
	return r0, args.Error(1)
}

func (m *MockKGClient) GetEdges(ctx context.Context, nodeID string) ([]schemas.Edge, error) {
	args := m.Called(ctx, nodeID)
	var r0 []schemas.Edge
	if args.Get(0) != nil {
		r0 = args.Get(0).([]schemas.Edge)
	}
	return r0, args.Error(1)
}

func (m *MockKGClient) GetNeighbors(ctx context.Context, nodeID string) ([]schemas.Node, error) {
	args := m.Called(ctx, nodeID)
	var r0 []schemas.Node
	if args.Get(0) != nil {
		r0 = args.Get(0).([]schemas.Node)
	}
	return r0, args.Error(1)
}

func (m *MockKGClient) QueryImprovementHistory(ctx context.Context, goalObjective string, limit int) ([]schemas.Node, error) {
	args := m.Called(ctx, goalObjective, limit)
	var r0 []schemas.Node
	if args.Get(0) != nil {
		r0 = args.Get(0).([]schemas.Node)
	}
	return r0, args.Error(1)
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

// -- Implementation of all schemas.SessionContext methods --

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
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*schemas.Artifacts), args.Error(1)
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

// -- Browser Manager Mock --

// MockBrowserManager mocks the schemas.BrowserManager interface.
type MockBrowserManager struct {
	mock.Mock
}

func (m *MockBrowserManager) NewAnalysisContext(sessionCtx context.Context, cfg interface{}, persona schemas.Persona, taintTemplate string, taintConfig string, findingsChan chan<- schemas.Finding) (schemas.SessionContext, error) {
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
