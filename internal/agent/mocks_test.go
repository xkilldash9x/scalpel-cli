package agent

import (
	"context"
	"sync"

	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph/graphmodel"
)


// Mock Definitions
// Comprehensive mocks for isolating the Agent components (Mind, Executors, Bus).


// Mocks the interfaces.LLMClient interface.
// Note: The LLMMind uses interfaces.LLMClient, which matches the definition in llm_mind.go,
// even though agent/interfaces.go defines a slightly different agent.LLMClient.
type MockLLMClient struct {
	mock.Mock
}

// Mocks the LLM generation call.
func (m *MockLLMClient) GenerateResponse(ctx context.Context, req interfaces.GenerationRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

// Mocks the knowledgegraph.GraphStore interface.
// Includes robust handling for concurrent access, which is critical as the Mind calls it concurrently.
type MockGraphStore struct {
	mock.Mock
	// Use a mutex to ensure the mock itself is thread safe.
	mu sync.RWMutex
}

// Simulates adding or updating a node.
func (m *MockGraphStore) AddNode(input graphmodel.NodeInput) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(input)
	return args.String(0), args.Error(1)
}

// Simulates adding an edge.
func (m *MockGraphStore) AddEdge(input graphmodel.EdgeInput) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(input)
	return args.String(0), args.Error(1)
}

// Simulates extracting the localized context for the Mind.
func (m *MockGraphStore) ExtractMissionSubgraph(ctx context.Context, missionID string, lookbackSteps int) (graphmodel.GraphExport, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	args := m.Called(ctx, missionID, lookbackSteps)
	// Robustness: Handle nil return for error scenarios
	if args.Get(0) == nil {
		// Return empty struct instead of nil interface for the concrete type
		return graphmodel.GraphExport{}, args.Error(1)
	}
	return args.Get(0).(graphmodel.GraphExport), args.Error(1)
}

// Mocks the interfaces.SessionContext interface (browser interaction).
type MockSessionContext struct {
	mock.Mock
}

// Implement all methods required by interfaces.SessionContext used in executors.go

func (m *MockSessionContext) Navigate(url string) error {
	args := m.Called(url)
	return args.Error(0)
}

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
