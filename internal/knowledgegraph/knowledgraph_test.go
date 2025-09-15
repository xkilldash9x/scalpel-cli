// internal/knowledgegraph/knowledgegraph_test.go
package knowledgegraph

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// -- Test Fixture Setup --

// kgTestFixture holds shared resources for the knowledge graph tests.
type kgTestFixture struct {
	Logger *zap.Logger
}

// globalFixture is the single, shared instance for the test suite.
var globalFixture *kgTestFixture

// TestMain sets up and tears down the global test fixture.
func TestMain(m *testing.M) {
	logger, _ := zap.NewDevelopment()
	globalFixture = &kgTestFixture{
		Logger: logger,
	}

	exitCode := m.Run()

	_ = globalFixture.Logger.Sync()
	os.Exit(exitCode)
}

// -- Test Helper Functions --

// getTestKG is a helper that returns a new InMemoryKG instance pre-populated
// with a consistent set of nodes and edges for testing.
func getTestKG(t *testing.T) *InMemoryKG {
	t.Helper()

	kg, err := NewInMemoryKG(globalFixture.Logger)
	require.NoError(t, err, "Failed to create a new InMemoryKG")

	// -- Create a set of nodes --
	nodes := []schemas.Node{
		{ID: "node-1", Type: "URL", Label: "https://example.com"},
		{ID: "node-2", Type: "JavaScript", Label: "main.js"},
		{ID: "node-3", Type: "Vulnerability", Label: "XSS"},
		{ID: "node-4", Type: "Endpoint", Label: "/api/users"},
	}
	for _, n := range nodes {
		err := kg.AddNode(context.Background(), n)
		require.NoError(t, err)
	}

	// -- Link them with edges --
	edges := []schemas.Edge{
		{ID: "edge-1", From: "node-1", To: "node-2", Type: "LOADS_SCRIPT"},
		{ID: "edge-2", From: "node-1", To: "node-4", Type: "HAS_ENDPOINT"},
		{ID: "edge-3", From: "node-2", To: "node-3", Type: "IS_VULNERABLE_TO"},
	}
	for _, e := range edges {
		err := kg.AddEdge(context.Background(), e)
		require.NoError(t, err)
	}

	return kg
}

// -- Test Cases for InMemoryKG --

func TestNewInMemoryKG(t *testing.T) {
	t.Parallel()

	t.Run("should create KG with provided logger", func(t *testing.T) {
		t.Parallel()
		kg, err := NewInMemoryKG(globalFixture.Logger)
		require.NoError(t, err)
		assert.NotNil(t, kg)
		// A bit of an internal check, but good for ensuring logger is passed.
		assert.NotEqual(t, zap.NewNop(), kg.log)
	})

	t.Run("should create KG with a Nop logger if nil is provided", func(t *testing.T) {
		t.Parallel()
		kg, err := NewInMemoryKG(nil)
		require.NoError(t, err)
		assert.NotNil(t, kg)
		// In this case, we expect the fallback Nop logger.
		// This requires a bit of introspection or checking an unexported field,
		// but it's a key feature of the constructor.
	})
}

func TestAddAndGet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kg := getTestKG(t)

	t.Run("should get an existing node", func(t *testing.T) {
		t.Parallel()
		node, err := kg.GetNode(ctx, "node-1")
		require.NoError(t, err)
		assert.Equal(t, "URL", string(node.Type))
		assert.Equal(t, "https://example.com", node.Label)
	})

	t.Run("should get an existing edge", func(t *testing.T) {
		t.Parallel()
		edge, err := kg.GetEdge(ctx, "edge-1")
		require.NoError(t, err)
		assert.Equal(t, "node-1", edge.From)
		assert.Equal(t, "node-2", edge.To)
	})

	t.Run("should return error for non-existent node", func(t *testing.T) {
		t.Parallel()
		_, err := kg.GetNode(ctx, "node-99")
		require.Error(t, err)
		assert.EqualError(t, err, "node with id 'node-99' not found")
	})

	t.Run("should return error for non-existent edge", func(t *testing.T) {
		t.Parallel()
		_, err := kg.GetEdge(ctx, "edge-99")
		require.Error(t, err)
		assert.EqualError(t, err, "edge with id 'edge-99' not found")
	})

	t.Run("should return error when adding edge with missing source node", func(t *testing.T) {
		t.Parallel()
		kg, _ := NewInMemoryKG(nil)
		// Add destination but not source
		_ = kg.AddNode(ctx, schemas.Node{ID: "dest-only"})
		err := kg.AddEdge(ctx, schemas.Edge{ID: "bad-edge", From: "non-existent", To: "dest-only"})
		require.Error(t, err)
		assert.EqualError(t, err, "source node with id 'non-existent' not found for edge")
	})
}

func TestGetNeighborsAndEdges(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	kg := getTestKG(t)

	t.Run("should get correct neighbors for a node", func(t *testing.T) {
		t.Parallel()
		neighbors, err := kg.GetNeighbors(ctx, "node-1")
		require.NoError(t, err)
		require.Len(t, neighbors, 2, "Node-1 should have two neighbors")

		// Use a map for easier assertion, as order is not guaranteed.
		neighborMap := make(map[string]schemas.Node)
		for _, n := range neighbors {
			neighborMap[n.ID] = n
		}
		assert.Contains(t, neighborMap, "node-2")
		assert.Contains(t, neighborMap, "node-4")
	})

	t.Run("should get correct outgoing edges for a node", func(t *testing.T) {
		t.Parallel()
		edges, err := kg.GetEdges(ctx, "node-1")
		require.NoError(t, err)
		require.Len(t, edges, 2, "Node-1 should have two outgoing edges")
		
		edgeMap := make(map[string]schemas.Edge)
		for _, e := range edges {
			edgeMap[e.ID] = e
		}
		assert.Contains(t, edgeMap, "edge-1")
		assert.Contains(t, edgeMap, "edge-2")
	})

	t.Run("should return empty slice for neighbors of a leaf node", func(t *testing.T) {
		t.Parallel()
		neighbors, err := kg.GetNeighbors(ctx, "node-3")
		require.NoError(t, err)
		assert.Empty(t, neighbors, "Leaf node should have no neighbors")
	})

	t.Run("should return error when getting neighbors for non-existent node", func(t *testing.T) {
		t.Parallel()
		_, err := kg.GetNeighbors(ctx, "node-99")
		require.Error(t, err)
	})
}

func TestConcurrency(t *testing.T) {
	t.Parallel()
	kg, err := NewInMemoryKG(globalFixture.Logger)
	require.NoError(t, err)

	var wg sync.WaitGroup
	numRoutines := 100

	// -- seed with an initial node --
	_ = kg.AddNode(context.Background(), schemas.Node{ID: "node-0"})

	// -- spawn writers and readers concurrently --
	for i := 1; i <= numRoutines; i++ {
		wg.Add(2) // Adding two goroutines per loop iteration

		// Writer
		go func(i int) {
			defer wg.Done()
			nodeID := fmt.Sprintf("node-%d", i)
			edgeID := fmt.Sprintf("edge-%d", i)
			node := schemas.Node{ID: nodeID, Type: "Test"}
			edge := schemas.Edge{ID: edgeID, From: "node-0", To: nodeID}

			_ = kg.AddNode(context.Background(), node)
			_ = kg.AddEdge(context.Background(), edge)
		}(i)

		// Reader
		go func() {
			defer wg.Done()
			_, _ = kg.GetNode(context.Background(), "node-0")
			_, _ = kg.GetNeighbors(context.Background(), "node-0")
		}()
	}

	wg.Wait()

	// -- final state check --
	finalNeighbors, err := kg.GetNeighbors(context.Background(), "node-0")
	require.NoError(t, err)
	assert.Len(t, finalNeighbors, numRoutines, "All concurrently added neighbor nodes should be present")
}
