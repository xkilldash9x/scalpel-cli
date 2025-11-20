// internal/knowledgegraph/knowledgegraph_test.go
package knowledgegraph

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

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
	// Use Nop logger for cleaner test output. Use NewDevelopment() for debugging.
	logger := zap.NewNop()
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
	})

	t.Run("should not panic if nil logger is provided", func(t *testing.T) {
		t.Parallel()
		// This test ensures the constructor is safe and provides a fallback
		// without being brittle by inspecting unexported fields.
		kg, err := NewInMemoryKG(nil)
		require.NoError(t, err)
		assert.NotNil(t, kg)
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

	// Verification for Fix 6
	t.Run("should correctly update indices when an edge is moved (source changes)", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		kg := getTestKG(t)

		// Initial state: edge-3 goes from node-2 to node-3.
		neighbors2, _ := kg.GetNeighbors(ctx, "node-2")
		require.Len(t, neighbors2, 1)
		edges2, _ := kg.GetEdges(ctx, "node-2")
		require.Len(t, edges2, 1)

		// Action: Update edge-3 to go from node-4 to node-3.
		updatedEdge := schemas.Edge{
			ID:   "edge-3",
			From: "node-4", // New source
			To:   "node-3",
			Type: "IS_VULNERABLE_TO_NOW",
		}
		err := kg.AddEdge(ctx, updatedEdge)
		require.NoError(t, err)

		// Verification:
		// 1. Verify the edge itself is updated.
		edge, err := kg.GetEdge(ctx, "edge-3")
		require.NoError(t, err)
		assert.Equal(t, "node-4", edge.From)

		// 2. Verify the old source node (node-2) no longer lists the neighbor/edge.
		neighbors2After, err := kg.GetNeighbors(ctx, "node-2")
		require.NoError(t, err)
		assert.Empty(t, neighbors2After, "Old source node should have no neighbors after edge move")
		edges2After, err := kg.GetEdges(ctx, "node-2")
		require.NoError(t, err)
		assert.Empty(t, edges2After, "Old source node should have no edges after edge move")

		// 3. Verify the new source node (node-4) now lists the neighbor/edge.
		neighbors4After, err := kg.GetNeighbors(ctx, "node-4")
		require.NoError(t, err)
		require.Len(t, neighbors4After, 1, "New source node should have the neighbor after edge move")
		assert.Equal(t, "node-3", neighbors4After[0].ID)
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

		// Use a map for easier assertion, as order is not guaranteed (especially after Fix 6 implementation).
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
	// Note: It is highly recommended to run this test with the -race flag
	// to detect potential data races: `go test -race ./...`
	t.Parallel()
	kg, err := NewInMemoryKG(globalFixture.Logger)
	require.NoError(t, err)

	var wg sync.WaitGroup
	numRoutines := 100
	errChan := make(chan error, numRoutines*2) // Buffer for potential errors from writers

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

			if err := kg.AddNode(context.Background(), node); err != nil {
				errChan <- fmt.Errorf("writer failed to add node: %w", err)
			}
			if err := kg.AddEdge(context.Background(), edge); err != nil {
				errChan <- fmt.Errorf("writer failed to add edge: %w", err)
			}
		}(i)

		// Reader
		go func() {
			defer wg.Done()
			_, _ = kg.GetNode(context.Background(), "node-0")
			_, _ = kg.GetNeighbors(context.Background(), "node-0")
		}()
	}

	wg.Wait()
	close(errChan)

	// -- check for any errors that occurred during concurrent writes --
	for err := range errChan {
		require.NoError(t, err, "Concurrency test encountered an unexpected error")
	}

	// -- final state check --
	finalNeighbors, err := kg.GetNeighbors(context.Background(), "node-0")
	require.NoError(t, err)
	assert.Len(t, finalNeighbors, numRoutines, "All concurrently added neighbor nodes should be present")
}

func TestQueryImprovementHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Setup: Create a KG with specific history nodes
	kg, err := NewInMemoryKG(globalFixture.Logger)
	require.NoError(t, err)

	objectiveA := "Improve API response time"
	objectiveB := "Reduce memory usage"

	// Create properties for nodes
	propsA1, _ := json.Marshal(schemas.ImprovementAttemptProperties{GoalObjective: objectiveA})
	propsA2, _ := json.Marshal(schemas.ImprovementAttemptProperties{GoalObjective: objectiveA})
	propsB1, _ := json.Marshal(schemas.ImprovementAttemptProperties{GoalObjective: objectiveB})
	// Verification for Fix 7: Nodes with invalid/null properties
	propsInvalid := json.RawMessage(`{"goal_objective": "Objective C", error: }`)
	propsNull := json.RawMessage(`null`)

	nodes := []schemas.Node{
		// These two match objective A, with A2 being the most recent
		{ID: "hist-a1", Type: schemas.NodeImprovementAttempt, Properties: propsA1, CreatedAt: time.Now().Add(-10 * time.Minute)},
		{ID: "hist-a2", Type: schemas.NodeImprovementAttempt, Properties: propsA2, CreatedAt: time.Now().Add(-5 * time.Minute)},
		// This one matches objective B
		{ID: "hist-b1", Type: schemas.NodeImprovementAttempt, Properties: propsB1, CreatedAt: time.Now()},
		// This is not an improvement attempt node and should be ignored
		{ID: "other-node", Type: "URL", Label: "ignore me"},
		// These should be safely ignored during query
		{ID: "hist-invalid", Type: schemas.NodeImprovementAttempt, Properties: propsInvalid, CreatedAt: time.Now()},
		{ID: "hist-null", Type: schemas.NodeImprovementAttempt, Properties: propsNull, CreatedAt: time.Now()},
	}

	for _, n := range nodes {
		err := kg.AddNode(ctx, n)
		require.NoError(t, err)
	}

	t.Run("should find all history for an objective and sort by most recent (ignoring invalid nodes)", func(t *testing.T) {
		t.Parallel()
		history, err := kg.QueryImprovementHistory(ctx, objectiveA, 0) // 0 limit means no limit
		require.NoError(t, err)
		require.Len(t, history, 2)
		// Verify descending order by checking that the first result is the newest one
		assert.Equal(t, "hist-a2", history[0].ID)
		assert.Equal(t, "hist-a1", history[1].ID)
	})

	t.Run("should respect the limit parameter", func(t *testing.T) {
		t.Parallel()
		history, err := kg.QueryImprovementHistory(ctx, objectiveA, 1)
		require.NoError(t, err)
		require.Len(t, history, 1)
		assert.Equal(t, "hist-a2", history[0].ID)
	})

	t.Run("should return empty slice for an objective with no history", func(t *testing.T) {
		t.Parallel()
		history, err := kg.QueryImprovementHistory(ctx, "A completely different objective", 0)
		require.NoError(t, err)
		assert.Empty(t, history)
	})
}
