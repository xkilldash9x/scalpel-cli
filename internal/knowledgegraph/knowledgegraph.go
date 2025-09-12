// internal/knowledgegraph/knowledgegraph.go
package knowledgegraph

import (
	"context"
	"fmt"
	"sync"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// InMemoryKG provides a fast, ephemeral, in-memory implementation of the KnowledgeGraph interface.
// It's great for testing, short lived scripts, or situations where persistence isn't required.
type InMemoryKG struct {
	nodes         map[string]schemas.Node
	edges         map[string]schemas.Edge // Key: edge ID
	outgoingEdges map[string][]string   // Key: node ID, Value: slice of edge IDs
	mu            sync.RWMutex
	log           *zap.Logger
}

// NewInMemoryKG creates a new, empty in-memory knowledge graph.
func NewInMemoryKG(logger *zap.Logger) (*InMemoryKG, error) {
	if logger == nil {
		// Fallback to Nop logger if none provided.
		// This makes initialization more robust.
		logger = zap.NewNop()
	}
	return &InMemoryKG{
		nodes:         make(map[string]schemas.Node),
		edges:         make(map[string]schemas.Edge),
		outgoingEdges: make(map[string][]string),
		log:           logger.Named("InMemoryKG"),
	}, nil
}

// AddNode adds a node to the graph. If a node with the same ID already exists,
// it is overwritten, making the operation idempotent.
func (kg *InMemoryKG) AddNode(ctx context.Context, node schemas.Node) error {
	kg.mu.Lock()
	defer kg.mu.Unlock()

	kg.nodes[node.ID] = node
	// Fixed a type casting issue here. The logger expects a string,
	// so we need to explicitly cast node.Type.
	kg.log.Debug("Node added or updated", zap.String("ID", node.ID), zap.String("Type", string(node.Type)))
	return nil
}

// AddEdge adds an edge to the graph. If an edge with the same ID already exists,
// it's overwritten. This also maintains an index for quick lookups of outgoing edges.
func (kg *InMemoryKG) AddEdge(ctx context.Context, edge schemas.Edge) error {
	kg.mu.Lock()
	defer kg.mu.Unlock()

	// Check if both nodes for the edge exist.
	if _, exists := kg.nodes[edge.From]; !exists {
		// For now, we enforce consistency. In a high-throughput system, we might relax this
		// if nodes are expected to arrive shortly after their corresponding edges.
		return fmt.Errorf("source node with id '%s' not found for edge", edge.From)
	}
	if _, exists := kg.nodes[edge.To]; !exists {
		return fmt.Errorf("destination node with id '%s' not found for edge", edge.To)
	}

	// Check if this edge is already registered for the 'From' node to avoid duplicates in the outgoingEdges slice.
	isNew := true
	if _, exists := kg.edges[edge.ID]; exists {
		isNew = false // The edge is being updated, not added.
	}

	kg.edges[edge.ID] = edge

	if isNew {
		kg.outgoingEdges[edge.From] = append(kg.outgoingEdges[edge.From], edge.ID)
	}

	kg.log.Debug("Edge added or updated", zap.String("ID", edge.ID), zap.String("From", edge.From), zap.String("To", edge.To))
	return nil
}

// GetNode retrieves a node by its ID.
func (kg *InMemoryKG) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	node, ok := kg.nodes[id]
	if !ok {
		return schemas.Node{}, fmt.Errorf("node with id '%s' not found", id)
	}
	return node, nil
}

// GetEdge retrieves an edge by its ID.
func (kg *InMemoryKG) GetEdge(ctx context.Context, id string) (schemas.Edge, error) {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	edge, ok := kg.edges[id]
	if !ok {
		return schemas.Edge{}, fmt.Errorf("edge with id '%s' not found", id)
	}
	return edge, nil
}

// GetNeighbors finds all nodes connected from the given node.
func (kg *InMemoryKG) GetNeighbors(ctx context.Context, nodeID string) ([]schemas.Node, error) {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	// Ensure the source node exists first.
	if _, ok := kg.nodes[nodeID]; !ok {
		return nil, fmt.Errorf("node with id '%s' not found", nodeID)
	}

	edgeIDs, ok := kg.outgoingEdges[nodeID]
	if !ok {
		return []schemas.Node{}, nil // No outgoing edges, so no neighbors.
	}

	neighbors := make([]schemas.Node, 0, len(edgeIDs))
	for _, edgeID := range edgeIDs {
		edge, ok := kg.edges[edgeID]
		if !ok {
			// This indicates a data consistency issue, which shouldn't happen with proper locking.
			kg.log.Error("Inconsistency detected: outgoing edge ID not in edges map", zap.String("edgeID", edgeID))
			continue
		}
		neighborNode, ok := kg.nodes[edge.To]
		if !ok {
			kg.log.Error("Inconsistency detected: neighbor node ID not in nodes map", zap.String("nodeID", edge.To))
			continue
		}
		neighbors = append(neighbors, neighborNode)
	}
	return neighbors, nil
}

// GetEdges retrieves all outgoing edges from a specific node ID.
func (kg *InMemoryKG) GetEdges(ctx context.Context, nodeID string) ([]schemas.Edge, error) {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	// Ensure the source node exists.
	if _, ok := kg.nodes[nodeID]; !ok {
		return nil, fmt.Errorf("node with id '%s' not found", nodeID)
	}

	edgeIDs, ok := kg.outgoingEdges[nodeID]
	if !ok {
		return []schemas.Edge{}, nil // No outgoing edges.
	}

	edges := make([]schemas.Edge, 0, len(edgeIDs))
	for _, edgeID := range edgeIDs {
		edge, ok := kg.edges[edgeID]
		if !ok {
			kg.log.Error("Inconsistency detected: outgoing edge ID not in edges map", zap.String("edgeID", edgeID))
			continue
		}
		edges = append(edges, edge)
	}

	return edges, nil
}

