package knowledgegraph

import (
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// KnowledgeGraph implements the interfaces.KnowledgeGraph interface.
type KnowledgeGraph struct {
	// For now, this is a placeholder. In a real implementation,
	// this would hold a database connection or other storage client.
	nodes map[string]*schemas.Node
	edges map[string][]*schemas.Edge
}

// NewKnowledgeGraph creates a new in-memory knowledge graph.
func NewKnowledgeGraph() *KnowledgeGraph {
	return &KnowledgeGraph{
		nodes: make(map[string]*schemas.Node),
		edges: make(map[string][]*schemas.Edge),
	}
}

// AddNode adds a node to the graph.
func (kg *KnowledgeGraph) AddNode(node *schemas.Node) error {
	kg.nodes[node.ID] = node
	return nil
}

// AddEdge adds an edge to the graph.
func (kg *KnowledgeGraph) AddEdge(edge *schemas.Edge) error {
	kg.edges[edge.From] = append(kg.edges[edge.From], edge)
	return nil
}

// GetNode retrieves a node by its ID.
func (kg *KnowledgeGraph) GetNode(id string) (*schemas.Node, error) {
	return kg.nodes[id], nil
}

// GetEdge retrieves an edge by its ID (not implemented for this in-memory example).
func (kg *KnowledgeGraph) GetEdge(id string) (*schemas.Edge, error) {
	return nil, nil
}

// GetNeighbors retrieves the neighbors of a given node.
func (kg *KnowledgeGraph) GetNeighbors(nodeID string) ([]*schemas.Node, error) {
	var neighbors []*schemas.Node
	for _, edge := range kg.edges[nodeID] {
		neighbors = append(neighbors, kg.nodes[edge.To])
	}
	return neighbors, nil
}

// GetEdges retrieves the edges of a given node.
func (kg *KnowledgeGraph) GetEdges(nodeID string) ([]*schemas.Edge, error) {
	return kg.edges[nodeID], nil
}
