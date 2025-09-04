package interfaces

import "github.com/xkilldash9x/scalpel-cli/pkg/schemas"

// KnowledgeGraph defines the standard interface for interacting with the graph database.
// This abstraction allows for different backend implementations (e.g., in-memory, PostgreSQL)
// to be used interchangeably throughout the application.
type KnowledgeGraph interface {
	AddNode(node *schemas.Node) error
	AddEdge(edge *schemas.Edge) error
	GetNode(id string) (*schemas.Node, error)
	GetEdge(id string) (*schemas.Edge, error)
	GetNeighbors(nodeID string) ([]*schemas.Node, error)
	GetEdges(nodeID string) ([]*schemas.Edge, error)
}
