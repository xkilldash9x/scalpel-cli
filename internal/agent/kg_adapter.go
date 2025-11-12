// internal/agent/kg_adapter.go
package agent

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// KnowledgeGraphClientAdapter adapts a GraphStore to the schemas.KnowledgeGraphClient interface.
type KnowledgeGraphClientAdapter struct {
	store GraphStore
}

// NewKnowledgeGraphClientAdapter creates a new adapter.
func NewKnowledgeGraphClientAdapter(store GraphStore) *KnowledgeGraphClientAdapter {
	return &KnowledgeGraphClientAdapter{store: store}
}

func (a *KnowledgeGraphClientAdapter) AddNode(ctx context.Context, node schemas.Node) error {
	return a.store.AddNode(ctx, node)
}

func (a *KnowledgeGraphClientAdapter) AddEdge(ctx context.Context, edge schemas.Edge) error {
	return a.store.AddEdge(ctx, edge)
}

func (a *KnowledgeGraphClientAdapter) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	return a.store.GetNode(ctx, id)
}

func (a *KnowledgeGraphClientAdapter) GetEdge(ctx context.Context, id string) (schemas.Edge, error) {
	return a.store.GetEdge(ctx, id)
}

func (a *KnowledgeGraphClientAdapter) GetEdges(ctx context.Context, nodeID string) ([]schemas.Edge, error) {
	return a.store.GetEdges(ctx, nodeID)
}

func (a *KnowledgeGraphClientAdapter) GetNeighbors(ctx context.Context, nodeID string) ([]schemas.Node, error) {
	return a.store.GetNeighbors(ctx, nodeID)
}

func (a *KnowledgeGraphClientAdapter) QueryImprovementHistory(ctx context.Context, goalObjective string, limit int) ([]schemas.Node, error) {
	return a.store.QueryImprovementHistory(ctx, goalObjective, limit)
}
