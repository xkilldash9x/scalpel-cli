package knowledgegraph

import (
	"context"
	"fmt"
	"sync"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

type InMemoryKG struct {
	nodes map[string]schemas.Node
	edges map[string][]schemas.Edge
	mu    sync.RWMutex
	log   *zap.Logger
}

func NewInMemoryKG(logger *zap.Logger) (*InMemoryKG, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}
	return &InMemoryKG{
		nodes: make(map[string]schemas.Node),
		edges: make(map[string][]schemas.Edge),
		log:   logger.Named("InMemoryKG"),
	}, nil
}

func (kg *InMemoryKG) AddNode(ctx context.Context, node schemas.Node) error {
	kg.mu.Lock()
	defer kg.mu.Unlock()

	if _, exists := kg.nodes[node.ID]; exists {
		// idempotency
		return nil
	}
	kg.nodes[node.ID] = node
	kg.log.Debug("Node added", zap.String("ID", node.ID), zap.String("Type", node.Type))
	return nil
}

func (kg *InMemoryKG) AddEdge(ctx context.Context, edge schemas.Edge) error {
	kg.mu.Lock()
	defer kg.mu.Unlock()

	kg.edges[edge.From] = append(kg.edges[edge.From], edge)
	kg.log.Debug("Edge added", zap.String("From", edge.From), zap.String("To", edge.To), zap.String("Type", edge.Type))
	return nil
}

func (kg *InMemoryKG) GetNode(ctx context.Context, id string) (schemas.Node, error) {
	kg.mu.RLock()
	defer kg.mu.RUnlock()

	node, ok := kg.nodes[id]
	if !ok {
		return schemas.Node{}, fmt.Errorf("node not found: %s", id)
	}
	return node, nil
}