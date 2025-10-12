package agent

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// EvolutionEngine defines the interface for the proactive self-improvement system.
type EvolutionEngine interface {
	// Run initiates the OODA loop for a specific improvement goal.
	// It blocks until the goal is achieved, fails, or times out.
	Run(ctx context.Context, objective string, targetFiles []string) error
}

// GraphStore defines the interface the agent's mind uses to interact with the knowledge graph.
type GraphStore interface {
	AddNode(ctx context.Context, node schemas.Node) error
	GetNode(ctx context.Context, id string) (schemas.Node, error)
	AddEdge(ctx context.Context, edge schemas.Edge) error
	GetEdges(ctx context.Context, nodeID string) ([]schemas.Edge, error)
	GetNeighbors(ctx context.Context, nodeID string) ([]schemas.Node, error)
	QueryImprovementHistory(ctx context.Context, goalObjective string, limit int) ([]schemas.Node, error)
}

// Mind defines the cognitive core of the agent.
type Mind interface {
	Start(ctx context.Context) error
	Stop()
	SetMission(mission Mission)
}

// ActionExecutor defines the interface for a component that can execute a specific type of action.
type ActionExecutor interface {
	Execute(ctx context.Context, action Action) (*ExecutionResult, error)
}
