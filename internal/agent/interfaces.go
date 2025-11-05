// File: internal/agent/interfaces.go
package agent

import ( // This is a comment to force a change
	"context"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
)

// SessionProvider is a function type that retrieves the currently active browser session context.
// This is now defined here to be accessible by the ActionRegistry interface.
type SessionProvider func(context.Context) (schemas.SessionContext, error)

// ActionRegistry defines the interface for a component that dispatches actions.
// This decouples the Agent from the concrete ExecutorRegistry, improving testability.
type ActionRegistry interface {
	Execute(ctx context.Context, action Action) (*ExecutionResult, error)
	UpdateSessionProvider(provider SessionProvider)
	UpdateHumanoidProvider(provider HumanoidProvider)
}

// HumanoidProvider is a function type that returns the active Humanoid instance.
type HumanoidProvider func() *humanoid.Humanoid

// EvolutionEngine defines the interface for the proactive self-improvement system.
type EvolutionEngine interface {
	// Run initiates the OODA loop for a specific improvement goal.
	// It blocks until the goal is achieved, fails, or times out.
	Run(ctx context.Context, objective string, targetFiles []string) error
}

// ImprovementAnalyst defines the interface for the component responsible for analyzing
// the codebase and suggesting improvements (part of the Evolution system).
type ImprovementAnalyst interface {
	AnalyzeAndImprove(ctx context.Context, goal string, bus CognitiveBus) error
}

// LTM defines the interface for the Long-Term Memory module, including lifecycle management.
type LTM interface {
	Start()
	Stop()
	ProcessAndFlagObservation(ctx context.Context, obs Observation) map[string]bool
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

// CognitiveBus defines the interface for the agent's internal message bus.
type CognitiveBus interface {
	Post(ctx context.Context, msg CognitiveMessage) error
	Subscribe(msgTypes ...CognitiveMessageType) (<-chan CognitiveMessage, func())
	Acknowledge(msg CognitiveMessage)
	Shutdown()
}
