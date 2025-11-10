// File: internal/agent/interfaces.go
package agent

import ( // This is a comment to force a change
	"context"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// SessionProvider is a function type that acts as a dynamic getter for the
// currently active browser session. This allows components to be initialized
// before a session is available and to always access the most current session.
type SessionProvider func() schemas.SessionContext

// ActionRegistry defines the interface for a component, like the ExecutorRegistry,
// that is responsible for dispatching actions to the appropriate executor. This
// abstraction decouples the Agent from the concrete implementation, making it
// more modular and easier to test.
type ActionRegistry interface {
	// Execute dispatches and executes a given action.
	Execute(ctx context.Context, action Action) (*ExecutionResult, error)
	// UpdateSessionProvider allows for the dynamic injection of the session provider.
	UpdateSessionProvider(provider SessionProvider)
}

// EvolutionEngine defines the interface for the agent's proactive
// self-improvement subsystem.
type EvolutionEngine interface {
	// Run initiates the full OODA (Observe, Orient, Decide, Act) loop for a
	// specific improvement objective, blocking until the process completes,
	// fails, or the context is cancelled.
	Run(ctx context.Context, objective string, targetFiles []string) error
}

// LTM (Long-Term Memory) defines the interface for a module that provides the
// agent with memory and learning capabilities. It processes observations to
// identify patterns and flags novel or interesting events.
type LTM interface {
	Start() // Starts any background processes for the LTM.
	Stop()  // Stops the LTM's background processes.
	// ProcessAndFlagObservation analyzes an observation and returns a map of
	// flags indicating its novelty or significance.
	ProcessAndFlagObservation(ctx context.Context, obs Observation) map[string]bool
}

// GraphStore defines a generic interface for interacting with a graph database,
// abstracting the specific implementation (e.g., in-memory, PostgreSQL). This is
// used by the agent and its components to interact with the knowledge graph.
type GraphStore interface {
	AddNode(ctx context.Context, node schemas.Node) error
	GetNode(ctx context.Context, id string) (schemas.Node, error)
	AddEdge(ctx context.Context, edge schemas.Edge) error
	GetEdge(ctx context.Context, id string) (schemas.Edge, error)
	GetEdges(ctx context.Context, nodeID string) ([]schemas.Edge, error)
	GetNeighbors(ctx context.Context, nodeID string) ([]schemas.Node, error)
	QueryImprovementHistory(ctx context.Context, goalObjective string, limit int) ([]schemas.Node, error)
}

// Mind represents the cognitive core of the agent. It is responsible for
// processing observations, reasoning about the current state, and deciding on
// the next course of action.
type Mind interface {
	Start(ctx context.Context) error // Starts the mind's cognitive loop.
	Stop()                           // Gracefully stops the cognitive loop.
	SetMission(mission Mission)      // Assigns a new mission to the mind.
}

// ActionExecutor defines a standard interface for any component that can execute
// a specific type of action. This allows for a modular system where different
// executors handle different capabilities (e.g., browser interaction vs.
// codebase analysis).
type ActionExecutor interface {
	// Execute performs the action and returns the result of the execution.
	Execute(ctx context.Context, action Action) (*ExecutionResult, error)
}
