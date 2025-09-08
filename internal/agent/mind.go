package agent

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	// Updated import path to use the interface
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
)

// Mind defines the interface for the agent's cognitive core (The OODA loop implementation).
type Mind interface {
	// Initialize sets up the Mind with access to shared resources.
	// Now accepts the GraphStore interface instead of the concrete implementation.
	Initialize(cfg config.AgentConfig, kg knowledgegraph.GraphStore, bus *CognitiveBus) error

	// Start begins the cognitive processing loop.
	Start(ctx context.Context) error

	// SetMission updates the Mind's current objective.
	SetMission(mission Mission)

	// Stop gracefully shuts down the cognitive processes.
	Stop()
}
