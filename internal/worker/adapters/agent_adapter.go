// internal/worker/adapters/agent_adapter.go --
package adapters

import (
	"context"
	"fmt"

	"github.com/xkilldash9x/scalpel-cli/internal/agent"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// AgentAdapter integrates the autonomous agent as a standard worker module.
type AgentAdapter struct {
	// The agent itself will be initialized on-demand when a mission is received.
}

// NewAgentAdapter creates a new adapter for agent missions.
func NewAgentAdapter() *AgentAdapter {
	return &AgentAdapter{}
}

// Name returns the identifier for this adapter.
func (a *AgentAdapter) Name() string {
	return "AgentAdapter"
}

// Type returns the analyzer type.
func (a *AgentAdapter) Type() core.AnalyzerType {
	return core.TypeAgent
}

// Analyze is the entry point for an agent mission.
func (a *AgentAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Agent mission received. Initializing agent...")

	// Extract mission parameters from the task.
	missionBrief, ok := analysisCtx.Task.Parameters["mission_brief"].(string)
	if !ok || missionBrief == "" {
		return fmt.Errorf("agent mission task is missing a 'mission_brief' parameter")
	}

	// The agent needs access to the global context to use shared services
	// like the logger, browser manager, and knowledge graph.
	agentCfg := agent.Config{
		Mission: missionBrief,
		Target:  analysisCtx.Task.TargetURL,
	}

	// Here's the magic: The agent gets the full global context, allowing it to
	// access the TaskEngine (if we add it there) to submit new tasks.
	agentInstance, err := agent.New(ctx, agentCfg, analysisCtx.Global)
	if err != nil {
		return fmt.Errorf("failed to initialize agent: %w", err)
	}

	analysisCtx.Logger.Info("Agent initialized. Starting mission execution.")

	// Run the agent's main logic loop.
	// This is a blocking call that will run until the mission is complete or the context is cancelled.
	missionResult, err := agentInstance.RunMission(ctx)
	if err != nil {
		return fmt.Errorf("agent mission failed: %w", err)
	}

	// The agent's findings and graph updates would be part of the missionResult
	// and should be added to the analysisCtx here.
	analysisCtx.Logger.Info("Agent mission completed.", "summary", missionResult.Summary)
	analysisCtx.Findings = append(analysisCtx.Findings, missionResult.Findings...)
	analysisCtx.KGUpdates.Nodes = append(analysisCtx.KGUpdates.Nodes, missionResult.KGUpdates.Nodes...)
	analysisCtx.KGUpdates.Edges = append(analysisCtx.KGUpdates.Edges, missionResult.KGUpdates.Edges...)

	return nil
}
