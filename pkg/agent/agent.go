// pkg/worker/adapters/agent_adapter.go
package agent

import (
	"context"
	"fmt"

	"github.com/xkilldash9x/scalpel-cli/pkg/agent"
	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// AgentAdapter integrates the autonomous agent as a standard worker module.
type AgentAdapter struct {
	core.BaseAnalyzer
	// The agent itself will be initialized on-demand when a mission is received.
}

// NewAgentAdapter creates a new adapter for agent missions.
func NewAgentAdapter() *AgentAdapter {
	return &AgentAdapter{
		BaseAnalyzer: core.NewBaseAnalyzer("AgentAdapter", core.TypeAgent),
	}
}

// Analyze is the entry point for an agent mission.
func (a *AgentAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	analysisCtx.Logger.Info("Agent mission received. Initializing agent...")

	// BUG FIX: Use a type assertion to safely access typed parameters.
	params, ok := analysisCtx.Task.Parameters.(schemas.AgentMissionParams)
	if !ok || params.MissionBrief == "" {
		return fmt.Errorf("agent mission task is missing parameters or a 'mission_brief'")
	}

	// The agent needs access to the global context to use shared services
	// like the logger, browser manager, and knowledge graph.
	agentCfg := agent.Config{
		Mission: params.MissionBrief,
		Target:  analysisCtx.Task.TargetURL,
	}

	// The agent gets the full global context, allowing it to
	// access the TaskEngine to submit new tasks.
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

	// The agent's findings and graph updates are part of the missionResult
	// and are added to the analysisCtx here.
	analysisCtx.Logger.Info("Agent mission completed.", "summary", missionResult.Summary)
	analysisCtx.Findings = append(analysisCtx.Findings, missionResult.Findings...)
	analysisCtx.KGUpdates.Nodes = append(analysisCtx.KGUpdates.Nodes, missionResult.KGUpdates.Nodes...)
	analysisCtx.KGUpdates.Edges = append(analysisCtx.KGUpdates.Edges, missionResult.KGUpdates.Edges...)

	return nil
}
