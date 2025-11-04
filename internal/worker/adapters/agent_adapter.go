// File: internal/worker/adapters/agent_adapter.go
package adapters

import (
	"context"
	"fmt"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// AgentAdapter is the bridge that lets our autonomous agent operate as a standard worker module.
type AgentAdapter struct {
	// Embed BaseAnalyzer by value for consistency.
	core.BaseAnalyzer
}

// NewAgentAdapter creates a new adapter for agent missions.
func NewAgentAdapter() *AgentAdapter {
	return &AgentAdapter{
		// Initialize the embedded struct by dereferencing the pointer from the constructor.
		BaseAnalyzer: *core.NewBaseAnalyzer("AgentAdapter", "Executes autonomous agent missions", core.TypeAgent, zap.NewNop()),
	}
}

func (a *AgentAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	// Use the logger from the context.
	logger := analysisCtx.Logger.With(zap.String("adapter", a.Name()))
	logger.Info("Agent mission received. Initializing agent...")

	// 1. Parameter Validation and Extraction
	var params schemas.AgentMissionParams
	switch p := analysisCtx.Task.Parameters.(type) {
	case schemas.AgentMissionParams:
		params = p
	case *schemas.AgentMissionParams:
		if p == nil {
			return fmt.Errorf("invalid parameters: nil pointer for Agent mission")
		}
		params = *p
	default:
		actualType := fmt.Sprintf("%T", analysisCtx.Task.Parameters)
		logger.Error("Invalid parameter type assertion for Agent mission",
			zap.String("expected", "schemas.AgentMissionParams or pointer"),
			zap.String("actual", actualType))
		return fmt.Errorf("invalid parameters type for Agent mission; expected schemas.AgentMissionParams or *schemas.AgentMissionParams, got %s", actualType)
	}

	if params.MissionBrief == "" {
		return fmt.Errorf("validation error: agent mission task is missing required 'MissionBrief'")
	}

	// 2. Resource Acquisition (Browser Session)
	if analysisCtx.Global == nil || analysisCtx.Global.BrowserManager == nil {
		return fmt.Errorf("critical error: BrowserManager is not available in GlobalContext")
	}

	session, err := analysisCtx.Global.BrowserManager.NewAnalysisContext(
		ctx,
		analysisCtx.Task,
		schemas.DefaultPersona,
		"", // initialURL
		"", // initialData
		analysisCtx.Global.FindingsChan,
	)
	if err != nil {
		return fmt.Errorf("failed to create browser session for agent: %w", err)
	}
	// Ensure the session is closed. Use a background context for cleanup in case the main context is canceled.
	defer session.Close(context.Background())

	// 3. Agent Initialization
	agentMission := agent.Mission{
		ID:        analysisCtx.Task.TaskID,
		Objective: params.MissionBrief,
		TargetURL: analysisCtx.Task.TargetURL,
	}

	// Pass the newly created session to the agent constructor.
	agentInstance, err := agent.New(ctx, agentMission, analysisCtx.Global, session)
	if err != nil {
		return fmt.Errorf("failed to initialize agent: %w", err)
	}

	// 4. Execution
	logger.Info("Agent initialized. Starting mission execution.")
	missionResult, err := agentInstance.RunMission(ctx)
	if err != nil {
		// Handle context cancellation gracefully.
		if ctx.Err() != nil {
			logger.Warn("Agent mission interrupted or timed out.", zap.Error(err))
			return ctx.Err()
		}
		return fmt.Errorf("agent mission failed: %w", err)
	}

	// 5. Result Processing
	logger.Info("Agent mission completed.", zap.String("summary", missionResult.Summary))

	if len(missionResult.Findings) > 0 {
		for _, finding := range missionResult.Findings {
			analysisCtx.AddFinding(finding)
		}
	}

	// Ensure KGUpdates is initialized before modification (defensive check against nil pointer)
	if analysisCtx.KGUpdates == nil {
		// Initialize if nil, assuming the expected type based on usage.
		analysisCtx.KGUpdates = &schemas.KnowledgeGraphUpdate{}
	}

	if missionResult.KGUpdates != nil {
		analysisCtx.KGUpdates.NodesToAdd = append(analysisCtx.KGUpdates.NodesToAdd, missionResult.KGUpdates.NodesToAdd...)
		analysisCtx.KGUpdates.EdgesToAdd = append(analysisCtx.KGUpdates.EdgesToAdd, missionResult.KGUpdates.EdgesToAdd...)
	}

	return nil
}
