package adapters

import ( // This is a comment to force a change
	"context"
	"fmt"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// the bridge that lets our autonomous agent play nice as a standard worker module.
type AgentAdapter struct {
	*core.BaseAnalyzer
}

// creates a new adapter for agent missions.
func NewAgentAdapter() *AgentAdapter {
	return &AgentAdapter{
		BaseAnalyzer: core.NewBaseAnalyzer("AgentAdapter", "Executes autonomous agent missions", core.TypeAgent, zap.NewNop()),
	}
}

func (a *AgentAdapter) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	a.Logger = analysisCtx.Logger
	a.Logger.Info("Agent mission received. Initializing agent...")

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
		a.Logger.Error("Invalid parameter type assertion for Agent mission",
			zap.String("expected", "schemas.AgentMissionParams or pointer"),
			zap.String("actual", actualType))
		return fmt.Errorf("invalid parameters type for Agent mission; expected schemas.AgentMissionParams or *schemas.AgentMissionParams, got %s", actualType)
	}

	if params.MissionBrief == "" {
		return fmt.Errorf("validation error: agent mission task is missing required 'MissionBrief'")
	}

	agentMission := agent.Mission{
		ID:        analysisCtx.Task.TaskID,
		Objective: params.MissionBrief,
		TargetURL: analysisCtx.Task.TargetURL,
	}

	// The agent is an active module that requires a browser session to run.
	// We create one here and pass it to the agent's constructor.
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
	defer session.Close(context.Background())

	// Pass the newly created session as the fourth argument.
	agentInstance, err := agent.New(ctx, agentMission, analysisCtx.Global, session)
	if err != nil {
		return fmt.Errorf("failed to initialize agent: %w", err)
	}

	a.Logger.Info("Agent initialized. Starting mission execution.")

	missionResult, err := agentInstance.RunMission(ctx)
	if err != nil {
		if ctx.Err() != nil {
			a.Logger.Warn("Agent mission interrupted or timed out.", zap.Error(err))
			return ctx.Err()
		}
		return fmt.Errorf("agent mission failed: %w", err)
	}

	a.Logger.Info("Agent mission completed.", zap.String("summary", missionResult.Summary))

	if len(missionResult.Findings) > 0 {
		for _, finding := range missionResult.Findings {
			analysisCtx.AddFinding(finding)
		}
	}

	if missionResult.KGUpdates != nil {
		analysisCtx.KGUpdates.NodesToAdd = append(analysisCtx.KGUpdates.NodesToAdd, missionResult.KGUpdates.NodesToAdd...)
		analysisCtx.KGUpdates.EdgesToAdd = append(analysisCtx.KGUpdates.EdgesToAdd, missionResult.KGUpdates.EdgesToAdd...)
	}

	return nil
}
