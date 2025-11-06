// File: internal/worker/adapters/agent_adapter.go
package adapters

import (
	"context"
	"fmt"
	"time"

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
		// Pass nil for the logger; it will be retrieved from the AnalysisContext during Analyze.
		// This prevents issues with global logger initialization order.
		BaseAnalyzer: *core.NewBaseAnalyzer("AgentAdapter", "Executes autonomous agent missions", core.TypeAgent, nil),
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
		actualType := fmt.Sprintf("%T", p)
		logger.Error("Invalid parameter type assertion for Agent mission",
			zap.String("expected", "schemas.AgentMissionParams or pointer"),
			zap.String("actual", actualType))
		return fmt.Errorf("invalid parameters type for Agent mission; expected schemas.AgentMissionParams or *schemas.AgentMissionParams, got %T", p)
	}

	if params.MissionBrief == "" {
		return fmt.Errorf("validation error: agent mission task is missing required 'MissionBrief'")
	}

	// 2. Resource Acquisition (Validation)
	// We only check for the manager; the agent will create the session itself.
	if analysisCtx.Global == nil || analysisCtx.Global.BrowserManager == nil {
		return fmt.Errorf("critical error: BrowserManager is not available in GlobalContext")
	}
	// (We no longer create a session here)

	// 3. Agent Initialization
	// FIX 1: Use 'mission' instead of 'agentMission'
	mission := agent.Mission{
		ID:        analysisCtx.Task.TaskID,
		ScanID:    analysisCtx.Task.ScanID,
		Objective: params.MissionBrief,
		TargetURL: analysisCtx.Task.TargetURL,
		StartTime: time.Now(),
	}

	// FIX 2: Pass 'analysisCtx.Global' instead of 'globalCtx'
	agentInstance, err := agent.New(ctx, &mission, analysisCtx.Global)
	if err != nil {
		return fmt.Errorf("failed to initialize agent: %w", err)
	}

	// 4. Execution
	// FIX 3: Replace 'RunMission' with 'Start' and asynchronous result handling.
	logger.Info("Agent initialized. Starting mission execution.")

	// Start the agent in a goroutine.
	startErrChan := make(chan error, 1)
	go func() {
		// Start blocks until ctx is cancelled or a critical error occurs.
		startErrChan <- agentInstance.Start(ctx)
	}()

	var missionResult agent.MissionResult

	// Wait for the mission to complete (via resultChan) or for the context to be cancelled.
	select {
	case result := <-agentInstance.GetResultChan(): // Assumes a getter `GetResultChan()` exists on Agent
		missionResult = result
		// Mission finished. The agent's Start() loop is still running,
		// but it will be stopped when `ctx` is cancelled by the caller of `Analyze`.

	case err = <-startErrChan:
		// Agent's Start() method failed or stopped unexpectedly before sending a result.
		return fmt.Errorf("agent failed to start or stopped unexpectedly: %w", err)

	case <-ctx.Done():
		// The entire analysis task was cancelled.
		logger.Warn("Agent mission interrupted or timed out.", zap.Error(ctx.Err()))
		// Wait for the Start() goroutine to exit.
		select {
		case err = <-startErrChan:
			// Log the final error from Start(), if any
			logger.Warn("Agent Start() routine exited on cancellation.", zap.Error(err))
		case <-time.After(5 * time.Second): // Failsafe timeout
			logger.Error("Timeout waiting for agent Start() to exit after cancellation.")
		}
		return ctx.Err()
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

	// FIX 4: Removed the 'missionResult.KGUpdates' block, as that field
	// does not exist on the 'MissionResult' struct.
	// if missionResult.KGUpdates != nil { ... }

	return nil
}

/*
Note: This fix requires one small addition to `internal/agent/agent.go` to allow the adapter to access the result channel:

func (a *Agent) GetResultChan() <-chan MissionResult {
	return a.resultChan
}
*/
