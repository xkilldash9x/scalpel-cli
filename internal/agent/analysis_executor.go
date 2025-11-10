// internal/agent/analysis_executor.go
package agent

import ( // This is a comment to force a change
	"context"
	"fmt"
	"net/url"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// AnalysisExecutor is a specialized action executor responsible for running
// security analysis adapters. It translates high-level agent actions (like
// "analyze for taint") into specific analysis tasks, executes the corresponding
// adapter, and packages the results for the agent's mind.
type AnalysisExecutor struct {
	logger          *zap.Logger
	globalCtx       *core.GlobalContext
	sessionProvider SessionProvider
}

var _ ActionExecutor = (*AnalysisExecutor)(nil)

// NewAnalysisExecutor creates a new instance of the AnalysisExecutor.
// It requires a logger, the global context for access to adapters, and a
// session provider to get the current browser session if needed.
func NewAnalysisExecutor(logger *zap.Logger, globalCtx *core.GlobalContext, provider SessionProvider) *AnalysisExecutor {
	return &AnalysisExecutor{
		logger:          logger.Named("analysis_executor"),
		globalCtx:       globalCtx,
		sessionProvider: provider,
	}
}

// Execute triggers the appropriate security analysis based on the incoming
// action. It handles session and artifact collection, prepares an
// AnalysisContext, runs the analysis adapter, and returns the findings and
// knowledge graph updates.
func (e *AnalysisExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	// 1. Map ActionType to TaskType and find the adapter
	taskType, err := e.mapActionToTaskType(action.Type)
	if err != nil {
		return e.fail(ErrCodeUnknownAction, err.Error(), nil), nil
	}

	if e.globalCtx.Adapters == nil {
		return e.fail(ErrCodeFeatureDisabled, "Analysis adapter registry is not available in GlobalContext.", nil), nil
	}

	analyzer, ok := e.globalCtx.Adapters[taskType]
	if !ok {
		return e.fail(ErrCodeNotImplemented, fmt.Sprintf("Adapter not found for task type: %s (Action: %s)", taskType, action.Type), nil), nil
	}

	// 2. Preparation: Session requirements and Artifact collection.
	session := e.sessionProvider()
	var artifacts *schemas.Artifacts

	if session != nil {
		// Fail fast if the parent context is already cancelled before attempting a potentially long operation.
		if ctx.Err() != nil {
			e.logger.Warn("Parent context cancelled before artifact collection.", zap.Error(ctx.Err()))
			return e.fail(ErrCodeTimeoutError, "Context cancelled before analysis could start.", nil), nil
		}

		// If a session exists, collect artifacts to capture the current state (DOM, HAR, Storage).
		e.logger.Debug("Collecting artifacts from current session before analysis", zap.String("analyzer", analyzer.Name()))
		// Use a timeout for artifact collection to avoid hanging the agent loop.
		artifactCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		artifacts, err = session.CollectArtifacts(artifactCtx)
		if err != nil {
			e.logger.Warn("Failed to collect artifacts, proceeding without them.", zap.Error(err))
			// Proceed without artifacts rather than failing the analysis.
			artifacts = nil
		}
	} else if analyzer.Type() == core.TypeActive || analyzer.Type() == core.TypeAgent {
		// Active analyzers require a session context.
		return e.fail(ErrCodeExecutionFailure, "No active browser session available for active analysis.", nil), nil
	}

	// 3. Initialize AnalysisContext
	// Create a pseudo-task derived from the Agent's action.
	pseudoTask := schemas.Task{
		TaskID:     action.ID, // Use Action ID as the Task ID for this execution
		ScanID:     action.ScanID,
		Type:       taskType,
		TargetURL:  action.Value, // Use Action.Value if the adapter needs a specific URL
		Parameters: action.Metadata,
	}

	var parsedURL *url.URL
	if action.Value != "" {
		parsedURL, _ = url.Parse(action.Value)
	}

	analysisCtx := &core.AnalysisContext{
		Global:    e.globalCtx,
		Task:      pseudoTask,
		TargetURL: parsedURL,
		Logger:    e.logger.With(zap.String("task_id", action.ID), zap.String("analyzer", analyzer.Name())),
		Artifacts: artifacts,
		Session:   session, // CRUCIAL: Pass the existing session
		Findings:  []schemas.Finding{},
		KGUpdates: &schemas.KnowledgeGraphUpdate{
			NodesToAdd: []schemas.NodeInput{},
			EdgesToAdd: []schemas.EdgeInput{},
		},
	}

	// 4. Run the analyzer
	e.logger.Info("Starting analysis adapter", zap.String("analyzer", analyzer.Name()))
	startTime := time.Now()
	err = analyzer.Analyze(ctx, analysisCtx)
	duration := time.Since(startTime)
	e.logger.Info("Analysis adapter finished", zap.String("analyzer", analyzer.Name()), zap.Duration("duration", duration), zap.Int("findings_count", len(analysisCtx.Findings)))

	// 5. Process the results
	if err != nil {
		return e.fail(ErrCodeExecutionFailure, fmt.Sprintf("Analysis failed: %v", err), nil), nil
	}

	// Summary data for the Mind's observation node.
	resultData := map[string]interface{}{
		"analyzer_name":  analyzer.Name(),
		"duration_ms":    duration.Milliseconds(),
		"findings_count": len(analysisCtx.Findings),
		"kg_nodes_added": len(analysisCtx.KGUpdates.NodesToAdd),
		"kg_edges_added": len(analysisCtx.KGUpdates.EdgesToAdd),
	}

	// Return the results, including Findings and KGUpdates, for the Agent/Mind to process.
	return &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedAnalysisResult,
		Data:            resultData,
		Findings:        analysisCtx.Findings,
		KGUpdates:       analysisCtx.KGUpdates,
	}, nil
}

// mapActionToTaskType translates the Agent's semantic action into the corresponding TaskType used by the worker/adapters.
func (e *AnalysisExecutor) mapActionToTaskType(actionType ActionType) (schemas.TaskType, error) {
	switch actionType {
	case ActionAnalyzeTaint:
		return schemas.TaskAnalyzeWebPageTaint, nil
	case ActionAnalyzeProtoPollution:
		return schemas.TaskAnalyzeWebPageProtoPP, nil
	case ActionAnalyzeHeaders:
		return schemas.TaskAnalyzeHeaders, nil
	case ActionTestRaceCondition:
		return schemas.TaskTestRaceCondition, nil
	default:
		return "", fmt.Errorf("unsupported analysis action type: %s", actionType)
	}
}

func (e *AnalysisExecutor) fail(code ErrorCode, message string, data map[string]interface{}) *ExecutionResult {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["message"] = message
	return &ExecutionResult{
		Status:          "failed",
		ObservationType: ObservedSystemState,
		ErrorCode:       code,
		ErrorDetails:    data,
	}
}
