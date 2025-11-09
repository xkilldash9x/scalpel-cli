// File: internal/agent/agent.go
package agent

import ( // This is a comment to force a change
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	json "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/analyst"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/llmclient"
)

// Agent orchestrates the components of an autonomous security mission.
type Agent struct {
	mission    Mission
	logger     *zap.Logger
	globalCtx  *core.GlobalContext
	mind       Mind
	bus        *CognitiveBus
	executors  ActionExecutor
	wg         sync.WaitGroup
	resultChan chan MissionResult
	isFinished bool
	mu         sync.Mutex
	humanoid   humanoid.Controller
	kg         GraphStore
	llmClient  schemas.LLMClient
	ltm        LTM

	// Manages the self-healing subsystem.
	selfHeal *SelfHealOrchestrator
	// Manages the proactive self-improvement subsystem.
	evolution EvolutionEngine
}

// NewGraphStoreFromConfig acts as a factory to create the appropriate GraphStore.
// It is a variable to allow for mocking in tests.
var NewGraphStoreFromConfig = func(
	ctx context.Context,
	cfg config.KnowledgeGraphConfig,
	pool *pgxpool.Pool,
	logger *zap.Logger,
) (GraphStore, error) {
	switch cfg.Type {
	case "postgres":
		if pool == nil {
			return nil, fmt.Errorf("PostgreSQL store requires a valid database connection pool")
		}
		return knowledgegraph.NewPostgresKG(pool, logger), nil
	case "in-memory":
		return knowledgegraph.NewInMemoryKG(logger)
	default:
		return nil, fmt.Errorf("unknown knowledge_graph type specified: %s", cfg.Type)
	}
}

// NewLLMClient is a variable to allow for mocking in tests.
// It should be defined in the llmclient package, but we declare it here
// to satisfy the compiler for the current scope.
var NewLLMClient = llmclient.NewClient

// Creates and initializes a fully featured agent instance.
func New(ctx context.Context, mission Mission, globalCtx *core.GlobalContext, session schemas.SessionContext) (*Agent, error) {
	agentID := uuid.New().String()[:8]
	logger := globalCtx.Logger.With(zap.String("agent_id", agentID), zap.String("mission_id", mission.ID))

	// 1. Long-Term Memory (LTM)
	ltm := NewLTM(globalCtx.Config.Agent().LTM, logger)

	// 2. Core Components (Bus, KG, LLM)
	bus := NewCognitiveBus(logger, 100)

	kg, err := NewGraphStoreFromConfig(ctx, globalCtx.Config.Agent().KnowledgeGraph, globalCtx.DBPool, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create knowledge graph store: %w", err)
	}

	llmRouter, err := NewLLMClient(globalCtx.Config.Agent(), logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM router for agent: %w", err)
	}

	// 3. Mind
	mind := NewLLMMind(logger, llmRouter, globalCtx.Config.Agent(), kg, bus, ltm)

	// 4. Executors and Humanoid
	projectRoot, _ := os.Getwd()
	executors := NewExecutorRegistry(logger, projectRoot, globalCtx)
	executors.UpdateSessionProvider(func() schemas.SessionContext {
		return session
	})

	// Pass the specific humanoid configuration struct that the New function now expects.
	browserCfg := globalCtx.Config.Browser()
	h := humanoid.New(browserCfg.Humanoid, logger.Named("humanoid"), session)
	// Connect the humanoid controller to the executor registry so that humanoid actions
	// can be dispatched correctly.
	executors.UpdateHumanoidProvider(func() *humanoid.Humanoid {
		return h
	})

	// 5. Initialize Self-Healing (Autofix) System.
	// This initializes the system but does not start monitoring yet.
	selfHeal, err := NewSelfHealOrchestrator(logger, globalCtx.Config, llmRouter)
	if err != nil {
		// If initialization fails (e.g., missing log file config), log the error
		// but allow the agent to continue without self-healing.
		logger.Error("Failed to initialize Self-Healing system. Proceeding without it.", zap.Error(err))
		selfHeal = nil
	}

	// 6. Initialize Self-Improvement (Evolution) System.
	evoAnalyst, err := analyst.NewImprovementAnalyst(logger, globalCtx.Config, llmRouter, kg)
	if err != nil {
		// If initialization fails (e.g., cannot determine project root), log the error
		// but allow the agent to continue without evolution capabilities.
		logger.Error("Failed to initialize Evolution system (ImprovementAnalyst). Proceeding without it.", zap.Error(err))
	}

	agent := &Agent{
		mission:    mission,
		logger:     logger,
		globalCtx:  globalCtx,
		mind:       mind,
		bus:        bus,
		executors:  executors,
		resultChan: make(chan MissionResult, 1),
		humanoid:   h,
		kg:         kg,
		llmClient:  llmRouter,
		ltm:        ltm,
		selfHeal:   selfHeal,
		evolution:  evoAnalyst, // Assign the analyst (which might be nil if disabled)
	}
	return agent, nil
}

// Executes the agent's main loop.
func (a *Agent) RunMission(ctx context.Context) (*MissionResult, error) {
	a.logger.Info("Agent is commencing mission.", zap.String("objective", a.mission.Objective))
	missionCtx, cancelMission := context.WithCancel(ctx)
	defer cancelMission() // Ensures all subsystems are stopped when mission ends.
	startupErrChan := make(chan error, 1)

	// Start the LTM's background processes.
	a.ltm.Start()

	// Start the Self-Healing system if initialized.
	if a.selfHeal != nil {
		// The self-healing system runs concurrently for the duration of the mission context.
		go a.selfHeal.Start(missionCtx)
	}

	// Subscribe to actions before starting the loops. This ensures no actions generated
	// immediately by the mind (e.g., after SetMission) are missed by the actionLoop.
	actionChan, unsubscribeActions := a.bus.Subscribe(MessageTypeAction)
	// Ensure unsubscription happens when RunMission returns (via defer).
	defer unsubscribeActions()

	// Start the Mind's cognitive loop.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.mind.Start(missionCtx); err != nil {
			// If the mind fails to start and the context wasn't already canceled,
			// it's a critical startup failure.
			if missionCtx.Err() == nil {
				a.logger.Error("Mind process failed to start", zap.Error(err))
				// Use select to prevent blocking if main loop already exited.
				select {
				case startupErrChan <- err:
				default:
				}
			}
		}
	}()

	// Start the Action execution loop.
	a.wg.Add(1)
	// Pass the pre-subscribed channel to the actionLoop.
	go a.actionLoop(missionCtx, actionChan)

	// Kick off the mission.
	a.mind.SetMission(a.mission)

	// Wait for completion or cancellation.
	select {
	case result := <-a.resultChan:
		a.logger.Info("Mission finished. Returning results.")

		// Ensure graceful shutdown of the bus.
		a.bus.Shutdown()

		// Ensure the self-heal system shuts down gracefully.
		if a.selfHeal != nil {
			// cancelMission() stops the loop; WaitForShutdown waits for completion.
			a.selfHeal.WaitForShutdown()
		}
		a.wg.Wait()
		return &result, nil
	case <-missionCtx.Done():
		a.logger.Warn("Mission context cancelled.", zap.Error(missionCtx.Err()))
		// Ensure graceful shutdown of components.
		a.mind.Stop()
		a.bus.Shutdown()
		if a.selfHeal != nil {
			a.selfHeal.WaitForShutdown()
		}
		a.wg.Wait() // Wait for actionLoop and mind loop to finish.

		// FIX (Group 2): When the mission is cancelled (missionCtx.Done()), the parent context (ctx) might also be cancelled.
		// We must use a new context with a timeout to allow the conclusion summary to be generated successfully.
		// If we passed the cancelled 'ctx', the LLM call in concludeMission would fail immediately.
		conclusionCtx, conclusionCancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer conclusionCancel()

		// Return a concluding summary, but also propagate the context error.
		result, concludeErr := a.concludeMission(conclusionCtx)
		if concludeErr != nil {
			a.logger.Error("Failed to generate conclusion on mission cancellation.", zap.Error(concludeErr))
		}
		// The primary reason for exiting is the context error.
		return result, missionCtx.Err()
	case err := <-startupErrChan:
		// Ensure cleanup occurs on startup failure.
		cancelMission()
		a.mind.Stop()
		a.bus.Shutdown()
		if a.selfHeal != nil {
			a.selfHeal.WaitForShutdown()
		}
		a.wg.Wait()
		return nil, err
	}
}

func (a *Agent) actionLoop(ctx context.Context, actionChan <-chan CognitiveMessage) {
	defer a.wg.Done()

	for {
		select {
		case msg, ok := <-actionChan:
			if !ok {
				return
			}

			action, ok := msg.Payload.(Action)
			if !ok {
				a.logger.Error("Received invalid payload for ACTION message", zap.Any("payload", msg.Payload))
				a.bus.Acknowledge(msg)
				continue
			}

			var execResult *ExecutionResult
			var execErr error

			switch action.Type {
			case ActionConclude:
				a.logger.Info("Mind decided to conclude mission.", zap.String("rationale", action.Rationale))
				result, err := a.concludeMission(ctx)
				if err != nil {
					a.logger.Error("Failed to generate final mission result", zap.Error(err))
					a.bus.Acknowledge(msg)
					continue
				}
				if result != nil {
					// CRITICAL: Acknowledge BEFORE calling finish().
					// finish() calls bus.Shutdown(), which waits for this acknowledgment.
					a.bus.Acknowledge(msg)
					a.finish(ctx, *result)
				}
				return // End the action loop.

			case ActionEvolveCodebase:
				a.logger.Info("Agent decided to initiate self-improvement (Evolution).", zap.String("rationale", action.Rationale))
				execResult = a.executeEvolution(ctx, action)

			}

			// If execResult is not yet set, it means the action should be handled by the ExecutorRegistry.
			if execResult == nil {
				a.logger.Debug("Dispatching action to ExecutorRegistry", zap.String("type", string(action.Type)))
				execResult, execErr = a.executors.Execute(ctx, action)
			}

			// Centralized error and nil-result handling.
			if execErr != nil {
				a.logger.Error("Action execution failed with a raw error", zap.String("action_type", string(action.Type)), zap.Error(execErr))
				execResult = &ExecutionResult{
					Status:          "failed",
					ObservationType: ObservedSystemState,
					ErrorCode:       ErrCodeExecutionFailure,
					ErrorDetails:    map[string]interface{}{"message": execErr.Error()},
				}
			} else if execResult == nil {
				// This is a safeguard against a logic error where an action handler returns (nil, nil).
				a.logger.Error("CRITICAL: Action handler returned nil result and nil error.", zap.String("action_type", string(action.Type)))
				// Create a fallback result to prevent nil pointer in postObservation
				execResult = &ExecutionResult{
					Status:          "failed",
					ObservationType: ObservedSystemState,
					ErrorCode:       ErrCodeExecutionFailure,
					ErrorDetails:    map[string]interface{}{"message": "Internal Error: Action handler returned nil result."},
				}
			}

			a.postObservation(ctx, action, execResult)
			a.bus.Acknowledge(msg)

		case <-ctx.Done():
			return
		}
	}
}

// executeEvolution handles the EVOLVE_CODEBASE action by invoking the EvolutionEngine.
func (a *Agent) executeEvolution(ctx context.Context, action Action) *ExecutionResult {
	if a.evolution == nil {
		// This handles cases where initialization failed or the feature was disabled in config.
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeFeatureDisabled,
			ErrorDetails:    map[string]interface{}{"message": "Evolution capability is disabled or failed to initialize."},
		}
	}

	// 1. Extract parameters
	objective := action.Value
	if objective == "" {
		if obj, ok := action.Metadata["objective"].(string); ok {
			objective = obj
		}
	}

	if objective == "" {
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeInvalidParameters,
			ErrorDetails:    map[string]interface{}{"message": "EVOLVE_CODEBASE requires an objective (in 'value' or 'metadata.objective')."},
		}
	}

	var targetFiles []string
	if filesRaw, ok := action.Metadata["target_files"]; ok {
		switch v := filesRaw.(type) {
		case []string:
			targetFiles = v
		case []interface{}:
			for _, item := range v {
				if fileName, ok := item.(string); ok {
					targetFiles = append(targetFiles, fileName)
				}
			}
		}
	}

	if len(targetFiles) == 0 {
		a.logger.Warn("EVOLVE_CODEBASE initiated without specific target_files. Analyst will determine scope.")
	}

	// 2. Run the Evolution Engine
	a.logger.Info("Starting Evolution Analyst OODA loop...", zap.String("objective", objective), zap.Strings("target_files", targetFiles))
	evoCtx, cancel := context.WithTimeout(ctx, 45*time.Minute)
	defer cancel()

	err := a.evolution.Run(evoCtx, objective, targetFiles)

	// 3. Process the result
	result := &ExecutionResult{
		ObservationType: ObservedEvolutionResult,
	}

	if err != nil {
		a.logger.Error("Evolution Analyst finished with error.", zap.Error(err))
		result.Status = "failed"
		errorCode := ErrCodeEvolutionFailure
		// FIX (Group 3): Use errors.Is() for robust detection of context deadline exceeded,
		// regardless of whether the context itself cancelled (evoCtx.Err()) or the underlying operation returned the error (err).
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(evoCtx.Err(), context.DeadlineExceeded) || strings.Contains(err.Error(), "timed out") {
			errorCode = ErrCodeTimeoutError
		}

		result.ErrorCode = errorCode
		result.ErrorDetails = map[string]interface{}{"message": err.Error()}
		result.Data = map[string]string{"status": "Failed/Timeout", "objective": objective, "error": err.Error()}
	} else {
		a.logger.Info("Evolution Analyst finished successfully.")
		result.Status = "success"
		result.Data = map[string]string{"status": "Completed", "objective": objective, "message": "Self-improvement cycle completed successfully."}
	}

	return result
}

func (a *Agent) postObservation(ctx context.Context, sourceAction Action, result *ExecutionResult) {
	// Safeguard against nil result pointer if execution logic had a bug (e.g. missing return in a switch case).
	if result == nil {
		a.logger.Error("CRITICAL: postObservation called with nil ExecutionResult. Creating fallback.", zap.String("action_id", sourceAction.ID))
		result = &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": "Internal Error: ExecutionResult was nil."},
		}
	}

	// Persist findings immediately if any were generated (e.g., by AnalysisExecutor).
	if len(result.Findings) > 0 {
		a.logger.Info("Processing findings generated by action", zap.Int("count", len(result.Findings)), zap.String("action_id", sourceAction.ID))
		for _, finding := range result.Findings {
			// Ensure findings have necessary metadata
			if finding.ScanID == "" {
				finding.ScanID = sourceAction.ScanID
			}
			if finding.TaskID == "" {
				// Use Action ID if Task ID is missing (AnalysisExecutor uses ActionID as pseudo TaskID)
				finding.TaskID = sourceAction.ID
			}
			// Send to the global findings channel
			select {
			case a.globalCtx.FindingsChan <- finding:
			case <-ctx.Done():
				a.logger.Warn("Failed to send finding: context cancelled.")
				return
			default:
				// Log if the channel is full, indicating a bottleneck.
				a.logger.Warn("Findings channel is full, finding dropped.", zap.String("finding_id", finding.ID))
			}
		}
	}

	obs := Observation{
		ID:             uuid.New().String(),
		MissionID:      sourceAction.MissionID,
		SourceActionID: sourceAction.ID,
		Type:           result.ObservationType,
		Data:           result.Data,
		Result:         *result,
		Timestamp:      time.Now().UTC(),
	}

	if err := a.bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: obs}); err != nil {
		a.logger.Error("Failed to post observation to bus", zap.Error(err))
	}
}

func (a *Agent) concludeMission(ctx context.Context) (*MissionResult, error) {
	a.logger.Info("Concluding mission with intelligent summary.")
	subgraph, err := a.gatherMissionContext(ctx, a.mission.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to gather final context for summary: %w", err)
	}

	subgraphJSON, err := json.MarshalIndent(subgraph, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subgraph for summary prompt: %w", err)
	}

	systemPrompt := "You are the Mind of 'scalpel-cli'. The mission has concluded. Your task is to act as a security analyst and write the final report summary."
	userPrompt := fmt.Sprintf(
		"The mission to '%s' has concluded. Based on the complete knowledge graph provided below, synthesize a summary of your findings. Identify the most critical vulnerabilities, noteworthy observations (including any EVOLVE_CODEBASE actions), and provide a concise, professional report summary. The summary should be in plain text format.\n\nKnowledge Graph Snapshot:\n%s",
		a.mission.Objective, string(subgraphJSON),
	)

	req := schemas.GenerationRequest{
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Tier:         schemas.TierPowerful,
		Options:      schemas.GenerationOptions{ForceJSONFormat: false, Temperature: 0.1},
	}

	summaryCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	summaryText, err := a.llmClient.Generate(summaryCtx, req)
	if err != nil {
		a.logger.Error("LLM failed to generate final mission summary", zap.Error(err))
		summaryText = "Mission concluded, but the AI failed to generate a summary. Please review the raw findings."
	}

	return &MissionResult{
		Summary:   strings.TrimSpace(summaryText),
		Findings:  []schemas.Finding{},
		KGUpdates: &schemas.KnowledgeGraphUpdate{},
	}, nil
}

func (a *Agent) gatherMissionContext(ctx context.Context, missionID string) (*schemas.Subgraph, error) {
	// Note (Group 4): This function is designed to be resilient to KG errors.
	// If GetNode or GetEdges fails, it logs a warning (see below) and continues the traversal,
	// returning a partial (or empty) subgraph and a nil error.
	queue := []string{missionID}
	visitedNodes := make(map[string]schemas.Node)
	visitedEdges := make(map[string]struct{})
	var subgraphEdges []schemas.Edge

	for len(queue) > 0 {
		nodeID := queue[0]
		queue = queue[1:]

		if _, visited := visitedNodes[nodeID]; visited {
			continue
		}

		node, err := a.kg.GetNode(ctx, nodeID)
		if err != nil {
			a.logger.Warn("Failed to get node during context gathering", zap.String("nodeID", nodeID), zap.Error(err))
			continue
		}
		visitedNodes[nodeID] = node

		edges, err := a.kg.GetEdges(ctx, nodeID)
		if err != nil {
			a.logger.Warn("Failed to get edges during context gathering", zap.String("nodeID", nodeID), zap.Error(err))
			continue
		}

		for _, edge := range edges {
			if _, visited := visitedEdges[edge.ID]; !visited {
				subgraphEdges = append(subgraphEdges, edge)
				visitedEdges[edge.ID] = struct{}{}
				queue = append(queue, edge.From)
				queue = append(queue, edge.To)
			}
		}
	}

	subgraphNodes := make([]schemas.Node, 0, len(visitedNodes))
	for _, node := range visitedNodes {
		subgraphNodes = append(subgraphNodes, node)
	}

	return &schemas.Subgraph{Nodes: subgraphNodes, Edges: subgraphEdges}, nil
}

// finish handles the final steps of the mission lifecycle.
// It now accepts a context to prevent goroutine leaks when sending the result.
func (a *Agent) finish(ctx context.Context, result MissionResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isFinished {
		return
	}
	a.isFinished = true
	a.mind.Stop()
	// Bus shutdown is handled in RunMission after the result is successfully received.

	// Use select to send result, preventing blocking forever if the runner (RunMission)
	// has already exited (e.g., due to timeout/cancellation).
	select {
	case a.resultChan <- result:
	case <-ctx.Done():
		a.logger.Warn("Failed to send mission result: context cancelled before runner received it.")
	}
}
