package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/llmclient"
)

// -- UPGRADE NOTE: Defined Constants --
// Adding some structured error codes and new action types here for clarity.
// This helps make the observations sent back to the Mind more consistent.
const (
	ErrCodeNotImplemented            = "NOT_IMPLEMENTED"
	ErrCodeExecutionFailure          = "EXECUTION_FAILURE"
	ErrCodeHumanoidInteractionFailed = "HUMANOID_INTERACTION_FAILED"

	// This assumes ActionHumanoidDragAndDrop is a new action type.
	ActionHumanoidDragAndDrop ActionType = "HUMANOID_DRAG_AND_DROP"
)

// Agent orchestrates the components of an autonomous security mission.
type Agent struct {
	mission    Mission
	logger     *zap.Logger
	globalCtx  *core.GlobalContext
	mind       Mind
	bus        *CognitiveBus
	executors  *ExecutorRegistry
	wg         sync.WaitGroup
	resultChan chan MissionResult
	isFinished bool
	mu         sync.Mutex

	// -- UPGRADE NOTE: Interface-based Humanoid Controller --
	// The agent now holds the humanoid instance as an interface.
	// This makes it easier to swap out implementations or mock for testing.
	humanoid humanoid.Controller

	kg        GraphStore
	llmClient schemas.LLMClient
}

// Acts as a factory to create the appropriate GraphStore.
func NewGraphStoreFromConfig(
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
		return knowledgegraph.NewPostgresKG(ctx, pool, logger)
	case "in-memory":
		return knowledgegraph.NewInMemoryKG(logger)
	default:
		return nil, fmt.Errorf("unknown knowledge_graph type specified: %s", cfg.Type)
	}
}

// Creates and initializes a fully featured agent instance.
func New(ctx context.Context, mission Mission, globalCtx *core.GlobalContext, session schemas.SessionContext) (*Agent, error) {
	agentID := uuid.New().String()[:8]
	logger := globalCtx.Logger.With(zap.String("agent_id", agentID), zap.String("mission_id", mission.ID))

	// 1. Initialize Cognitive Bus
	bus := NewCognitiveBus(logger, 100)

	// 2. Initialize Knowledge Graph Store
	kg, err := NewGraphStoreFromConfig(ctx, globalCtx.Config.Agent.KnowledgeGraph, globalCtx.DBPool, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create knowledge graph store: %w", err)
	}

	// 3. Initialize LLM Client and Router
	llmRouter, err := llmclient.NewClient(globalCtx.Config.Agent, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM router for agent: %w", err)
	}

	// 4. Initialize the Mind
	mind := NewLLMMind(logger, llmRouter, globalCtx.Config.Agent, kg, bus)

	// 5. Initialize Executors
	projectRoot, _ := os.Getwd()
	executors := NewExecutorRegistry(logger, projectRoot)
	// Provide the session for actions that are still managed by the registry.
	executors.UpdateSessionProvider(func() schemas.SessionContext {
		return session
	})

	// 6. Create a new humanoid instance using the provided session as the executor.
	// This works because schemas.SessionContext is compatible with humanoid.Executor.
	h := humanoid.New(humanoid.DefaultConfig(), logger.Named("humanoid"), session)

	agent := &Agent{
		mission:    mission,
		logger:     logger,
		globalCtx:  globalCtx,
		mind:       mind,
		bus:        bus,
		executors:  executors,
		resultChan: make(chan MissionResult, 1),
		// Assign the concrete humanoid instance to our new interface field.
		humanoid:  h,
		kg:        kg,
		llmClient: llmRouter,
	}
	return agent, nil
}

// Executes the agent's main loop.
func (a *Agent) RunMission(ctx context.Context) (*MissionResult, error) {
	a.logger.Info("Agent is commencing mission.", zap.String("objective", a.mission.Objective))
	missionCtx, cancelMission := context.WithCancel(ctx)
	defer cancelMission()

	// 1. Start the Mind's cognitive loop.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.mind.Start(missionCtx); err != nil {
			// Only log an error if the context wasn't cancelled.
			// Otherwise it's just expected shutdown behavior.
			if missionCtx.Err() == nil {
				a.logger.Error("Mind process failed", zap.Error(err))
			}
		}
	}()

	// 2. Start the main action/observation loop.
	a.wg.Add(1)
	go a.actionLoop(missionCtx)

	// 3. Prime the Mind with the mission objective.
	a.mind.SetMission(a.mission)

	// 4. Wait for the mission to complete or be cancelled.
	select {
	case result := <-a.resultChan:
		a.logger.Info("Mission finished. Returning results.")
		return &result, nil
	case <-missionCtx.Done():
		a.logger.Warn("Mission context cancelled.", zap.Error(missionCtx.Err()))
		// Still try to conclude intelligently even on cancellation.
		return a.concludeMission(missionCtx)
	}
}

// -- UPGRADE NOTE: Action Loop as a Switchboard --
// This is the new, refactored action loop. It acts as a central orchestrator.
// Instead of a series of 'if' checks, it uses a clean switch statement to route
// actions to the correct handler, whether it's a meta-action, the humanoid
// controller, or the basic executor registry. This is way more maintainable.
func (a *Agent) actionLoop(ctx context.Context) {
	defer a.wg.Done()
	actionChan, unsubscribe := a.bus.Subscribe(MessageTypeAction)
	defer unsubscribe()

	for {
		select {
		case msg, ok := <-actionChan:
			if !ok {
				return
			}

			// Spin up a goroutine to handle the action so we don't block the main loop.
			go func(actionMsg CognitiveMessage) {
				defer a.bus.Acknowledge(actionMsg)

				action, ok := actionMsg.Payload.(Action)
				if !ok {
					a.logger.Error("Received invalid payload for ACTION message", zap.Any("payload", actionMsg.Payload))
					return
				}

				var execResult *ExecutionResult

				// -- Action Orchestration Switchboard --
				switch action.Type {

				// -- Meta Actions --
				case ActionConclude:
					a.logger.Info("Mind decided to conclude mission.", zap.String("rationale", action.Rationale))
					result, err := a.concludeMission(ctx)
					if err != nil {
						a.logger.Error("Failed to generate final mission result", zap.Error(err))
					}
					if result != nil {
						a.finish(*result)
					}
					return // CONCLUDE stops further processing for this message.

				// -- Humanoid Browser Actions (Basic and Advanced) --
				// These actions are intercepted by the Agent and handled by the Humanoid module for more realistic interaction.
				case ActionClick, ActionInputText, ActionHumanoidDragAndDrop:
					a.logger.Debug("Orchestrating humanoid action", zap.String("type", string(action.Type)))
					// Pass the mission context to the humanoid action for cancellation/timeout propagation.
					execResult = a.executeHumanoidAction(ctx, action)

				// -- Complex/High-Level Actions (Placeholders for now) --
				case ActionPerformComplexTask:
					a.logger.Info("Agent is orchestrating a complex task (Placeholder)", zap.Any("metadata", action.Metadata))
					taskName, _ := action.Metadata["task_name"].(string)
					execResult = &ExecutionResult{
						Status:          "failed",
						ObservationType: ObservedSystemState,
						ErrorCode:       ErrCodeNotImplemented,
						ErrorDetails:    map[string]interface{}{"task_name": taskName},
					}

				// -- Delegated Actions (Static analysis, remaining browser actions) --
				// These are dispatched to the ExecutorRegistry.
				case ActionGatherCodebaseContext, ActionNavigate, ActionWaitForAsync, ActionSubmitForm, ActionScroll:
					a.logger.Debug("Dispatching action to ExecutorRegistry", zap.String("type", string(action.Type)))
					var err error
					execResult, err = a.executors.Execute(ctx, action)
					if err != nil {
						// Create a structured error if the executor returns a raw Go error.
						a.logger.Error("ExecutorRegistry failed with raw error", zap.String("action_type", string(action.Type)), zap.Error(err))
						execResult = &ExecutionResult{
							Status:          "failed",
							ObservationType: ObservedSystemState,
							ErrorCode:       ErrCodeExecutionFailure,
							ErrorDetails:    map[string]interface{}{"message": err.Error()},
						}
					}

				default:
					a.logger.Warn("Received unknown action type", zap.String("type", string(action.Type)))
					execResult = &ExecutionResult{
						Status:          "failed",
						ObservationType: ObservedSystemState,
						ErrorCode:       "UNKNOWN_ACTION_TYPE",
					}
				}

				// Post the result of the execution back to the bus as an observation.
				a.postObservation(ctx, action, execResult)

			}(msg)

		case <-ctx.Done():
			return
		}
	}
}

// -- UPGRADE NOTE: New Humanoid Action Handler --
// This function is the dedicated handler for all actions that require the humanoid
// module. It maps our abstract Action types to concrete humanoid method calls and,
// critically, translates any errors into structured, meaningful feedback for the Mind.
func (a *Agent) executeHumanoidAction(ctx context.Context, action Action) *ExecutionResult {
	var err error

	// Map the Action to the corresponding humanoid method.
	switch action.Type {
	case ActionClick:
		if action.Selector == "" {
			err = fmt.Errorf("ActionClick requires a 'selector'")
			break
		}
		// Use IntelligentClick for realistic interaction.
		err = a.humanoid.IntelligentClick(ctx, action.Selector, nil)

	case ActionInputText:
		if action.Selector == "" {
			err = fmt.Errorf("ActionInputText requires a 'selector'")
			break
		}
		// Use Type for realistic typing simulation.
		err = a.humanoid.Type(ctx, action.Selector, action.Value)

	case ActionHumanoidDragAndDrop:
		startSelector := action.Selector
		targetSelectorRaw, okMeta := action.Metadata["target_selector"]
		targetSelector, okCast := targetSelectorRaw.(string)

		if !okMeta || !okCast || startSelector == "" || targetSelector == "" {
			err = fmt.Errorf("ActionHumanoidDragAndDrop requires 'selector' (start) and 'metadata.target_selector' (end, string)")
			break
		}
		err = a.humanoid.DragAndDrop(ctx, startSelector, targetSelector)

	default:
		// This should ideally not happen if actionLoop is configured correctly.
		err = fmt.Errorf("unsupported humanoid action type: %s", action.Type)
	}

	// Standardize the result format.
	result := &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedDOMChange, // Assume DOM change for successful interaction.
	}

	if err != nil {
		// -- Enhanced Feedback Loop --
		// Here we translate raw errors from the humanoid into something the LLM can understand.
		result.Status = "failed"

		// Assuming ParseBrowserError is a function that can parse common CDP errors.
		// It might live in the executors package or a shared utility package.
		errorCode, errorDetails := ParseBrowserError(err, action)

		// Refine the error code based on the humanoid context. If the generic parser
		// couldn't figure it out, we can give it a more specific code here.
		if errorCode == ErrCodeExecutionFailure {
			errStr := err.Error()
			if strings.Contains(errStr, "failed to click") || strings.Contains(errStr, "failed to type") {
				errorCode = ErrCodeHumanoidInteractionFailed
			}
		}

		result.ErrorCode = errorCode
		result.ErrorDetails = errorDetails
		a.logger.Warn("Humanoid action execution failed", zap.String("action", string(action.Type)), zap.String("error_code", errorCode), zap.Error(err))
	}

	return result
}

// A helper to create and post an observation to the bus.
func (a *Agent) postObservation(ctx context.Context, sourceAction Action, result *ExecutionResult) {
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

// Performs a final act of intelligence to synthesize the mission's findings.
func (a *Agent) concludeMission(ctx context.Context) (*MissionResult, error) {
	a.logger.Info("Concluding mission with intelligent summary.")
	// 1. OBSERVE: Gather the entire mission's subgraph from the Knowledge Graph.
	subgraph, err := a.gatherMissionContext(ctx, a.mission.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to gather final context for summary: %w", err)
	}

	subgraphJSON, err := json.MarshalIndent(subgraph, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subgraph for summary prompt: %w", err)
	}

	// 2. ORIENT: Formulate a new, summary oriented prompt for the LLM.
	systemPrompt := "You are the Mind of 'scalpel-cli'. The mission has concluded. Your task is to act as a security analyst and write the final report summary."
	userPrompt := fmt.Sprintf(
		"The mission to '%s' has concluded. Based on the complete knowledge graph provided below, synthesize a summary of your findings. Identify the most critical vulnerabilities, noteworthy observations, and provide a concise, professional report summary. The summary should be in plain text format.\n\nKnowledge Graph Snapshot:\n%s",
		a.mission.Objective, string(subgraphJSON),
	)

	// 3. DECIDE: The LLM's response becomes the summary text.
	req := schemas.GenerationRequest{
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Tier:         schemas.TierPowerful,
		Options:      schemas.GenerationOptions{ForceJSONFormat: false, Temperature: 0.1},
	}

	// Use a dedicated context for the final LLM call.
	summaryCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	summaryText, err := a.llmClient.Generate(summaryCtx, req)
	if err != nil {
		a.logger.Error("LLM failed to generate final mission summary", zap.Error(err))
		summaryText = "Mission concluded, but the AI failed to generate a summary. Please review the raw findings."
	}

	// 4. ACT: Populate the 'MissionResult' struct.
	// In a full implementation, this would also query the KG for all VULNERABILITY nodes.
	return &MissionResult{
		Summary:   strings.TrimSpace(summaryText),
		Findings:  []schemas.Finding{}, // Placeholder for actual findings aggregation.
		KGUpdates: &schemas.KnowledgeGraphUpdate{},
	}, nil
}

// A helper to collect all nodes related to the mission.
func (a *Agent) gatherMissionContext(ctx context.Context, missionID string) (*schemas.Subgraph, error) {
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
				// Add both ends of the edge to the queue to ensure we traverse the full connected component.
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

// Safely sends the final result and shuts down the agent's components.
func (a *Agent) finish(result MissionResult) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.isFinished {
		return
	}
	a.isFinished = true
	a.mind.Stop()
	a.bus.Shutdown()
	a.resultChan <- result
}

// A placeholder for a utility function that would parse
// common browser automation errors into structured codes.
func ParseBrowserError(err error, action Action) (string, map[string]interface{}) {
	// In a real implementation, this would inspect the error string for patterns like:
	// "no node found for selector", "waiting for selector timed out", etc.
	errStr := err.Error()
	details := map[string]interface{}{"message": errStr}
	if action.Selector != "" {
		details["selector"] = action.Selector
	}

	if strings.Contains(errStr, "no node found") || strings.Contains(errStr, "could not find element") {
		return "ELEMENT_NOT_FOUND", details
	}
	if strings.Contains(errStr, "timed out") {
		return "TIMEOUT_ERROR", details
	}

	return ErrCodeExecutionFailure, details
}
