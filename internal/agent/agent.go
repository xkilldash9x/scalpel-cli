// internal/agent/agent.go
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"[github.com/google/uuid](https://github.com/google/uuid)"
	"[github.com/jackc/pgx/v5/pgxpool](https://github.com/jackc/pgx/v5/pgxpool)"
	"go.uber.org/zap"

	"[github.com/xkilldash9x/scalpel-cli/api/schemas](https://github.com/xkilldash9x/scalpel-cli/api/schemas)"
	"[github.com/xkilldash9x/scalpel-cli/internal/analysis/core](https://github.com/xkilldash9x/scalpel-cli/internal/analysis/core)"
	// Import autofix implicitly as it's used by the orchestrator.
	// _ "[github.com/xkilldash9x/scalpel-cli/internal/autofix](https://github.com/xkilldash9x/scalpel-cli/internal/autofix)" 
	"[github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid](https://github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid)"
	"[github.com/xkilldash9x/scalpel-cli/internal/config](https://github.com/xkilldash9x/scalpel-cli/internal/config)"
	"[github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph](https://github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph)"
	"[github.com/xkilldash9x/scalpel-cli/internal/llmclient](https://github.com/xkilldash9x/scalpel-cli/internal/llmclient)"
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
	humanoid   humanoid.Controller
	kg         GraphStore
	llmClient  schemas.LLMClient

	// Manages the self-healing subsystem.
	selfHeal *SelfHealOrchestrator
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
		return knowledgegraph.NewPostgresKG(pool), nil
	case "in-memory":
		// Corrected initialization based on the prompt's context.
		return knowledgegraph.NewInMemoryKG(logger)
	default:
		return nil, fmt.Errorf("unknown knowledge_graph type specified: %s", cfg.Type)
	}
}

// Creates and initializes a fully featured agent instance.
func New(ctx context.Context, mission Mission, globalCtx *core.GlobalContext, session schemas.SessionContext) (*Agent, error) {
	agentID := uuid.New().String()[:8]
	logger := globalCtx.Logger.With(zap.String("agent_id", agentID), zap.String("mission_id", mission.ID))

	// 1. Core Components (Bus, KG, LLM)
	bus := NewCognitiveBus(logger, 100)

	kg, err := NewGraphStoreFromConfig(ctx, globalCtx.Config.Agent.KnowledgeGraph, globalCtx.DBPool, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create knowledge graph store: %w", err)
	}

	llmRouter, err := llmclient.NewClient(globalCtx.Config.Agent, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM router for agent: %w", err)
	}

	// 2. Mind
	mind := NewLLMMind(logger, llmRouter, globalCtx.Config.Agent, kg, bus)

	// 3. Executors and Humanoid
	projectRoot, _ := os.Getwd() 
	executors := NewExecutorRegistry(logger, projectRoot)
	executors.UpdateSessionProvider(func() schemas.SessionContext {
		return session
	})

	h := humanoid.New(humanoid.DefaultConfig(), logger.Named("humanoid"), session)

	// 4. Initialize Self-Healing (Autofix) System.
	// This initializes the system but does not start monitoring yet.
	selfHeal, err := NewSelfHealOrchestrator(logger, globalCtx.Config, llmRouter)
	if err != nil {
		// If initialization fails (e.g., missing log file config), log the error 
		// but allow the agent to continue without self-healing.
		logger.Error("Failed to initialize Self-Healing system. Proceeding without it.", zap.Error(err))
		selfHeal = nil 
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
		selfHeal:   selfHeal,
	}
	return agent, nil
}

// Executes the agent's main loop.
func (a *Agent) RunMission(ctx context.Context) (*MissionResult, error) {
	a.logger.Info("Agent is commencing mission.", zap.String("objective", a.mission.Objective))
	missionCtx, cancelMission := context.WithCancel(ctx)
	defer cancelMission() // Ensures all subsystems (including selfHeal) are stopped when mission ends.

	// Start the Self-Healing system if initialized.
	if a.selfHeal != nil {
		// The self-healing system runs concurrently for the duration of the mission context.
		go a.selfHeal.Start(missionCtx)
	}

	// Start the Mind's cognitive loop.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.mind.Start(missionCtx); err != nil {
			if missionCtx.Err() == nil {
				a.logger.Error("Mind process failed", zap.Error(err))
			}
		}
	}()

	// Start the Action execution loop.
	a.wg.Add(1)
	go a.actionLoop(missionCtx)

	// Kick off the mission.
	a.mind.SetMission(a.mission)

	// Wait for completion or cancellation.
	select {
	case result := <-a.resultChan:
		a.logger.Info("Mission finished. Returning results.")
		// Ensure the self-heal system shuts down gracefully.
		if a.selfHeal != nil {
			// cancelMission() stops the loop; WaitForShutdown waits for completion.
			a.selfHeal.WaitForShutdown()
		}
		return &result, nil
	case <-missionCtx.Done():
		a.logger.Warn("Mission context cancelled.", zap.Error(missionCtx.Err()))
		if a.selfHeal != nil {
			a.selfHeal.WaitForShutdown()
		}
		return a.concludeMission(missionCtx)
	}
}
func (a *Agent) actionLoop(ctx context.Context) {
	defer a.wg.Done()
	actionChan, unsubscribe := a.bus.Subscribe(MessageTypeAction)
	defer unsubscribe()

	for {
		select {
		case 
		msg, ok := <-actionChan:
			if !ok {
				return
			}

			go func(actionMsg CognitiveMessage) {
				defer a.bus.Acknowledge(actionMsg)

				action, ok := actionMsg.Payload.(Action)
				if !ok {
					a.logger.Error("Received invalid payload for ACTION message", zap.Any("payload", actionMsg.Payload))
					return
				}

				var execResult *ExecutionResult

				switch action.Type {
				case ActionConclude:
					a.logger.Info("Mind decided to conclude mission.", zap.String("rationale", action.Rationale))
					result, err := a.concludeMission(ctx)
					if err != nil {
						a.logger.Error("Failed to generate final mission result", zap.Error(err))
					}
					if result != nil {
						a.finish(*result)
					}
					return

				case ActionClick, ActionInputText, ActionHumanoidDragAndDrop:
					a.logger.Debug("Orchestrating humanoid action", zap.String("type", string(action.Type)))
					execResult = a.executeHumanoidAction(ctx, action)

				case ActionPerformComplexTask:
					a.logger.Info("Agent is orchestrating a complex task (Placeholder)", zap.Any("metadata", action.Metadata))
					taskName, _ := action.Metadata["task_name"].(string)
					execResult = &ExecutionResult{
						Status:          "failed",
						ObservationType: ObservedSystemState,
						ErrorCode:       ErrCodeNotImplemented,
						ErrorDetails:    map[string]interface{}{"task_name": taskName},
					}

				case ActionGatherCodebaseContext, ActionNavigate, ActionWaitForAsync, ActionSubmitForm, ActionScroll:
					a.logger.Debug("Dispatching action to ExecutorRegistry", zap.String("type", string(action.Type)))
					var err error
					execResult, err = a.executors.Execute(ctx, action)
					if err != nil {
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
						ErrorCode:       ErrCodeUnknownAction,
					}
				}

				a.postObservation(ctx, action, execResult)

			}(msg)

		case <-ctx.Done():
			return
		}
	}
}

func (a *Agent) executeHumanoidAction(ctx context.Context, action Action) *ExecutionResult {
	var err error

	switch action.Type {
	case ActionClick:
		if action.Selector == "" {
			err = fmt.Errorf("ActionClick requires a 'selector'")
			break
		}
		err = a.humanoid.IntelligentClick(ctx, action.Selector, nil)
	case ActionInputText:
		if action.Selector == "" {
			err = fmt.Errorf("ActionInputText requires a 'selector'")
			break
		}
		err = a.humanoid.Type(ctx, action.Selector, action.Value, nil)
	case ActionHumanoidDragAndDrop:
		startSelector := action.Selector
		targetSelectorRaw, okMeta := action.Metadata["target_selector"]
		targetSelector, okCast := targetSelectorRaw.(string)
		if !okMeta || !okCast || startSelector == "" || targetSelector == "" {
			err = fmt.Errorf("ActionHumanoidDragAndDrop requires 'selector' (start) and 'metadata.target_selector' (end, string)")
			break
		}
		err = a.humanoid.DragAndDrop(ctx, startSelector, targetSelector, nil)
	default:
		err = fmt.Errorf("unsupported humanoid action type: %s", action.Type)
	}

	result := &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedDOMChange,
	}

	if err != nil {
		result.Status = "failed"
		
		// -- FIX APPLIED --
		// Assumes ParseBrowserError returns an ErrorCode type, not a string.
		errorCode, errorDetails := ParseBrowserError(err, action)

		if errorCode == ErrCodeExecutionFailure {
			errStr := err.Error()
			if strings.Contains(errStr, "failed to click") || strings.Contains(errStr, "failed to type") {
				errorCode = ErrCodeHumanoidInteractionFailed
			}
		}

		result.ErrorCode = errorCode
		result.ErrorDetails = errorDetails
		a.logger.Warn("Humanoid action execution failed", zap.String("action", string(action.Type)), zap.String("error_code", string(errorCode)), zap.Error(err))
	}

	return result
}

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
		"The mission to '%s' has concluded. Based on the complete knowledge graph provided below, synthesize a summary of your findings. Identify the most critical vulnerabilities, noteworthy observations, and provide a concise, professional report summary. The summary should be in plain text format.\n\nKnowledge Graph Snapshot:\n%s",
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