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
	humanoid   *humanoid.Humanoid
	// -- REFACTORING NOTE --
	// The agent now holds a direct reference to the knowledge graph and LLM client
	// to support advanced behaviors like the intelligent mission conclusion.
	kg        GraphStore
	llmClient schemas.LLMClient
}

// NewGraphStoreFromConfig acts as a factory to create the appropriate GraphStore.
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

// -- REFACTORING NOTE --
// The `New` function now accepts a pre configured `SessionContext`. This decouples the agent's
// creation from the browser session's lifecycle, making the agent more modular and easier to test.
// The humanoid instance is created immediately using this session.

// New creates and initializes a fully featured agent instance.
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
	// Immediately update the provider with the session we were given.
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
		humanoid:   h,
		kg:         kg,
		llmClient:  llmRouter,
	}
	return agent, nil
}

// -- REFACTORING NOTE --
// `RunMission` no longer creates the browser session. It assumes the agent was already
// initialized with an active session in the `New` function. This simplifies the run loop
// and reinforces the decoupling of agent logic from session management.

// RunMission executes the agent's main loop.
func (a *Agent) RunMission(ctx context.Context) (*MissionResult, error) {
	a.logger.Info("Agent is commencing mission.", zap.String("objective", a.mission.Objective))
	missionCtx, cancelMission := context.WithCancel(ctx)
	defer cancelMission()

	// 1. Start the Mind's cognitive loop.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.mind.Start(missionCtx); err != nil {
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

			go func(actionMsg CognitiveMessage) {
				defer a.bus.Acknowledge(actionMsg)

				action, ok := actionMsg.Payload.(Action)
				if !ok {
					a.logger.Error("Received invalid payload for ACTION message", zap.Any("payload", actionMsg.Payload))
					return
				}

				// -- REFACTORING NOTE: Agent as Orchestrator --
				// The agent now intercepts high level tasks before they reach the simple executor registry.
				// This allows the agent to use its own complex capabilities (like humanoid) to perform
				// multi step actions, making the Mind's job easier and the process more robust.
				if action.Type == ActionPerformComplexTask {
					a.logger.Info("Agent is orchestrating a complex task", zap.Any("metadata", action.Metadata))
					// In a real implementation, this would dispatch to different humanoid behaviors.
					// For now, it's a placeholder to demonstrate the architectural pattern.
					execResult := &ExecutionResult{
						Status:          "failed",
						ObservationType: ObservedSystemState,
						ErrorCode:       "NOT_IMPLEMENTED",
						ErrorDetails:    map[string]interface{}{"task_name": action.Metadata["task_name"]},
					}
					a.postObservation(ctx, action, execResult)
					return // End handling for this action here.
				}

				if action.Type == ActionConclude {
					a.logger.Info("Mind decided to conclude mission.", zap.String("rationale", action.Rationale))
					result, err := a.concludeMission(ctx)
					if err != nil {
						a.logger.Error("Failed to generate final mission result", zap.Error(err))
					}
					if result != nil {
						a.finish(*result)
					}
					return
				}

				execResult, err := a.executors.Execute(ctx, action)
				if err != nil {
					a.logger.Error("Executor failed", zap.String("action_type", string(action.Type)), zap.Error(err))
					// Create a structured error for execution failures.
					execResult = &ExecutionResult{
						Status:          "failed",
						ObservationType: ObservedSystemState,
						ErrorCode:       "EXECUTION_FAILURE",
						ErrorDetails:    map[string]interface{}{"message": err.Error()},
					}
				}
				a.postObservation(ctx, action, execResult)

			}(msg)

		case <-ctx.Done():
			return
		}
	}
}

// postObservation is a helper to create and post an observation to the bus.
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

// -- REFACTORING NOTE: Intelligent Mission Conclusion --
// This function is now implemented to perform a final act of intelligence. It triggers
// a specialized OODA loop to synthesize the mission's findings into a coherent summary
// by leveraging the knowledge graph and the LLM one last time.

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

// gatherMissionContext is a helper to collect all nodes related to the mission.
// It's adapted from the logic in llm_mind.go for a complete, non depth limited traversal.
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
