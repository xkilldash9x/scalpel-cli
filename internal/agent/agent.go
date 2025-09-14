package agent

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
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
}

// NewGraphStoreFromConfig acts as a factory to create the appropriate GraphStore.
func NewGraphStoreFromConfig(
	ctx context.Context,
	cfg config.KnowledgeGraphConfig, // Your config struct for the KG settings
	pool *pgxpool.Pool, // The database connection pool
	logger *zap.Logger,
) (GraphStore, error) {

	switch cfg.Type {
	case "postgres":
		if pool == nil {
			return nil, fmt.Errorf("PostgreSQL store requires a valid database connection pool")
		}
		// The store.New function from your postgres implementation
		// This is temporarily using the in-memory version to resolve build errors.
		// You will need to ensure your store.Store implementation correctly satisfies the GraphStore interface.
		return knowledgegraph.NewInMemoryKG(logger)
	case "in-memory":
		// The in-memory constructor
		return knowledgegraph.NewInMemoryKG(logger)
	default:
		return nil, fmt.Errorf("unknown knowledge_graph type specified: %s", cfg.Type)
	}
}

// New creates and initializes a fully-featured agent instance.
func New(ctx context.Context, mission Mission, globalCtx *core.GlobalContext) (*Agent, error) {
	agentID := uuid.New().String()[:8]
	logger := globalCtx.Logger.With(zap.String("agent_id", agentID), zap.String("mission_id", mission.ID))

	// 1. Initialize Cognitive Bus
	bus := NewCognitiveBus(logger, 100)

	// 2. Initialize Knowledge Graph Store using the factory
	kg, err := NewGraphStoreFromConfig(
		ctx,
		globalCtx.Config.Agent.KnowledgeGraph, // Pass the KG config
		globalCtx.DBPool,                       // Pass the DB Pool from global context
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create knowledge graph store: %w", err)
	}

	// 3. Initialize LLM Client and Router
	// The function is NewClient and it expects the entire AgentConfig.
	llmRouter, err := llmclient.NewClient(globalCtx.Config.Agent, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM router for agent: %w", err)
	}

	// 4. Initialize the Mind
	mind := NewLLMMind(logger, llmRouter, globalCtx.Config.Agent, kg, bus)

	// 5. Initialize Executors
	projectRoot, _ := os.Getwd()
	// The registry is created, and the session provider will be set later during the mission's runtime.
	executors := NewExecutorRegistry(logger, projectRoot)

	agent := &Agent{
		mission:    mission,
		logger:     logger,
		globalCtx:  globalCtx,
		mind:       mind,
		bus:        bus,
		executors:  executors,
		resultChan: make(chan MissionResult, 1),
	}
	return agent, nil
}

// RunMission executes the agent's main loop.
func (a *Agent) RunMission(ctx context.Context) (*MissionResult, error) {
	a.logger.Info("Agent is commencing mission.", zap.String("objective", a.mission.Objective))
	missionCtx, cancelMission := context.WithCancel(ctx)
	defer cancelMission()

	// 1. Create a dedicated browser session.
	session, err := a.globalCtx.BrowserManager.InitializeSession(missionCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get browser session for agent: %w", err)
	}
	defer session.Close(context.Background())

	// Verifies that the browser session implements the expected interface for our executors.
	sessionCtx, ok := interface{}(session).(SessionContext)
	if !ok {
		// If this fails, the browser package needs to be updated to implement the agent.SessionContext interface.
		return nil, fmt.Errorf("browser session (type %T) does not implement agent.SessionContext interface", session)
	}

	// Inject the live session provider into the executor registry.
	a.executors.UpdateSessionProvider(func() SessionContext {
		return sessionCtx
	})

	// 2. Start the Mind's cognitive loop.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.mind.Start(missionCtx); err != nil {
			// Do not log a cancellation error, as it is expected on shutdown.
			if missionCtx.Err() == nil {
				a.logger.Error("Mind process failed", zap.Error(err))
			}
		}
	}()

	// 3. Start the main action/observation loop.
	a.wg.Add(1)
	go a.actionLoop(missionCtx)

	// 4. Prime the Mind with the mission objective.
	a.mind.SetMission(a.mission)

	// 5. Wait for the mission to complete or be cancelled.
	select {
	case result := <-a.resultChan:
		a.logger.Info("Mission finished. Returning results.")
		return &result, nil
	case <-missionCtx.Done():
		a.logger.Warn("Mission context cancelled.", zap.Error(missionCtx.Err()))
		return a.concludeMission(missionCtx)
	}
}

// actionLoop listens for actions, executes them, and posts back observations.
func (a *Agent) actionLoop(ctx context.Context) {
	defer a.wg.Done()
	// Subscribe specifically to actions.
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
					// Pre-execution failure (e.g., no session, invalid parameters)
					a.logger.Error("Executor pre-check failed", zap.String("action_type", string(action.Type)), zap.Error(err))
					execResult = &ExecutionResult{Status: "failed", Error: err.Error(), ObservationType: ObservedSystemState}
				}

				// Create the observation.
				obs := Observation{
					ID:             uuid.New().String(),
					MissionID:      action.MissionID,
					SourceActionID: action.ID,
					Type:           execResult.ObservationType,
					Data:           execResult.Data,
					Result:         *execResult,
					Timestamp:      time.Now().UTC(),
				}

				if err := a.bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: obs}); err != nil {
					a.logger.Error("Failed to post observation to bus", zap.Error(err))
				}

			}(msg)

		case <-ctx.Done():
			return
		}
	}
}

// concludeMission gathers the final findings and knowledge graph updates.
func (a *Agent) concludeMission(ctx context.Context) (*MissionResult, error) {
	// A placeholder for the actual implementation.
	return &MissionResult{
		Summary:   "Mission concluded. Final results gathered from knowledge graph.",
		Findings:  []schemas.Finding{},
		KGUpdates: &schemas.KnowledgeGraphUpdate{},
	}, nil
}

// finish sends the final result and gracefully stops all agent processes.
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