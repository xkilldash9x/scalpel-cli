package agent

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
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

// New creates and initializes a fully-featured agent instance.
// This function acts as the composition root for a single agent mission.
func New(ctx context.Context, mission Mission, globalCtx *core.GlobalContext) (*Agent, error) {
	agentID := uuid.New().String()[:8]
	logger := globalCtx.Logger.With(zap.String("agent_id", agentID), zap.String("mission_id", mission.ID))

	// 1. Initialize Cognitive Bus (The Agent's Nervous System)
	bus := NewCognitiveBus(logger, 100)

	// 2. Initialize Knowledge Graph Store for this mission
	kg, err := knowledgegraph.NewInMemoryKG(logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create in-memory knowledge graph: %w", err)
	}

	// 3. Initialize LLM Client and Router
	// The agent needs its own LLM client instance based on the global config.
	llmRouter, err := llmclient.NewLLMRouterFromConfig(globalCtx.Config.Agent.LLM, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM router for agent: %w", err)
	}

	// 4. Initialize the Mind (The Agent's Brain)
	mind := NewLLMMind(logger, llmRouter, globalCtx.Config.Agent, kg, bus)

	// 5. Initialize Executors (The Agent's Hands)
	// The session provider will be set by RunMission when the session is created.
	var sessionProvider SessionProvider
	// Get the project root for the codebase executor. A bit of a hack for now.
	projectRoot, _ := os.Getwd()
	executors := NewExecutorRegistry(logger, &sessionProvider, projectRoot)

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

// RunMission executes the agent's main loop and blocks until the mission is complete.
func (a *Agent) RunMission(ctx context.Context) (*MissionResult, error) {
	a.logger.Info("Agent is commencing mission.", zap.String("objective", a.mission.Objective))
	missionCtx, cancelMission := context.WithCancel(ctx)
	defer cancelMission()

	// 1. Create a dedicated browser session for this mission.
	session, err := a.globalCtx.BrowserManager.InitializeSession(missionCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get browser session for agent: %w", err)
	}
	defer session.Close(context.Background()) // Ensure cleanup even on panic

	// Inject the live session provider into the executor registry.
	a.executors.sessionProvider = func() *browser.AnalysisContext {
		return session
	}

	// 2. Start the Mind's cognitive loop in the background.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.mind.Start(missionCtx); err != nil {
			if missionCtx.Err() == nil { // Don't log expected context cancellations as errors
				a.logger.Error("Mind process failed", zap.Error(err))
			}
		}
	}()

	// 3. Start the main action/observation loop.
	a.wg.Add(1)
	go a.actionLoop(missionCtx)

	// 4. Prime the Mind with the mission objective.
	a.mind.SetMission(a.mission)

	// 5. Wait for the mission to complete or the context to be cancelled.
	select {
	case result := <-a.resultChan:
		a.logger.Info("Mission finished. Returning results.")
		return &result, nil
	case <-missionCtx.Done():
		a.logger.Warn("Mission context cancelled.", zap.Error(missionCtx.Err()))
		// Still try to gather a partial result.
		return a.concludeMission(missionCtx)
	}
}

// actionLoop listens for actions from the Mind, executes them, and posts back observations.
func (a *Agent) actionLoop(ctx context.Context) {
	defer a.wg.Done()
	actionChan, unsubscribe := a.bus.Subscribe(MessageTypeAction)
	defer unsubscribe()

	for {
		select {
		case msg, ok := <-actionChan:
			if !ok {
				a.logger.Info("Action channel closed, action loop stopping.")
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
					a.finish(*result)
					return
				}

				execResult, err := a.executors.Execute(ctx, action)
				if err != nil {
					a.logger.Error("Executor pre-check failed", zap.String("action_type", string(action.Type)), zap.Error(err))
					execResult = &ExecutionResult{Status: "failed", Error: err.Error()}
				}

				obs := Observation{
					ID:             uuid.New().String(),
					MissionID:      action.MissionID,
					SourceActionID: action.ID,
					Type:           execResult.ObservationType,
					Data:           execResult,
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

// concludeMission gathers the final findings and KG updates.
func (a *Agent) concludeMission(ctx context.Context) (*MissionResult, error) {
	// In a real implementation, this would query the knowledge graph for all findings
	// and updates related to this missionID. For now, we return a placeholder.
	return &MissionResult{
		Summary:   "Mission concluded. Final results gathered from knowledge graph.",
		Findings:  []schemas.Finding{},
		KGUpdates: &schemas.KnowledgeGraphUpdate{},
	}, nil
}

// finish sends the final result and stops all agent processes.
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
	close(a.resultChan)
}