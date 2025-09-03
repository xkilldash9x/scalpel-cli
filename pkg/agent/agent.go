package agent

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	// All dependencies are abstract interfaces for better decoupling.
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// Agent is the autonomous unit responsible for executing security analysis missions.
// It orchestrates the mind, cognitive bus, and action executors to achieve a given objective.
type Agent struct {
	ID                  string
	cfg                 *config.Config
	logger              *zap.Logger
	globalCtx           *core.GlobalContext
	Mind                interfaces.Mind         // The decision-making component.
	CognitiveBus        *CognitiveBus           // The internal message bus for the agent.
	KnowledgeGraph      interfaces.KnowledgeGraph // The long-term memory and data store.
	Executors           map[schemas.ActionType]interfaces.ActionExecutor
	BrowserInteractor   interfaces.SessionManager // Manages browser sessions.
	CurrentSession      interfaces.SessionContext   // The active browser session for the current mission.
	CurrentMission      schemas.Mission
	missionCompleteChan chan error
}

// New initializes a new autonomous agent.
// It accepts dependencies as interfaces, allowing for flexible and testable composition.
func New(
	ctx context.Context,
	agentCfg config.AgentConfig,
	globalCtx *core.GlobalContext,
	llmClient interfaces.LLMClient,
	kgClient interfaces.KnowledgeGraph,
) (*Agent, error) {
	agentID := fmt.Sprintf("agent-%s", uuid.New().String()[:8])
	agentLogger := globalCtx.Logger.Named("agent").With(zap.String("agent_id", agentID))

	bus := NewCognitiveBus(agentLogger, 100)

	// The agent's mind is instantiated here, with its own dependencies injected.
	mind := NewLLMMind(agentLogger, llmClient, agentCfg, kgClient, bus)

	agent := &Agent{
		ID:                  agentID,
		cfg:                 globalCtx.Config,
		logger:              agentLogger,
		globalCtx:           globalCtx,
		Mind:                mind,
		CognitiveBus:        bus,
		KnowledgeGraph:      kgClient,
		BrowserInteractor:   globalCtx.BrowserManager,
		missionCompleteChan: make(chan error, 1),
		Executors:           make(map[schemas.ActionType]interfaces.ActionExecutor),
	}

	agent.registerExecutors()
	return agent, nil
}

// registerExecutors initializes and registers the various action executors.
// Each executor is responsible for handling a specific type of action (e.g., browser actions).
func (a *Agent) registerExecutors() {
	// Browser executor handles all actions related to web browser interaction.
	browserExec := NewBrowserExecutor(a.logger, func() interfaces.SessionContext {
		return a.CurrentSession
	})
	a.Executors[schemas.ActionNavigate] = browserExec
	a.Executors[schemas.ActionClick] = browserExec
	a.Executors[schemas.ActionInputText] = browserExec
	a.Executors[schemas.ActionSubmitForm] = browserExec
	a.Executors[schemas.ActionScroll] = browserExec
	a.Executors[schemas.ActionWaitForAsync] = browserExec

	// Mission control executor handles meta-actions for the mission itself.
	a.Executors[schemas.ActionConclude] = NewMissionControlExecutor(a)
}

// RunMission is the primary entry point for executing a mission.
// It sets up the necessary context (like a browser session) and starts the agent's cognitive loops.
func (a *Agent) RunMission(ctx context.Context, mission schemas.Mission) (schemas.MissionResult, error) {
	a.CurrentMission = mission
	a.logger.Info("Starting new mission", zap.String("mission_id", a.CurrentMission.ID), zap.String("objective", a.CurrentMission.Objective))

	// If the mission requires a web browser, initialize a session.
	if a.CurrentMission.TargetURL != "" {
		session, err := a.BrowserInteractor.InitializeSession(ctx)
		if err != nil {
			return schemas.MissionResult{}, fmt.Errorf("failed to initialize browser session for mission: %w", err)
		}
		a.CurrentSession = session
		defer a.cleanupSession()
	}

	// Start the mind's thinking process and the action execution loop in parallel.
	go a.Mind.Start(ctx)
	go a.runExecutionLoop(ctx)

	// Block until the mission completes, fails, or the context is cancelled (e.g., timeout).
	select {
	case <-ctx.Done():
		a.logger.Warn("Mission timed out or was cancelled externally", zap.Error(ctx.Err()))
		return schemas.MissionResult{}, ctx.Err()
	case err := <-a.missionCompleteChan:
		if err != nil {
			a.logger.Error("Mission failed", zap.Error(err))
			return schemas.MissionResult{}, err
		}
		a.logger.Info("Mission completed successfully")
		return a.summarizeMissionResult(), nil
	}
}

// runExecutionLoop listens to the cognitive bus for new actions from the Mind and executes them.
func (a *Agent) runExecutionLoop(ctx context.Context) {
	actionChan, unsubscribe := a.CognitiveBus.Subscribe(schemas.MessageTypeAction)
	defer unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-actionChan:
			if !ok {
				return // Channel closed
			}
			if action, ok := msg.Payload.(schemas.Action); ok {
				a.executeAction(ctx, action)
			}
			// Acknowledge the message so it can be removed from the bus.
			a.CognitiveBus.Acknowledge(msg)
		}
	}
}

// executeAction finds the correct executor for a given action and runs it.
func (a *Agent) executeAction(ctx context.Context, action schemas.Action) {
	executor, exists := a.Executors[action.Type]
	if !exists {
		a.logger.Error("No executor registered for action type", zap.String("type", string(action.Type)))
		return
	}

	a.logger.Info("Executing action", zap.String("type", string(action.Type)), zap.Any("params", action.Parameters))
	result, err := executor.Execute(ctx, action)
	if err != nil {
		a.logger.Error("Action execution failed", zap.Error(err), zap.String("action_id", action.ID))
		// Report the failure as an observation so the mind can react.
		a.postObservation(action.ID, &schemas.ExecutionResult{
			Status:          "failed",
			Error:           err.Error(),
			ObservationType: schemas.ObservedSystemState,
		})
		return
	}

	// Post the successful result of the execution as an observation.
	a.postObservation(action.ID, result)
}

// postObservation sends the outcome of an action back to the cognitive bus for the Mind to process.
func (a *Agent) postObservation(sourceActionID string, result *schemas.ExecutionResult) {
	obs := schemas.Observation{
		ID:             uuid.NewString(),
		MissionID:      a.CurrentMission.ID,
		SourceActionID: sourceActionID,
		Type:           result.ObservationType,
		Data:           result,
		Timestamp:      time.Now().UTC(),
	}

	msg := schemas.CognitiveMessage{Type: schemas.MessageTypeObservation, Payload: obs}
	if err := a.CognitiveBus.Post(context.Background(), msg); err != nil {
		a.logger.Error("Failed to post observation to bus", zap.Error(err))
	}
}

// cleanupSession ensures the browser session is properly closed after a mission.
func (a *Agent) cleanupSession() {
	if a.CurrentSession != nil {
		a.logger.Info("Closing browser session")
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := a.CurrentSession.Close(cleanupCtx); err != nil {
			a.logger.Warn("Error closing browser session", zap.Error(err))
		}
		a.CurrentSession = nil
	}
}

// summarizeMissionResult collects the final state from the knowledge graph to create a result summary.
func (a *Agent) summarizeMissionResult() schemas.MissionResult {
	// In a real implementation, this would query the KnowledgeGraph for findings and generate a report.
	a.logger.Info("Summarizing mission results")
	return schemas.MissionResult{
		Summary: "Mission concluded successfully. All objectives met.",
	}
}

// --- Mission Control Executor ---

// missionControlExecutor is a special executor for handling meta-actions related to mission state.
type missionControlExecutor struct {
	agent *Agent
}

// NewMissionControlExecutor returns an executor for meta-actions like concluding a mission.
func NewMissionControlExecutor(agent *Agent) interfaces.ActionExecutor {
	return &missionControlExecutor{agent: agent}
}

// Execute handles the 'Conclude' action to signal that the mission is complete.
func (e *missionControlExecutor) Execute(ctx context.Context, action schemas.Action) (*schemas.ExecutionResult, error) {
	if action.Type == schemas.ActionConclude {
		e.agent.logger.Info("Mind has decided to conclude the mission.")
		// Signal success on the mission completion channel.
		e.agent.missionCompleteChan <- nil
		return &schemas.ExecutionResult{Status: "success", ObservationType: schemas.ObservedSystemState}, nil
	}
	return nil, fmt.Errorf("unsupported mission control action: %s", action.Type)
}