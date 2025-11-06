package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	json "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/llmclient"
	"github.com/xkilldash9x/scalpel-cli/internal/store"
)

// HealthChecker is an optional interface for SessionContext implementations to report health.
type HealthChecker interface {
	IsHealthy(context.Context) bool
}

// Agent orchestrates the components of an autonomous security mission.
type Agent struct {
	logger         *zap.Logger
	globalCtx      *core.GlobalContext
	mind           Mind
	bus            CognitiveBus // Renamed from tbus
	executors      ActionRegistry
	resultChan     chan MissionResult
	wg             sync.WaitGroup
	ctx            context.Context    // Agent's main lifecycle context (set in Start)
	cancelFunc     context.CancelFunc // Function to cancel the main context
	mu             sync.Mutex
	evolution      ImprovementAnalyst
	kgClient       schemas.KnowledgeGraphClient // Canonical KG Client
	llmClient      schemas.LLMClient
	ltm            LTM
	browserManager schemas.BrowserManager // Reference to the shared browser manager

	// State related to the current mission, if any.
	mission   Mission
	missionMu sync.RWMutex

	// State related to the current browser session for this agent/mission.
	currentSession schemas.SessionContext
	sessionMu      sync.RWMutex

	dataStore *store.Store // Access to the persistent data store (for findings etc.)

	// ADDED: WebSocket manager for real-time communication
	wsManager *WSManager

	// Manages the self-healing subsystem.
	selfHeal *SelfHealOrchestrator
}

// MissionResult encapsulates the final output of a mission.
type MissionResult struct {
	ID              string    `json:"id"`
	ScanID          string    `json:"scan_id"`
	Objective       string    `json:"objective"`
	Summary         string    `json:"summary"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	KnowledgeGraph  any       `json:"knowledge_graph,omitempty"`
	Findings        []schemas.Finding
	FinalLLMRequest *schemas.GenerationRequest `json:"final_llm_request,omitempty"`
}

// NewDatabasePool is a function type for creating a new pgxpool.Pool, used for dependency injection.
var NewDatabasePool = pgxpool.New

// NewLLMClient is a function type for creating a new LLMClient, used for dependency injection.
// This allows for mocking the LLM client in tests, ensuring that no actual LLM calls are made.
// It is defined as a variable so that it can be reassigned during testing, but it's not meant
// to satisfy the compiler for the current scope.
var NewLLMClient = llmclient.NewClient

// New initializes a fully featured agent instance.
func New(ctx context.Context, mission *Mission, globalCtx *core.GlobalContext) (*Agent, error) {
	agentID := uuid.New().String()[:8]
	logger := globalCtx.Logger.With(zap.String("agent_id", agentID))
	agentCfg := globalCtx.Config.Agent()

	// 1. Long-Term Memory (LTM)
	ltm := NewLTM(agentCfg.LTM, logger)

	// 2. LLM Client Router
	// Use the NewLLMClient factory variable, passing the correct arguments (config.AgentConfig, logger).
	llmRouter, err := NewLLMClient(agentCfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM client router: %w", err)
	}

	// 3. Cognitive Bus
	//    This now correctly assigns the *CognitiveBusService struct
	//    to the CognitiveBus interface field in the Agent.
	bus := NewCognitiveBus(logger, 100) // 100 is default, adjust as needed

	// 4. Executors
	projectRoot, _ := os.Getwd()
	executors := NewExecutorRegistry(logger, projectRoot, globalCtx)

	// 5. Initialize Self-Healing (Autofix) System.
	selfHeal, err := NewSelfHealOrchestrator(logger, globalCtx.Config, llmRouter)
	if err != nil {
		logger.Error("Failed to initialize SelfHealOrchestrator. Continuing without self-healing.", zap.Error(err))
		selfHeal = nil
	}

	// 6. Initialize Evolution (Self-Improvement) System.
	evoAnalyst, err := NewImprovementAnalyst(globalCtx.Config, llmRouter, logger)
	if err != nil {
		logger.Error("Failed to initialize Evolution system (ImprovementAnalyst). Proceeding without it.", zap.Error(err))
	}

	// 7. Initialize Mind and Knowledge Graph
	// Use the KGClient from the global context.
	kgClient := globalCtx.KGClient
	var mind Mind

	// Initialize an in-memory fallback KG if the persistent client is unavailable.
	if kgClient == nil {
		logger.Warn("KnowledgeGraphClient (Persistent) is not available in GlobalContext. Falling back to InMemoryKG.")
		inMemKG, err := knowledgegraph.NewInMemoryKG(logger)
		if err != nil {
			// If fallback fails, we cannot initialize the mind.
			logger.Error("Failed to initialize fallback InMemoryKG. Mind will not be initialized.", zap.Error(err))
		} else {
			// Update the agent's kgClient field to use the fallback.
			kgClient = inMemKG
		}
	}

	if kgClient != nil {
		// Initialize Mind (mind).
		mind = NewLLMMind(logger, llmRouter, agentCfg, kgClient, bus, ltm)
	}

	// 8. Initialize Data Store (for querying findings)
	var dataStore *store.Store
	if globalCtx.DBPool != nil {
		// Use a short timeout context for initialization/ping
		initCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		var storeErr error
		// store.New expects DBPool interface, which *pgxpool.Pool satisfies.
		dataStore, storeErr = store.New(initCtx, globalCtx.DBPool, logger)
		if storeErr != nil {
			logger.Error("Failed to initialize Data Store. Agent will not be able to retrieve persisted findings.", zap.Error(storeErr))
			dataStore = nil // Ensure it's nil if initialization failed
		}
	} else {
		logger.Warn("DBPool not available in GlobalContext. Agent will not be able to retrieve persisted findings.")
	}

	var initialMission Mission
	if mission != nil {
		initialMission = *mission
		logger = logger.With(zap.String("mission_id", mission.ID))
	}

	// Check for BrowserManager availability
	browserMgr := globalCtx.BrowserManager
	if browserMgr == nil {
		logger.Warn("BrowserManager is not available in GlobalContext. Agent will not be able to perform browser tasks.")
	}

	agent := &Agent{
		mission:        initialMission,
		logger:         logger,
		globalCtx:      globalCtx,
		browserManager: browserMgr,
		mind:           mind,
		bus:            bus,
		executors:      executors,
		resultChan:     make(chan MissionResult, 1),
		evolution:      evoAnalyst,
		kgClient:       kgClient, // Use the canonical client
		llmClient:      llmRouter,
		ltm:            ltm,
		dataStore:      dataStore,
		selfHeal:       selfHeal,
	}

	// ADDED: Initialize WebSocket Manager
	wsManager := NewWSManager(logger, agent)
	agent.wsManager = wsManager

	// Update executors with the dynamic session provider function.
	executors.UpdateSessionProvider(agent.GetSession)

	return agent, nil
}

// GetSession returns the current active browser session, creating one if it doesn't exist (Lazy Initialization).
// This is the implementation of the SessionProviderFunc type used by ExecutorRegistry.
func (a *Agent) GetSession(ctx context.Context) (schemas.SessionContext, error) {
	if a.browserManager == nil {
		return nil, errors.New("browser manager not initialized, cannot create session")
	}

	// 1. Quick check with RLock
	a.sessionMu.RLock()
	session := a.currentSession
	isHealthy := false

	if session != nil {
		// TODO: Add a check here to ensure the session is still healthy (e.g., browser tab hasn't crashed).
		// Check if the session implementation supports health checks.
		if checker, ok := session.(HealthChecker); ok {
			// Use a short timeout for the health check itself.
			healthCheckCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if checker.IsHealthy(healthCheckCtx) {
				isHealthy = true
			} else {
				a.logger.Warn("Current session is unhealthy, will attempt to recreate.", zap.String("session_id", session.ID()))
			}
			cancel()
		} else {
			// If it doesn't support health checks, assume it's healthy if it exists.
			isHealthy = true
		}
	}

	if isHealthy {
		a.sessionMu.RUnlock()
		return session, nil
	}

	// If not healthy or nil, release RLock and proceed to acquire Write lock.
	a.sessionMu.RUnlock()

	// 2. Acquire write lock to create or recreate the session
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()

	// Double-check if another goroutine created the session while waiting for the lock
	if a.currentSession != nil {
		// If the pointer changed (another routine fixed it), return the new session.
		if a.currentSession != session {
			return a.currentSession, nil
		}

		// It's the same unhealthy session. Close it first.
		// We must call the internal close helper as a.CloseSession() also acquires the lock (deadlock).
		a.logger.Info("Closing unhealthy browser session before recreation.", zap.String("session_id", a.currentSession.ID()))
		// Use background context with timeout for closing.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		a.closeSessionInternal(closeCtx)
		closeCancel()
		// a.currentSession is now nil.
	}

	// Create a new session
	a.logger.Info("Initializing new browser session for agent.")

	// Define the persona (TODO: make this dynamic based on mission)
	persona := schemas.DefaultPersona

	// Ensure the findings channel is available
	if a.globalCtx.FindingsChan == nil {
		return nil, errors.New("findings channel not available in GlobalContext")
	}

	// Create the session. We use context.Background() for the session lifetime context,
	// as the agent manages the lifecycle explicitly (closing when mission ends/agent stops).
	// Operations (Navigate, Click) will respect the action context (ctx) passed to the executor.
	session, err := a.browserManager.NewAnalysisContext(
		context.Background(), // Session lifetime context
		a.globalCtx.Config,
		persona,
		"", // Taint template (TODO: load if necessary for specific missions)
		"", // Taint config (TODO: load if necessary)
		a.globalCtx.FindingsChan,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create new browser session: %w", err)
	}

	a.currentSession = session

	// Initialize Humanoid for this new session and update the executor registry
	browserCfg := a.globalCtx.Config.Browser()
	h := humanoid.New(browserCfg.Humanoid, a.logger.Named("humanoid"), session)

	// Update the ExecutorRegistry with the new Humanoid instance provider
	if a.executors != nil {
		a.executors.UpdateHumanoidProvider(func() *humanoid.Humanoid {
			return h
		})
	}

	a.logger.Info("Browser session and Humanoid initialized.", zap.String("session_id", session.ID()))
	return session, nil
}

// closeSessionInternal handles the logic for closing the session.
// It MUST be called while holding the sessionMu write lock.
func (a *Agent) closeSessionInternal(ctx context.Context) error {
	session := a.currentSession
	if session == nil {
		return nil
	}

	// Attempt to close the session using the provided context.
	err := session.Close(ctx)
	if err != nil {
		a.logger.Error("Failed to close browser session cleanly.", zap.Error(err), zap.String("session_id", session.ID()))
		// Continue cleanup even if close failed (e.g., timeout)
	}

	// Reset internal state
	a.currentSession = nil
	if a.executors != nil {
		a.executors.UpdateHumanoidProvider(nil)
	}
	return err
}

// CloseSession closes the currently active browser session if it exists.
func (a *Agent) CloseSession(ctx context.Context) error {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()

	if a.currentSession == nil {
		return nil
	}

	a.logger.Info("Closing agent browser session.", zap.String("session_id", a.currentSession.ID()))

	return a.closeSessionInternal(ctx)
}

// RegisterInteractionRoutes sets up the HTTP routes for user interaction.
func (a *Agent) RegisterInteractionRoutes(r chi.Router) {
	// ADDED: WebSocket endpoint
	r.Get("/ws/v1/interact", a.wsManager.HandleWS)

	// The agent-specific health check confirms internal components are ready.
	r.Get("/healthz/agent", a.HandleHealthCheck)
}

// HandleHealthCheck is a simple handler to confirm the agent is responsive and its core components are initialized.
func (a *Agent) HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	// Check if critical components are initialized.
	if a.mind == nil || a.bus == nil || a.executors == nil {
		// This reflects the placeholders in New(). In a real application, this means the agent is degraded.
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Agent components (Mind/Bus/Executors) not fully initialized (Placeholders active)"))
		return
	}

	// KGClient might be optional depending on configuration, so we reflect its status without failing the health check entirely.
	if a.kgClient == nil {
		a.logger.Warn("Agent health check: KnowledgeGraphClient is unavailable.")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Agent OK (Degraded: Knowledge Graph unavailable)"))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Agent OK"))
}

// SetMission updates the agent's current objective.
func (a *Agent) SetMission(mission Mission) {
	a.missionMu.Lock()
	a.mission = mission
	a.missionMu.Unlock()

	// Inform the mind about the new mission (Mind handles empty mission IDs internally)
	if a.mind != nil {
		a.mind.SetMission(mission)
	}
}

// GetMission returns the current mission safely.
func (a *Agent) GetMission() Mission {
	a.missionMu.RLock()
	defer a.missionMu.RUnlock()
	return a.mission
}

// GetResultChan returns a read-only channel for the agent's mission result.
// This allows external components (like an adapter) to wait for the mission to conclude.
func (a *Agent) GetResultChan() <-chan MissionResult {
	return a.resultChan
}

// Start executes the agent's main cognitive loops.
func (a *Agent) Start(ctx context.Context) error {
	// Check if critical components were initialized (reflects placeholders in New)
	if a.mind == nil || a.ltm == nil || a.bus == nil || a.executors == nil {
		// In a production system, this should be a fatal error.
		return fmt.Errorf("agent cannot start: critical components (Mind, LTM, Bus, or Executors) are not initialized (Placeholders active)")
	}

	if a.kgClient == nil {
		a.logger.Warn("Agent starting without KnowledgeGraphClient. Persistence and complex reasoning may be unavailable.")
	}

	// Initialize the agent's lifecycle context.
	agentCtx, cancelAgent := context.WithCancel(ctx)
	a.mu.Lock()
	a.ctx = agentCtx
	a.cancelFunc = cancelAgent
	a.mu.Unlock()

	defer cancelAgent() // Ensures all subsystems are stopped when Start returns.
	startupErrChan := make(chan error, 1)

	// Start the LTM's background processes.
	// LTM interface defines Start/Stop, not Run(ctx).
	a.ltm.Start()

	// Start the Self-Healing system if initialized.
	if a.selfHeal != nil {
		// The self-healing system runs concurrently for the duration of the agent context.
		go a.selfHeal.Start(agentCtx)
	}

	// ADDED: Start the WebSocket manager loop
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		// The WSManager stops when agentCtx is cancelled.
		a.wsManager.Run(agentCtx)
	}()

	// Subscribe to actions before starting the loops.
	// CognitiveBus.Subscribe returns (<-chan CognitiveMessage, func()).
	actionChan, unsubscribeActions := a.bus.Subscribe(MessageTypeAction)
	// unsubscribeActions will be called by the actionLoop when it exits.

	// Start the Mind's cognitive loop.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.mind.Start(agentCtx); err != nil {
			// If the mind fails to start and the context wasn't already canceled,
			// it's a critical failure.
			if agentCtx.Err() == nil {
				a.logger.Error("Mind process stopped unexpectedly", zap.Error(err))
				// Use select to prevent blocking if main loop already exited.
				select {
				case startupErrChan <- err:
				default:
				}
				// If the mind stops, the whole agent should stop.
				cancelAgent()
			}
		}
	}()

	// Start the Action execution loop.
	a.wg.Add(1)
	// Pass the pre-subscribed channel to the actionLoop.
	go a.actionLoop(agentCtx, actionChan, unsubscribeActions)

	// Kick off the mission if one exists.
	mission := a.GetMission()
	if mission.ID != "" {
		a.logger.Info("Agent commencing initial mission.", zap.String("objective", mission.Objective))
		a.mind.SetMission(mission)
	}

	// Main loop: Wait for mission results or agent termination signals.
	for {
		select {
		case result := <-a.resultChan:
			// A specific mission concluded. The agent persists.
			a.logger.Info("Mission finished.", zap.String("MissionID", result.ID))

			// Close the browser session used for this mission
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := a.CloseSession(closeCtx); err != nil {
				a.logger.Warn("Error closing session after mission finished", zap.Error(err))
			}
			closeCancel()

			// Reset the mission state to allow new interactions or missions.
			a.SetMission(Mission{})
			// Continue the loop.

		case <-agentCtx.Done():
			a.logger.Warn("Agent context cancelled. Initiating shutdown.", zap.Error(agentCtx.Err()))
			// --- Graceful Shutdown Sequence ---
			// 1. Stop the mind from generating new actions.
			a.mind.Stop()
			// 2. Shut down the bus (waits for current actions to finish).
			a.bus.Shutdown()
			// 3. Stop the self-heal system.
			if a.selfHeal != nil {
				a.selfHeal.WaitForShutdown()
			}
			// 3.5 Stop LTM background processes.
			a.ltm.Stop()
			// 4. Wait for loops (Mind loop, Action loop) to finish.
			a.wg.Wait()

			// 5. Close the browser session if it exists
			shutdownCloseCtx, shutdownCloseCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := a.CloseSession(shutdownCloseCtx); err != nil {
				a.logger.Warn("Error closing session during agent shutdown", zap.Error(err))
			}
			shutdownCloseCancel()

			// Generate a concluding summary if a mission was active during shutdown.
			if a.GetMission().ID != "" {
				// Use a new context with a timeout for conclusion generation.
				conclusionCtx, conclusionCancel := context.WithTimeout(context.Background(), 90*time.Second)
				defer conclusionCancel()

				_, concludeErr := a.concludeMission(conclusionCtx)
				if concludeErr != nil {
					a.logger.Error("Failed to generate conclusion on shutdown.", zap.Error(concludeErr))
				}
			}
			// The primary reason for exiting is the context error.
			return agentCtx.Err()

		case err := <-startupErrChan:
			// Ensure cleanup occurs on startup failure.
			cancelAgent()
			// Repeat shutdown sequence
			a.mind.Stop()
			a.bus.Shutdown()
			if a.selfHeal != nil {
				a.selfHeal.WaitForShutdown()
			}
			a.ltm.Stop()
			a.wg.Wait()

			// Ensure session is closed if it was created before failure
			cleanupCloseCtx, cleanupCloseCancel := context.WithTimeout(context.Background(), 10*time.Second)
			a.CloseSession(cleanupCloseCtx)
			cleanupCloseCancel()

			return err
		}
	}
}

// postObservation creates an observation from an action's result and posts it to the bus.
func (a *Agent) postObservation(ctx context.Context, action Action, result *ExecutionResult) {
	// The observation ID should be unique.
	// Rationale, LLMTrace, Screenshots are now part of ExecutionResult (which is embedded in Observation).
	// Initializing them explicitly here caused errors as they were missing from the Observation struct definition.
	obs := Observation{
		ID:             uuid.New().String(),
		MissionID:      action.MissionID,
		SourceActionID: action.ID,
		Type:           result.ObservationType,
		Data:           result.Data,
		Result:         *result,
		Timestamp:      time.Now().UTC(),
	}

	// Post the observation back to the cognitive bus for the Mind to process.
	if err := a.bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: obs}); err != nil {
		// If the context is done, this error is expected during shutdown.
		if ctx.Err() == nil {
			a.logger.Error("Failed to post observation to cognitive bus", zap.Error(err))
		}
	}
}

// executeEvolution handles the self-improvement action.
func (a *Agent) executeEvolution(ctx context.Context, action Action) *ExecutionResult {
	if a.evolution == nil {
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeNotAvailable,
			ErrorDetails:    map[string]interface{}{"message": "Evolution system is not initialized."},
		}
	}

	// The 'Value' of the action contains the high-level goal for the evolution.
	goal := action.Value
	if goal == "" {
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeInvalidParameters,
			ErrorDetails:    map[string]interface{}{"message": "Evolution goal cannot be empty."},
		}
	}

	// The evolution process is asynchronous. We trigger it and report back that it has started.
	// The ImprovementAnalyst will post its own observations to the bus as it works.
	go func() {
		// Create a new context for the evolution task to avoid being cancelled by short-lived action contexts.
		// It should be tied to the agent's main context.
		a.mu.Lock()
		parentCtx := a.ctx
		a.mu.Unlock()

		if parentCtx == nil {
			// Fallback if agent is not running via Start()
			parentCtx = context.Background()
		}

		evoCtx, cancel := context.WithCancel(parentCtx)
		defer cancel()

		if err := a.evolution.AnalyzeAndImprove(evoCtx, goal, a.bus); err != nil {
			a.logger.Error("Evolution process failed", zap.Error(err), zap.String("goal", goal))
			// Post a failure observation so the mind is aware.
			obs := Observation{
				ID:             uuid.New().String(),
				MissionID:      action.MissionID,
				SourceActionID: action.ID, // Correlate with the triggering action
				Type:           ObservedSystemState,
				Result: ExecutionResult{
					Status:          "failed",
					ObservationType: ObservedSystemState,
					ErrorCode:       ErrCodeExecutionFailure,
					ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("Evolution process failed: %v", err)},
				},
				Timestamp: time.Now().UTC(),
			}
			if postErr := a.bus.Post(context.Background(), CognitiveMessage{Type: MessageTypeObservation, Payload: obs}); postErr != nil {
				a.logger.Error("Failed to post evolution failure observation", zap.Error(postErr))
			}
		}
	}()

	// Return an immediate success result indicating the task was started.
	return &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedSystemState,
		Data:            map[string]interface{}{"message": fmt.Sprintf("Initiated codebase evolution process with goal: %s. The process will run in the background.", goal)},
	}
}

func (a *Agent) concludeMission(ctx context.Context) (*MissionResult, error) {
	mission := a.GetMission()
	a.logger.Info("Concluding mission with intelligent summary", zap.String("mission_id", mission.ID))
	subgraphMap, err := a.gatherMissionContext(ctx, mission.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to gather final context for summary: %w", err)
	}

	// Check if subgraph is nil (e.g., KGClient unavailable)
	if subgraphMap == nil {
		a.logger.Warn("Knowledge graph context is unavailable. Cannot generate an intelligent summary.")
		return &MissionResult{
			ID:        mission.ID,
			ScanID:    mission.ScanID,
			Objective: mission.Objective,
			Summary:   "Mission concluded. Knowledge Graph unavailable for summary generation.",
			StartTime: mission.StartTime,
			EndTime:   time.Now().UTC(),
		}, nil
	}

	// Check for actual data within the map structure (assuming gatherMissionContext returns a map representation of a Subgraph)
	nodes, nodesOk := subgraphMap["nodes"].([]schemas.Node)
	// edges, edgesOk := subgraphMap["edges"].([]schemas.Edge) // Edges currently unused in this check

	if !nodesOk || len(nodes) == 0 {
		a.logger.Warn("Knowledge graph is empty. Cannot generate a meaningful summary.")
		return &MissionResult{
			ID:        mission.ID,
			ScanID:    mission.ScanID,
			Objective: mission.Objective,
			Summary:   "Mission concluded, but no significant activities were recorded in the Knowledge Graph.",
			StartTime: mission.StartTime,
			EndTime:   time.Now().UTC(),
		}, nil
	}

	subgraphJSON, err := json.Marshal(subgraphMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subgraph for LLM prompt: %w", err)
	}

	// Construct the prompt for the LLM to generate the final summary.
	systemPrompt := "You are the Mind of 'scalpel-cli'. The mission has concluded. Your task is to act as a security analyst and write the final report summary."
	userPrompt := fmt.Sprintf("The mission to '%s' has concluded. Based on the complete knowledge graph provided below, synthesize a summary of your findings. Identify the most critical vulnerabilities, noteworthy observations (including any EVOLVE_CODEBASE actions), and provide a concise, professional report summary. The summary should be in plain text format.\n\nKnowledge Graph Snapshot:\n%s", mission.Objective, string(subgraphJSON))

	req := schemas.GenerationRequest{
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Tier:         schemas.TierPowerful, // Use powerful model for summary
		Options: schemas.GenerationOptions{
			Temperature: 0.2, // Low temperature for a factual, consistent summary.
		},
	}

	// Generate the summary using the LLM.
	// The client returns (string, error), not a struct
	summary, err := a.llmClient.Generate(ctx, req)
	if err != nil {
		// If summary generation fails, return an error. The caller can decide how to handle this.
		return nil, fmt.Errorf("failed to generate mission summary via LLM: %w", err)
	}

	if summary == "" {
		summary = "Failed to generate an intelligent summary. Please review the knowledge graph manually."
	}

	// Retrieve persisted findings using the ScanID associated with the mission. (TODO implementation)
	// We rely on the database store as the system of record for finalized findings.
	var findings []schemas.Finding
	if a.dataStore != nil && mission.ScanID != "" {
		var findingsErr error
		findings, findingsErr = a.dataStore.GetFindingsByScanID(ctx, mission.ScanID)
		if findingsErr != nil {
			a.logger.Error("Failed to retrieve findings from Data Store.", zap.Error(findingsErr), zap.String("scan_id", mission.ScanID))
			// Continue with empty findings if retrieval fails
			findings = []schemas.Finding{}
		}
	} else {
		if mission.ScanID != "" && a.dataStore == nil {
			a.logger.Warn("Cannot retrieve persisted findings: Data Store unavailable.")
		}
		// If ScanID is empty (e.g., interactive agent session) or store unavailable.
		findings = []schemas.Finding{}
	}

	result := &MissionResult{
		ID:              mission.ID,
		ScanID:          mission.ScanID,
		Objective:       mission.Objective,
		Summary:         summary,
		StartTime:       mission.StartTime,
		EndTime:         time.Now().UTC(),
		KnowledgeGraph:  subgraphMap,
		Findings:        findings,
		FinalLLMRequest: &req,
	}

	return result, nil
}

// actionLoop is the primary consumer of Action messages from the CognitiveBus.
func (a *Agent) actionLoop(ctx context.Context, actionChan <-chan CognitiveMessage, unsubscribe func()) {
	defer a.wg.Done()
	defer unsubscribe() // Ensure we unsubscribe when the loop finishes.
	a.logger.Info("Action loop started.")

	for {
		select {
		case <-ctx.Done():
			a.logger.Info("Action loop stopping due to context cancellation.")
			return
		case msg, ok := <-actionChan:
			if !ok {
				a.logger.Info("Action channel closed. Action loop stopping.")
				return
			}

			// Process the message sequentially.
			func() {
				defer a.bus.Acknowledge(msg)

				if action, ok := msg.Payload.(Action); ok {
					a.executeAction(ctx, action)
				} else {
					a.logger.Error("Received non-Action payload on ACTION channel.", zap.Any("payload_type", fmt.Sprintf("%T", msg.Payload)))
				}
			}()
		}
	}
}

// executeAction handles the execution of a single action and posts the observation.
func (a *Agent) executeAction(ctx context.Context, action Action) {
	a.logger.Info("Executing action",
		zap.String("action_id", action.ID),
		zap.String("type", string(action.Type)),
		zap.String("rationale", action.Rationale))

	var result *ExecutionResult
	var err error

	// Use a timeout for the individual action execution.
	actionCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Handle panic recovery within the executor.
	defer func() {
		if r := recover(); r != nil {
			a.logger.Error("Panic recovered during action execution",
				zap.Any("panic_value", r),
				zap.String("action_id", action.ID),
				zap.Stack("stack"),
			)
			// Create a result indicating the panic.
			result = &ExecutionResult{
				Status:          "failed",
				ObservationType: ObservedSystemState,
				ErrorCode:       ErrCodeExecutorPanic,
				ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("Executor panicked: %v", r)},
			}
			// Post observation even on panic, using the parent context (ctx).
			a.postObservation(ctx, action, result)
		}
	}()

	// Dispatch logic: Handle cognitive/orchestration actions internally, dispatch others to the registry.
	switch action.Type {
	case ActionConclude:
		result, err = a.handleConclude(actionCtx, action)
	case ActionEvolveCodebase:
		result = a.executeEvolution(actionCtx, action)
	// case ActionRespondToUser: // TODO: Implement if needed
	default:
		// Default dispatch to the ExecutorRegistry.
		result, err = a.executors.Execute(actionCtx, action)
	}

	// Error handling and result normalization.
	if err != nil {
		// If the executor returned a raw error, it indicates a system failure.
		a.logger.Error("Action execution resulted in system error", zap.Error(err), zap.String("action_id", action.ID))
		// Wrap the raw error in a structured ExecutionResult.
		result = &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("System error during execution: %v", err)},
		}
	}

	// Ensure result is never nil.
	if result == nil {
		a.logger.Error("Executor returned nil result and nil error.", zap.String("action_type", string(action.Type)))
		result = &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": "Executor returned nil result (Internal error)."},
		}
	}

	// Post the result back as an observation. Use the parent context (ctx).
	a.postObservation(ctx, action, result)
}

// handleConclude orchestrates the mission conclusion process.
func (a *Agent) handleConclude(ctx context.Context, action Action) (*ExecutionResult, error) {
	// 1. Generate the final summary and artifacts.
	missionResult, err := a.concludeMission(ctx)

	// 2. Determine the ExecutionResult based on whether conclusion succeeded.
	var execResult *ExecutionResult
	if err == nil && missionResult != nil {
		execResult = &ExecutionResult{
			Status:          "success",
			ObservationType: ObservedSystemState,
			Data:            map[string]interface{}{"summary": missionResult.Summary, "findings_count": len(missionResult.Findings)},
			Rationale:       "Mission concluded successfully.",
		}
	} else {
		// If conclusion fails, report it in the ExecutionResult.
		errMsg := fmt.Sprintf("Failed to generate final report: %v", err)
		a.logger.Error("Failed to generate mission conclusion artifacts.", zap.Error(err))
		execResult = &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": errMsg},
			Rationale:       "Attempted to conclude mission, but report generation failed.",
		}
	}

	// 3. Signal the main Start() loop that the mission is complete.
	if missionResult != nil {
		a.finish(ctx, *missionResult)
	} else {
		// Fallback if missionResult is nil
		m := a.GetMission()
		a.finish(ctx, MissionResult{
			ID:        m.ID,
			ScanID:    m.ScanID,
			Objective: m.Objective,
			Summary:   fmt.Sprintf("Mission concluded by Mind, but finalization process failed: %v", err),
			StartTime: m.StartTime,
			EndTime:   time.Now().UTC(),
		})
	}

	return execResult, nil
}

// gatherMissionContext fetches the relevant subgraph from the Knowledge Graph.
func (a *Agent) gatherMissionContext(ctx context.Context, missionID string) (map[string]interface{}, error) {
	if a.kgClient == nil {
		a.logger.Warn("Knowledge Graph client is not initialized. Cannot gather mission context.")
		return nil, nil
	}

	// Implementation using Breadth-First Search (BFS) traversal to collect the entire subgraph connected to the mission.
	a.logger.Debug("Starting full graph traversal (BFS) for mission context.", zap.String("mission_id", missionID))

	// Start BFS from the mission node.
	queue := []string{missionID}
	visitedNodes := make(map[string]schemas.Node)

	// 1. Fetch the starting node.
	startNode, err := a.kgClient.GetNode(ctx, missionID)
	if err != nil {
		// If the mission node doesn't exist, return an empty context.
		a.logger.Warn("Mission start node not found in KG.", zap.String("mission_id", missionID), zap.Error(err))
		return map[string]interface{}{
			"nodes": []schemas.Node{},
			"edges": []schemas.Edge{},
		}, nil
	}
	visitedNodes[missionID] = startNode

	// 2. Traverse the graph and collect all nodes.
	// Use an index based loop to iterate over the growing queue slice efficiently.
	currentIndex := 0
	for len(queue) > currentIndex {
		currentNodeID := queue[currentIndex]
		currentIndex++

		// GetNeighbors fetches nodes connected by outgoing edges.
		neighbors, err := a.kgClient.GetNeighbors(ctx, currentNodeID)
		if err != nil {
			a.logger.Warn("Failed to get neighbors during context gathering", zap.String("node_id", currentNodeID), zap.Error(err))
			continue
		}

		for _, neighbor := range neighbors {
			if _, found := visitedNodes[neighbor.ID]; !found {
				visitedNodes[neighbor.ID] = neighbor
				queue = append(queue, neighbor.ID)
			}
		}
	}

	// 3. Collect all edges connecting the visited nodes.
	subgraphNodes := make([]schemas.Node, 0, len(visitedNodes))
	// Use a map to ensure unique edges by ID.
	subgraphEdgesMap := make(map[string]schemas.Edge)

	for nodeID, node := range visitedNodes {
		subgraphNodes = append(subgraphNodes, node)

		edges, err := a.kgClient.GetEdges(ctx, nodeID)
		if err != nil {
			a.logger.Warn("Failed to get edges for subgraph node", zap.String("node_id", nodeID), zap.Error(err))
			continue
		}
		for _, edge := range edges {
			// Since we traversed via outgoing edges, the destination should be in visitedNodes.
			// We add the edge to the map (handles duplicates automatically).
			subgraphEdgesMap[edge.ID] = edge
		}
	}

	subgraphEdges := make([]schemas.Edge, 0, len(subgraphEdgesMap))
	for _, edge := range subgraphEdgesMap {
		subgraphEdges = append(subgraphEdges, edge)
	}

	a.logger.Info("Mission context gathered.", zap.Int("nodes_count", len(subgraphNodes)), zap.Int("edges_count", len(subgraphEdges)))

	// Return the result in the expected map format (representing schemas.Subgraph).
	return map[string]interface{}{
		"nodes": subgraphNodes,
		"edges": subgraphEdges,
	}, nil
}

// finish handles the final steps of the mission lifecycle.
// It signals the Start() loop that the mission is complete.
func (a *Agent) finish(ctx context.Context, result MissionResult) {
	// NOTE: We do not lock or set an isFinished flag here anymore.
	// The state is managed by the mission object and the Start() loop.
	// We do not stop the mind or shut down the bus.

	// Use select to send result, preventing blocking forever if the runner (RunMission)
	// has already exited (e.g., due to timeout/cancellation).
	select {
	case a.resultChan <- result:
	case <-ctx.Done():
		a.logger.Warn("Failed to send mission result: context cancelled before Start loop received it.")
	}
}

// --- Placeholder Implementations ---

// Placeholder definitions to satisfy the compiler as ImprovementAnalyst implementation is missing.

type PlaceholderImprovementAnalyst struct{}

func (p *PlaceholderImprovementAnalyst) AnalyzeAndImprove(ctx context.Context, goal string, bus CognitiveBus) error {
	return fmt.Errorf("ImprovementAnalyst (Evolution) is not implemented (Placeholder active)")
}

func NewImprovementAnalyst(cfg config.Interface, llmClient schemas.LLMClient, logger *zap.Logger) (ImprovementAnalyst, error) {
	logger.Warn("Using Placeholder ImprovementAnalyst. Self-improvement capabilities are disabled.")
	return &PlaceholderImprovementAnalyst{}, nil
}
