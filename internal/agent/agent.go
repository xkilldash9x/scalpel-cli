package agent

import ( // This is a comment to force a change
	"context"
	"errors"
	"net/http"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	json "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/core"
	"github.com/xkilldash9x/scalpel-cli/internal/llmclient"
)

// InteractionRequest represents an incoming prompt from the user via HTTP.
type InteractionRequest struct {
	Prompt string `json:"prompt"`
}

// Agent orchestrates the components of an autonomous security mission.
type Agent struct {
	logger     *zap.Logger
	globalCtx  *core.GlobalContext
	mind       Mind
	bus        CognitiveBus
	executors  *ExecutorRegistry
	resultChan chan MissionResult
	wg         sync.WaitGroup
	mu         sync.Mutex
	isFinished bool
	evolution  ImprovementAnalyst
	kg         GraphStore
	llmClient  schemas.LLMClient
	ltm        LTM

	// State related to the current mission, if any.
	mission    Mission
	missionMu  sync.RWMutex

	// Map to correlate interaction requests with response channels
	responseListeners map[string]chan string
	responseMu        sync.Mutex

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
	LLMInteraction  *schemas.LLMInteractionLog
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
// If mission is nil, the agent starts ready to accept interactions or a new mission (Server Mode).
// SessionContext might be nil if the agent is started without an immediate browser requirement.
func New(ctx context.Context, mission *Mission, globalCtx *core.GlobalContext, session schemas.SessionContext) (*Agent, error) {
	agentID := uuid.New().String()[:8]
	logger := globalCtx.Logger.With(zap.String("agent_id", agentID))

	// 1. Long-Term Memory (LTM)
	ltm := NewLTM(globalCtx.Config.Agent().LTM, logger)

	// 2. LLM Client Router
	llmRouter, err := llmclient.NewRouter(ctx, globalCtx.Config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create LLM client router: %w", err)
	}

	// 3. Cognitive Bus
	bus := NewCognitiveBus(logger)

	// 4. Executors and Humanoid
	projectRoot, _ := os.Getwd()
	executors := NewExecutorRegistry(logger, projectRoot, globalCtx)

	var h humanoid.Controller
	// Initialize browser components only if a session is provided
	// NOTE: If an agent starts without a session (e.g., Master Agent) it cannot currently initiate browser tasks.
	// This requires future enhancement for dynamic browser pool management.
	if session != nil {
		executors.UpdateSessionProvider(func() schemas.SessionContext {
			return session
		})

		browserCfg := globalCtx.Config.Browser()
		h_concrete := humanoid.New(browserCfg.Humanoid, logger.Named("humanoid"), session)
		h = h_concrete
		executors.UpdateHumanoidProvider(func() *humanoid.Humanoid {
			return h_concrete
		})
	}

	// 5. Initialize Self-Healing (Autofix) System.
	selfHeal, err := NewSelfHealOrchestrator(logger, globalCtx.Config, llmRouter)
	if err != nil {
		// If initialization fails (e.g., missing log file config), log the error
		// but allow the agent to continue without self-healing capabilities.
		logger.Error("Failed to initialize SelfHealOrchestrator. Continuing without self-healing.", zap.Error(err))
		selfHeal = nil // Ensure selfHeal is nil if it failed to initialize.
	}

	// 6. Initialize Evolution (Self-Improvement) System.
	evoAnalyst, err := NewImprovementAnalyst(globalCtx.Config, llmRouter, logger)
	if err != nil {
		// Log the error but continue, as evolution is an enhancement, not a critical function.
		logger.Error("Failed to initialize Evolution system (ImprovementAnalyst). Proceeding without it.", zap.Error(err))
	}

	var initialMission Mission
	if mission != nil {
		initialMission = *mission
		logger = logger.With(zap.String("mission_id", mission.ID))
	}

	agent := &Agent{
		mission:    initialMission,
		logger:     logger, // Use the potentially updated logger
		globalCtx:  globalCtx,
		mind:       mind,
		bus:        bus,
		executors:  executors,
		resultChan: make(chan MissionResult, 1),
		evolution:  evoAnalyst,
		kg:         kg,
		llmClient:  llmRouter,
		ltm:        ltm,
		selfHeal:   selfHeal,
		evolution:  evoAnalyst,
		responseListeners: make(map[string]chan string),
	}
	return agent, nil
}

// RegisterInteractionRoutes sets up the HTTP routes for user interaction.
func (a *Agent) RegisterInteractionRoutes(r chi.Router) {
	r.Post("/api/v1/interact", a.HandleInteract)
	// The old MCP command endpoint is superseded by the interaction endpoint.
	r.Get("/healthz", a.HandleHealthCheck)
}

// HandleHealthCheck is a simple handler to confirm the agent is responsive.
func (a *Agent) HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Agent OK"))
}

// HandleInteract is the main entry point for user prompts via HTTP.
func (a *Agent) HandleInteract(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	w.Header().Set("Content-Type", "application/json")

	// 1. Decode the request body
	var req InteractionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.logger.Warn("Invalid interaction request body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Invalid request body: %v", err)})
		return
	}

	if req.Prompt == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Prompt cannot be empty"})
		return
	}

	// Simple snippet for logging
	snippetLen := len(req.Prompt)
	if snippetLen > 50 {
		snippetLen = 50
	}
	a.logger.Info("Received interaction prompt", zap.String("prompt_snippet", req.Prompt[:snippetLen]))

	// 2. Ensure a mission context exists. If not, create a default one for the conversation.
	mission := a.GetMission()
	if mission.ID == "" {
		mission = Mission{
			ID:        "convo-" + uuid.New().String()[:8],
			ScanID:    "convo-scan", // Assign a scan ID for correlation
			Objective: "Interact with the user, answer questions, and perform tasks as requested.",
			StartTime: time.Now(),
		}
		a.SetMission(mission)
	}

	// 3. Prepare synchronization
	requestID := uuid.New().String()
	responseChan := make(chan string, 1)

	a.registerResponseListener(requestID, responseChan)
	defer a.unregisterResponseListener(requestID)

	// 4. Send input to the Agent's cognitive bus as an Observation
	obs := Observation{
		ID:        uuid.New().String(),
		MissionID: mission.ID,
		Type:      ObservedUserInput,
		Data: map[string]string{
			"prompt":     req.Prompt,
			"request_id": requestID,
		},
		Result: ExecutionResult{
			Status: "success", // The input was successfully observed
			ObservationType: ObservedUserInput,
		},
		Timestamp: time.Now().UTC(),
	}

	if err := a.bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: obs}); err != nil {
		a.logger.Error("Failed to post user input to cognitive bus", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Internal agent processing error"})
		return
	}

	// 5. Wait for the response synchronously
	// Use a timeout specific to interaction processing
	timeout := time.After(60 * time.Second)

	select {
	case response := <-responseChan:
		// Success: Send response back to HTTP client
		json.NewEncoder(w).Encode(map[string]string{"response": response})
	case <-timeout:
		// Timeout waiting for the agent's mind to respond
		a.logger.Warn("Timeout waiting for agent response", zap.String("request_id", requestID))
		w.WriteHeader(http.StatusGatewayTimeout)
		json.NewEncoder(w).Encode(map[string]string{"error": "Agent did not respond in time"})
	case <-ctx.Done():
		// Client cancelled the request
		a.logger.Warn("Client cancelled interaction request", zap.Error(ctx.Err()))
	}
}

// SetMission updates the agent's current objective.
func (a *Agent) SetMission(mission Mission) {
	a.missionMu.Lock()
	a.mission = mission
	a.missionMu.Unlock()

	// Inform the mind about the new mission (Mind handles empty mission IDs internally)
	a.mind.SetMission(mission)
}

// GetMission returns the current mission safely.
func (a *Agent) GetMission() Mission {
	a.missionMu.RLock()
	defer a.missionMu.RUnlock()
	return a.mission
}

// Start executes the agent's main cognitive loops. It blocks until the context is cancelled or a critical error occurs.
// Renamed from RunMission and refactored for persistence.
func (a *Agent) Start(ctx context.Context) error {
	a.logger.Info("Agent is starting cognitive loops.")
	agentCtx, cancelAgent := context.WithCancel(ctx)
	defer cancelAgent() // Ensures all subsystems are stopped when Start returns.
	startupErrChan := make(chan error, 1)

	// Start the LTM's background processes.
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		a.ltm.Run(agentCtx)
	}()

	// Start the Self-Healing system if initialized.
	if a.selfHeal != nil {
		// The self-healing system runs concurrently for the duration of the agent context.
		go a.selfHeal.Start(agentCtx)
	}

	// Subscribe to actions before starting the loops. This ensures no actions generated
	// during startup are missed. The actionLoop will be responsible for handling these.
	actionChan, err := a.bus.Subscribe(ctx, MessageTypeAction)
	if err != nil {
		return fmt.Errorf("failed to subscribe to action messages: %w", err)
	}

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
	go a.actionLoop(agentCtx, actionChan)

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
			a.logger.Info("Mission finished.", zap.String("MissionID", a.GetMission().ID))

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
			// 4. Wait for loops (Mind loop, Action loop) to finish.
			a.wg.Wait()

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
			a.wg.Wait()
			return err
		}
	}
}

func (a *Agent) registerResponseListener(requestID string, listener chan string) {
	a.responseMu.Lock()
	defer a.responseMu.Unlock()
	a.responseListeners[requestID] = listener
}

func (a *Agent) unregisterResponseListener(requestID string) {
	a.responseMu.Lock()
	defer a.responseMu.Unlock()
	// Check if it exists before deleting to handle potential race where dispatch already removed it.
	if _, exists := a.responseListeners[requestID]; exists {
		delete(a.responseListeners, requestID)
	}
}

// dispatchResponse sends the generated response back to the waiting HTTP handler.
func (a *Agent) dispatchResponse(requestID string, response string) {
	a.responseMu.Lock()
	defer a.responseMu.Unlock()
	if listener, ok := a.responseListeners[requestID]; ok {
		select {
		case listener <- response:
			a.logger.Info("Dispatched response to listener", zap.String("request_id", requestID))
		default:
			// Listener might have timed out and gone away (channel buffer full)
			a.logger.Warn("Failed to dispatch response: listener not ready or channel full", zap.String("request_id", requestID))
		}
		// Once dispatched (or failed to dispatch), the listener is removed.
		delete(a.responseListeners, requestID)
	} else {
		// This can happen if the HTTP request timed out before the agent generated the response.
		a.logger.Warn("No listener found for response (client likely timed out)", zap.String("request_id", requestID))
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
					// Acknowledge the message.
					a.bus.Acknowledge(msg)
					// Signal that the mission is finished via the result channel.
					// The main Start() loop handles this signal and resets the mission state.
					a.finish(ctx, *result)
				}
				// CRITICAL FIX: Do not return. The loop must continue for the agent to persist.
				continue

			case ActionRespondToUser:
				// Simple snippet for logging
				snippetLen := len(action.Value)
				if snippetLen > 100 {
					snippetLen = 100
				}
				a.logger.Info("Agent decided to respond to user.", zap.String("response_snippet", action.Value[:snippetLen]))

				requestID, ok := action.Metadata["request_id"].(string)
				if !ok || requestID == "" {
					a.logger.Error("ActionRespondToUser missing required 'metadata.request_id'")
					// We must post an observation about this failure so the Mind can potentially recover.
					execResult = &ExecutionResult{
						Status:       "failed",
						ErrorCode:    ErrCodeInvalidParameters,
						ErrorDetails: map[string]interface{}{"message": "Missing request_id for response dispatch."},
					}
				} else {
					a.dispatchResponse(requestID, action.Value)
					// The execution is successful from the Mind's perspective.
					execResult = &ExecutionResult{Status: "success", ObservationType: ObservedSystemState}
				}

			case ActionEvolveCodebase:
				a.logger.Info("Agent decided to initiate self-improvement (Evolution).", zap.String("rationale", action.Rationale))
				execResult = a.executeEvolution(ctx, action)

			case ActionPerformComplexTask:
				a.logger.Info("Agent is orchestrating a complex task (Placeholder)", zap.Any("metadata", action.Metadata))
				taskName, _ := action.Metadata["task_name"].(string)
				execResult = &ExecutionResult{
					Status:          "failed",
					ObservationType: ObservedSystemState,
					ErrorCode:       ErrCodeNotImplemented,
					ErrorDetails:    map[string]interface{}{"task_name": taskName},
				}
				// FIX: Removed the default case that was incorrectly handling all other actions.
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

// postObservation creates an observation from an action's result and posts it to the bus.
func (a *Agent) postObservation(ctx context.Context, action Action, result *ExecutionResult) {
	// The observation ID should be unique.
	obs := Observation{
		ID:          uuid.New().String(),
		MissionID:   action.MissionID,
		ActionID:    action.ID,
		Type:        result.ObservationType,
		Data:        result.Data,
		Result:      *result,
		Rationale:   result.Rationale,
		Timestamp:   time.Now().UTC(),
		LLMTrace:    result.LLMTrace,
		Screenshots: result.Screenshots,
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
		evoCtx, cancel := context.WithCancel(a.globalCtx.Ctx)
		defer cancel()

		if err := a.evolution.AnalyzeAndImprove(evoCtx, goal, a.bus); err != nil {
			a.logger.Error("Evolution process failed", zap.Error(err), zap.String("goal", goal))
			// Post a failure observation so the mind is aware.
			obs := Observation{
				ID:        uuid.New().String(),
				MissionID: action.MissionID,
				ActionID:  action.ID, // Correlate with the triggering action
				Type:      ObservedSystemState,
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
		Rationale:       fmt.Sprintf("Initiated codebase evolution process with goal: %s. The process will run in the background.", goal),
	}
}

func (a *Agent) concludeMission(ctx context.Context) (*MissionResult, error) {
	mission := a.GetMission()
	a.logger.Info("Concluding mission with intelligent summary", zap.String("mission_id", mission.ID))
	subgraph, err := a.gatherMissionContext(ctx, mission.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to gather final context for summary: %w", err)
	}

	// If there's no data, we can't generate a summary.
	if subgraph == nil || len(subgraph) == 0 {
		a.logger.Warn("Knowledge graph is empty. Cannot generate a meaningful summary.")
		return &MissionResult{
			ID:        mission.ID,
			ScanID:    mission.ScanID,
			Objective: mission.Objective,
			Summary:   "Mission concluded, but no significant activities were recorded.",
			StartTime: mission.StartTime,
			EndTime:   time.Now().UTC(),
		}, nil
	}

	subgraphJSON, err := json.Marshal(subgraph)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subgraph for LLM prompt: %w", err)
	}

	// Construct the prompt for the LLM to generate the final summary.
	systemPrompt := "You are the Mind of 'scalpel-cli'. The mission has concluded. Your task is to act as a security analyst and write the final report summary."
	userPrompt := fmt.Sprintf(
		"The mission to '%s' has concluded. Based on the complete knowledge graph provided below, synthesize a summary of your findings. Identify the most critical vulnerabilities, noteworthy observations (including any EVOLVE_CODEBASE actions), and provide a concise, professional report summary. The summary should be in plain text format.

Knowledge Graph Snapshot:
%s",
		mission.Objective, string(subgraphJSON),
	)

	req := schemas.GenerationRequest{
		SystemPrompt: systemPrompt,
		Prompt:       userPrompt,
		Temperature:  0.2, // Low temperature for a factual, consistent summary.
		Model:        config.ModelSonnet35,
	}

	// Generate the summary using the LLM.
	resp, err := a.llmClient.Generate(ctx, req)
	if err != nil {
		// If summary generation fails, return an error. The caller can decide how to handle this.
		return nil, fmt.Errorf("failed to generate mission summary via LLM: %w", err)
	}

	summary := resp.Text
	if summary == "" {
		summary = "Failed to generate an intelligent summary. Please review the knowledge graph manually."
	}

	// TODO: Extract findings from the knowledge graph.
	// This is a placeholder for a more sophisticated extraction process.
	findings := make([]schemas.Finding, 0)

	result := &MissionResult{
		ID:              mission.ID,
		ScanID:          mission.ScanID,
		Objective:       mission.Objective,
		Summary:         summary,
		StartTime:       mission.StartTime,
		EndTime:         time.Now().UTC(),
		KnowledgeGraph:  subgraph,
		Findings:        findings,
		LLMInteraction:  resp.Log,
		FinalLLMRequest: &req,
	}

	return result, nil
}

// gatherMissionContext retrieves all nodes and edges related to the mission from the graph store.
func (a *Agent) gatherMissionContext(ctx context.Context, missionID string) (map[string]interface{}, error) {
	if a.kg == nil {
		a.logger.Warn("Knowledge Graph store is not initialized. Cannot gather mission context.")
		return nil, nil
	}
	// This is a conceptual method. The actual implementation depends on the GraphStore interface.
	// For example, it might be: `return a.kg.GetSubgraphByMission(ctx, missionID)`
	// For now, we'll assume a placeholder function that returns a map.
	// In a real implementation, this would query the graph database.
	return a.kg.Export(ctx)
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