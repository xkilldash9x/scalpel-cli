// File: internal/agent/llm_mind.go
package agent

import (
	"context"
	encodingjson "encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	json "github.com/json-iterator/go"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// LLMMind implements the Mind interface using a Large Language Model for decision making.
// It operates on an OODA (Observe, Orient, Decide, Act) loop, interacting with other
// agent components via the CognitiveBus and using a Knowledge Graph for memory.
type LLMMind struct {
	cfg            config.AgentConfig
	logger         *zap.Logger
	kg             schemas.KnowledgeGraphClient // Use the canonical interface
	bus            CognitiveBus                 // This should be the interface
	llmClient      schemas.LLMClient
	ltm            LTM
	currentMission Mission
	currentState   AgentState
	mu             sync.RWMutex
	wg             sync.WaitGroup
	stopChan       chan struct{}
	// stopOnce ensures the Stop method is idempotent and safe for concurrent calls.
	stopOnce       sync.Once
	stateReadyChan chan struct{}

	contextLookbackSteps int
}

// Allows for mocking in tests.
var uuidNewString = uuid.NewString

// Statically assert that LLMMind implements the Mind interface.
var _ Mind = (*LLMMind)(nil)

// Creates a new LLMMind instance.
func NewLLMMind(
	logger *zap.Logger,
	client schemas.LLMClient,
	cfg config.AgentConfig,
	kg schemas.KnowledgeGraphClient,
	bus CognitiveBus, // This should be the interface
	ltm LTM,
) *LLMMind {

	// Determine the context lookback depth from configuration, with a sensible default.
	// Assuming cfg.Mind.ContextLookbackSteps exists for this refinement.
	contextLookbackSteps := cfg.Mind.ContextLookbackSteps
	if contextLookbackSteps <= 0 {
		contextLookbackSteps = 10 // Default lookback if not configured or invalid
	}

	m := &LLMMind{
		logger:               logger.Named("llm_mind"),
		llmClient:            client,
		cfg:                  cfg,
		kg:                   kg,
		bus:                  bus,
		ltm:                  ltm,
		currentState:         StateInitializing,
		stopChan:             make(chan struct{}),
		stateReadyChan:       make(chan struct{}, 1),
		contextLookbackSteps: contextLookbackSteps,
	}

	m.logger.Info("LLMMind initialized", zap.String("default_model", cfg.LLM.DefaultPowerfulModel), zap.Int("context_lookback", m.contextLookbackSteps), zap.Bool("evolution_enabled", cfg.Evolution.Enabled))
	return m
}

// Begins the cognitive processing loop (OODA).
func (m *LLMMind) Start(ctx context.Context) error {
	m.logger.Info("Starting LLMMind cognitive loops.")

	// Ensure Stop is always called when Start returns, to clean up resources like LTM.
	defer m.Stop()

	m.wg.Add(1)
	go m.runObserverLoop(ctx)

	m.mu.RLock()
	initialState := m.currentState
	m.mu.RUnlock()

	if initialState == StateInitializing {
		m.updateState(StateObserving)
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Context cancelled, stopping cognitive loop.")
			m.wg.Wait()
			return ctx.Err()
		case <-m.stopChan:
			m.logger.Info("Stop signal received, stopping cognitive loop.")
			m.wg.Wait()
			return nil
		case <-m.stateReadyChan:
			// Wrap the execution cycle in an anonymous function to handle panics gracefully.
			func() {
				defer func() {
					if r := recover(); r != nil {
						m.logger.Error("Panic recovered during decision cycle (OODA)",
							zap.Any("panic_value", r),
							zap.Stack("stack"),
						)
						// Transition back to Observing to allow potential recovery,
						// unless the state is already terminal (handled by updateState).
						m.updateState(StateObserving)
					}
				}()
				m.executeDecisionCycle(ctx)
			}()
		}
	}
}

// Implements the "Observe" part of the OODA loop. It listens for
// observations from the CognitiveBus and processes them.
func (m *LLMMind) runObserverLoop(ctx context.Context) {
	defer m.wg.Done()
	m.logger.Info("Observer loop started.")
	obsChan, unsubscribe := m.bus.Subscribe(MessageTypeObservation)
	defer unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case msg, ok := <-obsChan:
			if !ok {
				return
			}

			processingFailed := false
			func() {
				defer m.bus.Acknowledge(msg)

				// Setup panic recovery for observation processing.
				defer func() {
					if r := recover(); r != nil {
						m.logger.Error("Panic recovered during observation processing (Mind)",
							zap.Any("panic_value", r),
							zap.String("message_id", msg.ID),
							zap.Stack("stack"),
						)
						// If the Mind panics while processing input, it cannot continue reliably.
						processingFailed = true
					}
				}()

				m.updateState(StateObserving)
				if obs, ok := msg.Payload.(Observation); ok {
					if err := m.processObservation(ctx, obs); err != nil {
						m.logger.Error("Failed to process observation", zap.Error(err))
						if strings.Contains(err.Error(), "failed to record observation in KG") {
							processingFailed = true
						}
					}
				} else {
					m.logger.Error("Received invalid payload for OBSERVATION message type.", zap.Any("payload_type", fmt.Sprintf("%T", msg.Payload)))
				}

				if !processingFailed {
					m.signalStateReady()
				}
			}()

			if processingFailed {
				m.updateState(StateFailed)
				return // Stop the loop on critical failure.
			}
		}
	}
}

// Notifies the main decision loop that new information has been
// processed and it's time to run the next decision cycle.
func (m *LLMMind) signalStateReady() {
	select {
	case m.stateReadyChan <- struct{}{}:
	default:
		// Channel is already full, a cycle is already pending.
	}
}

// Performs the Orient, Decide, and Act steps of the loop.
func (m *LLMMind) executeDecisionCycle(ctx context.Context) {
	m.mu.RLock()
	missionID := m.currentMission.ID
	currentState := m.currentState
	m.mu.RUnlock()

	if missionID == "" || currentState == StateCompleted || currentState == StateFailed || currentState == StatePaused {
		return
	}

	// -- ORIENT --
	m.updateState(StateOrienting)
	contextSnapshot, err := m.gatherContext(ctx, missionID)
	if err != nil {
		m.logger.Error("Failed to gather context from Knowledge Graph", zap.Error(err))
		m.updateState(StateObserving)
		return
	}

	// -- DECIDE --
	m.updateState(StateDeciding)
	action, err := m.decideNextAction(ctx, contextSnapshot)
	if err != nil {
		m.logger.Error("Failed to decide next action", zap.Error(err))
		m.updateState(StateObserving)
		return
	}

	isConcluding := action.Type == ActionConclude

	if isConcluding {
		m.logger.Info("Mission concluded by LLM decision.", zap.String("rationale", action.Rationale))
		m.updateState(StateCompleted)
	}

	// -- ACT --
	// Use the local variable 'isConcluding' instead of checking the shared 'm.currentState' to prevent a data/logical race.
	if !isConcluding {
		m.updateState(StateActing)
	}

	if err := m.recordActionKG(ctx, action); err != nil {
		m.logger.Error("Critical failure: Cannot record action to Knowledge Graph.", zap.Error(err))
		m.updateState(StateFailed)
		return
	}

	if err := m.bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: action}); err != nil {
		m.logger.Error("Failed to post action to CognitiveBus", zap.Error(err))
		busErrorResult := ExecutionResult{
			Status:       "failed",
			ErrorCode:    "BUS_POST_FAILURE",
			ErrorDetails: map[string]interface{}{"message": err.Error()},
		}
		if updateErr := m.updateActionStatus(ctx, action.ID, schemas.StatusError, busErrorResult); updateErr != nil {
			m.logger.Error("Failed to update action status after bus failure", zap.Error(updateErr))
			m.updateState(StateFailed)
		} else if action.Type != ActionConclude {
			m.updateState(StateObserving)
		}
		return
	}

	if action.Type != ActionConclude {
		m.updateState(StateObserving)
	}
}

// Performs a depth limited BFS traversal from the mission node
// to collect a relevant subgraph for the LLM's context.
func (m *LLMMind) gatherContext(ctx context.Context, missionID string) (*schemas.Subgraph, error) {
	type bfsItem struct {
		nodeID string
		depth  int
	}

	queue := []bfsItem{{nodeID: missionID, depth: 0}}
	visitedNodes := make(map[string]schemas.Node)

	startNode, err := m.kg.GetNode(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission start node '%s': %w", missionID, err)
	}
	visitedNodes[missionID] = startNode

	for len(queue) > 0 {
		currentItem := queue[0]
		queue = queue[1:]

		if currentItem.depth >= m.contextLookbackSteps {
			continue
		}

		neighbors, err := m.kg.GetNeighbors(ctx, currentItem.nodeID)
		if err != nil {
			m.logger.Warn("Failed to get neighbors during context gathering", zap.String("nodeID", currentItem.nodeID), zap.Error(err))
			continue
		}

		for _, neighbor := range neighbors {
			if _, found := visitedNodes[neighbor.ID]; !found {
				visitedNodes[neighbor.ID] = neighbor
				queue = append(queue, bfsItem{nodeID: neighbor.ID, depth: currentItem.depth + 1})
			}
		}
	}

	subgraphNodes := make([]schemas.Node, 0, len(visitedNodes))
	var subgraphEdges []schemas.Edge

	for _, node := range visitedNodes {
		subgraphNodes = append(subgraphNodes, node)
		edges, err := m.kg.GetEdges(ctx, node.ID)
		if err != nil {
			m.logger.Warn("Failed to get edges for subgraph node", zap.String("nodeID", node.ID), zap.Error(err))
			continue
		}
		for _, edge := range edges {
			if _, destInSubgraph := visitedNodes[edge.To]; destInSubgraph {
				if _, sourceInSubgraph := visitedNodes[edge.From]; sourceInSubgraph {
					subgraphEdges = append(subgraphEdges, edge)
				}
			}
		}
	}

	result := &schemas.Subgraph{Nodes: subgraphNodes, Edges: subgraphEdges}
	m.logger.Debug("Gathered localized context", zap.Int("nodes", len(result.Nodes)), zap.Int("edges", len(result.Edges)))
	return result, nil
}

// Queries the LLM with the current context to determine the next action.
func (m *LLMMind) decideNextAction(ctx context.Context, contextSnapshot *schemas.Subgraph) (Action, error) {
	systemPrompt := m.generateSystemPrompt()
	userPrompt, err := m.generateUserPrompt(contextSnapshot)
	if err != nil {
		return Action{}, err
	}

	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req := schemas.GenerationRequest{
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Tier:         schemas.TierPowerful,
		Options:      schemas.GenerationOptions{ForceJSONFormat: true, Temperature: 0.2},
	}

	response, err := m.llmClient.Generate(apiCtx, req)
	if err != nil {
		return Action{}, fmt.Errorf("llm generation failed: %w", err)
	}

	action, err := m.parseActionResponse(response)
	if err != nil {
		return Action{}, fmt.Errorf("failed to parse llm response: %w", err)
	}

	action.ID = uuidNewString()
	action.MissionID = m.currentMission.ID
	action.ScanID = m.currentMission.ScanID
	action.Timestamp = time.Now().UTC()
	return action, nil
}

// generateSystemPrompt constructs the core instruction set for the agent's brain dynamically.
func (m *LLMMind) generateSystemPrompt() string {
	basePrompt := `You are the Mind of 'scalpel-cli', an advanced, autonomous security analysis agent.
Your goal is to achieve the Mission Objective by exploring a web application, analyzing its components, and identifying vulnerabilities.
You operate in a continuous OODA loop. You receive the state as a JSON Knowledge Graph snapshot and must respond with a single JSON object for the next action.`

	// Conditionally include the evolution prompt if enabled in the configuration.
	evolutionPrompt := ""
	if m.cfg.Evolution.Enabled {
		evolutionPrompt = `
    4. Proactive Self-Improvement (Evolution):
    - EVOLVE_CODEBASE: Initiate an autonomous OODA loop to improve the agent's own source code.
      **WHEN TO USE:** Only when you identify a limitation, bug, or inefficiency in the agent's capabilities that prevents achieving the mission objective, AND you have context about the relevant code (e.g., from GATHER_CODEBASE_CONTEXT).
      **PARAMETERS:**
        - value: The objective of the improvement (Required, String).
        - metadata.target_files: List of relevant file paths (Optional, Array[string]).
      Example: {"type": "EVOLVE_CODEBASE", "value": "Improve error handling for timeouts in BrowserExecutor", "metadata": {"target_files": ["internal/agent/executors.go"]}, "rationale": "Repeated timeouts require better handling."}
`
	}

	vulnerabilityProbingPrompt := `    **Advanced Vulnerability Probing Strategies**:
    When testing for vulnerabilities like SQL Injection, do not use a single payload. Follow a multi-stage diagnostic process.
    1.  **Character Probing**: Start by injecting single characters (` + "`" + `'` + "`" + `, ` + "`" + `"` + "`" + `) to trigger database errors. An error is a strong signal.
    2.  **Boolean-Based Blind Probing**: If no errors appear, try to force a different application response using logical conditions.
        - Inject a TRUE condition (e.g., ` + "`" + `admin' AND '1'='1'` + "`" + `). Observe the response (e.g., "Incorrect password").
        - Inject a FALSE condition (e.g., ` + "`" + `admin' AND '1'='2'` + "`" + `). Observe the response (e.g., "User not found").
        - If the responses differ, you have confirmed a blind SQLi.
    3.  **Time-Based Blind Probing**: If Boolean responses are identical, attempt to introduce a time delay. This is your final confirmation method for blind injection.
        - Inject a time-delay payload (e.g., ` + "`" + `admin' AND pg_sleep(5)--` + "`" + ` for PostgreSQL, or ` + "`" + `admin' AND SLEEP(5)--` + "`" + ` for MySQL).
        - Observe the response time. A significant delay confirms the vulnerability.
    
    Record your findings from each stage in the ` + "`thought`" + ` and ` + "`rationale`" + ` fields of your action. Use the observations from one step to inform the next. For example, if a single quote causes an error, all subsequent payloads should use single quotes.`

	// Generate the error handling prompt dynamically to ensure EVOLVE_CODEBASE is only mentioned if enabled.
	errorHandlingPrompt := m.generateErrorHandlingPrompt()

	return basePrompt + m.getActionListPrompt() + evolutionPrompt + errorHandlingPrompt + vulnerabilityProbingPrompt + m.getClosingPrompt()
}

// getActionListPrompt returns the static list of available actions.
func (m *LLMMind) getActionListPrompt() string {
	return `
Available Action Types:

    1. Basic Browser Interaction (Executed realistically via Humanoid):
    - NAVIGATE: Go to a specific URL. (Params: value)
    - CLICK: Click on an element. (Params: selector)
    - INPUT_TEXT: Type text into a field. (Params: selector, value)
    - SUBMIT_FORM: Submit a form. (Params: selector)
    - SCROLL: Scroll the page. (Params: value="up" or "down")
    - WAIT_FOR_ASYNC: Pause execution. (Params: metadata={"duration_ms": 1500})

    1.5. User Interaction & System Management (For Persistent/Master Agent):
    - RESPOND_TO_USER: Send a message back to the user. Used to ask questions, report findings, or respond to prompts.
      **PARAMETERS:**
        - value: The message content (Required, String).
        - metadata.request_id: The ID from the USER_INPUT observation being responded to (Required, String).
    - QUERY_FINDINGS: Query the database for existing findings. (Params: metadata={scan_id, severity, limit, sort_by, sort_order})
      Example: {"type": "QUERY_FINDINGS", "metadata": {"severity": "CRITICAL", "limit": 10}, "rationale": "Fetching critical findings for the user."}
    - START_SCAN: Initiate a new background scan (orchestrated as a sub-agent). (Params: metadata={target, depth, concurrency, scope})
      Example: {"type": "START_SCAN", "metadata": {"target": "http://new-target.com"}, "rationale": "Starting scan requested by user."}

    2. Advanced/Complex Interaction:
    - HUMANOID_DRAG_AND_DROP: Move an element from one location to another. Use 'selector' for the element to drag, and 'metadata.target_selector' for the drop target.
      Example: {"type": "HUMANOID_DRAG_AND_DROP", "selector": "#item-1", "metadata": {"target_selector": "#cart"}, "rationale": "Testing cart functionality."}
    - PERFORM_COMPLEX_TASK: Instruct the agent to perform a high level action (e.g., 'LOGIN'). Use sparingly.

    3. Analysis & System:
    - ANALYZE_TAINT: (Active) Scan the current page context for data flows (Taint analysis/XSS). Use after navigation or significant UI changes. The analysis runs on the current browser state.
      Example: {"type": "ANALYZE_TAINT", "rationale": "Analyzing the user profile page inputs for XSS vulnerabilities."}
    - ANALYZE_PROTO_POLLUTION: (Active) Scan the current page context for client-side prototype pollution and DOM clobbering.
      Example: {"type": "ANALYZE_PROTO_POLLUTION", "rationale": "Analyzing the dashboard JS environment for pollution vulnerabilities."}
    - ANALYZE_HEADERS: (Passive) Analyze the HTTP headers captured in the current browser state artifacts for security misconfigurations.
      Example: {"type": "ANALYZE_HEADERS", "rationale": "Checking security headers on the main application responses."}
    - GATHER_CODEBASE_CONTEXT: Read source code for a module. (Params: metadata={"module_path": "..."})
    - CONCLUDE: Finish the mission.`
}

// generateErrorHandlingPrompt creates the instructions for error recovery strategies dynamically.
func (m *LLMMind) generateErrorHandlingPrompt() string {
	// Base error handling instructions applicable always.
	baseErrorHandling := `

    **Crucial Error Handling Instructions**:
    Analyze the "error_code" (in the KG node properties) if a previous action failed (status="ERROR").
    - ` + "`ELEMENT_NOT_FOUND`" + `: The selector was incorrect or the element does not exist. Strategy: Try a different selector or navigate elsewhere.
    - ` + "`HUMANOID_GEOMETRY_INVALID`" + `: The element exists but has zero size or invalid structure. Strategy: Try interacting with a parent element or skip this target.
    - ` + "`HUMANOID_TARGET_NOT_VISIBLE`" + `: The element exists but is obscured or off-screen.
      -> Strategy: You MUST use ` + "`SCROLL`" + ` or interact with other UI elements (like closing a modal) to make it visible BEFORE retrying the interaction.
    - ` + "`NAVIGATION_ERROR`" + `: The URL could not be reached. Strategy: Verify the URL or navigate back.
    - ` + "`FEATURE_DISABLED`" + `: You attempted to use a feature that is disabled. Strategy: Find an alternative approach; do not retry the action.
    - ` + "`INVALID_PARAMETERS`" + `: The parameters for the action were missing or invalid. Strategy: Correct the parameters (e.g., provide the missing selector) and retry the action.`

	// Conditional instructions related to Evolution capabilities.
	conditionalErrorHandling := ""
	if m.cfg.Evolution.Enabled {
		// If enabled, provide detailed strategies involving EVOLVE_CODEBASE.
		conditionalErrorHandling = `
    - ` + "`TIMEOUT_ERROR`" + `: The operation took too long. Strategy: Consider using ` + "`WAIT_FOR_ASYNC`" + ` before retrying. If ` + "`EVOLVE_CODEBASE`" + ` timed out, the objective was likely too complex.
    - ` + "`EVOLUTION_FAILURE`" + `: The self-improvement cycle failed. Strategy: Analyze the failure details (` + "`error_details`" + `), and either retry with a refined objective or abandon the evolution attempt.
    - ` + "`EXECUTION_FAILURE`" + `: If details suggest an internal bug. Strategy: Consider using ` + "`EVOLVE_CODEBASE`" + ` to fix the bug after gathering context.`
	} else {
		// If disabled, provide simpler strategies without mentioning EVOLVE_CODEBASE.
		conditionalErrorHandling = `
    - ` + "`TIMEOUT_ERROR`" + `: The operation took too long. Strategy: Consider using ` + "`WAIT_FOR_ASYNC`" + ` before retrying.
    - ` + "`EXECUTION_FAILURE`" + `: A generic failure occurred. Strategy: Analyze the error_details and try an alternative approach.`
	}

	return baseErrorHandling + conditionalErrorHandling
}

// getClosingPrompt returns the final instructions for the LLM.
func (m *LLMMind) getClosingPrompt() string {
	return `

    Analyze the provided state and objective, then decide your next move.
    Your response must be only the JSON for your chosen action.`
}

// Constructs the user facing part of the prompt, including the mission and KG state.
func (m *LLMMind) generateUserPrompt(contextSnapshot *schemas.Subgraph) (string, error) {
	contextJSON, err := json.Marshal(contextSnapshot)
	if err != nil {
		return "", fmt.Errorf("failed to marshal context snapshot: %w", err)
	}

	m.mu.RLock()
	objective := m.currentMission.Objective
	targetURL := m.currentMission.TargetURL
	m.mu.RUnlock()

	return fmt.Sprintf(`Mission Objective: %s
    Target: %s

    Current Localized State (Knowledge Graph JSON):
    %s

    Determine the next Action. Respond with a single JSON object.`, objective, targetURL, string(contextJSON)), nil
}

// A regex to robustly extract a JSON object from a markdown code block.
var jsonBlockRegex = regexp.MustCompile(fmt.Sprintf("(?s)%s(?:json)?\\s*(.*?)\\s*%s", "```", "```"))

// Robustly extracts a JSON object from the LLM's response,
// handling markdown code blocks or raw JSON.
func (m *LLMMind) parseActionResponse(response string) (Action, error) {
	response = strings.TrimSpace(response)
	var action Action
	var jsonStringToParse string

	matches := jsonBlockRegex.FindStringSubmatch(response)
	if len(matches) > 1 {
		jsonStringToParse = strings.TrimSpace(matches[1])
	} else {
		firstBracket := strings.Index(response, "{")
		if firstBracket == -1 {
			jsonStringToParse = response
		} else {
			braceCount := 0
			endIndex := -1
			for i := firstBracket; i < len(response); i++ {
				if response[i] == '{' {
					braceCount++
				} else if response[i] == '}' {
					braceCount--
					if braceCount == 0 {
						endIndex = i
						break
					}
				}
			}

			if endIndex != -1 {
				jsonStringToParse = response[firstBracket : endIndex+1]
			} else {
				jsonStringToParse = response[firstBracket:]
			}
		}
	}

	if jsonStringToParse == "" {
		return Action{}, fmt.Errorf("could not find any JSON in the LLM response")
	}

	err := json.Unmarshal([]byte(jsonStringToParse), &action)
	if err != nil {
		m.logger.Warn("Failed to unmarshal LLM response",
			zap.String("raw_response", response),
			zap.String("extracted_json", jsonStringToParse),
			zap.Error(err))
		return Action{}, fmt.Errorf("failed to unmarshal extracted JSON: %w", err)
	}

	if action.Type == "" {
		return Action{}, fmt.Errorf("LLM response missing required 'type' field after successful JSON parsing")
	}
	return action, nil
}

// The entry point for handling a new observation.
func (m *LLMMind) processObservation(ctx context.Context, obs Observation) error {
	m.logger.Debug("Processing observation", zap.String("obs_id", obs.ID), zap.String("type", string(obs.Type)))

	// Call the LTM to get heuristic flags for the observation.
	flags := m.ltm.ProcessAndFlagObservation(ctx, obs)

	if err := m.recordObservationKG(ctx, obs, flags); err != nil {
		return fmt.Errorf("failed to record observation in KG: %w", err)
	}

	if err := m.orientOnObservation(ctx, obs); err != nil {
		m.logger.Error("Failed to orient on observation", zap.String("obs_id", obs.ID), zap.Error(err))
	}

	if obs.SourceActionID != "" {
		if err := m.updateActionStatusFromObservation(ctx, obs); err != nil {
			m.logger.Error("Failed to update action status from observation", zap.String("action_id", obs.SourceActionID), zap.Error(err))
		}
	}
	return nil
}

// -- REFACTORING NOTE --
// This function is now more robust. It handles cases where observation data might be nil,
// empty, or not a string, preventing panics and improving data resilience.
// Orients on the observation, specifically looking for codebase context to analyze.
func (m *LLMMind) orientOnObservation(ctx context.Context, obs Observation) error {
	if obs.Type != ObservedCodebaseContext {
		return nil
	}

	var codeContext string
	if strData, ok := obs.Data.(string); ok {
		codeContext = strData
	} else if obs.Data != nil { // Keep nil check here since json.Marshal(nil) -> "null"
		dataBytes, err := json.Marshal(obs.Data)
		if err != nil {
			m.logger.Warn("Failed to marshal non-string observation data for codebase context.", zap.Error(err))
			return nil
		}
		codeContext = string(dataBytes)
	}

	if codeContext == "" || codeContext == "null" {
		m.logger.Debug("Observation data for codebase context is empty or nil, skipping orientation.", zap.String("obs_id", obs.ID))
		return nil
	}

	m.logger.Info("Orienting on new codebase context, extracting dependencies.", zap.String("obs_id", obs.ID))

	var deps map[string][]string
	if err := json.Unmarshal([]byte(codeContext), &deps); err != nil {
		return fmt.Errorf("failed to unmarshal dependency map from observation data: %w", err)
	}

	return m.addDependenciesToKG(ctx, obs.ID, deps)
}

// Adds extracted file dependencies as nodes and edges to the KG.
func (m *LLMMind) addDependenciesToKG(ctx context.Context, sourceObservationID string, deps map[string][]string) error {
	var lastErr error

	for sourceFile, dependencies := range deps {
		sourceNode := schemas.Node{
			ID:         sourceFile,
			Type:       schemas.NodeFile,
			Label:      sourceFile,
			Status:     schemas.StatusAnalyzed,
			Properties: encodingjson.RawMessage(fmt.Sprintf(`{"source": "%s"}`, sourceObservationID)),
		}
		if err := m.kg.AddNode(ctx, sourceNode); err != nil {
			lastErr = err
			m.logger.Warn("Failed to add file node to KG", zap.String("file", sourceFile), zap.Error(err))
			continue
		}

		for _, depFile := range dependencies {
			depNode := schemas.Node{
				ID:         depFile,
				Type:       schemas.NodeFile,
				Label:      depFile,
				Status:     schemas.StatusAnalyzed,
				Properties: encodingjson.RawMessage(fmt.Sprintf(`{"source": "%s"}`, sourceObservationID)),
			}
			if err := m.kg.AddNode(ctx, depNode); err != nil {
				lastErr = err
				m.logger.Warn("Failed to add dependency file node to KG", zap.String("file", depFile), zap.Error(err))
				continue
			}

			edge := schemas.Edge{
				ID:         uuidNewString(),
				From:       sourceFile,
				To:         depFile,
				Type:       schemas.RelationshipImports, // Use standardized constant.
				Label:      "Imports",
				Properties: encodingjson.RawMessage(fmt.Sprintf(`{"source_obs_id": "%s"}`, sourceObservationID)),
			}
			if err := m.kg.AddEdge(ctx, edge); err != nil {
				lastErr = err
				m.logger.Error("Failed to record file dependency in KG", zap.String("from", sourceFile), zap.String("to", depFile), zap.Error(err))
			}
		}
	}

	m.logger.Info("Enriched knowledge graph with codebase dependencies.", zap.Int("files_analyzed", len(deps)))
	return lastErr
}

// Sets the final status of an action based on its result.
func (m *LLMMind) updateActionStatusFromObservation(ctx context.Context, obs Observation) error {
	status := schemas.StatusAnalyzed
	if obs.Result.Status == "failed" {
		status = schemas.StatusError
	}
	return m.updateActionStatus(ctx, obs.SourceActionID, status, obs.Result)
}

// Updates an action's node in the KG with its execution result,
// including any structured error data.
func (m *LLMMind) updateActionStatus(ctx context.Context, actionID string, status schemas.NodeStatus, result ExecutionResult) error {
	node, err := m.kg.GetNode(ctx, actionID)
	if err != nil {
		return fmt.Errorf("kg.GetNode failed for action status update: %w", err)
	}

	node.Status = status
	node.LastSeen = time.Now().UTC()

	propsMap := make(map[string]interface{})
	if len(node.Properties) > 0 && !strings.EqualFold(string(node.Properties), "null") {
		if err := json.Unmarshal(node.Properties, &propsMap); err != nil {
			m.logger.Warn("Failed to unmarshal existing properties, overwriting.", zap.Error(err))
			propsMap = make(map[string]interface{})
		}
	}

	propsMap["status"] = string(status)
	if result.ErrorCode != "" {
		propsMap["error_code"] = result.ErrorCode
		propsMap["error_details"] = result.ErrorDetails
	}

	updatedProps, err := json.Marshal(propsMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated properties: %w", err)
	}
	node.Properties = encodingjson.RawMessage(updatedProps)

	if err := m.kg.AddNode(ctx, node); err != nil {
		return fmt.Errorf("kg.AddNode failed for action status update: %w", err)
	}
	return nil
}

// Converts a map to json.RawMessage.
func (m *LLMMind) marshalProperties(propsMap map[string]interface{}) (encodingjson.RawMessage, error) {
	propsBytes, err := json.Marshal(propsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal properties: %w", err)
	}
	return encodingjson.RawMessage(propsBytes), nil
}

// Creates a new node and edge in the KG for an observation, AND applies any embedded KGUpdates.
func (m *LLMMind) recordObservationKG(ctx context.Context, obs Observation, flags map[string]bool) error {
	now := time.Now().UTC()

	// 1. Apply KG Updates from the observation result (if any)
	if obs.Result.KGUpdates != nil && (len(obs.Result.KGUpdates.NodesToAdd) > 0 || len(obs.Result.KGUpdates.EdgesToAdd) > 0) {
		m.logger.Debug("Applying KG Updates from observation",
			zap.String("obs_id", obs.ID),
			zap.Int("nodes", len(obs.Result.KGUpdates.NodesToAdd)),
			zap.Int("edges", len(obs.Result.KGUpdates.EdgesToAdd)))

		// Apply nodes
		for _, nodeInput := range obs.Result.KGUpdates.NodesToAdd {
			node := schemas.Node{
				ID:         nodeInput.ID,
				Type:       nodeInput.Type,
				Label:      nodeInput.Label,
				Status:     nodeInput.Status,
				Properties: nodeInput.Properties,
				CreatedAt:  now,
				LastSeen:   now,
			}
			if node.ID == "" {
				node.ID = uuid.NewString() // Ensure ID exists
			}
			if err := m.kg.AddNode(ctx, node); err != nil {
				m.logger.Error("Failed to add node from KGUpdate", zap.String("node_id", node.ID), zap.Error(err))
				// Continue processing other updates even if one fails.
			}
		}

		// Apply edges
		for _, edgeInput := range obs.Result.KGUpdates.EdgesToAdd {
			edge := schemas.Edge{
				ID:         edgeInput.ID,
				From:       edgeInput.From,
				To:         edgeInput.To,
				Type:       edgeInput.Type,
				Label:      edgeInput.Label,
				Properties: edgeInput.Properties,
				CreatedAt:  now,
				LastSeen:   now,
			}
			// Generate ID if missing
			if edge.ID == "" {
				edge.ID = uuid.NewString()
			}
			if err := m.kg.AddEdge(ctx, edge); err != nil {
				m.logger.Error("Failed to add edge from KGUpdate", zap.String("edge_id", edge.ID), zap.Error(err))
			}
		}
	}

	// 2. Record the observation node itself (existing logic)
	propsMap := map[string]interface{}{
		"type":               string(obs.Type),
		"timestamp":          obs.Timestamp,
		"data_raw":           obs.Data,
		"exec_status":        obs.Result.Status,
		"exec_error_code":    obs.Result.ErrorCode,
		"exec_error_details": obs.Result.ErrorDetails,
		"ltm_flags":          flags,
	}
	propsBytes, err := json.Marshal(propsMap)
	if err != nil {
		return err
	}

	obsNode := schemas.Node{
		ID:         obs.ID,
		Type:       schemas.NodeObservation,
		Label:      fmt.Sprintf("Observation: %s", obs.Type),
		Status:     schemas.StatusNew,
		CreatedAt:  now,
		LastSeen:   now,
		Properties: encodingjson.RawMessage(propsBytes),
	}
	if err := m.kg.AddNode(ctx, obsNode); err != nil {
		return fmt.Errorf("kg.AddNode failed for observation: %w", err)
	}

	if obs.SourceActionID != "" {
		actionEdge := schemas.Edge{
			ID:        uuidNewString(),
			From:      obs.SourceActionID,
			To:        obs.ID,
			Type:      schemas.RelationshipHasObservation,
			Label:     "Generates Observation",
			CreatedAt: now,
			LastSeen:  now,
		}
		if err := m.kg.AddEdge(ctx, actionEdge); err != nil {
			m.logger.Error("Failed to record Action->Observation edge in KG", zap.Error(err))
		}
	}

	return nil
}

// -- REFACTORING NOTE --
// Metadata values are now stored directly without string conversion.
// This preserves the original data type (e.g., numbers for duration_ms),
// which is better for structured data integrity in the Knowledge Graph.
// Creates a node and corresponding edges in the knowledge graph for a given action.
func (m *LLMMind) recordActionKG(ctx context.Context, action Action) error {
	now := time.Now().UTC()

	propsMap := map[string]interface{}{
		"type":      string(action.Type),
		"rationale": action.Rationale,
		"timestamp": action.Timestamp,
		"status":    string(schemas.StatusNew),
	}
	if action.Selector != "" {
		propsMap["selector"] = action.Selector
	}
	if action.Value != "" {
		const maxLen = 256
		if utf8.RuneCountInString(action.Value) > maxLen {
			runes := []rune(action.Value) // FIX: Correctly handle multi-byte characters when truncating.
			propsMap["value"] = string(runes[:maxLen]) + "..."
		} else {
			propsMap["value"] = action.Value
		}
	}
	for k, v := range action.Metadata {
		propsMap[fmt.Sprintf("meta_%s", k)] = v
	}

	propsBytes, err := json.Marshal(propsMap)
	if err != nil {
		return err
	}

	actionNode := schemas.Node{
		ID:         action.ID,
		Type:       schemas.NodeAction,
		Label:      fmt.Sprintf("Action: %s", action.Type),
		Status:     schemas.StatusNew,
		CreatedAt:  now,
		LastSeen:   now,
		Properties: encodingjson.RawMessage(propsBytes),
	}
	if err := m.kg.AddNode(ctx, actionNode); err != nil {
		return fmt.Errorf("kg.AddNode failed for action: %w", err)
	}

	edge := schemas.Edge{
		ID:        uuidNewString(),
		From:      action.MissionID,
		To:        action.ID,
		Type:      schemas.RelationshipExecuted,
		Label:     "Executes Action",
		CreatedAt: now,
		LastSeen:  now,
	}
	if err := m.kg.AddEdge(ctx, edge); err != nil {
		return fmt.Errorf("kg.AddEdge failed for mission->action link: %w", err)
	}
	return nil
}

// Safely transitions the Mind to a new state, enforcing state machine rules.
func (m *LLMMind) updateState(newState AgentState) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Rule 1: Do not transition if the state is already the target state.
	if m.currentState == newState {
		return
	}

	// Rule 2: Terminal states (FAILED, COMPLETED) cannot be exited.
	if m.currentState == StateFailed || m.currentState == StateCompleted {
		// Log an attempt to transition out of a terminal state, but prevent it.
		m.logger.Warn("Attempted to transition out of a terminal state. Ignoring.",
			zap.String("current_state", string(m.currentState)),
			zap.String("attempted_state", string(newState)))
		return
	}

	// Transition is valid.
	m.logger.Debug("Mind state transition", zap.String("from", string(m.currentState)), zap.String("to", string(newState)))
	m.currentState = newState
}

// Assigns a new mission to the Mind and creates the initial mission node in the KG.
func (m *LLMMind) SetMission(mission Mission) {
	m.mu.Lock()
	// If the incoming mission ID is empty, we are resetting the mission.
	if mission.ID == "" {
		m.currentMission = Mission{}
		m.mu.Unlock()
		return
	}
	m.currentMission = mission
	if m.currentState == StateInitializing || m.currentState == StateObserving {
		m.currentState = StateObserving
	}
	missionID := mission.ID
	objective := mission.Objective
	m.mu.Unlock()

	m.logger.Info("New mission assigned", zap.String("mission_id", missionID), zap.String("objective", objective))

	ctx := context.Background()
	if _, err := m.kg.GetNode(ctx, missionID); err != nil {
		now := time.Now().UTC()
		propsMap := map[string]interface{}{
			"objective":  mission.Objective,
			"target_url": mission.TargetURL,
		}
		propsBytes, _ := m.marshalProperties(propsMap)

		missionNode := schemas.Node{
			ID:         missionID,
			Type:       schemas.NodeMission,
			Label:      fmt.Sprintf("Mission: %s", mission.Objective),
			Status:     schemas.StatusProcessing,
			CreatedAt:  now,
			LastSeen:   now,
			Properties: encodingjson.RawMessage(propsBytes),
		}
		if err := m.kg.AddNode(ctx, missionNode); err != nil {
			m.logger.Error("Failed to record new Mission node in KG", zap.Error(err))
			m.updateState(StateFailed)
			return
		}
	}

	m.signalStateReady()
}

// Gracefully shuts down the Mind's cognitive loops.
func (m *LLMMind) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopChan)
		m.ltm.Stop() // Gracefully stop the LTM's background processes.
	})
}
