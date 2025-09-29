// File: internal/agent/llm_mind.go
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// LLMMind implements the Mind interface using a Large Language Model for decision making.
// It operates on an OODA (Observe, Orient, Decide, Act) loop, interacting with other
// agent components via the CognitiveBus and using a Knowledge Graph for memory.
type LLMMind struct {
	cfg                  config.AgentConfig
	logger               *zap.Logger
	kg                   GraphStore
	bus                  *CognitiveBus
	llmClient            schemas.LLMClient
	currentMission       Mission
	currentState         AgentState
	mu                   sync.RWMutex
	wg                   sync.WaitGroup
	stopChan             chan struct{}
	stateReadyChan       chan struct{}
	contextLookbackSteps int
}

// Statically assert that LLMMind implements the Mind interface.
var _ Mind = (*LLMMind)(nil)

// Creates a new LLMMind instance.
func NewLLMMind(
	logger *zap.Logger,
	client schemas.LLMClient,
	cfg config.AgentConfig,
	kg GraphStore,
	bus *CognitiveBus,
) *LLMMind {
	contextLookbackSteps := 10 // Default lookback

	m := &LLMMind{
		logger:               logger.Named("llm_mind"),
		llmClient:            client,
		cfg:                  cfg,
		kg:                   kg,
		bus:                  bus,
		currentState:         StateInitializing,
		stopChan:             make(chan struct{}),
		stateReadyChan:       make(chan struct{}, 1),
		contextLookbackSteps: contextLookbackSteps,
	}

	m.logger.Info("LLMMind initialized", zap.String("default_model", cfg.LLM.DefaultPowerfulModel), zap.Int("context_lookback", m.contextLookbackSteps))
	return m
}

// Begins the cognitive processing loop (OODA).
func (m *LLMMind) Start(ctx context.Context) error {
	m.logger.Info("Starting LLMMind cognitive loops.")

	m.wg.Add(1)
	go m.runObserverLoop(ctx)

	if m.currentState == StateInitializing {
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
			m.executeDecisionCycle(ctx)
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

	if action.Type == ActionConclude {
		m.logger.Info("Mission concluded by LLM decision.", zap.String("rationale", action.Rationale))
		m.updateState(StateCompleted)
	}

	// -- ACT --
	if m.currentState != StateCompleted {
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
			Status:    "failed",
			ErrorCode: "BUS_POST_FAILURE",
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

	action.ID = uuid.NewString()
	action.MissionID = m.currentMission.ID
	action.Timestamp = time.Now().UTC()
	return action, nil
}

// -- REFACTORING NOTE --
// The system prompt is the core instruction set for the agent's brain.
// This version is updated with the new HUMANOID_DRAG_AND_DROP action and,
// most importantly, explicit instructions for error handling strategies.
// This teaches the agent how to recover from common failures.
func (m *LLMMind) generateSystemPrompt() string {
	return `You are the Mind of 'scalpel-cli', an advanced, autonomous security analysis agent. Your goal is to achieve the Mission Objective by exploring a web application, analyzing its components, and identifying vulnerabilities.
You operate in a continuous OODA loop. You receive the state as a JSON Knowledge Graph snapshot and must respond with a single JSON object for the next action.

Available Action Types:

1. Basic Browser Interaction (Executed realistically via Humanoid):
- NAVIGATE: Go to a specific URL. (Params: value)
- CLICK: Click on an element. (Params: selector)
- INPUT_TEXT: Type text into a field. (Params: selector, value)
- SUBMIT_FORM: Submit a form. (Params: selector)
- SCROLL: Scroll the page. (Params: value="up" or "down")
- WAIT_FOR_ASYNC: Pause execution. (Params: metadata={"duration_ms": 1500})

2. Advanced/Complex Interaction:
- HUMANOID_DRAG_AND_DROP: Move an element from one location to another.
  Use 'selector' for the element to drag, and 'metadata.target_selector' for the drop target.
  Example: {"type": "HUMANOID_DRAG_AND_DROP", "selector": "#item-1", "metadata": {"target_selector": "#cart"}, "rationale": "Testing cart functionality."}
- PERFORM_COMPLEX_TASK: Instruct the agent to perform a high level action (e.g., 'LOGIN'). Use sparingly.

3. Analysis & System:
- GATHER_CODEBASE_CONTEXT: Read source code for a module. (Params: value="module_path")
- CONCLUDE: Finish the mission.

**Crucial Error Handling Instructions**:
Analyze the "error_code" (in the KG node properties) if a previous action failed (status="ERROR").

- ELEMENT_NOT_FOUND: The selector was incorrect or the element does not exist. Strategy: Try a different selector or navigate elsewhere.
- HUMANOID_GEOMETRY_INVALID: The element exists but has zero size or invalid structure. Strategy: Try interacting with a parent element or skip this target.
- HUMANOID_TARGET_NOT_VISIBLE: The element exists but is obscured or off-screen.
  -> Strategy: You MUST use SCROLL or interact with other UI elements (like closing a modal) to make it visible BEFORE retrying the interaction.
- TIMEOUT_ERROR: The operation took too long. Strategy: Consider using WAIT_FOR_ASYNC before retrying.
- NAVIGATION_ERROR: The URL could not be reached. Strategy: Verify the URL or navigate back.

Analyze the provided state and objective, then decide your next move. Your response must be only the JSON for your chosen action.`
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
		lastBracket := strings.LastIndex(response, "}")
		if firstBracket != -1 && lastBracket != -1 && lastBracket > firstBracket {
			jsonStringToParse = response[firstBracket : lastBracket+1]
		} else {
			jsonStringToParse = response
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

	if err := m.recordObservationKG(ctx, obs); err != nil {
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
	if obs.Data == nil {
		m.logger.Debug("Observation data for codebase context is nil, skipping orientation.", zap.String("obs_id", obs.ID))
		return nil
	}

	var codeContext string
	if strData, ok := obs.Data.(string); ok {
		codeContext = strData
	} else {
		dataBytes, err := json.Marshal(obs.Data)
		if err != nil {
			m.logger.Warn("Failed to marshal non-string observation data for codebase context.", zap.Error(err))
			return nil
		}
		codeContext = string(dataBytes)
	}

	if codeContext == "" || codeContext == "null" {
		m.logger.Debug("Observation data for codebase context is empty, skipping orientation.", zap.String("obs_id", obs.ID))
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
			Properties: json.RawMessage(fmt.Sprintf(`{"source": "%s"}`, sourceObservationID)),
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
				Properties: json.RawMessage(fmt.Sprintf(`{"source": "%s"}`, sourceObservationID)),
			}
			if err := m.kg.AddNode(ctx, depNode); err != nil {
				lastErr = err
				m.logger.Warn("Failed to add dependency file node to KG", zap.String("file", depFile), zap.Error(err))
				continue
			}

			edge := schemas.Edge{
				ID:         uuid.NewString(),
				From:       sourceFile,
				To:         depFile,
				Type:       schemas.RelationshipImports, // Use standardized constant.
				Label:      "Imports",
				Properties: json.RawMessage(fmt.Sprintf(`{"source_obs_id": "%s"}`, sourceObservationID)),
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
	node.Properties = updatedProps

	if err := m.kg.AddNode(ctx, node); err != nil {
		return fmt.Errorf("kg.AddNode failed for action status update: %w", err)
	}
	return nil
}

// Converts a map to json.RawMessage.
func (m *LLMMind) marshalProperties(propsMap map[string]interface{}) (json.RawMessage, error) {
	propsBytes, err := json.Marshal(propsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal properties: %w", err)
	}
	return propsBytes, nil
}

// Creates a new node and edge in the KG for an observation.
func (m *LLMMind) recordObservationKG(ctx context.Context, obs Observation) error {
	now := time.Now().UTC()

	propsMap := map[string]interface{}{
		"type":               string(obs.Type),
		"timestamp":          obs.Timestamp,
		"data_raw":           obs.Data,
		"exec_status":        obs.Result.Status,
		"exec_error_code":    obs.Result.ErrorCode,
		"exec_error_details": obs.Result.ErrorDetails,
	}
	propsBytes, err := m.marshalProperties(propsMap)
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
		Properties: propsBytes,
	}
	if err := m.kg.AddNode(ctx, obsNode); err != nil {
		return fmt.Errorf("kg.AddNode failed for observation: %w", err)
	}

	if obs.SourceActionID != "" {
		actionEdge := schemas.Edge{
			ID:        uuid.NewString(),
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
			runes := []rune(action.Value)
			propsMap["value"] = string(runes[:maxLen]) + "..."
		} else {
			propsMap["value"] = action.Value
		}
	}
	for k, v := range action.Metadata {
		propsMap[fmt.Sprintf("meta_%s", k)] = v
	}

	propsBytes, err := m.marshalProperties(propsMap)
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
		Properties: propsBytes,
	}
	if err := m.kg.AddNode(ctx, actionNode); err != nil {
		return fmt.Errorf("kg.AddNode failed for action: %w", err)
	}

	edge := schemas.Edge{
		ID:        uuid.NewString(),
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

// Assigns a new mission to the Mind and creates the initial mission node in the KG.
func (m *LLMMind) SetMission(mission Mission) {
	m.mu.Lock()
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
			Properties: propsBytes,
		}
		if err := m.kg.AddNode(ctx, missionNode); err != nil {
			m.logger.Error("Failed to record new Mission node in KG", zap.Error(err))
			m.updateState(StateFailed)
			return
		}
	}

	m.signalStateReady()
}

// Safely transitions the Mind to a new state.
func (m *LLMMind) updateState(newState AgentState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentState != newState {
		m.logger.Debug("Mind state transition", zap.String("from", string(m.currentState)), zap.String("to", string(newState)))
		m.currentState = newState
	}
}

// Gracefully shuts down the Mind's cognitive loops.
func (m *LLMMind) Stop() {
	select {
	case <-m.stopChan:
	default:
		close(m.stopChan)
	}
}
