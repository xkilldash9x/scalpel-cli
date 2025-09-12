// internal/agent/llm_mind.go
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
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph" // Import the knowledgegraph package
)

// LLMMind implements the Mind interface.
type LLMMind struct {
	cfg    config.AgentConfig
	logger *zap.Logger
	// Use the GraphStore interface from the knowledgegraph package
	kg        knowledgegraph.GraphStore
	bus       *CognitiveBus
	// Use the LLMClient interface defined in schemas
	llmClient schemas.LLMClient
	currentMission schemas.Mission
	currentState   schemas.AgentState
	mu             sync.RWMutex
	stopChan       chan struct{}
	stateReadyChan chan struct{}
	contextLookbackSteps int
}

// Statically assert that LLMMind implements the Mind interface.
var _ Mind = (*LLMMind)(nil)

// NewLLMMind creates a new LLMMind instance.
func NewLLMMind(
	logger *zap.Logger,
	client schemas.LLMClient,
	cfg config.AgentConfig,
	kg knowledgegraph.GraphStore,
	bus *CognitiveBus,
) *LLMMind {
	contextLookbackSteps := 10 // Default lookback

	m := &LLMMind{
		logger:               logger.Named("llm_mind"),
		llmClient:            client,
		cfg:                  cfg,
		kg:                   kg,
		bus:                  bus,
		currentState:         schemas.StateInitializing,
		stopChan:             make(chan struct{}),
		stateReadyChan:       make(chan struct{}, 1),
		contextLookbackSteps: contextLookbackSteps,
	}

	m.logger.Info("LLMMind initialized", zap.String("default_model", cfg.LLM.DefaultPowerfulModel), zap.Int("context_lookback", m.contextLookbackSteps))
	return m
}

// Start begins the cognitive processing loop (OODA).
func (m *LLMMind) Start(ctx context.Context) error {
	m.logger.Info("Starting LLMMind cognitive loops.")
	go m.runObserverLoop(ctx)

	if m.currentState == schemas.StateInitializing {
		m.updateState(schemas.StateObserving)
	}

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Context cancelled, stopping cognitive loop.")
			return ctx.Err()
		case <-m.stopChan:
			m.logger.Info("Stop signal received, stopping cognitive loop.")
			return nil
		case <-m.stateReadyChan:
			m.executeDecisionCycle(ctx)
		}
	}
}

// runObserverLoop listens for observations and integrates them into the KG.
func (m *LLMMind) runObserverLoop(ctx context.Context) {
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
				m.logger.Info("Observation channel closed, observer loop stopping.")
				return
			}

			// Process the observation.
			func() {
				// Acknowledge the message when processing is complete.
				defer m.bus.Acknowledge(msg)

				m.updateState(schemas.StateObserving)
				if obs, ok := msg.Payload.(schemas.Observation); ok {
					if err := m.processObservation(ctx, obs); err != nil {
						m.logger.Error("Failed to process observation", zap.Error(err))
						// Continue processing other observations rather than failing immediately.
					}
				} else {
					m.logger.Error("Received invalid payload for OBSERVATION message type.", zap.Any("payload_type", fmt.Sprintf("%T", msg.Payload)))
				}

				// Signal the decision cycle that the state is updated.
				m.signalStateReady()
			}()
		}
	}
}

// signalStateReady notifies the decision loop that the state is updated.
func (m *LLMMind) signalStateReady() {
	select {
	case m.stateReadyChan <- struct{}{}:
	default:
		// Channel is already full, loop is already pending.
	}
}

// executeDecisionCycle performs the Orient, Decide, and Act steps.
func (m *LLMMind) executeDecisionCycle(ctx context.Context) {
	m.mu.RLock()
	missionID := m.currentMission.ID
	currentState := m.currentState
	m.mu.RUnlock()

	if missionID == "" {
		return
	}
	if currentState == schemas.StateCompleted || currentState == schemas.StateFailed || currentState == schemas.StatePaused {
		return
	}

	// -- ORIENT --
	m.updateState(schemas.StateOrienting)
	contextSnapshot, err := m.gatherContext(ctx, missionID)
	if err != nil {
		m.logger.Error("Failed to gather context from Knowledge Graph", zap.Error(err))
		m.updateState(schemas.StateObserving)
		return
	}

	// -- DECIDE --
	m.updateState(schemas.StateDeciding)
	action, err := m.decideNextAction(ctx, contextSnapshot)
	if err != nil {
		m.logger.Error("Failed to decide next action", zap.Error(err))
		m.updateState(schemas.StateObserving)
		return
	}

	// Handle CONCLUDE action specifically
	if action.Type == schemas.ActionConclude {
		m.logger.Info("Mission concluded by LLM decision.", zap.String("rationale", action.Rationale))
		m.updateState(schemas.StateCompleted)
		return
	}

	// -- ACT --
	m.updateState(schemas.StateActing)
	if err := m.recordActionKG(ctx, action); err != nil {
		m.logger.Error("Critical failure: Cannot record action to Knowledge Graph.", zap.Error(err))
		m.updateState(schemas.StateFailed)
		return
	}

	err = m.bus.Post(ctx, CognitiveMessage{
		Type:    MessageTypeAction,
		Payload: action,
	})
	if err != nil {
		m.logger.Error("Failed to post action to CognitiveBus", zap.Error(err))
		if updateErr := m.updateActionStatus(ctx, action.ID, schemas.StatusFailed, fmt.Sprintf("Bus error: %v", err)); updateErr != nil {
			m.logger.Error("Failed to update the action status after bus failure", zap.Error(updateErr))
			m.updateState(schemas.StateFailed)
		} else {
			m.updateState(schemas.StateObserving)
		}
		return
	}

	m.updateState(schemas.StateObserving)
}

// gatherContext performs a depth-limited BFS graph traversal.
// Uses the pointer-based GraphStore interface.
func (m *LLMMind) gatherContext(ctx context.Context, missionID string) (*schemas.Subgraph, error) {
	type bfsItem struct {
		nodeID string
		depth  int
	}

	queue := []bfsItem{{nodeID: missionID, depth: 0}}
	visitedNodes := make(map[string]*schemas.Node)

	startNode, err := m.kg.GetNode(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission start node '%s': %w", missionID, err)
	}
	// Interface ensures startNode is not nil if err is nil, but we add a safety check.
	if startNode == nil {
		return nil, fmt.Errorf("mission start node '%s' not found (GetNode returned nil)", missionID)
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
			// Log warning but continue traversal if possible.
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

	subgraphNodes := make([]*schemas.Node, 0, len(visitedNodes))
	var subgraphEdges []*schemas.Edge

	for _, node := range visitedNodes {
		subgraphNodes = append(subgraphNodes, node)
		edges, err := m.kg.GetEdges(ctx, node.ID)
		if err != nil {
			m.logger.Warn("Failed to get edges for subgraph node", zap.String("nodeID", node.ID), zap.Error(err))
			continue
		}
		for _, edge := range edges {
			if _, destinationInSubgraph := visitedNodes[edge.To]; destinationInSubgraph {
				subgraphEdges = append(subgraphEdges, edge)
			}
		}
	}

	result := &schemas.Subgraph{
		Nodes: subgraphNodes,
		Edges: subgraphEdges,
	}
	m.logger.Debug("Gathered localized context", zap.Int("nodes", len(result.Nodes)), zap.Int("edges", len(result.Edges)))
	return result, nil
}

func (m *LLMMind) decideNextAction(ctx context.Context, contextSnapshot *schemas.Subgraph) (schemas.Action, error) {
	systemPrompt := m.generateSystemPrompt()
	userPrompt, err := m.generateUserPrompt(contextSnapshot)
	if err != nil {
		return schemas.Action{}, err
	}

	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Use the GenerationRequest defined in schemas
	req := schemas.GenerationRequest{
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Tier:         schemas.TierPowerful,
		Options: schemas.GenerationOptions{
			ForceJSONFormat: true,
			Temperature:     0.2,
		},
	}

	response, err := m.llmClient.GenerateResponse(apiCtx, req)
	if err != nil {
		return schemas.Action{}, fmt.Errorf("llm generation failed: %w", err)
	}

	action, err := m.parseActionResponse(response)
	if err != nil {
		return schemas.Action{}, fmt.Errorf("failed to parse llm response: %w", err)
	}

	action.ID = uuid.NewString()
	action.MissionID = m.currentMission.ID
	action.Timestamp = time.Now().UTC()
	return action, nil
}

func (m *LLMMind) generateSystemPrompt() string {
	// Placeholder for the actual system prompt.
	return `You are the Mind of 'scalpel-cli', an advanced, autonomous security analysis agent...`
}

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

var jsonBlockRegex = regexp.MustCompile("(?s)```(?:json)?\\s*(.*?)```")

func (m *LLMMind) parseActionResponse(response string) (schemas.Action, error) {
	response = strings.TrimSpace(response)
	var action schemas.Action

	matches := jsonBlockRegex.FindStringSubmatch(response)
	jsonStringToParse := ""

	if len(matches) > 1 {
		jsonStringToParse = matches[1]
	} else {
		jsonStringToParse = response
	}

	err := json.Unmarshal([]byte(jsonStringToParse), &action)
	if err != nil {
		m.logger.Warn("Failed to unmarshal LLM response", zap.String("raw_response", response), zap.String("extracted_json", jsonStringToParse), zap.Error(err))
		return schemas.Action{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if action.Type == "" {
		return schemas.Action{}, fmt.Errorf("LLM response missing required 'type' field")
	}
	return action, nil
}

func (m *LLMMind) processObservation(ctx context.Context, obs schemas.Observation) error {
	m.logger.Debug("Processing observation", zap.String("obs_id", obs.ID), zap.String("type", string(obs.Type)))

	if err := m.recordObservationKG(ctx, obs); err != nil {
		return fmt.Errorf("failed to record observation in KG: %w", err)
	}

	if obs.SourceActionID != "" {
		if err := m.updateActionStatusFromObservation(ctx, obs); err != nil {
			// Log error but don't fail the entire processing if status update fails.
			m.logger.Error("Failed to update action status from observation", zap.String("action_id", obs.SourceActionID), zap.Error(err))
		}
	}
	return nil
}

func (m *LLMMind) updateActionStatusFromObservation(ctx context.Context, obs schemas.Observation) error {
	var result schemas.ExecutionResult
	var ok bool

	// Robustly handle different potential types for obs.Data (interface{})
	if resPtr, asserted := obs.Data.(*schemas.ExecutionResult); asserted && resPtr != nil {
		result = *resPtr
		ok = true
	} else if obs.Data != nil {
		// Attempt conversion if it came through JSON/marshalling (e.g., map[string]interface{})
		dataBytes, err := json.Marshal(obs.Data)
		if err == nil {
			if json.Unmarshal(dataBytes, &result) == nil && result.Status != "" {
				ok = true
			}
		}
	}

	status := schemas.StatusCompleted
	errMsg := ""

	if ok {
		if result.Status == "failed" {
			status = schemas.StatusFailed
		}
		errMsg = result.Error
	} else {
		m.logger.Debug("Observation data format unexpected or missing ExecutionResult.", zap.String("action_id", obs.SourceActionID))
	}

	return m.updateActionStatus(ctx, obs.SourceActionID, status, errMsg)
}

// updateActionStatus updates the status and properties of an Action node.
// Handles the complexity of manipulating json.RawMessage properties.
func (m *LLMMind) updateActionStatus(ctx context.Context, actionID string, status schemas.NodeStatus, errMsg string) error {
	node, err := m.kg.GetNode(ctx, actionID)
	if err != nil {
		return fmt.Errorf("kg.GetNode failed for action status update: %w", err)
	}

	// Update basic fields
	node.Status = status
	node.LastSeen = time.Now().UTC()

	// Update Properties (json.RawMessage)
	propsMap := make(map[string]interface{})

	// Unmarshal existing properties if they exist and are valid JSON.
	if len(node.Properties) > 0 && !strings.EqualFold(string(node.Properties), "null") {
		if err := json.Unmarshal(node.Properties, &propsMap); err != nil {
			// If unmarshalling fails, log it and proceed by overwriting properties.
			m.logger.Warn("Failed to unmarshal existing properties, overwriting.", zap.Error(err))
			propsMap = make(map[string]interface{})
		}
	}

	if errMsg != "" {
		propsMap["error"] = errMsg
	}
	// Update status in properties as well for easier querying.
	propsMap["status"] = string(status)

	updatedProps, err := json.Marshal(propsMap)
	if err != nil {
		return fmt.Errorf("failed to marshal updated properties: %w", err)
	}
	node.Properties = updatedProps

	// Save the updated node (Upsert)
	if err := m.kg.AddNode(ctx, node); err != nil {
		return fmt.Errorf("kg.AddNode failed for action status update: %w", err)
	}
	return nil
}

// marshalProperties converts a map to json.RawMessage for storage in the KG.
func (m *LLMMind) marshalProperties(propsMap map[string]interface{}) (json.RawMessage, error) {
	propsBytes, err := json.Marshal(propsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal properties: %w", err)
	}
	return propsBytes, nil
}

// recordObservationKG records an Observation node and its links in the KG.
func (m *LLMMind) recordObservationKG(ctx context.Context, obs schemas.Observation) error {
	now := time.Now().UTC()

	propsMap := map[string]interface{}{
		"type":      string(obs.Type),
		"timestamp": obs.Timestamp,
		"data_raw":  obs.Data,
	}
	propsBytes, err := m.marshalProperties(propsMap)
	if err != nil {
		return err
	}

	obsNode := &schemas.Node{
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

	// Link Action -> Observation
	if obs.SourceActionID != "" {
		actionEdge := &schemas.Edge{
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

	// Link Observation -> Mission
	missionEdge := &schemas.Edge{
		ID:        uuid.NewString(),
		From:      obs.ID,
		To:        obs.MissionID,
		Type:      schemas.RelationshipInforms,
		Label:     "Informs Mission",
		CreatedAt: now,
		LastSeen:  now,
	}
	if err := m.kg.AddEdge(ctx, missionEdge); err != nil {
		m.logger.Error("Failed to record Observation->Mission edge in KG", zap.Error(err))
	}
	return nil
}

// recordActionKG records a planned Action node and its link to the Mission in the KG.
func (m *LLMMind) recordActionKG(ctx context.Context, action schemas.Action) error {
	now := time.Now().UTC()

	propsMap := map[string]interface{}{
		"type":      string(action.Type),
		"rationale": action.Rationale,
		"timestamp": action.Timestamp,
		"status":    string(schemas.StatusPlanned),
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
		propsMap[fmt.Sprintf("meta_%s", k)] = fmt.Sprintf("%v", v)
	}

	propsBytes, err := m.marshalProperties(propsMap)
	if err != nil {
		return err
	}

	actionNode := &schemas.Node{
		ID:         action.ID,
		Type:       schemas.NodeAction,
		Label:      fmt.Sprintf("Action: %s", action.Type),
		Status:     schemas.StatusPlanned,
		CreatedAt:  now,
		LastSeen:   now,
		Properties: propsBytes,
	}

	if err := m.kg.AddNode(ctx, actionNode); err != nil {
		return fmt.Errorf("kg.AddNode failed for action: %w", err)
	}

	// Link Mission -> Action
	edge := &schemas.Edge{
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

func (m *LLMMind) SetMission(mission schemas.Mission) {
	m.mu.Lock()
	m.currentMission = mission
	// Ensure state transitions correctly when a mission is set.
	if m.currentState == schemas.StateInitializing || m.currentState == schemas.StateObserving {
		m.currentState = schemas.StateObserving
	}
	missionID := mission.ID
	objective := mission.Objective
	m.mu.Unlock()

	m.logger.Info("New mission assigned", zap.String("mission_id", missionID), zap.String("objective", objective))

	// Ensure the mission node exists in the KG.
	ctx := context.Background()
	if _, err := m.kg.GetNode(ctx, missionID); err != nil {
		// Node not found (or error), try to record it.
		now := time.Now().UTC()
		propsMap := map[string]interface{}{
			"objective":  mission.Objective,
			"target_url": mission.TargetURL,
		}
		propsBytes, _ := m.marshalProperties(propsMap)
		
		missionNode := &schemas.Node{
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
			m.updateState(schemas.StateFailed)
			return
		}
	}
	
	m.signalStateReady()
}

func (m *LLMMind) updateState(newState schemas.AgentState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentState != newState {
		m.logger.Debug("Mind state transition", zap.String("from", string(m.currentState)), zap.String("to", string(newState)))
		m.currentState = newState
	}
}

func (m *LLMMind) Stop() {
	select {
	case <-m.stopChan:
		// Already closed.
	default:
		close(m.stopChan)
	}
}