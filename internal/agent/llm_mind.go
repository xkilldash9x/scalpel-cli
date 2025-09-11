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
)

// NOTE: These types are used throughout this file. Ensure they are correctly defined
// in your `schemas` package to match this usage. I've consolidated the fields
// from your original schema and the usage in this file.

// -- Expected Struct Definitions (in `api/schemas`) --

/*
// In `api/schemas/agent.go`
type Action struct {
	ID        string                 `json:"id,omitempty"`
	MissionID string                 `json:"mission_id,omitempty"`
	Timestamp time.Time              `json:"timestamp,omitempty"`
	Type      string                 `json:"type"`
	Selector  string                 `json:"selector,omitempty"`
	Value     string                 `json:"value,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Rationale string                 `json:"rationale"`
}

type AgentState string

const (
	StateInitializing AgentState = "INITIALIZING"
	StateObserving    AgentState = "OBSERVING"
	StateOrienting    AgentState = "ORIENTING"
	StateDeciding     AgentState = "DECIDING"
	StateActing       AgentState = "ACTING"
	StateCompleted    AgentState = "COMPLETED"
	StatePaused       AgentState = "PAUSED"
	StateFailed       AgentState = "FAILED"
)

type Mission struct {
	ID        string
	Objective string
	TargetURL string
}

type Observation struct {
    ID             string
    MissionID      string
    SourceActionID string
    Timestamp      time.Time
    Type           string
    Data           interface{}
}

type ExecutionResult struct {
    Status string // e.g., "success", "failure"
    Error  string
}
*/

// LLMMind implements the Mind interface using an LLM for orientation and decision-making.
// It operates an event-driven OODA loop.
type LLMMind struct {
	cfg                  config.AgentConfig
	logger               *zap.Logger
	kg                   interfaces.KnowledgeGraph // Use the central interface
	bus                  *CognitiveBus
	llmClient            interfaces.LLMClient
	currentMission       schemas.Mission
	currentState         schemas.AgentState
	mu                   sync.RWMex
	stopChan             chan struct{}
	stateReadyChan       chan struct{}
	contextLookbackSteps int
}

// NewLLMMind creates a new, fully initialized LLMMind instance.
func NewLLMMind(
	logger *zap.Logger,
	client interfaces.LLMClient,
	cfg config.AgentConfig,
	kg interfaces.KnowledgeGraph, // Use the central interface
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

	m.logger.Info("LLMMind initialized", zap.String("model", cfg.LLM.Model), zap.Int("context_lookback", m.contextLookbackSteps))
	return m
}

// Start begins the cognitive processing loop (OODA).
func (m *LLMMind) Start(ctx context.Context) error {
	m.logger.Info("Starting LLMMind cognitive loops.")
	go m.runObserverLoop(ctx)

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

			// CORRECTED: Acknowledge the message at the end of the iteration.
			// Using 'defer' here is a bug as it would only run when the function exits.
			func() {
				m.updateState(schemas.StateObserving)
				if obs, ok := msg.Payload.(schemas.Observation); ok {
					if err := m.processObservation(obs); err != nil {
						m.logger.Error("Failed to process observation, agent state may be inconsistent", zap.Error(err))
						m.updateState(schemas.StateFailed)
					}
				} else {
					m.logger.Error("Received invalid payload for OBSERVATION message type.")
				}

				m.signalStateReady()
				m.bus.Acknowledge(msg) // Acknowledge after processing is complete.
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

// executeDecisionCycle performs the Orient (part 2), Decide, and Act steps.
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

	m.updateState(schemas.StateOrienting)
	contextSnapshot, err := m.gatherContext(ctx, missionID)
	if err != nil {
		m.logger.Error("Failed to gather context from Knowledge Graph", zap.Error(err))
		m.updateState(schemas.StateObserving)
		return
	}

	m.updateState(schemas.StateDeciding)
	action, err := m.decideNextAction(ctx, contextSnapshot)
	if err != nil {
		m.logger.Error("Failed to decide next action", zap.Error(err))
		m.updateState(schemas.StateObserving)
		return
	}

	m.updateState(schemas.StateActing)
	if err := m.recordActionKG(action); err != nil {
		m.logger.Error("Critical failure: Cannot record action to Knowledge Graph. Aborting action.", zap.Error(err))
		m.updateState(schemas.StateFailed)
		return
	}

	err = m.bus.Post(ctx, CognitiveMessage{
		Type:    MessageTypeAction,
		Payload: action,
	})
	if err != nil {
		m.logger.Error("Failed to post action to CognitiveBus", zap.Error(err))
		if updateErr := m.updateActionStatus(action.ID, "failed", fmt.Sprintf("Bus error: %v", err)); updateErr != nil {
			m.logger.Error("Failed to even update the action status after bus failure", zap.Error(updateErr))
			m.updateState(schemas.StateFailed)
		} else {
			m.updateState(schemas.StateObserving)
		}
		return
	}

	m.updateState(schemas.StateObserving)
}

// CORRECTED: This is the new BFS-based implementation.
// gatherContext performs a depth-limited graph traversal from a starting mission node.
func (m *LLMMind) gatherContext(ctx context.Context, missionID string) (*schemas.Subgraph, error) {
	// Helper struct for the BFS queue.
	type bfsItem struct {
		nodeID string
		depth  int
	}

	queue := []bfsItem{{nodeID: missionID, depth: 0}}
	visitedNodes := make(map[string]*schemas.Node)

	startNode, err := m.kg.GetNode(missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission start node '%s': %w", missionID, err)
	}
	if startNode == nil {
		return nil, fmt.Errorf("mission start node '%s' not found in knowledge graph", missionID)
	}
	visitedNodes[missionID] = startNode

	for len(queue) > 0 {
		currentItem := queue[0]
		queue = queue[1:]

		if currentItem.depth >= m.contextLookbackSteps {
			continue
		}

		neighbors, err := m.kg.GetNeighbors(currentItem.nodeID)
		if err != nil {
			return nil, fmt.Errorf("failed to get neighbors for node '%s': %w", currentItem.nodeID, err)
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
		edges, err := m.kg.GetEdges(node.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get edges for subgraph node '%s': %w", node.ID, err)
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

// CORRECTED: Signature updated to use schemas.Subgraph.
func (m *LLMMind) decideNextAction(ctx context.Context, contextSnapshot *schemas.Subgraph) (schemas.Action, error) {
	systemPrompt := m.generateSystemPrompt()
	userPrompt, err := m.generateUserPrompt(contextSnapshot)
	if err != nil {
		return schemas.Action{}, err
	}

	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req := interfaces.GenerationRequest{
		SystemPrompt: systemPrompt,
		UserPrompt:   userPrompt,
		Options: interfaces.GenerationOptions{
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
	// This prompt is well-defined, no changes needed.
	return `You are the Mind of 'scalpel-cli', an advanced, autonomous security analysis agent...` // Unchanged
}

// CORRECTED: Signature updated to use schemas.Subgraph.
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
	// This function is well-defined, no changes needed.
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

func (m *LLMMind) processObservation(obs schemas.Observation) error {
	m.logger.Debug("Processing observation", zap.String("obs_id", obs.ID), zap.String("type", string(obs.Type)))

	if err := m.recordObservationKG(obs); err != nil {
		return fmt.Errorf("failed to record observation in KG: %w", err)
	}

	if obs.SourceActionID != "" {
		if err := m.updateActionStatusFromObservation(obs); err != nil {
			return fmt.Errorf("failed to update action status from observation: %w", err)
		}
	}
	return nil
}

func (m *LLMMind) updateActionStatusFromObservation(obs schemas.Observation) error {
	result, ok := obs.Data.(*schemas.ExecutionResult)
	if !ok {
		m.logger.Warn("Observation data format unexpected, cannot update action status precisely.", zap.String("action_id", obs.SourceActionID), zap.Any("data_type", fmt.Sprintf("%T", obs.Data)))
		return m.updateActionStatus(obs.SourceActionID, "success", "")
	}
	return m.updateActionStatus(obs.SourceActionID, result.Status, result.Error)
}

// CORRECTED: Rewritten to use schemas.Node instead of graphmodel.
func (m *LLMMind) updateActionStatus(actionID string, status string, errMsg string) error {
	node, err := m.kg.GetNode(actionID)
	if err != nil || node == nil {
		m.logger.Error("Failed to find Action node to update status", zap.String("action_id", actionID), zap.Error(err))
		return fmt.Errorf("kg.GetNode failed for action status update: %w", err)
	}

	node.Status = status
	node.LastSeen = time.Now().UTC()
	if node.Properties == nil {
		node.Properties = make(map[string]interface{})
	}
	if errMsg != "" {
		node.Properties["error"] = errMsg
	}

	if err := m.kg.AddNode(node); err != nil { // AddNode should handle updates (upsert)
		m.logger.Error("Failed to update Action node status in KG", zap.String("action_id", actionID), zap.Error(err))
		return fmt.Errorf("kg.AddNode failed for action status update: %w", err)
	}
	return nil
}

// CORRECTED: Rewritten to use schemas.Node and schemas.Edge.
func (m *LLMMind) recordObservationKG(obs schemas.Observation) error {
	now := time.Now().UTC()
	obsNode := &schemas.Node{
		ID:        obs.ID,
		Type:      "Observation",
		Label:     fmt.Sprintf("Observation: %s", obs.Type),
		Status:    "recorded",
		CreatedAt: now,
		LastSeen:  now,
		Properties: map[string]interface{}{
			"type":      obs.Type,
			"timestamp": obs.Timestamp,
			"data_raw":  obs.Data,
		},
	}

	if err := m.kg.AddNode(obsNode); err != nil {
		m.logger.Error("Failed to record Observation node in KG", zap.Error(err))
		return fmt.Errorf("kg.AddNode failed for observation: %w", err)
	}

	if obs.SourceActionID != "" {
		edge := &schemas.Edge{
			ID:        uuid.NewString(),
			From:      obs.SourceActionID,
			To:        obs.ID,
			Type:      "GENERATES",
			Label:     "Generates Observation",
			CreatedAt: now,
			LastSeen:  now,
		}
		if err := m.kg.AddEdge(edge); err != nil {
			m.logger.Error("Failed to record Action->Observation edge in KG", zap.Error(err))
			return fmt.Errorf("kg.AddEdge failed for action->observation link: %w", err)
		}
	}

	missionEdge := &schemas.Edge{
		ID:        uuid.NewString(),
		From:      obs.ID,
		To:        obs.MissionID,
		Type:      "INFORMS",
		Label:     "Informs Mission",
		CreatedAt: now,
		LastSeen:  now,
	}
	if err := m.kg.AddEdge(missionEdge); err != nil {
		m.logger.Error("Failed to record Observation->Mission edge in KG", zap.Error(err))
		return fmt.Errorf("kg.AddEdge failed for observation->mission link: %w", err)
	}
	return nil
}

// CORRECTED: Rewritten to use schemas.Node and schemas.Edge.
func (m *LLMMind) recordActionKG(action schemas.Action) error {
	now := time.Now().UTC()
	props := map[string]interface{}{
		"type":      action.Type,
		"rationale": action.Rationale,
		"timestamp": action.Timestamp,
		"status":    "planned",
	}
	if action.Selector != "" {
		props["selector"] = action.Selector
	}
	if action.Value != "" {
		const maxLen = 256
		if utf8.RuneCountInString(action.Value) > maxLen {
			runes := []rune(action.Value)
			props["value"] = string(runes[:maxLen]) + "..."
		} else {
			props["value"] = action.Value
		}
	}
	for k, v := range action.Metadata {
		props[fmt.Sprintf("meta_%s", k)] = fmt.Sprintf("%v", v)
	}

	actionNode := &schemas.Node{
		ID:         action.ID,
		Type:       "Action",
		Label:      fmt.Sprintf("Action: %s", action.Type),
		Status:     "planned",
		CreatedAt:  now,
		LastSeen:   now,
		Properties: props,
	}

	if err := m.kg.AddNode(actionNode); err != nil {
		m.logger.Error("Failed to record Action node in KG", zap.Error(err))
		return fmt.Errorf("kg.AddNode failed for action: %w", err)
	}

	edge := &schemas.Edge{
		ID:        uuid.NewString(),
		From:      action.MissionID,
		To:        action.ID,
		Type:      "EXECUTES",
		Label:     "Executes Action",
		CreatedAt: now,
		LastSeen:  now,
	}
	if err := m.kg.AddEdge(edge); err != nil {
		m.logger.Error("Failed to record Mission->Action edge in KG", zap.Error(err))
		return fmt.Errorf("kg.AddEdge failed for mission->action link: %w", err)
	}
	return nil
}

func (m *LLMMind) SetMission(mission schemas.Mission) {
	m.mu.Lock()
	m.currentMission = mission
	m.currentState = schemas.StateObserving
	missionID := mission.ID
	objective := mission.Objective
	m.mu.Unlock()

	m.logger.Info("New mission assigned", zap.String("mission_id", missionID), zap.String("objective", objective))
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