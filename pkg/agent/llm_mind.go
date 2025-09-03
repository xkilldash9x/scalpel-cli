// -- pkg/agent/llm_mind.go --
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/graphmodel"
	"github.com/xkilldash9x/scalpel-cli/pkg/knowledgegraph"
)

// LLMMind implements the Mind interface using an LLM for orientation and decision-making.
// It operates an event-driven OODA loop.
type LLMMind struct {
	cfg   config.AgentConfig
	logger *zap.Logger
	// kg now uses the GraphStore interface.
	kg      knowledgegraph.GraphStore
	bus     *CognitiveBus
	llmClient LLMClient

	currentMission Mission
	currentState   AgentState
	mu             sync.RWMutex // Protects state and mission data.
	stopChan       chan struct{}

	// Channel to signal that new observations have been processed and the state is ready for the next decision cycle.
	stateReadyChan chan struct{}
	// Configuration for how far back to look in the KG for context.
	contextLookbackSteps int
}

// NewLLMMind creates a new LLMMind instance.
func NewLLMMLMind(logger *zap.Logger, client LLMClient) *LLMMind {
	return &LLMMind{
		logger:               logger.Named("llm_mind"),
		llmClient:            client,
		stopChan:             make(chan struct{}),
		stateReadyChan:       make(chan struct{}, 1), // Buffered channel to prevent blocking the observer.
		contextLookbackSteps: 10,                      // Default lookback
	}
}

func (m *LLMMind) Initialize(cfg config.AgentConfig, kg knowledgegraph.GraphStore, bus *CognitiveBus) error {
	m.cfg = cfg
	m.kg = kg
	m.bus = bus
	m.currentState = StateInitializing
	// If the config provided a specific lookback, it would be loaded here.
	// e.g., if cfg.ContextLookback > 0 { m.contextLookbackSteps = cfg.ContextLookback }
	m.logger.Info("LLMMind initialized", zap.String("model", cfg.LLM.Model), zap.Int("context_lookback", m.contextLookbackSteps))
	return nil
}

// Start begins the cognitive processing loop (OODA).
// This is now event-driven, reacting to state changes rather than a fixed timer.
func (m *LLMMind) Start(ctx context.Context) error {
	m.logger.Info("Starting LLMMind cognitive loops.")

	// Start the Observer loop in a separate goroutine.
	go m.runObserverLoop(ctx)

	// Start the main Decision/Action loop.
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Context cancelled, stopping cognitive loop.")
			return ctx.Err()
		case <-m.stopChan:
			m.logger.Info("Stop signal received, stopping cognitive loop.")
			return nil
		case <-m.stateReadyChan:
			// The state has been updated (Orient phase complete), proceed to Decide and Act.
			m.executeDecisionCycle(ctx)
		}
	}
}

// runObserverLoop (Observe & Orient part 1) listens for observations and integrates them into the KG.
func (m *LLMMind) runObserverLoop(ctx context.Context) {
	m.logger.Info("Observer loop started.")
	// Subscribe only to Observation messages.
	obsChan := m.bus.Subscribe(MessageTypeObservation)

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

			m.updateState(StateObserving)
			if obs, ok := msg.Payload.(Observation); ok {
				// Process the observation and update the Knowledge Graph.
				m.processObservation(obs)
			} else {
				m.logger.Error("Received invalid payload for OBSERVATION message type.")
			}

			m.bus.Acknowledge(msg)

			// Signal the main loop that the state is ready for the next cycle (Orient phase complete).
			m.signalStateReady()
		}
	}
}

// signalStateReady notifies the decision loop that the state is updated.
func (m *LLMMind) signalStateReady() {
	select {
	case m.stateReadyChan <- struct{}{}:
	default:
		// If the channel is already full, the decision loop is already aware of a pending state change.
	}
}

// executeDecisionCycle performs the Orient (part 2), Decide, and Act steps.
func (m *LLMMind) executeDecisionCycle(ctx context.Context) {
	m.mu.RLock()
	missionID := m.currentMission.ID
	currentState := m.currentState
	m.mu.RUnlock()

	// Do not process if there is no active mission or if the state is terminal.
	if missionID == "" {
		// If no mission is set, we wait passively.
		return
	}

	if currentState == StateCompleted || currentState == StateFailed || currentState == StatePaused {
		return
	}

	// 1. Orient (Gather Context from KG)
	m.updateState(StateOrienting)
	// Gather localized context relevant to the current mission.
	contextSnapshot, err := m.gatherContext(ctx, missionID)
	if err != nil {
		m.logger.Error("Failed to gather context from Knowledge Graph", zap.Error(err))
		// If context gathering fails, we return to observing state.
		m.updateState(StateObserving)
		return
	}

	// 2. Decide (Generate Next Action using LLM)
	m.updateState(StateDeciding)
	action, err := m.decideNextAction(ctx, contextSnapshot)
	if err != nil {
		m.logger.Error("Failed to decide next action", zap.Error(err))
		// TODO: Implement failure threshold logic.
		m.updateState(StateObserving)
		return
	}

	// 3. Act (Post Action to the Bus)
	m.updateState(StateActing)

	// Record the action in the KG before posting it. This ensures the action node exists
	// when the subsequent observation arrives and needs to link back to it.
	m.recordActionKG(action)

	err = m.bus.Post(ctx, CognitiveMessage{
		Type:    MessageTypeAction,
		Payload: action,
	})
	if err != nil {
		m.logger.Error("Failed to post action to CognitiveBus", zap.Error(err))
		// If posting fails, update the action status to reflect this failure.
		m.updateActionStatus(action.ID, "failed", fmt.Sprintf("Bus error: %v", err))
		m.updateState(StateObserving)
		return
	}

	// Transition back to Observing, waiting for the Agent to execute the action and generate observations.
	m.updateState(StateObserving)
}

// gatherContext extracts relevant information from the KnowledgeGraph for the LLM prompt.
// It now uses the localized subgraph extraction method.
func (m *LLMMind) gatherContext(ctx context.Context, missionID string) (*graphmodel.GraphExport, error) {
	// Use the localized extraction method instead of the full export.
	subgraph, err := m.kg.ExtractMissionSubgraph(ctx, missionID, m.contextLookbackSteps)
	if err != nil {
		return nil, fmt.Errorf("failed to extract mission subgraph: %w", err)
	}

	m.logger.Debug("Gathered localized context", zap.Int("nodes", len(subgraph.Nodes)), zap.Int("edges", len(subgraph.Edges)))
	return &subgraph, nil
}

// decideNextAction formats the prompt and calls the LLM to determine the next step.
func (m *LLMMind) decideNextAction(ctx context.Context, contextSnapshot *graphmodel.GraphExport) (Action, error) {
	systemPrompt := m.generateSystemPrompt()
	userPrompt, err := m.generateUserPrompt(contextSnapshot)
	if err != nil {
		return Action{}, err
	}

	// Timeout for the LLM API call to prevent indefinite hanging.
	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	response, err := m.llmClient.GenerateResponse(apiCtx, systemPrompt, userPrompt)
	if err != nil {
		return Action{}, fmt.Errorf("llm generation failed: %w", err)
	}

	// Parse the LLM response into a structured Action using robust parsing.
	action, err := m.parseActionResponse(response)
	if err != nil {
		return Action{}, fmt.Errorf("failed to parse llm response: %w", err)
	}

	// Enrich the action with metadata.
	action.ID = uuid.NewString()
	action.MissionID = m.currentMission.ID
	action.Timestamp = time.Now().UTC()

	return action, nil
}

// generateSystemPrompt defines the persona and rules for the LLM.
func (m *LLMMind) generateSystemPrompt() string {
	// Prompt engineering is critical.
	// The prompt establishes the agent's identity, objectives, available actions, and output format constraints.
	return `You are the Mind of 'scalpel-cli', an advanced, autonomous security analysis agent.
Your purpose is to navigate web environments and identify potential vulnerabilities.
You operate within a strict OODA loop. You receive the current localized state (Knowledge Graph) and the Mission Objective.
You must respond ONLY with a single JSON object representing the next Action to take.
Available Action Types:
Interaction:
- NAVIGATE: {"type": "NAVIGATE", "value": "<URL>", "rationale": "..."}
- CLICK: {"type": "CLICK", "selector": "<CSS_SELECTOR>", "rationale": "..."}
- INPUT_TEXT: {"type": "INPUT_TEXT", "selector": "<CSS_SELECTOR>", "value": "<TEXT/PAYLOAD>", "rationale": "..."}
- WAIT_FOR_ASYNC: {"type": "WAIT_FOR_ASYNC", "metadata": {"duration_ms": 1000}, "rationale": "..."}

Mission Control:
- CONCLUDE: {"type": "CONCLUDE", "rationale": "Mission objective achieved or unachievable."}

Rules:
1. Analyze the provided Knowledge Graph (Nodes and Edges) to understand the environment structure and history of actions/observations.
2. Prioritize actions that directly progress towards the Mission Objective.
3. If analyzing a web application, be methodical: explore forms, input fields, and dynamic content.
Use precise CSS selectors based on the graph.
4. Maintain the core identity: surgically precise and devastatingly effective.
`
}

// generateUserPrompt provides the current state and objective to the LLM.
func (m *LLMMind) generateUserPrompt(contextSnapshot *graphmodel.GraphExport) (string, error) {
	// Marshaling the localized graph snapshot provides the LLM with the necessary context.
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

// Regex to find JSON blocks wrapped in markdown (` + "```" + `json ... ` + "```" + `) or plain JSON objects ({...}).
var jsonBlockRegex = regexp.MustCompile("(?s)(?:```json\\s*|)(\\{.*\\})(?:```|)")

// parseActionResponse attempts to unmarshal the LLM's JSON response into an Action struct using robust extraction.
func (m *LLMMind) parseActionResponse(response string) (Action, error) {
	response = strings.TrimSpace(response)
	var action Action

	// 1. Attempt to find the JSON block using regex.
	matches := jsonBlockRegex.FindStringSubmatch(response)
	jsonStringToParse := ""

	if len(matches) > 1 {
		// Found a match (either markdown wrapped or plain JSON).
		jsonStringToParse = matches[1]
	} else {
		// If no regex match, try parsing the raw response as a last resort.
		jsonStringToParse = response
	}

	// 2. Attempt to unmarshal the extracted string.
	err := json.Unmarshal([]byte(jsonStringToParse), &action)
	if err != nil {
		m.logger.Warn("Failed to unmarshal LLM response", zap.String("raw_response", response), zap.String("extracted_json", jsonStringToParse), zap.Error(err))
		return Action{}, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// 3. Validate the parsed action structure.
	if action.Type == "" {
		return Action{}, fmt.Errorf("LLM response missing required 'type' field")
	}

	return action, nil
}

// processObservation integrates the observed data into the Knowledge Graph.
// (The core of the Observer role).
func (m *LLMMind) processObservation(obs Observation) {
	m.logger.Debug("Processing observation", zap.String("obs_id", obs.ID), zap.String("type", string(obs.Type)))

	// 1. Record the observation itself in the KG.
	m.recordObservationKG(obs)

	// 2. Update the status of the source action based on the observation data.
	if obs.SourceActionID != "" {
		m.updateActionStatusFromObservation(obs)
	}

	// 3. (Future Enhancement): Perform specialized processing based on ObservationType.
	// E.g., if ObservedDOMChange, parse the DOM and update KG structure.
}

// updateActionStatusFromObservation determines the action status from the observation data and updates the KG.
func (m *LLMMind) updateActionStatusFromObservation(obs Observation) {
	// CORRECTED: Use a type assertion to the strongly-typed ExecutionResult.
	result, ok := obs.Data.(*ExecutionResult)
	if !ok {
		// Data is not in expected format, cannot determine detailed status.
		m.logger.Warn("Observation data format unexpected, cannot update action status precisely.", zap.String("action_id", obs.SourceActionID), zap.Any("data_type", fmt.Sprintf("%T", obs.Data)))
		// Fallback for non-ExecutionResult data (e.g., from browser instrumentation)
		m.updateActionStatus(obs.SourceActionID, "success", "")
		return
	}

	m.updateActionStatus(obs.SourceActionID, result.Status, result.Error)
}

// updateActionStatus updates the KG node for the action.
func (m *LLMMind) updateActionStatus(actionID string, status string, errMsg string) {
	// Prepare updates for the action node.
	updates := graphmodel.Properties{
		"status": status,
	}
	if errMsg != "" {
		updates["error"] = errMsg
	}

	// Update the node in the KG using Upsert (AddNode).
	// We must specify the Type for the upsert logic to validate immutability correctly.
	_, err := m.kg.AddNode(graphmodel.NodeInput{
		ID:         actionID,
		Type:       graphmodel.NodeTypeAction,
		Properties: updates,
	})
	if err != nil {
		m.logger.Error("Failed to update Action node status in KG", zap.String("action_id", actionID), zap.Error(err))
	}
}

// recordObservationKG persists the observation in the KG.
// (Moved from Agent to Mind).
func (m *LLMMind) recordObservationKG(obs Observation) {
	props := graphmodel.Properties{
		"type":      obs.Type,
		"timestamp": obs.Timestamp,
	}
	// Store the raw data.
	// The in-memory KG handles complex types, but persistent stores might require JSON marshaling.
	props["data_raw"] = obs.Data

	_, err := m.kg.AddNode(graphmodel.NodeInput{
		ID:         obs.ID,
		Type:       graphmodel.NodeTypeObservation,
		Properties: props,
	})
	if err != nil {
		m.logger.Error("Failed to record Observation node in KG", zap.Error(err))
		return
	}

	// Link Action -> Observation
	if obs.SourceActionID != "" {
		_, err = m.kg.AddEdge(graphmodel.EdgeInput{
			SourceID:     obs.SourceActionID,
			TargetID:     obs.ID,
			Relationship: graphmodel.RelationshipTypeGeneratesObservation,
		})
		if err != nil {
			m.logger.Error("Failed to record Action->Observation edge in KG", zap.Error(err))
		}
	}

	// Link Observation -> Mission
	_, err = m.kg.AddEdge(graphmodel.EdgeInput{
		SourceID:     obs.ID,
		TargetID:     obs.MissionID,
		Relationship: graphmodel.RelationshipTypeInformsMission,
	})
	if err != nil {
		m.logger.Error("Failed to record Observation->Mission edge in KG", zap.Error(err))
	}
}

// recordActionKG persists the planned action in the KG. (Moved from Agent to Mind, called before execution).
func (m *LLMMind) recordActionKG(action Action) {
	props := graphmodel.Properties{
		"type":      action.Type,
		"rationale": action.Rationale,
		"timestamp": action.Timestamp,
		"status":    "planned", // Initial status before execution.
	}
	if action.Selector != "" {
		props["selector"] = action.Selector
	}
	if action.Value != "" {
		// Truncate long values (e.g., payloads) for storage efficiency.
		if len(action.Value) > 256 {
			props["value"] = action.Value[:256] + "..."
		} else {
			props["value"] = action.Value
		}
	}
	// Store metadata properties with a prefix for clarity.
	for k, v := range action.Metadata {
		props[fmt.Sprintf("meta_%s", k)] = fmt.Sprintf("%v", v)
	}

	_, err := m.kg.AddNode(graphmodel.NodeInput{
		ID:         action.ID,
		Type:       graphmodel.NodeTypeAction,
		Properties: props,
	})
	if err != nil {
		m.logger.Error("Failed to record Action node in KG", zap.Error(err))
		return
	}
	// Link Mission -> Action
	_, err = m.kg.AddEdge(graphmodel.EdgeInput{
		SourceID:     action.MissionID,
		TargetID:     action.ID,
		Relationship: graphmodel.RelationshipTypeExecutesAction,
	})
	if err != nil {
		m.logger.Error("Failed to record Mission->Action edge in KG", zap.Error(err))
	}
}

func (m *LLMMind) SetMission(mission Mission) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.currentMission = mission
	// Reset state to Observing when a new mission starts.
	m.currentState = StateObserving
	m.logger.Info("New mission assigned", zap.String("mission_id", mission.ID), zap.String("objective", mission.Objective))
	// Signal the decision loop to start processing the new mission immediately.
	m.signalStateReady()
}

func (m *LLMMind) updateState(newState AgentState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.currentState != newState {
		m.logger.Debug("Mind state transition", zap.String("from", string(m.currentState)), zap.String("to", string(newState)))
		m.currentState = newState
	}
}

func (m *LLMMind) Stop() {
	// Graceful shutdown signaling.
	select {
	case <-m.stopChan:
		// Already closed.
	default:
		close(m.stopChan)
	}
}
