package agent
/* WARNING: This file contains a quirk that WILL prevent it from being able to be parsed correctly in a markdown env.
Specifically, the 'jsonBlockRegex' variable declaration can cause issues.
To sidestep this, you may need to handle that line separately from the rest of the file. Or not,
do whatever you think is best, I'm not your dad. **/
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
    "github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
)

// LLMMind implements the Mind interface.
type LLMMind struct {
    cfg                  config.AgentConfig
    logger               *zap.Logger
    kg                   knowledgegraph.GraphStore
    bus                  *CognitiveBus
    llmClient            schemas.LLMClient
    currentMission       Mission
    currentState         AgentState
    mu                   sync.RWMutex
    stopChan             chan struct{}
    stateReadyChan       chan struct{}
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
        currentState:         StateInitializing,
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

    if m.currentState == StateInitializing {
        m.updateState(StateObserving)
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

                m.updateState(StateObserving)
                if obs, ok := msg.Payload.(Observation); ok {
                    if err := m.processObservation(ctx, obs); err != nil {
                        m.logger.Error("Failed to process observation", zap.Error(err))
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
        // Channel is already full, loop is already pending. Actually..Come to think of it, what year did you say your mom graduated college?
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
    if currentState == StateCompleted || currentState == StateFailed || currentState == StatePaused {
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

    // Handle CONCLUDE action specifically
    if action.Type == ActionConclude {
        m.logger.Info("Mission concluded by LLM decision.", zap.String("rationale", action.Rationale))
        m.updateState(StateCompleted)
        return
    }

    // -- ACT --
    m.updateState(StateActing)
    if err := m.recordActionKG(ctx, action); err != nil {
        m.logger.Error("Critical failure: Cannot record action to Knowledge Graph.", zap.Error(err))
        m.updateState(StateFailed)
        return
    }

    err = m.bus.Post(ctx, CognitiveMessage{
        Type:    MessageTypeAction,
        Payload: action,
    })
    if err != nil {
        m.logger.Error("Failed to post action to CognitiveBus", zap.Error(err))
        if updateErr := m.updateActionStatus(ctx, action.ID, schemas.StatusError, fmt.Sprintf("Bus error: %v", err)); updateErr != nil {
            m.logger.Error("Failed to update the action status after bus failure", zap.Error(updateErr))
            m.updateState(StateFailed)
        } else {
            m.updateState(StateObserving)
        }
        return
    }

    m.updateState(StateObserving)
}

// gatherContext performs a depth-limited BFS graph traversal.
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
        Options: schemas.GenerationOptions{
            ForceJSONFormat: true,
            Temperature:     0.2,
        },
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

func (m *LLMMind) generateSystemPrompt() string {
    return `You are the Mind of 'scalpel-cli', an advanced, autonomous security analysis agent. Your goal is to achieve the Mission Objective by exploring a web application, analyzing its components, and identifying vulnerabilities.

You operate in a continuous OODA loop (Observe, Orient, Decide, Act).
- You receive the current state as a JSON snapshot from a Knowledge Graph.
- You must decide the single best next action to take and respond with a single JSON object for that action.

Available Action Types:
- NAVIGATE: Go to a specific URL.
- CLICK: Click on an element specified by a CSS selector.
- INPUT_TEXT: Type text into a field.
- SUBMIT_FORM: Submit a form.
- CONCLUDE: Finish the mission successfully.

**NEW CAPABILITY: Codebase Research**
If you are confused, lack context about how a feature works, or need to understand the underlying logic of a module, you can use the 'GATHER_CODEBASE_CONTEXT' action.
- This action reads the source code for a specified module and adds it to your knowledge graph.
- Use this when you need deeper insight before proceeding with other actions.
- Example: { "type": "GATHER_CODEBASE_CONTEXT", "metadata": { "module_path": "internal/reporting" }, "rationale": "I need to understand the reporting module's structure to test it effectively." }

Analyze the provided state and objective, then decide your next move. Your response must be only the JSON for your chosen action.`
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

// A regex to robustly extract a JSON object from a markdown code block.
var jsonBlockRegex = regexp.MustCompile(fmt.Sprintf("(?s)%s(?:json)?\\s*(.*?)\\s*%s", "```", "```"))

// parseActionResponse robustly extracts a JSON object from the LLM's response.
func (m *LLMMind) parseActionResponse(response string) (Action, error) {
    response = strings.TrimSpace(response)
    var action Action
    var jsonStringToParse string

    // 1. Try to extract from a markdown code block first. This is the most reliable method.
    matches := jsonBlockRegex.FindStringSubmatch(response)
    if len(matches) > 1 {
        jsonStringToParse = strings.TrimSpace(matches[1])
    } else {
        // 2. Fallback: Find the first '{' and last '}' if no markdown block is found.
        // This handles cases where the LLM returns raw JSON with conversational text.
        firstBracket := strings.Index(response, "{")
        lastBracket := strings.LastIndex(response, "}")
        if firstBracket != -1 && lastBracket != -1 && lastBracket > firstBracket {
            jsonStringToParse = response[firstBracket : lastBracket+1]
        } else {
            // 3. Last resort: Assume the whole thing is JSON.
            jsonStringToParse = response
        }
    }

    if jsonStringToParse == "" {
        return Action{}, fmt.Errorf("could not find any JSON in the LLM response")
    }

    // 4. Unmarshal the extracted JSON string.
    err := json.Unmarshal([]byte(jsonStringToParse), &action)
    if err != nil {
        m.logger.Warn("Failed to unmarshal LLM response",
            zap.String("raw_response", response),
            zap.String("extracted_json", jsonStringToParse),
            zap.Error(err))
        return Action{}, fmt.Errorf("failed to unmarshal extracted JSON: %w", err)
    }

    // 5. Final validation.
    if action.Type == "" {
        return Action{}, fmt.Errorf("LLM response missing required 'type' field after successful JSON parsing")
    }
    return action, nil
}

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

// orientOnObservation digests observations, extracts entities, and enriches the knowledge graph.
func (m *LLMMind) orientOnObservation(ctx context.Context, obs Observation) error {
    if obs.Type != ObservedCodebaseContext {
        return nil
    }

    codeContext, ok := obs.Data.(string)
    if !ok || codeContext == "" {
        return fmt.Errorf("observation data for codebase context is not a valid string")
    }

    m.logger.Info("Orienting on new codebase context via LLM analysis.", zap.String("obs_id", obs.ID))

    type ExtractedEntities struct {
        Functions   []string `json:"functions"`
        DataStructs []string `json:"data_structs"`
        APIRoutes   []string `json:"api_routes"`
    }

    systemPrompt := "You are a code analysis expert. Analyze the provided source code and extract key entities. Respond ONLY with a single JSON object containing the extracted entities."
    userPrompt := fmt.Sprintf(`Analyze the following Go source code context. Extract function names, data structure (struct) names, and any defined API routes.

Code Context:
--
%s
--

Respond with a JSON object with the keys "functions", "data_structs", and "api_routes".`, codeContext)

    req := schemas.GenerationRequest{
        SystemPrompt: systemPrompt,
        UserPrompt:   userPrompt,
        Tier:         schemas.TierFast,
        Options:      schemas.GenerationOptions{ForceJSONFormat: true, Temperature: 0.0},
    }

    apiCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
    defer cancel()

    response, err := m.llmClient.Generate(apiCtx, req)
    if err != nil {
        return fmt.Errorf("LLM entity extraction failed: %w", err)
    }

    var entities ExtractedEntities
    if err := json.Unmarshal([]byte(response), &entities); err != nil {
        return fmt.Errorf("failed to unmarshal extracted entities from LLM response: %w", err)
    }

    return m.addEntitiesToKG(ctx, obs.ID, entities)
}

// addEntitiesToKG adds the newly extracted entities as nodes to the KG.
func (m *LLMMind) addEntitiesToKG(ctx context.Context, sourceObservationID string, entities ExtractedEntities) error {
    now := time.Now().UTC()
    var lastErr error

    for _, funcName := range entities.Functions {
        node := schemas.Node{
            ID:         uuid.NewString(),
            Type:       "Function",
            Label:      funcName,
            Status:     schemas.StatusNew,
            CreatedAt:  now,
            LastSeen:   now,
            Properties: nil,
        }
        if err := m.kg.AddNode(ctx, node); err == nil {
            edge := schemas.Edge{
                ID:        uuid.NewString(),
                From:      sourceObservationID,
                To:        node.ID,
                Type:      "CONTAINS_ENTITY",
                Label:     "Contains Function",
                CreatedAt: now,
                LastSeen:  now,
            }
            m.kg.AddEdge(ctx, edge)
        } else {
            lastErr = err
        }
    }
    // Repeat for DataStructs and APIRoutes...

    m.logger.Info("Enriched knowledge graph with entities from observation.",
        zap.Int("functions", len(entities.Functions)),
        zap.Int("structs", len(entities.DataStructs)),
        zap.Int("routes", len(entities.APIRoutes)))

    return lastErr
}

func (m *LLMMind) updateActionStatusFromObservation(ctx context.Context, obs Observation) error {
    result := obs.Result
    status := schemas.StatusAnalyzed
    errMsg := ""

    if result.Status == "failed" {
        status = schemas.StatusError
    }
    errMsg = result.Error

    return m.updateActionStatus(ctx, obs.SourceActionID, status, errMsg)
}

func (m *LLMMind) updateActionStatus(ctx context.Context, actionID string, status schemas.NodeStatus, errMsg string) error {
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

    if errMsg != "" {
        propsMap["error"] = errMsg
    }
    propsMap["status"] = string(status)

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

func (m *LLMMind) marshalProperties(propsMap map[string]interface{}) (json.RawMessage, error) {
    propsBytes, err := json.Marshal(propsMap)
    if err != nil {
        return nil, fmt.Errorf("failed to marshal properties: %w", err)
    }
    return propsBytes, nil
}

func (m *LLMMind) recordObservationKG(ctx context.Context, obs Observation) error {
    now := time.Now().UTC()

    propsMap := map[string]interface{}{
        "type":        string(obs.Type),
        "timestamp":   obs.Timestamp,
        "data_raw":    obs.Data,
        "exec_status": obs.Result.Status,
        "exec_error":  obs.Result.Error,
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
        propsMap[fmt.Sprintf("meta_%s", k)] = fmt.Sprintf("%v", v)
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

func (m *LLMMind) updateState(newState AgentState) {
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
    default:
        close(m.stopChan)
    }
}

