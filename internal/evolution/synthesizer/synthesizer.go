package synthesizer

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/bus"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	"go.uber.org/zap"
)

// Synthesizer listens to observations, synthesizes information, remembers past attempts, and generates strategies (Step 2: ORIENT).
type Synthesizer struct {
	logger    *zap.Logger
	bus       *bus.EvolutionBus
	llmClient schemas.LLMClient
	kg        schemas.KnowledgeGraphClient

	// Field to hold the subscription
	msgChan <-chan bus.Message

	// Buffer observations per GoalID until the observation phase settles.
	buffer     map[string][]models.Observation
	bufferMu   sync.Mutex
	timers     map[string]*time.Timer
	settleTime time.Duration

	// Store the current goal context.
	goals   map[string]models.Goal
	goalsMu sync.RWMutex

	// WaitGroup to track active timers/processing goroutines.
	processingWg sync.WaitGroup
}

// NewSynthesizer initializes the Synthesizer and subscribes to the bus.
func NewSynthesizer(logger *zap.Logger, bus *bus.EvolutionBus, llmClient schemas.LLMClient, kg schemas.KnowledgeGraphClient) *Synthesizer {
	// Subscribe immediately upon creation.
	// Fix for Shutdown Deadlock: Ignore the unsubscribe function.
	msgChan, _ := bus.Subscribe(models.TypeGoal, models.TypeObservation)

	return &Synthesizer{
		logger:     logger.Named("synthesizer"),
		bus:        bus,
		llmClient:  llmClient,
		kg:         kg,
		msgChan:    msgChan,
		buffer:     make(map[string][]models.Observation),
		timers:     make(map[string]*time.Timer),
		settleTime: 500 * time.Millisecond, // Time to wait after the last observation arrives.
		goals:      make(map[string]models.Goal),
	}
}

func (s *Synthesizer) Start(ctx context.Context) {
	// 1. Wait for all background processing to complete before returning.
	defer s.processingWg.Wait()

	// 2. Cleanup: Stop timers.
	defer func() {
		// Actively stop all pending timers to speed up shutdown and prevent leaks.
		s.bufferMu.Lock()
		stoppedCount := 0
		for goalID, timer := range s.timers {
			if timer.Stop() {
				// Successfully stopped before firing. Decrement the WG count.
				s.processingWg.Done()
				stoppedCount++
			}
			// If Stop() returns false, the timer fired and the goroutine is running.
			// It will call Done() itself.
			delete(s.timers, goalID)
		}
		s.bufferMu.Unlock()

		if stoppedCount > 0 {
			s.logger.Debug("Stopped active timers during shutdown.", zap.Int("count", stoppedCount))
		}
	}()

	s.logger.Info("Synthesizer started, waiting for Observations...")

	for {
		select {
		case <-ctx.Done():
			// Return. Defer functions handle cleanup and waiting.
			return
		case msg, ok := <-s.msgChan:
			if !ok {
				// Channel closed by the bus during shutdown.
				return
			}
			s.handleMessage(ctx, msg)
			s.bus.Acknowledge(msg)
		}
	}
}

func (s *Synthesizer) handleMessage(ctx context.Context, msg bus.Message) {
	switch msg.Type {
	case models.TypeGoal:
		// Track the goal details.
		goal, ok := msg.Payload.(models.Goal)
		if !ok {
			return
		}
		s.goalsMu.Lock()
		s.goals[goal.ID] = goal
		s.goalsMu.Unlock()

	case models.TypeObservation:
		obs, ok := msg.Payload.(models.Observation)
		if !ok {
			return
		}
		s.bufferObservation(ctx, obs)
	}
}

// bufferObservation collects observations and manages the debounce timer synchronization.
func (s *Synthesizer) bufferObservation(ctx context.Context, obs models.Observation) {
	s.bufferMu.Lock()
	defer s.bufferMu.Unlock()

	goalID := obs.GoalID
	s.buffer[goalID] = append(s.buffer[goalID], obs)

	// Debounce logic with precise WaitGroup synchronization.
	if timer, exists := s.timers[goalID]; exists {
		if !timer.Stop() {
			// Timer already fired. Drain the channel. The associated goroutine will call Done().
			select {
			case <-timer.C:
			default:
			}
		} else {
			// Successfully stopped before firing. Decrement the WG count for the stopped timer.
			s.processingWg.Done()
		}
		// Resetting the timer. Increment WG for the new duration.
		s.processingWg.Add(1)
		timer.Reset(s.settleTime)
	} else {
		// New timer. Increment WG.
		s.processingWg.Add(1)
		// Capture ctx to ensure the processing respects cancellation.
		s.timers[goalID] = time.AfterFunc(s.settleTime, func() {
			defer s.processingWg.Done() // Decrement WG when processing finishes.
			s.processBuffer(ctx, goalID)
		})
	}
}

// processBuffer is called when the observation stream for a GoalID settles.
func (s *Synthesizer) processBuffer(ctx context.Context, goalID string) {
	s.bufferMu.Lock()
	observations := s.buffer[goalID]
	// We remove from timers here as well, in case a rapid succession of events occurred.
	// The primary removal happens in the Start defer during shutdown.
	delete(s.buffer, goalID)
	delete(s.timers, goalID)
	s.bufferMu.Unlock()

	if len(observations) == 0 {
		return
	}

	// Check context before starting heavy processing.
	if ctx.Err() != nil {
		s.logger.Info("Synthesis aborted due to context cancellation before processing.", zap.String("goal_id", goalID))
		return
	}

	s.logger.Info("Orient phase started. Synthesizing observations.", zap.String("goal_id", goalID), zap.Int("observations_count", len(observations)))

	s.goalsMu.RLock()
	goal, exists := s.goals[goalID]
	s.goalsMu.RUnlock()

	if !exists {
		s.logger.Error("Goal context not found for synthesis.", zap.String("goal_id", goalID))
		return
	}

	// Step 2: ORIENT - Synthesize, Remember, and Strategize.
	synthesis, err := s.synthesizeAndStrategize(ctx, goal, observations)
	if err != nil {
		// Log context cancellations differently from actual processing errors.
		if ctx.Err() != nil {
			s.logger.Info("Synthesis cancelled during processing.", zap.String("goal_id", goalID), zap.Error(err))
		} else {
			s.logger.Error("Failed to generate strategies.", zap.Error(err), zap.String("goal_id", goalID))
		}
		return
	}

	s.logger.Info("Orient phase completed. Strategies generated.", zap.String("goal_id", goalID), zap.Int("strategies_count", len(synthesis.Strategies)))

	// Publish the synthesis to the bus, which triggers the Decider.
	if err := s.bus.Post(ctx, models.TypeSynthesis, *synthesis); err != nil {
		// Log if the error is not due to context cancellation
		if ctx.Err() == nil {
			s.logger.Error("Failed to post synthesis to bus.", zap.Error(err))
		}
	}
}

func (s *Synthesizer) synthesizeAndStrategize(ctx context.Context, goal models.Goal, observations []models.Observation) (*models.Synthesis, error) {
	// Step 2a: Query the KnowledgeGraph (REMEMBER).
	history, err := s.queryHistory(ctx, goal.Objective)
	if err != nil {
		// Log the error but continue; the system can still operate without memory.
		s.logger.Warn("Failed to query improvement history from KG. Proceeding without historical context.", zap.Error(err))
	}

	// Step 2b: Construct the prompt with historical context.
	prompt := s.constructPrompt(goal, observations, history)

	// Call the LLM.
	req := schemas.GenerationRequest{
		SystemPrompt: s.getSystemPrompt(),
		UserPrompt:   prompt,
		Tier:         schemas.TierPowerful,
		Options: schemas.GenerationOptions{
			ForceJSONFormat: true,
			Temperature:     0.3, // Slightly higher temperature for strategic creativity.
		},
	}

	analysisCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	response, err := s.llmClient.Generate(analysisCtx, req)
	if err != nil {
		return nil, fmt.Errorf("LLM generation failed: %w", err)
	}

	// Parse the LLM's response.
	strategies, err := s.parseLLMResponse(response)
	if err != nil {
		s.logger.Error("Failed to parse LLM strategy response.", zap.Error(err), zap.String("raw_response", response))
		return nil, err
	}

	// Create the Synthesis object.
	synthesis := &models.Synthesis{
		ID:         uuid.New().String(),
		GoalID:     goal.ID,
		Strategies: strategies,
		Timestamp:  time.Now().UTC(),
	}

	return synthesis, nil
}

// queryHistory retrieves relevant past experiences from the KG.
func (s *Synthesizer) queryHistory(ctx context.Context, objective string) ([]schemas.ImprovementAttemptProperties, error) {
	nodes, err := s.kg.QueryImprovementHistory(ctx, objective, 10) // Limit to the 10 most recent attempts.
	if err != nil {
		return nil, err
	}

	if len(nodes) == 0 {
		return nil, nil
	}

	s.logger.Info("Retrieved historical attempts from KG.", zap.Int("count", len(nodes)))

	var history []schemas.ImprovementAttemptProperties
	for _, node := range nodes {
		var props schemas.ImprovementAttemptProperties
		if err := json.Unmarshal(node.Properties, &props); err != nil {
			s.logger.Warn("Failed to unmarshal historical attempt properties.", zap.String("node_id", node.ID), zap.Error(err))
			continue
		}
		history = append(history, props)
	}

	return history, nil
}

func (s *Synthesizer) getSystemPrompt() string {
	return `You are the 'Synthesizer', the strategic mind of an autonomous code improvement system (Scalpel-CLI).
    Your role is Step 2 (ORIENT) in the OODA loop.
    You receive a GOAL, OBSERVATIONS about the codebase, and HISTORICAL DATA about past attempts.
    Your task is NOT to write code, but to analyze the context holistically and propose distinct strategies.
    **Input Analysis Requirements:**
    1. Analyze the Goal: What is the desired outcome?
    2. Analyze the Current State: Review build/test status. Are we stable or recovering from a failure (see Previous Action Result)?
    3. Analyze the Code Context: Review source code, tests, dependencies, and static analysis.
    4. **[CRITICAL] Analyze the History:** Review the HISTORICAL ATTEMPTS section. Identify strategies that previously failed and understand *why* (the OutcomeOutput).
    **Output Requirements (Strict JSON Format):**
    Generate an array of 1 to 3 distinct strategies. Respond ONLY with the JSON array.
    Example: [{"description": "...", "rationale": "...", "complexity": 0.5, "impact": 0.2, "rank": 1}, ...]

    Each strategy must include:
    - description: A clear explanation of the approach.
    - rationale: Why this approach is viable, addresses the context, AND how it avoids past failures if applicable.
    - complexity: A score from 0.0 (trivial change) to 1.0 (major architectural refactor).
    - impact: A score from 0.0 (isolated change) to 1.0 (high risk of breaking changes).
    - rank: Your assessment of the best strategy (1 being the best/lowest risk).
    **Strategic Guidelines:**
    - Prefer iterative, small changes.
    - If the previous action failed, prioritize strategies that address the failure.
    - **DO NOT repeat strategies that recently failed for the same reason.** If a past attempt shows a dependency conflict when adding library X, your new strategy must explicitly address or avoid that conflict.`
}

// constructPrompt builds the comprehensive context prompt, now including history.
func (s *Synthesizer) constructPrompt(goal models.Goal, observations []models.Observation, history []schemas.ImprovementAttemptProperties) string {
	organizedObs := make(map[string][]string)
	var previousResult *models.Result
	buildStatus := "Unknown"
	testStatus := "Unknown"

	for _, obs := range observations {
		switch obs.Type {
		case models.ObsActionResult:
			if res, ok := obs.Data.(models.Result); ok {
				previousResult = &res
			} else if ptrRes, ok := obs.Data.(*models.Result); ok {
				previousResult = ptrRes
			}
		case models.ObsBuildStatus:
			if status, ok := obs.Data.(string); ok {
				buildStatus = fmt.Sprintf("Success: %v\nOutput:\n%s", !obs.IsError, status)
			}
		case models.ObsTestStatus:
			if status, ok := obs.Data.(string); ok {
				testStatus = fmt.Sprintf("Success: %v\nOutput:\n%s", !obs.IsError, status)
			}
		default:
			dataStr := ""
			if str, ok := obs.Data.(string); ok {
				dataStr = str
			} else {
				jsonData, err := json.MarshalIndent(obs.Data, "", "  ")
				if err == nil {
					dataStr = string(jsonData)
				} else {
					dataStr = fmt.Sprintf("%v", obs.Data)
				}
			}
			organizedObs[obs.Type] = append(organizedObs[obs.Type], fmt.Sprintf("-- %s --\n%s\n", obs.Source, dataStr))
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "**GOAL:** %s\n\n", goal.Objective)
	fmt.Fprintf(&sb, "**Target Files:** %v\n\n", goal.TargetFiles)

	if len(history) > 0 {
		fmt.Fprintf(&sb, "## HISTORICAL ATTEMPTS (Relevant Memory) ##\n")
		fmt.Fprintf(&sb, "WARNING: Pay close attention to past failures to avoid repeating mistakes.\n\n")
		for i, attempt := range history {
			fmt.Fprintf(&sb, "-- Attempt History #%d --\n", i+1)
			fmt.Fprintf(&sb, "Strategy: %s\n", attempt.StrategyDesc)
			fmt.Fprintf(&sb, "Action Type: %s\n", attempt.ActionType)
			payloadStr, _ := json.MarshalIndent(attempt.ActionPayload, "", "  ")
			fmt.Fprintf(&sb, "Action Payload:\n```json\n%s\n```\n", string(payloadStr))
			fmt.Fprintf(&sb, "Outcome (Errors/Logs):\n```\n%s\n```\n\n", attempt.OutcomeOutput)
		}
	}

	fmt.Fprintf(&sb, "## CURRENT STATE SUMMARY ##\n")
	if previousResult != nil {
		fmt.Fprintf(&sb, "**Previous Action Result:** Success: %v\nOutput:\n```\n%s\n```\n\n", previousResult.Success, previousResult.Output)
	}
	fmt.Fprintf(&sb, "**Build Status:**\n```\n%s\n```\n\n", buildStatus)
	fmt.Fprintf(&sb, "**Test Status:**\n```\n%s\n```\n\n", testStatus)

	fmt.Fprintf(&sb, "## DETAILED OBSERVATIONS ##\n\n")
	keyOrder := []string{models.ObsSourceCode, models.ObsUnitTest, models.ObsDependencies, models.ObsStaticAnalysis, models.ObsGitBlame}
	for _, key := range keyOrder {
		if items, ok := organizedObs[key]; ok {
			fmt.Fprintf(&sb, "### %s ###\n%s\n", key, strings.Join(items, "\n"))
			delete(organizedObs, key)
		}
	}
	for key, items := range organizedObs { // Print any remaining types
		fmt.Fprintf(&sb, "### %s ###\n%s\n", key, strings.Join(items, "\n"))
	}

	fmt.Fprintf(&sb, "\n## TASK ##\n")
	fmt.Fprintf(&sb, "Analyze the observations, the goal, and the historical attempts. Propose 1-3 distinct strategies to achieve the goal. Respond ONLY with the JSON array of strategies.\n")

	return sb.String()
}

// Regex to extract JSON array from markdown.
var jsonArrayRegex = regexp.MustCompile("(?s)`" + `(?:json)?\s*(\[.*\])\s*` + "```")

func (s *Synthesizer) parseLLMResponse(response string) ([]models.Strategy, error) {
	response = strings.TrimSpace(response)
	jsonStringToParse := response

	if strings.HasPrefix(response, "```") {
		matches := jsonArrayRegex.FindStringSubmatch(response)
		if len(matches) > 1 {
			jsonStringToParse = matches[1]
		}
	} else if !strings.HasPrefix(response, "[") {
		firstBracket := strings.Index(response, "[")
		lastBracket := strings.LastIndex(response, "]")
		if firstBracket != -1 && lastBracket != -1 && lastBracket > firstBracket {
			jsonStringToParse = response[firstBracket : lastBracket+1]
		}
	}

	var strategies []models.Strategy
	if err := json.Unmarshal([]byte(jsonStringToParse), &strategies); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LLM JSON response: %w. Extracted JSON: %.500s", err, jsonStringToParse)
	}

	if len(strategies) == 0 {
		s.logger.Warn("LLM response contained an empty list of strategies.")
	}

	for i := range strategies {
		strategies[i].ID = uuid.New().String()
		if strategies[i].Description == "" || strategies[i].Rationale == "" || strategies[i].Rank == 0 {
			return nil, fmt.Errorf("strategy at index %d is missing required fields (description, rationale, or rank)", i)
		}
	}

	return strategies, nil
}
