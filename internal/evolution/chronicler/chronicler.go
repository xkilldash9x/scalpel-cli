package chronicler

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/bus"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	"go.uber.org/zap"
)

// Chronicler is responsible for recording the experience of the OODA loop (Step 5: REMEMBER).
type Chronicler struct {
	logger *zap.Logger
	bus    *bus.EvolutionBus
	kg     schemas.KnowledgeGraphClient

	// Field to hold the subscription
	msgChan <-chan bus.Message

	// Context tracking: We need to remember the details of the Goal, Strategy, and Action
	// associated with the incoming Result, as the Result only contains IDs.
	goals      map[string]models.Goal
	strategies map[string]models.Strategy
	actions    map[string]models.Action
	mu         sync.RWMutex
}

// NewChronicler initializes the Chronicler component and subscribes to the bus.
func NewChronicler(logger *zap.Logger, bus *bus.EvolutionBus, kg schemas.KnowledgeGraphClient) *Chronicler {
	// Subscribe immediately upon creation.
	// Fix for Shutdown Deadlock: Ignore the unsubscribe function.
	msgChan, _ := bus.Subscribe(
		models.TypeGoal,
		models.TypeSynthesis,
		models.TypeAction,
		models.TypeResult,
	)

	return &Chronicler{
		logger:     logger.Named("chronicler"),
		bus:        bus,
		kg:         kg,
		msgChan:    msgChan,
		goals:      make(map[string]models.Goal),
		strategies: make(map[string]models.Strategy),
		actions:    make(map[string]models.Action),
	}
}

// P3: processMessage wraps message handling to guarantee acknowledgement and recover from panics.
func (c *Chronicler) processMessage(ctx context.Context, msg bus.Message) {
	// Acknowledge immediately; history recording is a side-effect and shouldn't block the main loop.
	defer func() {
		if r := recover(); r != nil {
			c.logger.Error("Panic recovered in Chronicler handler",
				zap.String("message_id", msg.ID),
				zap.String("message_type", string(msg.Type)),
				zap.Any("panic_value", r),
			)
		}
		c.bus.Acknowledge(msg)
	}()
	// The handleMessage function respects the ctx for its operations.
	c.handleMessage(ctx, msg)
}

func (c *Chronicler) Start(ctx context.Context) {
	c.logger.Info("Chronicler started, listening for OODA events (REMEMBER phase)...")

	for {
		select {
		case <-ctx.Done():
			// Return immediately on external cancellation. Bus handles draining.
			return
		case msg, ok := <-c.msgChan:
			if !ok {
				// Channel closed by the bus during shutdown.
				return
			}
			// P3: Use the wrapper for safe processing and acknowledgement.
			c.processMessage(ctx, msg)
		}
	}
}

func (c *Chronicler) handleMessage(ctx context.Context, msg bus.Message) {
	switch msg.Type {
	case models.TypeGoal:
		c.trackGoal(msg)
	case models.TypeSynthesis:
		c.trackStrategies(msg)
	case models.TypeAction:
		c.trackAction(msg)
	case models.TypeResult:
		c.recordExperience(ctx, msg)
	}
}

// -- Context Tracking Functions --
func (c *Chronicler) trackGoal(msg bus.Message) {
	goal, ok := msg.Payload.(models.Goal)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.goals[goal.ID] = goal
}

func (c *Chronicler) trackStrategies(msg bus.Message) {
	synthesis, ok := msg.Payload.(models.Synthesis)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Track all proposed strategies so we can retrieve the details later using StrategyID.
	for _, strategy := range synthesis.Strategies {
		c.strategies[strategy.ID] = strategy
	}
}

func (c *Chronicler) trackAction(msg bus.Message) {
	action, ok := msg.Payload.(models.Action)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actions[action.ID] = action
}

// -- Step 5: REMEMBER - Record the Experience --
func (c *Chronicler) recordExperience(ctx context.Context, msg bus.Message) {
	result, ok := msg.Payload.(models.Result)
	if !ok {
		return
	}

	// Check context before starting potentially expensive operations.
	if ctx.Err() != nil {
		return
	}

	c.logger.Info("Remember phase started. Recording experience.", zap.String("goal_id", result.GoalID), zap.Bool("success", result.Success))

	// 1. Retrieve the context (Goal, Strategy, Action)
	goal, strategy, action, err := c.retrieveContext(result)
	if err != nil {
		c.logger.Error("Failed to retrieve full context for recording experience. History will be incomplete.", zap.Error(err))
		// We continue to record what we can, even if some context is missing.
	}

	// 2. Define the properties for the KG node
	properties := schemas.ImprovementAttemptProperties{
		GoalObjective: goal.Objective,
		StrategyDesc:  strategy.Description,
		ActionType:    string(action.Type),
		ActionPayload: action.Payload,
		OutcomeOutput: result.Output,
	}

	// 3. Determine the status for the node label
	statusLabel := schemas.StatusFailure
	if result.Success {
		statusLabel = schemas.StatusSuccess
	}

	// 4. Create the Node structure
	node, err := c.createAttemptNode(properties, statusLabel)
	if err != nil {
		c.logger.Error("Failed to create ImprovementAttempt node structure.", zap.Error(err))
		return
	}

	// 5. Write to the Knowledge Graph
	// This operation respects the context (ctx).
	if err := c.kg.AddNode(ctx, node); err != nil {
		// Log if the error is not due to context cancellation
		if ctx.Err() == nil {
			c.logger.Error("Failed to write experience to Knowledge Graph.", zap.Error(err))
		} else {
			c.logger.Info("Recording experience cancelled during KG write.", zap.Error(err))
		}
		// This is a critical failure for the learning process if not cancelled.
		return
	}

	c.logger.Info("Remember phase completed. Experience recorded in KG.", zap.String("node_id", node.ID))

	// Clean up the specific action context now that it's recorded.
	c.mu.Lock()
	delete(c.actions, result.ActionID)
	c.mu.Unlock()
	// We might want to keep Goal/Strategies until the goal is officially concluded, but for now this is acceptable.
}

func (c *Chronicler) retrieveContext(result models.Result) (models.Goal, models.Strategy, models.Action, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var missingContext []string
	goal, gOk := c.goals[result.GoalID]
	if !gOk {
		missingContext = append(missingContext, "Goal")
		// Provide a placeholder if missing
		goal = models.Goal{Objective: fmt.Sprintf("Unknown Goal ID: %s", result.GoalID)}
	}

	// StrategyID is propagated through the Result
	strategy, sOk := c.strategies[result.StrategyID]
	if !sOk && result.StrategyID != "" {
		// Log if we expected a strategy but didn't find it
		missingContext = append(missingContext, "Strategy")
		strategy = models.Strategy{Description: fmt.Sprintf("Unknown Strategy ID: %s", result.StrategyID)}
	}

	action, aOk := c.actions[result.ActionID]
	if !aOk {
		missingContext = append(missingContext, "Action")
		action = models.Action{Type: "Unknown", Payload: map[string]interface{}{"error": "Action context lost"}}
	}

	if len(missingContext) > 0 {
		return goal, strategy, action, fmt.Errorf("missing context elements: %v", missingContext)
	}

	return goal, strategy, action, nil
}

func (c *Chronicler) createAttemptNode(props schemas.ImprovementAttemptProperties, statusLabel schemas.NodeStatus) (schemas.Node, error) {
	propsJSON, err := json.Marshal(props)
	if err != nil {
		return schemas.Node{}, fmt.Errorf("failed to marshal properties: %w", err)
	}

	now := time.Now().UTC()
	node := schemas.Node{
		ID:    uuid.New().String(),
		Type:  schemas.NodeImprovementAttempt,
		Label: fmt.Sprintf("Attempt: %s (%s)", props.ActionType, statusLabel),
		// We use a generic status for the node itself, the specific outcome is in the properties/label.
		Status:     schemas.StatusAnalyzed,
		Properties: propsJSON,
		CreatedAt:  now,
		LastSeen:   now,
	}
	return node, nil
}
