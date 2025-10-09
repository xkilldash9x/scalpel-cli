package decider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/bus"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	"go.uber.org/zap"
)

// Decider selects the optimal strategy and generates the concrete next action.
type Decider struct {
	logger    *zap.Logger
	bus       *bus.EvolutionBus
	llmClient schemas.LLMClient
	// Field to hold the subscription
	msgChan <-chan bus.Message
}

// LLMActionResponse defines the expected JSON structure from the LLM when asked to generate an action.
type LLMActionResponse struct {
	Rationale   string                 `json:"rationale"`
	ActionType  models.ActionType      `json:"action_type"`
	Description string                 `json:"description"`
	Payload     map[string]interface{} `json:"payload"`
}

var (
	// We compile regexes at the package level for efficiency.
	// We use regular (double-quoted) strings with \x60 for backticks because Go's raw strings cannot contain backticks.
	jsonObjectRegex = regexp.MustCompile("(?s)\x60\x60\x60(?:json)?\\s*({.*})\\s*\x60\x60\x60")
	patchBlockRegex = regexp.MustCompile("(?s)\x60\x60\x60(?:diff|patch)?\\s*(.*?)\\s*\x60\x60\x60")
)

// NewDecider initializes the Decider component and subscribes to the bus.
func NewDecider(logger *zap.Logger, bus *bus.EvolutionBus, llmClient schemas.LLMClient) *Decider {
	// Subscribe immediately upon creation.
	// Fix for Shutdown Deadlock: Ignore the unsubscribe function.
	msgChan, _ := bus.Subscribe(models.TypeSynthesis)

	return &Decider{
		logger:    logger.Named("decider"),
		bus:       bus,
		llmClient: llmClient,
		msgChan:   msgChan,
	}
}

// P3: processMessage wraps message handling to guarantee acknowledgement and recover from panics.
func (d *Decider) processMessage(ctx context.Context, msg bus.Message) {
	defer func() {
		if r := recover(); r != nil {
			d.logger.Error("Panic recovered in Decider handler",
				zap.String("message_id", msg.ID),
				zap.String("message_type", string(msg.Type)),
				zap.Any("panic_value", r),
			)
		}
		d.bus.Acknowledge(msg)
	}()
	d.handleSynthesis(ctx, msg)
}

func (d *Decider) Start(ctx context.Context) {
	d.logger.Info("Decider started, waiting for Synthesis...")

	for {
		select {
		case <-ctx.Done():
			// Return immediately on external cancellation. Bus handles draining.
			return
		case msg, ok := <-d.msgChan:
			if !ok {
				// Channel closed by the bus during shutdown.
				return
			}
			// P3: Use the wrapper for safe processing and acknowledgement.
			d.processMessage(ctx, msg)
		}
	}
}

func (d *Decider) handleSynthesis(ctx context.Context, msg bus.Message) {
	synthesis, ok := msg.Payload.(models.Synthesis)
	if !ok {
		return
	}

	d.logger.Info("Decide phase started. Evaluating strategies.", zap.String("goal_id", synthesis.GoalID))

	// Step 3: DECIDE - Choose the Optimal Path
	// 1. Decision Logic
	chosenStrategy := d.selectStrategy(synthesis.Strategies)
	if chosenStrategy == nil {
		d.logger.Warn("No viable strategy found in synthesis. Concluding goal.", zap.String("goal_id", synthesis.GoalID))
		// Pass an empty string for strategyID since none was chosen.
		d.concludeGoal(ctx, synthesis.GoalID, "No viable strategies identified by the Synthesizer.", "")
		return
	}

	d.logger.Info("Strategy selected.", zap.String("description", chosenStrategy.Description), zap.Int("rank", chosenStrategy.Rank), zap.String("strategy_id", chosenStrategy.ID))

	// 2. Action Plan: Generate the next action using the LLM.
	action, err := d.generateNextAction(ctx, synthesis.GoalID, *chosenStrategy)
	if err != nil {
		// Check if the error is due to context cancellation
		if ctx.Err() != nil {
			d.logger.Info("Decide phase cancelled during action generation.", zap.Error(err), zap.String("goal_id", synthesis.GoalID))
		} else {
			d.logger.Error("Failed to generate next action from strategy.", zap.Error(err), zap.String("goal_id", synthesis.GoalID))
			// Conclude the goal, linking the failure to this specific strategy.
			d.concludeGoal(ctx, synthesis.GoalID, fmt.Sprintf("Failed to generate action for selected strategy: %v", err), chosenStrategy.ID)
		}
		return
	}

	d.logger.Info("Decide phase completed. Action generated.", zap.String("action_type", string(action.Type)))

	// Publish the Action to the bus for the Executor.
	if err := d.bus.Post(ctx, models.TypeAction, *action); err != nil {
		// Log if the error is not due to context cancellation
		if ctx.Err() == nil {
			d.logger.Error("Failed to post action to bus.", zap.Error(err))
		}
	}
}

func (d *Decider) selectStrategy(strategies []models.Strategy) *models.Strategy {
	if len(strategies) == 0 {
		return nil
	}

	// Sort by Rank (1 is best), then by Impact, then by Complexity (lower is better for both).
	sort.Slice(strategies, func(i, j int) bool {
		if strategies[i].Rank != strategies[j].Rank {
			return strategies[i].Rank < strategies[j].Rank
		}
		if strategies[i].PotentialImpact != strategies[j].PotentialImpact {
			return strategies[i].PotentialImpact < strategies[j].PotentialImpact
		}
		return strategies[i].EstimatedComplexity < strategies[j].EstimatedComplexity
	})

	return &strategies[0]
}

func (d *Decider) generateNextAction(ctx context.Context, goalID string, strategy models.Strategy) (*models.Action, error) {
	// 1. Construct the prompt for the LLM.
	prompt := d.constructPrompt(strategy)

	// 2. Call the LLM.
	req := schemas.GenerationRequest{
		SystemPrompt: d.getSystemPrompt(),
		UserPrompt:   prompt,
		Tier:         schemas.TierPowerful,
		Options: schemas.GenerationOptions{
			ForceJSONFormat: true,
			Temperature:     0.1, // Low temperature for deterministic output.
		},
	}

	actionCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	response, err := d.llmClient.Generate(actionCtx, req)
	if err != nil {
		return nil, fmt.Errorf("LLM generation failed: %w", err)
	}

	// 3. Parse the response.
	llmAction, err := d.parseLLMResponse(response)
	if err != nil {
		d.logger.Error("Failed to parse LLM action response.", zap.Error(err), zap.String("raw_response", response))
		return nil, err
	}

	// 4. Validate and format the action.
	if err := d.validateAndFormatAction(llmAction); err != nil {
		return nil, fmt.Errorf("generated action failed validation: %w", err)
	}

	// 5. Create the final Action object.
	action := &models.Action{
		ID:     uuid.New().String(),
		GoalID: goalID,
		// Propagate the StrategyID into the Action for traceability.
		StrategyID:  strategy.ID,
		Type:        llmAction.ActionType,
		Description: llmAction.Description,
		Payload:     llmAction.Payload,
		Timestamp:   time.Now().UTC(),
	}

	return action, nil
}

func (d *Decider) getSystemPrompt() string {
	return `You are the 'Decider', the execution planner of an autonomous code improvement system (Scalpel-CLI).
    Your role is Step 3 (DECIDE) in the OODA loop.
    You receive the chosen STRATEGY and must generate the immediate next concrete ACTION required to implement it.
    **Input:** The chosen strategy (description, rationale).

    **Output Requirements (Strict JSON Format):**
    Generate a single JSON object representing the next action. Respond ONLY with this JSON object.
    {
      "rationale": "Your thought process for why this specific action is the necessary next step.",
      "action_type": "The type of operation (see below).",
      "description": "A concise description of the action (e.g., 'Apply patch to fix nil pointer').",
      "payload": { ... } // Specific data for the action type.
    }

    **Available Action Types:**

    1. APPLY_PATCH: Apply changes to existing files.
       Payload: {"patch": "Unified diff format (git diff). MUST include a/ and b/ prefixes and be relative to the project root."}

    2. RUN_COMMAND: Execute a shell command (e.g., install dependencies, run tools).
       Payload: {"command": "The command string."}
       Example: {"command": "go get github.com/new/library"}

    3. CREATE_FILE: Create a new file with initial content.
       Payload: {"path": "Relative file path.", "content": "The full content of the file."}

    4. CONCLUDE_GOAL: Mark the goal as complete if the strategy indicates the work is done.
       Payload: {"message": "Summary of the achievement."}

    **Guidelines:**
    - Actions must be minimal and iterative. Break down the strategy into the smallest possible verifiable step.
    - Code generation (APPLY_PATCH, CREATE_FILE) must be precise, idiomatic Go code.
    - Patches must be in valid unified diff format.`
}

func (d *Decider) constructPrompt(strategy models.Strategy) string {
	return fmt.Sprintf(`
    The following strategy has been selected for implementation.

    **Chosen Strategy:**
    - Description: %s
    - Rationale: %s
    - Complexity: %.2f
    - Impact: %.2f

    **Task:**
    Generate the immediate next concrete ACTION required to implement this strategy. Respond ONLY with the JSON object for the action.`, strategy.Description, strategy.Rationale, strategy.EstimatedComplexity, strategy.PotentialImpact)
}

func (d *Decider) parseLLMResponse(response string) (*LLMActionResponse, error) {
	response = strings.TrimSpace(response)
	jsonStringToParse := response

	// Handle markdown wrapping.
	if strings.HasPrefix(response, "```") {
		matches := jsonObjectRegex.FindStringSubmatch(response)
		if len(matches) > 1 {
			jsonStringToParse = matches[1]
		}
	} else if !strings.HasPrefix(response, "{") {
		// Attempt to find the object within the text if not clearly marked.
		firstBracket := strings.Index(response, "{")
		lastBracket := strings.LastIndex(response, "}")
		if firstBracket != -1 && lastBracket != -1 && lastBracket > firstBracket {
			jsonStringToParse = response[firstBracket : lastBracket+1]
		}
	}

	var actionResponse LLMActionResponse
	if err := json.Unmarshal([]byte(jsonStringToParse), &actionResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LLM JSON response: %w. Extracted JSON: %.500s", err, jsonStringToParse)
	}

	if actionResponse.ActionType == "" || actionResponse.Description == "" {
		return nil, fmt.Errorf("LLM response is missing required fields (action_type or description)")
	}

	return &actionResponse, nil
}

// validateAndFormatAction ensures the payload matches the action type and cleans up formats.
func (d *Decider) validateAndFormatAction(action *LLMActionResponse) error {
	switch action.ActionType {
	case models.ActionApplyPatch:
		patch, ok := action.Payload["patch"].(string)
		if !ok || patch == "" {
			return fmt.Errorf("APPLY_PATCH requires a non-empty string 'patch' in the payload")
		}
		// Clean up potential markdown wrapping within the payload string itself.
		patch = strings.TrimSpace(patch)
		if strings.HasPrefix(patch, "```") {
			matches := patchBlockRegex.FindStringSubmatch(patch)
			if len(matches) > 1 {
				patch = strings.TrimSpace(matches[1])
			}
		}
		if !strings.HasPrefix(patch, "--- a/") || !strings.Contains(patch, "+++ b/") {
			return fmt.Errorf("patch is not in valid unified diff format (missing a/ b/ prefixes). Patch:\n%s", patch)
		}
		action.Payload["patch"] = patch

	case models.ActionRunCommand:
		command, ok := action.Payload["command"].(string)
		if !ok || command == "" {
			return fmt.Errorf("RUN_COMMAND requires a non-empty string 'command' in the payload")
		}

	case models.ActionCreateFile:
		path, ok := action.Payload["path"].(string)
		if !ok || path == "" {
			return fmt.Errorf("CREATE_FILE requires a non-empty string 'path' in the payload")
		}
		_, ok = action.Payload["content"].(string)
		if !ok {
			return fmt.Errorf("CREATE_FILE requires a string 'content' in the payload")
		}

	case models.ActionConcludeGoal:
	// No specific validation needed.
	default:
		return fmt.Errorf("unknown or unsupported action type: %s", action.ActionType)
	}
	return nil
}

// concludeGoal sends an action to terminate the OODA loop.
func (d *Decider) concludeGoal(ctx context.Context, goalID, message, strategyID string) {
	action := models.Action{
		ID:          uuid.New().String(),
		GoalID:      goalID,
		StrategyID:  strategyID,
		Type:        models.ActionConcludeGoal,
		Description: message,
		Payload:     map[string]interface{}{"message": message},
		Timestamp:   time.Now().UTC(),
	}
	if err := d.bus.Post(ctx, models.TypeAction, action); err != nil {
		// Log if the error is not due to context cancellation
		if ctx.Err() == nil {
			d.logger.Error("Failed to post conclusion action.", zap.Error(err))
		}
	}
}
