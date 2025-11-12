// internal/agent/humanoid_executor.go
package agent

import (
	"context"
	"fmt"
	"strings"

	json "github.com/json-iterator/go"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"go.uber.org/zap"
)

// HumanoidProvider is a function type that acts as a dynamic getter for the
// active Humanoid controller instance. This allows the executor to be created
// before the humanoid controller is fully initialized.
type HumanoidProvider func() *humanoid.Humanoid

// HumanoidExecutor is a specialized action executor for handling complex,
// interactive browser tasks that require human-like simulation, such as
// intelligent clicks, typing, and drag-and-drop. It delegates these tasks to the
// `humanoid.Humanoid` controller.
type HumanoidExecutor struct {
	logger           *zap.Logger
	humanoidProvider HumanoidProvider
	handlers         map[ActionType]humanoidActionHandler
}

// humanoidActionHandler defines the function signature for a method that handles
// a specific type of humanoid action.
type humanoidActionHandler func(ctx context.Context, h *humanoid.Humanoid, action Action) error

var _ ActionExecutor = (*HumanoidExecutor)(nil) // Verify interface compliance.

// NewHumanoidExecutor creates and initializes a new HumanoidExecutor,
// registering all of its action handlers.
func NewHumanoidExecutor(logger *zap.Logger, provider HumanoidProvider) *HumanoidExecutor {
	e := &HumanoidExecutor{
		logger:           logger.Named("humanoid_executor"),
		humanoidProvider: provider,
		handlers:         make(map[ActionType]humanoidActionHandler),
	}
	e.registerHandlers()
	return e
}

// Execute retrieves the active humanoid controller, finds the correct handler
// for the given action, and executes it. It is responsible for parsing any
// resulting errors into a structured format that the agent's mind can use for
// decision-making.
func (e *HumanoidExecutor) Execute(ctx context.Context, action Action) (*ExecutionResult, error) {
	h := e.humanoidProvider()
	if h == nil {
		// Return a structured ExecutionResult instead of a raw error for consistency.
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeExecutionFailure,
			ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("cannot execute humanoid action (%s): no active humanoid controller", action.Type)},
		}, nil
	}

	handler, ok := e.handlers[action.Type]
	if !ok {
		// Defense-in-depth check.
		return &ExecutionResult{
			Status:          "failed",
			ObservationType: ObservedSystemState,
			ErrorCode:       ErrCodeUnknownAction,
			ErrorDetails:    map[string]interface{}{"message": fmt.Sprintf("HumanoidExecutor handler not found for type: %s", action.Type)},
		}, nil
	}

	err := handler(ctx, h, action)

	result := &ExecutionResult{
		Status:          "success",
		ObservationType: ObservedDOMChange,
	}

	if err != nil {
		// If the handler fails, use the specialized error parser to create a structured response.
		result.Status = "failed"
		result.ErrorCode, result.ErrorDetails = e.parseHumanoidError(err, action)
		e.logger.Warn("Humanoid action execution failed",
			zap.String("action", string(action.Type)),
			zap.String("selector", action.Selector),
			zap.String("error_code", string(result.ErrorCode)),
			zap.Error(err))
	}

	return result, nil
}

// parseHumanoidError classifies an error from a humanoid operation.
// It refines the generic browser error classification with humanoid-specific patterns.
func (e *HumanoidExecutor) parseHumanoidError(err error, action Action) (ErrorCode, map[string]interface{}) {
	// Start with the generic browser error parser (which now includes visibility checks).
	errorCode, details := ParseBrowserError(err, action)

	// Refine classification based on humanoid-specific error patterns if the generic parser didn't identify a specific issue.
	errStr := err.Error()

	// 1. Check for invalid geometry or interactability state not caught by visibility checks.
	if strings.Contains(errStr, "not interactable") ||
		strings.Contains(errStr, "zero size") ||
		strings.Contains(errStr, "detached from the DOM") {
		details["selector"] = action.Selector
		return ErrCodeHumanoidGeometryInvalid, details
	}

	// 2. General interaction failures (catch-all for specific operations).
	if errorCode == ErrCodeExecutionFailure {
		if strings.Contains(errStr, "failed to click") ||
			strings.Contains(errStr, "failed to type") ||
			strings.Contains(errStr, "drag and drop failed") {
			return ErrCodeHumanoidInteractionFailed, details
		}
	}

	// Fallback to the initial classification if no specific humanoid error is matched.
	return errorCode, details
}

// potentialFieldSource is a helper struct for unmarshaling from action metadata.
type potentialFieldSource struct {
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Strength float64 `json:"strength"`
	StdDev   float64 `json:"std_dev"`
}

// parseInteractionOptions extracts humanoid interaction options from the action's metadata.
func (e *HumanoidExecutor) parseInteractionOptions(metadata map[string]interface{}) *humanoid.InteractionOptions {
	if metadata == nil || len(metadata) == 0 {
		return nil // No metadata, so no options.
	}

	opts := &humanoid.InteractionOptions{}
	hasOptions := false

	// 1. Parse 'ensure_visible'.
	if val, ok := metadata["ensure_visible"]; ok {
		if ensureVisible, isBool := val.(bool); isBool {
			opts.EnsureVisible = &ensureVisible
			hasOptions = true
		} else {
			e.logger.Warn("Invalid type for 'ensure_visible' in metadata, expected bool.", zap.Any("value", val))
		}
	}

	// 2. Parse 'potential_field'.
	if val, ok := metadata["potential_field"]; ok {
		fieldData, isMap := val.(map[string]interface{})
		if !isMap {
			e.logger.Warn("Invalid type for 'potential_field' in metadata, expected an object.", zap.Any("value", val))
		} else {
			if sourcesRaw, hasSources := fieldData["sources"]; hasSources {
				if sourcesData, isArray := sourcesRaw.([]interface{}); isArray {
					field := e.parsePotentialFieldSources(sourcesData)
					if field != nil {
						opts.Field = field
						hasOptions = true
					}
				} else {
					e.logger.Warn("Invalid type for 'potential_field.sources', expected an array.", zap.Any("value", sourcesRaw))
				}
			}
		}
	}

	if !hasOptions {
		return nil // No valid options were parsed.
	}
	return opts // Return the populated options struct.
}

// parsePotentialFieldSources processes the array of source definitions.
func (e *HumanoidExecutor) parsePotentialFieldSources(sourcesData []interface{}) *humanoid.PotentialField {
	field := &humanoid.PotentialField{}
	var successfulSources int

	for _, s := range sourcesData {
		sourceMap, isMap := s.(map[string]interface{})
		if !isMap {
			continue
		}

		// Use JSON marshal/unmarshal for robust conversion from map[string]interface{} to the struct.
		jsonBytes, err := json.Marshal(sourceMap)
		if err != nil {
			// This handles cases where the map contains unserializable data (e.g., functions).
			continue
		}

		var parsedSource potentialFieldSource
		if err := json.Unmarshal(jsonBytes, &parsedSource); err == nil {
			// Use the public AddSource method to append to the unexported slice.
			field.AddSource(humanoid.Vector2D{X: parsedSource.X, Y: parsedSource.Y}, parsedSource.Strength, parsedSource.StdDev)
			successfulSources++
		}
	}

	if successfulSources > 0 {
		return field
	}
	return nil
}

// registerHandlers populates the internal map of action types to their handler functions.
func (e *HumanoidExecutor) registerHandlers() {
	e.handlers[ActionClick] = e.handleClick
	e.handlers[ActionInputText] = e.handleInputText
	e.handlers[ActionHumanoidDragAndDrop] = e.handleDragAndDrop
}

func (e *HumanoidExecutor) handleClick(ctx context.Context, h *humanoid.Humanoid, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionClick requires a 'selector'")
	}
	opts := e.parseInteractionOptions(action.Metadata)
	return h.IntelligentClick(ctx, action.Selector, opts)
}

func (e *HumanoidExecutor) handleInputText(ctx context.Context, h *humanoid.Humanoid, action Action) error {
	if action.Selector == "" {
		return fmt.Errorf("ActionInputText requires a 'selector'")
	}
	if action.Value == "" {
		e.logger.Debug("ActionInputText called with empty 'value'.", zap.String("selector", action.Selector))
	}
	opts := e.parseInteractionOptions(action.Metadata)
	return h.Type(ctx, action.Selector, action.Value, opts)
}

func (e *HumanoidExecutor) handleDragAndDrop(ctx context.Context, h *humanoid.Humanoid, action Action) error {
	startSelector := action.Selector
	if startSelector == "" {
		return fmt.Errorf("ActionHumanoidDragAndDrop requires a 'selector' for the start element")
	}

	targetSelectorRaw, okMeta := action.Metadata["target_selector"]
	if !okMeta {
		return fmt.Errorf("ActionHumanoidDragAndDrop requires 'metadata.target_selector' for the end element")
	}

	targetSelector, okCast := targetSelectorRaw.(string)
	if !okCast || targetSelector == "" {
		return fmt.Errorf("'metadata.target_selector' must be a non-empty string")
	}

	// Pass through any other interaction options from metadata.
	opts := e.parseInteractionOptions(action.Metadata)
	return h.DragAndDrop(ctx, startSelector, targetSelector, opts)
}
