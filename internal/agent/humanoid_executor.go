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

// HumanoidProvider is a function type that returns the active Humanoid instance.
type HumanoidProvider func() *humanoid.Humanoid

// HumanoidExecutor implements the ActionExecutor interface for complex, interactive browser tasks
// that require human-like simulation (e.g., clicking, typing).
type HumanoidExecutor struct {
	logger           *zap.Logger
	humanoidProvider HumanoidProvider
	handlers         map[ActionType]humanoidActionHandler
}

// humanoidActionHandler defines the function signature for a specific humanoid action handler.
type humanoidActionHandler func(ctx context.Context, h *humanoid.Humanoid, action Action) error

var _ ActionExecutor = (*HumanoidExecutor)(nil) // Verify interface compliance.

// NewHumanoidExecutor creates a new HumanoidExecutor.
func NewHumanoidExecutor(logger *zap.Logger, provider HumanoidProvider) *HumanoidExecutor {
	e := &HumanoidExecutor{
		logger:           logger.Named("humanoid_executor"),
		humanoidProvider: provider,
		handlers:         make(map[ActionType]humanoidActionHandler),
	}
	e.registerHandlers()
	return e
}

// Execute looks up and runs the appropriate handler for a given humanoid action.
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
		// Return a structured ExecutionResult instead of a raw error.
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
		// If the handler fails, use the shared browser error parser to create a structured response.
		result.Status = "failed"
		result.ErrorCode, result.ErrorDetails = e.parseHumanoidError(err, action) // Assign error code and details
		e.logger.Warn("Humanoid action execution failed",
			zap.String("action", string(action.Type)),
			zap.String("error_code", string(result.ErrorCode)), // Use the assigned error code for logging
			zap.Error(err))
	}

	return result, nil
}

// parseHumanoidError classifies an error from a humanoid operation.
// It first uses the generic browser error parser and then adds humanoid-specific classifications.
func (e *HumanoidExecutor) parseHumanoidError(err error, action Action) (ErrorCode, map[string]interface{}) {
	// Start with the generic browser error parser.
	errorCode, details := ParseBrowserError(err, action)

	// If it's a generic failure, check for more specific humanoid error patterns.
	if errorCode == ErrCodeExecutionFailure {
		errStr := err.Error()
		if strings.Contains(errStr, "not interactable") || strings.Contains(errStr, "zero size") {
			details["selector"] = action.Selector
			return ErrCodeHumanoidGeometryInvalid, details
		}
		// This is a good catch-all for when a click/type action fails for a non-specific reason.
		if strings.Contains(errStr, "failed to click") || strings.Contains(errStr, "failed to type") {
			return ErrCodeHumanoidInteractionFailed, details
		}
	}

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
	if metadata == nil {
		return nil // No metadata, so no options.
	}

	opts := &humanoid.InteractionOptions{}
	hasOptions := false

	// Check for 'ensure_visible'
	if val, ok := metadata["ensure_visible"]; ok {
		if ensureVisible, isBool := val.(bool); isBool {
			opts.EnsureVisible = &ensureVisible
			hasOptions = true
		} else {
			e.logger.Warn("Invalid type for 'ensure_visible' in metadata, expected bool.", zap.Any("value", val))
		}
	}

	// Check for 'potential_field'
	if val, ok := metadata["potential_field"]; ok {
		fieldData, isMap := val.(map[string]interface{})
		if !isMap {
			e.logger.Warn("Invalid type for 'potential_field' in metadata, expected a map.", zap.Any("value", val))
		} else {
			sourcesData, hasSources := fieldData["sources"].([]interface{})
			if !hasSources {
				e.logger.Warn("Invalid 'potential_field' structure, missing 'sources' array.", zap.Any("value", fieldData))
			} else {
				field := &humanoid.PotentialField{}
				var successfulSources int // <-- FIX: Track successful parses
				for _, s := range sourcesData {
					sourceMap, isMap := s.(map[string]interface{})
					if !isMap {
						continue
					}
					// A quick way to convert map[string]interface{} to a struct
					jsonBytes, err := json.Marshal(sourceMap)
					if err != nil {
						continue // This catches the func() {} marshal error
					}
					var parsedSource potentialFieldSource
					if err := json.Unmarshal(jsonBytes, &parsedSource); err == nil {
						// Use the public AddSource method to append to the unexported slice.
						field.AddSource(humanoid.Vector2D{X: parsedSource.X, Y: parsedSource.Y}, parsedSource.Strength, parsedSource.StdDev)
						successfulSources++ // <-- FIX: Increment on success
					}
				}

				// FIX: Only assign the field and set hasOptions if we actually parsed sources
				if successfulSources > 0 {
					opts.Field = field
					hasOptions = true
				}
			}
		}
	}

	if !hasOptions {
		return nil // No valid options were parsed.
	}
	return opts // Return the populated options struct.
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
		e.logger.Debug("ActionInputText called with empty 'value'.")
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
