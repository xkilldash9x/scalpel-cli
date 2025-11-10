// internal/agent/errors.go
package agent

// ErrorCode provides a structured, enumerable way to represent specific error
// conditions that can occur during an agent's action execution. This allows the
// agent's mind to reason about failures and make more intelligent decisions.
type ErrorCode string

// Constants defining the set of specific, structured error codes that can be
// returned by action executors.
const (
	// -- General Execution Errors --
	ErrCodeExecutionFailure  ErrorCode = "EXECUTION_FAILURE"  // A generic failure during the execution of an action.
	ErrCodeNotImplemented    ErrorCode = "NOT_IMPLEMENTED"    // The requested action or feature is not implemented.
	ErrCodeInvalidParameters ErrorCode = "INVALID_PARAMETERS" // The parameters provided for the action were invalid.
	ErrCodeJSONMarshalFailed ErrorCode = "JSON_MARSHAL_FAILED"// Failed to marshal data to JSON.
	ErrCodeUnknownAction     ErrorCode = "UNKNOWN_ACTION_TYPE"// The action type is not recognized by any executor.
	ErrCodeFeatureDisabled   ErrorCode = "FEATURE_DISABLED"   // The requested feature is disabled in the configuration.

	// -- Browser/DOM Errors --
	ErrCodeElementNotFound ErrorCode = "ELEMENT_NOT_FOUND" // The target DOM element could not be found.
	ErrCodeTimeoutError    ErrorCode = "TIMEOUT_ERROR"     // An operation timed out.
	ErrCodeNavigationError ErrorCode = "NAVIGATION_ERROR"  // An error occurred while navigating to a URL.

	// -- Humanoid-specific errors --
	// ErrCodeHumanoidTargetNotVisible indicates that a target element was found in the DOM
	// but is not currently visible in the viewport (e.g., it needs to be scrolled to).
	ErrCodeHumanoidTargetNotVisible ErrorCode = "HUMANOID_TARGET_NOT_VISIBLE"
	// ErrCodeHumanoidGeometryInvalid indicates that the geometry of the target element is
	// invalid for interaction (e.g., it has zero width or height).
	ErrCodeHumanoidGeometryInvalid ErrorCode = "HUMANOID_GEOMETRY_INVALID"
	// ErrCodeHumanoidInteractionFailed is a general failure during a complex humanoid
	// interaction like a click or drag.
	ErrCodeHumanoidInteractionFailed ErrorCode = "HUMANOID_INTERACTION_FAILED"

	// -- Evolution-specific errors --
	ErrCodeEvolutionFailure ErrorCode = "EVOLUTION_FAILURE" // An error occurred during the self-improvement/evolution process.

	// -- Internal System Errors --
	ErrCodeExecutorPanic ErrorCode = "EXECUTOR_PANIC" // An executor experienced an unrecoverable panic.
)
