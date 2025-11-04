// internal/agent/errors.go
package agent

// ErrorCode is a string type used for structured error reporting from action executors.
// Using a custom type ensures that only predefined constants can be used where an
// ErrorCode is expected, preventing a class of bugs.
type ErrorCode string

// Define specific error codes for Humanoid and general execution failures.
const (
	// -- General Execution Errors --
	ErrCodeExecutionFailure  ErrorCode = "EXECUTION_FAILURE"
	ErrCodeNotImplemented    ErrorCode = "NOT_IMPLEMENTED"
	ErrCodeInvalidParameters ErrorCode = "INVALID_PARAMETERS"
	ErrCodeJSONMarshalFailed ErrorCode = "JSON_MARSHAL_FAILED"
	ErrCodeUnknownAction     ErrorCode = "UNKNOWN_ACTION_TYPE"
	ErrCodeFeatureDisabled   ErrorCode = "FEATURE_DISABLED"
	// -- Browser/DOM Errors (used by both ExecutorRegistry and Agent/Humanoid) --
	ErrCodeElementNotFound ErrorCode = "ELEMENT_NOT_FOUND"
	ErrCodeTimeoutError    ErrorCode = "TIMEOUT_ERROR"
	ErrCodeNavigationError ErrorCode = "NAVIGATION_ERROR"

	// -- Humanoid-specific errors --
	// ErrCodeHumanoidTargetNotVisible indicates the element exists but cannot be
	// interacted with visually (e.g., obscured, off-screen). This is crucial
	// for the Mind to decide to scroll.
	ErrCodeHumanoidTargetNotVisible ErrorCode = "HUMANOID_TARGET_NOT_VISIBLE"
	// ErrCodeHumanoidGeometryInvalid indicates the element's coordinates or
	// structure are invalid (e.g., zero size).
	ErrCodeHumanoidGeometryInvalid ErrorCode = "HUMANOID_GEOMETRY_INVALID"
	// ErrCodeHumanoidInteractionFailed is a generic failure during the
	// interaction process.
	ErrCodeHumanoidInteractionFailed ErrorCode = "HUMANOID_INTERACTION_FAILED"

	// -- Evolution-specific errors --
	ErrCodeEvolutionFailure ErrorCode = "EVOLUTION_FAILURE"

	// -- Internal System Errors --
	ErrCodeExecutorPanic ErrorCode = "EXECUTOR_PANIC"
)
