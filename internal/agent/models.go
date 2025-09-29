package agent

import (
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// AgentState represents the current status of the agent within the OODA loop.
type AgentState string

const (
	StateInitializing AgentState = "INITIALIZING"
	StateObserving    AgentState = "OBSERVING"
	StateOrienting    AgentState = "ORIENTING"
	StateDeciding     AgentState = "DECIDING"
	StateActing       AgentState = "ACTING"
	StatePaused       AgentState = "PAUSED"
	StateCompleted    AgentState = "COMPLETED"
	StateFailed       AgentState = "FAILED"
)

// Mission represents the high-level objective assigned to the agent.
type Mission struct {
	ID          string                 `json:"id"`
	Objective   string                 `json:"objective"`
	TargetURL   string                 `json:"target_url"`
	Constraints []string               `json:"constraints"`
	Parameters  map[string]interface{} `json:"parameters"`
	StartTime   time.Time              `json:"start_time"`
}

// ActionType defines the categories of actions the agent can perform.
type ActionType string

const (
	// Environmental Interaction (Basic)
	ActionNavigate     ActionType = "NAVIGATE"
	ActionClick        ActionType = "CLICK"
	ActionInputText    ActionType = "INPUT_TEXT"
	ActionSubmitForm   ActionType = "SUBMIT_FORM"
	ActionScroll       ActionType = "SCROLL"
	ActionWaitForAsync ActionType = "WAIT_FOR_ASYNC"


    // High-Level Humanoid Actions (Complex, multi-step interactions)
    ActionHumanoidDragAndDrop      ActionType = "HUMANOID_DRAG_AND_DROP"

	// Analysis and Injection (Kept for completeness)
	ActionAnalyzeElement ActionType = "ANALYZE_ELEMENT"
	ActionInjectPayload  ActionType = "INJECT_PAYLOAD"

	// Codebase Interaction
	ActionGatherCodebaseContext ActionType = "GATHER_CODEBASE_CONTEXT"


    // High-Level, Complex Actions (Orchestrated by the Agent directly)
    ActionPerformComplexTask ActionType = "PERFORM_COMPLEX_TASK"

	// Mission Control
	ActionConclude ActionType = "CONCLUDE"
)

// Action represents a specific step decided by the Mind.
type Action struct {
	ID        string                 `json:"id"`
	MissionID string                 `json:"mission_id"`
	Type      ActionType             `json:"type"`
	Selector  string                 `json:"selector,omitempty"` // Primary selector
	Value     string                 `json:"value,omitempty"`
	// Metadata holds secondary parameters (e.g., 'target_selector' for DragAndDrop, 'duration_ms' for Wait)
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	Rationale string                 `json:"rationale"`
	Timestamp time.Time              `json:"timestamp"`
}

// ObservationType defines the categories of data observed by the agent.
type ObservationType string

const (
	ObservedNetworkActivity ObservationType = "NETWORK_ACTIVITY"
	ObservedDOMChange       ObservationType = "DOM_CHANGE"
	ObservedConsoleMessage  ObservationType = "CONSOLE_MESSAGE"
	ObservedTaintFlow       ObservationType = "TAINT_FLOW"
	ObservedCodebaseContext ObservationType = "CODEBASE_CONTEXT"
	ObservedVulnerability   ObservationType = "VULNERABILITY"
	ObservedSystemState     ObservationType = "SYSTEM_STATE"
)

// Observation represents data collected from the environment after an action.
type Observation struct {
	ID             string          `json:"id"`
	MissionID      string          `json:"mission_id"`
	SourceActionID string          `json:"source_action_id"`
	Type           ObservationType `json:"type"`
	Data           interface{}     `json:"data"`   // The raw result payload.
	Result         ExecutionResult `json:"result"` // The status of the execution itself.
	Timestamp      time.Time       `json:"timestamp"`
}

// ExecutionResult is a structured return type for ActionExecutors.

// Added ErrorCode and ErrorDetails to provide structured feedback to the Mind.
type ExecutionResult struct {
	Status          string                 `json:"status"` // "success" or "failed"
	ObservationType ObservationType        `json:"observation_type"`
	Data            interface{}            `json:"data,omitempty"`
	ErrorCode       string                 `json:"error_code,omitempty"`
	ErrorDetails    map[string]interface{} `json:"error_details,omitempty"`
}


// Define specific error codes for Humanoid and general execution failures.
const (
    // General Execution Errors
    ErrCodeExecutionFailure = "EXECUTION_FAILURE"
    ErrCodeNotImplemented   = "NOT_IMPLEMENTED"
    ErrCodeInvalidParameters = "INVALID_PARAMETERS"

    // Browser/DOM Errors (used by both ExecutorRegistry and Agent/Humanoid)
    ErrCodeElementNotFound = "ELEMENT_NOT_FOUND"
    ErrCodeTimeoutError    = "TIMEOUT_ERROR"
    ErrCodeNavigationError = "NAVIGATION_ERROR"

    // Humanoid-specific errors
    // ErrCodeHumanoidTargetNotVisible indicates the element exists but cannot be interacted with visually (e.g., obscured, off-screen).
    // This is crucial for the Mind to decide to scroll.
    ErrCodeHumanoidTargetNotVisible = "HUMANOID_TARGET_NOT_VISIBLE"
    // ErrCodeHumanoidGeometryInvalid indicates the element's coordinates or structure are invalid (e.g., zero size).
    ErrCodeHumanoidGeometryInvalid  = "HUMANOID_GEOMETRY_INVALID"
    // ErrCodeHumanoidInteractionFailed is a generic failure during the interaction process.
    ErrCodeHumanoidInteractionFailed = "HUMANOID_INTERACTION_FAILED"
)

// CognitiveMessageType defines the message types used on the CognitiveBus.
type CognitiveMessageType string

const (
	MessageTypeAction      CognitiveMessageType = "ACTION"
	MessageTypeObservation CognitiveMessageType = "OBSERVATION"
	MessageTypeStateChange CognitiveMessageType = "STATE_CHANGE"
	MessageTypeInterrupt   CognitiveMessageType = "INTERRUPT"
)

// MissionResult summarizes the outcome of a completed mission.
type MissionResult struct {
	Summary   string
	Findings  []schemas.Finding
	KGUpdates *schemas.KnowledgeGraphUpdate
}

