// -- pkg/agent/models.go --
package agent

import (
	"time"
	// Removed dependency on knowledgegraph/graphmodel as CognitiveMessage is moved to cognitive_bus.go.
)

// AgentState represents the current status of the agent within the OODA loop.
type AgentState string

const (
	StateInitializing AgentState = "Initializing"
	StateObserving    AgentState = "Observing"
	StateOrienting    AgentState = "Orienting"
	StateDeciding     AgentState = "Deciding"
	StateActing       AgentState = "Acting"
	StatePaused       AgentState = "Paused"
	StateCompleted    AgentState = "Completed"
	StateFailed       AgentState = "Failed"
)

// Mission represents the high-level objective assigned to the agent.
type Mission struct {
	ID          string                 `json:"id"`
	Objective   string                 `json:"objective"`
	TargetURL   string                 `json:"target_url"` // Can also be a binary identifier for HARDEN_BINARY tasks.
	Constraints []string               `json:"constraints"`
	Parameters  map[string]interface{} `json:"parameters"`
	StartTime   time.Time              `json:"start_time"`
}

// ActionType defines the categories of actions the agent can perform.
type ActionType string

const (
	// Environmental Interaction
	ActionNavigate     ActionType = "NAVIGATE"
	ActionClick        ActionType = "CLICK"
	ActionInputText    ActionType = "INPUT_TEXT"
	ActionSubmitForm   ActionType = "SUBMIT_FORM"
	ActionScroll       ActionType = "SCROLL"
	ActionWaitForAsync ActionType = "WAIT_FOR_ASYNC"

	// Analysis and Injection
	ActionAnalyzeElement ActionType = "ANALYZE_ELEMENT"
	ActionInjectPayload  ActionType = "INJECT_PAYLOAD"

	// Mission Control
	ActionConclude ActionType = "CONCLUDE"
)

// Action represents a specific step decided by the Mind.
type Action struct {
	ID        string                 `json:"id"`
	MissionID string                 `json:"mission_id"`
	Type      ActionType             `json:"type"`
	Selector  string                 `json:"selector,omitempty"`
	Value     string                 `json:"value,omitempty"`
	// Metadata carries parameters for complex actions (e.g., build server host, policy details).
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
	ObservedVulnerability   ObservationType = "VULNERABILITY"
	ObservedSystemState     ObservationType = "SYSTEM_STATE"
)

// Observation represents data collected from the environment after an action.
type Observation struct {
	ID             string          `json:"id"`
	MissionID      string          `json:"mission_id"`
	SourceActionID string          `json:"source_action_id"`
	Type           ObservationType `json:"type"`
	Data           interface{}     `json:"data"`
	Timestamp      time.Time       `json:"timestamp"`
}

// CORRECTED: Added a strongly-typed struct for executor results.
// ExecutionResult is a structured return type for ActionExecutors.
type ExecutionResult struct {
	// Status can be "success" or "failed".
	Status string `json:"status"`
	// Error message if the execution failed.
	Error string `json:"error,omitempty"`
	// ObservationType provides a hint to the Mind about how to categorize the resulting observation.
	ObservationType ObservationType `json:"observation_type"`
}


// CognitiveMessageType defines the message types used on the CognitiveBus.
type CognitiveMessageType string

const (
	MessageTypeAction      CognitiveMessageType = "ACTION"
	MessageTypeObservation CognitiveMessageType = "OBSERVATION"
	MessageTypeStateChange CognitiveMessageType = "STATE_CHANGE"
	MessageTypeInterrupt   CognitiveMessageType = "INTERRUPT"
)

// CognitiveMessage definition moved to cognitive_bus.go.
