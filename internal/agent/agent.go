//internal/agent/agent.go
package agent

import "time"

// ModelTier represents the desired capability level of the LLM for a given task.
type ModelTier string

const (
	TierFast     ModelTier = "fast"
	TierPowerful ModelTier = "powerful"
)

// GenerationOptions holds parameters for controlling LLM generation.
type GenerationOptions struct {
	Temperature     float32
	MaxTokens       int
	ForceJSONFormat bool
}

// GenerationRequest encapsulates all inputs for a single LLM API call.
type GenerationRequest struct {
	SystemPrompt string
	UserPrompt   string
	Tier         ModelTier
	Options      GenerationOptions
}

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
	TargetURL   string                 `json:"target_url"`
	Constraints []string               `json:"constraints"`
	Parameters  map[string]interface{} `json:"parameters"`
	StartTime   time.Time              `json:"start_time"`
}

// ActionType defines the categories of actions the agent can perform.
type ActionType string

const (
	ActionNavigate       ActionType = "NAVIGATE"
	ActionClick          ActionType = "CLICK"
	ActionInputText      ActionType = "INPUT_TEXT"
	ActionSubmitForm     ActionType = "SUBMIT_FORM"
	ActionScroll         ActionType = "SCROLL"
	ActionWaitForAsync   ActionType = "WAIT_FOR_ASYNC"
	ActionAnalyzeElement ActionType = "ANALYZE_ELEMENT"
	ActionInjectPayload  ActionType = "INJECT_PAYLOAD"
	ActionConclude       ActionType = "CONCLUDE"
)

// Action represents a specific step decided by the Mind.
type Action struct {
	ID        string                 `json:"id"`
	MissionID string                 `json:"mission_id"`
	Type      ActionType             `json:"type"`
	Selector  string                 `json:"selector,omitempty"`
	Value     string                 `json:"value,omitempty"`
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

// ExecutionResult is a structured return type for ActionExecutors.
type ExecutionResult struct {
	Status          string          `json:"status"`
	Error           string          `json:"error,omitempty"`
	ObservationType ObservationType `json:"observation_type"`
}

// MissionResult summarizes the outcome of a completed mission.
type MissionResult struct {
	Summary   string
	Findings  []Finding
	KGUpdates *KGUpdates
}
