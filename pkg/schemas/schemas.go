// This file consolidates all agent-related data models.

package schemas

import "time"

// -- Agent Cognitive State --

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

// -- Mission and Action Primitives --

type Mission struct {
	ID          string                 `json:"id"`
	Objective   string                 `json:"objective"`
	TargetURL   string                 `json:"target_url"`
	Constraints []string               `json:"constraints"`
	Parameters  map[string]interface{} `json:"parameters"`
	StartTime   time.Time              `json:"start_time"`
}

type ActionType string

const (
	ActionNavigate     ActionType = "NAVIGATE"
	ActionClick        ActionType = "CLICK"
	ActionInputText    ActionType = "INPUT_TEXT"
	ActionSubmitForm   ActionType = "SUBMIT_FORM"
	ActionScroll       ActionType = "SCROLL"
	ActionWaitForAsync ActionType = "WAIT_FOR_ASYNC"
	ActionAnalyzeElement ActionType = "ANALYZE_ELEMENT"
	ActionInjectPayload  ActionType = "INJECT_PAYLOAD"
	ActionConclude     ActionType = "CONCLUDE"
)

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

// -- Observation Primitives --

type ObservationType string

const (
	ObservedNetworkActivity ObservationType = "NETWORK_ACTIVITY"
	ObservedDOMChange       ObservationType = "DOM_CHANGE"
	ObservedConsoleMessage  ObservationType = "CONSOLE_MESSAGE"
	ObservedTaintFlow       ObservationType = "TAINT_FLOW"
	ObservedVulnerability   ObservationType = "VULNERABILITY"
	ObservedSystemState     ObservationType = "SYSTEM_STATE"
)

type Observation struct {
	ID             string          `json:"id"`
	MissionID      string          `json:"mission_id"`
	SourceActionID string          `json:"source_action_id"`
	Type           ObservationType `json:"type"`
	Data           interface{}     `json:"data"`
	Timestamp      time.Time       `json:"timestamp"`
}

type ExecutionResult struct {
	Status          string          `json:"status"`
	Error           string          `json:"error,omitempty"`
	ObservationType ObservationType `json:"observation_type"`
}

type MissionResult struct {
	Summary   string
	Findings  []Finding
	KGUpdates *KGUpdates
}


// -- LLM Interaction Schemas --

type ModelTier string

const (
	TierFast     ModelTier = "fast"
	TierPowerful ModelTier = "powerful"
)

type GenerationOptions struct {
	Temperature     float32
	MaxTokens       int
	ForceJSONFormat bool
}

type GenerationRequest struct {
	SystemPrompt string
	UserPrompt   string
	Tier         ModelTier
	Options      GenerationOptions
}
