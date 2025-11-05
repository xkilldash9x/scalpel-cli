// internal/agent/models.go
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
	ScanID      string                 `json:"scan_id"` // Correlates the mission to a parent scan operation.
	Objective   string                 `json:"objective"`
	TargetURL   string                 `json:"target_url"`
	Constraints []string               `json:"constraints"`
	Parameters  map[string]interface{} `json:"parameters"`
	StartTime   time.Time              `json:"start_time"`
}

// ActionType defines the categories of actions the agent can perform.
type ActionType string

const (
	// -- Environmental Interaction (Basic) --
	ActionNavigate     ActionType = "NAVIGATE"
	ActionClick        ActionType = "CLICK"
	ActionInputText    ActionType = "INPUT_TEXT"
	ActionSubmitForm   ActionType = "SUBMIT_FORM"
	ActionScroll       ActionType = "SCROLL"
	ActionWaitForAsync ActionType = "WAIT_FOR_ASYNC"

	// -- User Interaction & System Management (Used by persistent/master agents) --
	ActionRespondToUser ActionType = "RESPOND_TO_USER"
	ActionQueryFindings ActionType = "QUERY_FINDINGS"
	ActionStartScan     ActionType = "START_SCAN"

	// -- High-Level Humanoid Actions --
	// Complex, multi-step interactions emulating human behavior.
	ActionHumanoidDragAndDrop ActionType = "HUMANOID_DRAG_AND_DROP"

	// -- Specific Analysis Actions --
	// Invoked by the agent to perform targeted analysis.
	ActionAnalyzeTaint          ActionType = "ANALYZE_TAINT"
	ActionAnalyzeProtoPollution ActionType = "ANALYZE_PROTO_POLLUTION"
	ActionAnalyzeHeaders        ActionType = "ANALYZE_HEADERS"

	// -- Codebase Interaction --
	ActionGatherCodebaseContext ActionType = "GATHER_CODEBASE_CONTEXT"

	// -- Proactive Self-Improvement --
	ActionEvolveCodebase ActionType = "EVOLVE_CODEBASE"

	// -- High-Level, Complex Actions --
	// Orchestrated by the Agent directly for multi-step tasks.
	ActionPerformComplexTask ActionType = "PERFORM_COMPLEX_TASK"

	// -- Mission Control --
	ActionConclude ActionType = "CONCLUDE"
)

// Action represents a specific step decided by the Mind.
type Action struct {
	ID        string `json:"id"`
	MissionID string `json:"mission_id"`
	ScanID    string `json:"scan_id"` // Propagated for correlation.

	// Thought captures the step-by-step reasoning (Chain-of-Thought) of the LLM
	// before it decided on the final action. This is crucial for debugging and
	// improving the agent's decision-making process.
	Thought string `json:"thought,omitempty"`

	Type     ActionType `json:"type"`
	Selector string     `json:"selector,omitempty"` // Primary selector for UI elements.
	Value    string     `json:"value,omitempty"`    // Value for input actions.
	// Metadata holds secondary parameters (e.g., 'target_selector' for DragAndDrop).
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
	ObservedEvolutionResult ObservationType = "EVOLUTION_RESULT"
	ObservedVulnerability   ObservationType = "VULNERABILITY"
	ObservedSystemState     ObservationType = "SYSTEM_STATE"
	ObservedUserInput       ObservationType = "USER_INPUT"
	ObservedQueryResult     ObservationType = "QUERY_RESULT"
	ObservedScanStatus      ObservationType = "SCAN_STATUS"
	// ObservedAnalysisResult is a generic type for results from analysis adapters.
	ObservedAnalysisResult ObservationType = "ANALYSIS_RESULT"
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
// It provides detailed feedback to the Mind, including structured error
// information and direct outputs like findings or knowledge graph updates.
type ExecutionResult struct {
	Status          string                 `json:"status"` // "success" or "failed"
	ObservationType ObservationType        `json:"observation_type"`
	Data            interface{}            `json:"data,omitempty"`
	ErrorCode       ErrorCode              `json:"error_code,omitempty"`
	ErrorDetails    map[string]interface{} `json:"error_details,omitempty"`
	// Findings may be populated by analysis actions.
	Findings []schemas.Finding `json:"findings,omitempty"`
	// KGUpdates can be suggested to update the central knowledge graph.
	KGUpdates *schemas.KnowledgeGraphUpdate `json:"kg_updates,omitempty"`
}

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
