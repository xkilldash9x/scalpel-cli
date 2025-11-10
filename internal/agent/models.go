// internal/agent/models.go
package agent

import (
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// AgentState represents the agent's current phase within its OODA (Observe,
// Orient, Decide, Act) loop. This is used to track the agent's internal
// cognitive state.
type AgentState string

const (
	StateInitializing AgentState = "INITIALIZING" // The agent is setting up its components.
	StateObserving    AgentState = "OBSERVING"    // The agent is processing new information from its environment.
	StateOrienting    AgentState = "ORIENTING"    // The agent is integrating new information and updating its world model.
	StateDeciding     AgentState = "DECIDING"     // The agent is reasoning about the next action to take.
	StateActing       AgentState = "ACTING"       // The agent has dispatched an action and is waiting for the result.
	StatePaused       AgentState = "PAUSED"       // The agent's cognitive loop is temporarily paused.
	StateCompleted    AgentState = "COMPLETED"    // The agent has successfully completed its mission.
	StateFailed       AgentState = "FAILED"       // The agent has encountered a critical, unrecoverable error.
)

// Mission defines the high-level objective and parameters for an agent's
// operation. It encapsulates the "what" and "where" of the agent's task.
type Mission struct {
	ID          string                 `json:"id"`          // A unique identifier for this mission.
	ScanID      string                 `json:"scan_id"`     // Correlates the mission to a parent scan operation.
	Objective   string                 `json:"objective"`   // The high-level goal for the agent to achieve.
	TargetURL   string                 `json:"target_url"`  // The primary URL target for the mission.
	Constraints []string               `json:"constraints"` // Any rules or limitations the agent must adhere to.
	Parameters  map[string]interface{} `json:"parameters"`  // Mission-specific parameters.
	StartTime   time.Time              `json:"start_time"`  // The time the mission was initiated.
}

// ActionType is an enumeration of all possible actions the agent can decide to
// perform. This provides a structured vocabulary for the agent's capabilities.
type ActionType string

const (
	// -- Environmental Interaction (Basic) --
	ActionNavigate   ActionType = "NAVIGATE"     // Navigates to a URL.
	ActionClick      ActionType = "CLICK"        // Clicks on a UI element.
	ActionInputText  ActionType = "INPUT_TEXT"   // Types text into an input field.
	ActionSubmitForm ActionType = "SUBMIT_FORM" // Submits a form.
	ActionScroll     ActionType = "SCROLL"      // Scrolls the page.
	ActionWaitForAsync ActionType = "WAIT_FOR_ASYNC" // Pauses for a specified duration.

	// -- High-Level Humanoid Actions --
	ActionHumanoidDragAndDrop ActionType = "HUMANOID_DRAG_AND_DROP" // Performs a human-like drag-and-drop.

	// -- Specific Analysis Actions --
	ActionAnalyzeTaint          ActionType = "ANALYZE_TAINT"            // Initiates a taint analysis scan on the current page.
	ActionAnalyzeProtoPollution ActionType = "ANALYZE_PROTO_POLLUTION" // Scans for prototype pollution.
	ActionAnalyzeHeaders        ActionType = "ANALYZE_HEADERS"          // Analyzes HTTP security headers.

	// -- Codebase Interaction --
	ActionGatherCodebaseContext ActionType = "GATHER_CODEBASE_CONTEXT" // Gathers static analysis context from the agent's own codebase.

	// -- Proactive Self-Improvement --
	ActionEvolveCodebase ActionType = "EVOLVE_CODEBASE" // Initiates the self-improvement (evolution) process.

	// -- High-Level, Complex Actions --
	ActionPerformComplexTask ActionType = "PERFORM_COMPLEX_TASK" // A placeholder for future complex, multi-step tasks.

	// -- Mission Control --
	ActionConclude ActionType = "CONCLUDE" // Concludes the current mission.
)

// Action represents a single, concrete step decided upon by the agent's mind.
// It includes the type of action, all necessary parameters, and the agent's
// reasoning (thought process and rationale) behind the decision.
type Action struct {
	ID        string `json:"id"`        // A unique identifier for this action instance.
	MissionID string `json:"mission_id"`// The ID of the mission this action is a part of.
	ScanID    string `json:"scan_id"`   // The parent scan ID for correlation.

	// Thought provides a step-by-step "chain of thought" from the LLM, showing
	// the reasoning process that led to this specific action. This is invaluable
	// for debugging and understanding the agent's behavior.
	Thought string `json:"thought,omitempty"`

	Type      ActionType             `json:"type"`                 // The specific type of action to perform.
	Selector  string                 `json:"selector,omitempty"`   // The primary CSS selector for UI-based actions.
	Value     string                 `json:"value,omitempty"`      // The value to be used (e.g., text to type, URL to navigate to).
	Metadata  map[string]interface{} `json:"metadata,omitempty"`   // A flexible map for additional, action-specific parameters.
	Rationale string                 `json:"rationale"`            // A concise justification for why this action was chosen.
	Timestamp time.Time              `json:"timestamp"`            // The time the action was decided.
}

// ObservationType categorizes the different kinds of information the agent can
// perceive from its environment or internal state.
type ObservationType string

const (
	ObservedNetworkActivity ObservationType = "NETWORK_ACTIVITY" // An observation of network traffic (e.g., from a HAR file).
	ObservedDOMChange       ObservationType = "DOM_CHANGE"       // An observation of a change in the Document Object Model.
	ObservedConsoleMessage  ObservationType = "CONSOLE_MESSAGE"  // An observation of a browser console message.
	ObservedTaintFlow       ObservationType = "TAINT_FLOW"       // An observation of a data flow from a source to a sink.
	ObservedCodebaseContext ObservationType = "CODEBASE_CONTEXT" // An observation containing source code and dependency information.
	ObservedEvolutionResult ObservationType = "EVOLUTION_RESULT" // The outcome of a self-improvement attempt.
	ObservedVulnerability   ObservationType = "VULNERABILITY"    // A specific security vulnerability has been identified.
	ObservedSystemState     ObservationType = "SYSTEM_STATE"     // An observation about the agent's own internal state or a system error.
	ObservedAnalysisResult  ObservationType = "ANALYSIS_RESULT"  // A generic wrapper for the output of a security analysis adapter.
)

// Observation represents a piece of information that the agent's mind has
// received. It is the result of an action and forms the "Observe" part of the
// OODA loop. It contains the raw data and the execution status of the action that
// produced it.
type Observation struct {
	ID             string          `json:"id"`               // A unique identifier for this observation.
	MissionID      string          `json:"mission_id"`       // The mission this observation belongs to.
	SourceActionID string          `json:"source_action_id"` // The ID of the action that generated this observation.
	Type           ObservationType `json:"type"`             // The category of the observation.
	Data           interface{}     `json:"data"`             // The raw data payload of the observation.
	Result         ExecutionResult `json:"result"`           // The status and metadata of the action's execution.
	Timestamp      time.Time       `json:"timestamp"`        // The time the observation was made.
}

// ExecutionResult is a standardized structure for reporting the outcome of an
// action. It provides detailed feedback to the mind, including success/failure
// status, any discovered findings, suggested knowledge graph updates, and
// structured error information.
type ExecutionResult struct {
	Status          string                        `json:"status"` // "success" or "failed"
	ObservationType ObservationType               `json:"observation_type"`
	Data            interface{}                   `json:"data,omitempty"`
	ErrorCode       ErrorCode                     `json:"error_code,omitempty"`
	ErrorDetails    map[string]interface{}        `json:"error_details,omitempty"`
	Findings        []schemas.Finding             `json:"findings,omitempty"`   // Findings to be reported.
	KGUpdates       *schemas.KnowledgeGraphUpdate `json:"kg_updates,omitempty"` // Suggested updates for the knowledge graph.
}

// CognitiveMessageType defines the different types of messages that can be sent
// over the agent's internal cognitive bus.
type CognitiveMessageType string

const (
	MessageTypeAction      CognitiveMessageType = "ACTION"      // A message containing a new action to be executed.
	MessageTypeObservation CognitiveMessageType = "OBSERVATION" // A message containing a new observation for the mind to process.
	MessageTypeStateChange CognitiveMessageType = "STATE_CHANGE" // A message indicating a change in the agent's state.
	MessageTypeInterrupt   CognitiveMessageType = "INTERRUPT"   // A message to interrupt the agent's current process.
)

// MissionResult encapsulates the final output of a completed mission, including
// a summary of findings and any knowledge graph updates.
type MissionResult struct {
	Summary   string
	Findings  []schemas.Finding
	KGUpdates *schemas.KnowledgeGraphUpdate
}
