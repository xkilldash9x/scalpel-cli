package schemas

import "time"

// NodeType defines the categories of entities in the graph.
type NodeType string

// RelationshipType defines the nature of the connection between nodes.
type RelationshipType string

// Constants for specific System Node IDs
const (
	RootNodeID  = "SYSTEM:ROOT"
	OSINTNodeID = "SYSTEM:OSINT"
)

// Constants for Node Types (Entities)
const (
	NodeTypeScanRoot          NodeType = "ScanRoot"
	NodeTypeDataSource        NodeType = "DataSource"
	NodeTypeDomain            NodeType = "Domain"
	NodeTypeIPAddress         NodeType = "IPAddress"
	NodeTypeURL               NodeType = "URL"
	NodeTypeBinary            NodeType = "Binary"
	NodeTypeIdentifier        NodeType = "Identifier"
	NodeTypeTechnology        NodeType = "Technology"
	NodeTypeAPIEndpoint       NodeType = "APIEndpoint"
	NodeTypeParameter         NodeType = "Parameter"
	NodeTypeBrowserStorage    NodeType = "BrowserStorage"
	NodeTypeVulnerability     NodeType = "Vulnerability"
	NodeTypeUserIdentity      NodeType = "UserIdentity"
	NodeTypeMission           NodeType = "Mission"
	NodeTypeAction            NodeType = "Action"
	NodeTypeObservation       NodeType = "Observation"
	NodeTypeTAOPolicyArtifact NodeType = "TAO_PolicyArtifact"
)

// Constants for Relationship Types (Edges)
const (
	RelationshipTypeLinksTo              RelationshipType = "LINKS_TO"
	RelationshipTypeRedirectsTo          RelationshipType = "REDIRECTS_TO"
	RelationshipTypeResolvesTo           RelationshipType = "RESOLVES_TO"
	RelationshipTypeHasParameter         RelationshipType = "HAS_PARAMETER"
	RelationshipTypeContains             RelationshipType = "CONTAINS"
	RelationshipTypeUsesTechnology       RelationshipType = "USES_TECHNOLOGY"
	RelationshipTypeDerivedFrom          RelationshipType = "DERIVED_FROM"
	RelationshipTypeDataFlowsTo          RelationshipType = "DATA_FLOWS_TO"
	RelationshipTypeAffects              RelationshipType = "AFFECTS"
	RelationshipTypeExecutesAction       RelationshipType = "EXECUTES_ACTION"
	RelationshipTypeGeneratesObservation RelationshipType = "GENERATES_OBSERVATION"
	RelationshipTypeInformsMission       RelationshipType = "INFORMS_MISSION"
	RelationshipTypeNextAction           RelationshipType = "NEXT_ACTION"
	RelationshipTypeGeneratesArtifact    RelationshipType = "GENERATES_ARTIFACT"
	RelationshipTypeAppliesTo            RelationshipType = "APPLIES_TO"
)

// Properties is a generic map for storing attributes.
type Properties map[string]interface{}

// Node represents an entity in the Knowledge Graph.
type Node struct {
	ID         string     `json:"id"`
	Type       NodeType   `json:"type"`
	Properties Properties `json:"properties"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Edge represents a directed relationship between two nodes.
type Edge struct {
	SourceID     string           `json:"source_id"`
	TargetID     string           `json:"target_id"`
	Relationship RelationshipType `json:"relationship"`
	Properties   Properties       `json:"properties"`
	Timestamp    time.Time        `json:"timestamp"`
}

// NodeInput is used for creating or updating a node.
type NodeInput struct {
	ID         string
	Type       NodeType
	Properties Properties
}

// EdgeInput is used for creating or updating an edge.
type EdgeInput struct {
	SourceID     string
	TargetID     string
	Relationship RelationshipType
	Properties   Properties
}

// Query defines the parameters for finding nodes.
type Query struct {
	Type       NodeType
	Properties Properties
}

// NeighborsResult organizes connected nodes by direction and relationship.
type NeighborsResult struct {
	Outbound map[RelationshipType][]*Node `json:"outbound"`
	Inbound  map[RelationshipType][]*Node `json:"inbound"`
}

// GraphExport is a structure for exporting the entire graph or a subgraph.
type GraphExport struct {
	Nodes []*Node `json:"nodes"`
	Edges []*Edge `json:"edges"`
}

// DeepCopy creates a true copy of the Properties map.
func (p Properties) DeepCopy() Properties {
	if p == nil {
		return nil
	}
	copy := make(Properties, len(p))
	for k, v := range p {
		copy[k] = v
	}
	return copy
}

// Clone creates a deep copy of a Node.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	return &Node{
		ID:         n.ID,
		Type:       n.Type,
		Properties: n.Properties.DeepCopy(),
		CreatedAt:  n.CreatedAt,
		UpdatedAt:  n.UpdatedAt,
	}
}

// Clone creates a deep copy of an Edge.
func (e *Edge) Clone() *Edge {
	if e == nil {
		return nil
	}
	return &Edge{
		SourceID:     e.SourceID,
		TargetID:     e.TargetID,
		Relationship: e.Relationship,
		Properties:   e.Properties.DeepCopy(),
		Timestamp:    e.Timestamp,
	}
}
```eof

---
### `pkg/schemas/agent.go`

This file contains the models for the AI Agent and LLM interactions, formerly in `pkg/agent/models.go` and `pkg/agent/interfaces.go`.

```go:Agent & LLM Schemas:pkg/schemas/agent.go
package schemas

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
```eof

---
### `pkg/schemas/browser.go`

This file now contains the data structures related to browser automation, moved from `pkg/browser/types.go`.

```go:Browser Schemas:pkg/schemas/browser.go
package schemas

import (
	"github.com/chromedp/cdproto/har"
	"github.com/chromedp/cdproto/network"
)

// Artifacts represents the data collected from a browser session.
type Artifacts struct {
	HAR         *har.HAR
	DOM         string
	ConsoleLogs []ConsoleLog
	Storage     StorageState
}

// ConsoleLog represents a single entry from the browser console.
type ConsoleLog struct {
	Type string
	Text string
}

// StorageState captures the state of cookies, localStorage, and sessionStorage.
type StorageState struct {
	Cookies        []*network.Cookie
	LocalStorage   map[string]string `json:"localStorage"`
	SessionStorage map[string]string `json:"sessionStorage"`
}

// InteractionConfig holds parameters for automated interaction/crawling.
type InteractionConfig struct {
	MaxDepth                int
	MaxInteractionsPerDepth int
	InteractionDelayMs      int
	PostInteractionWaitMs   int
}
```eof

---
### `pkg/schemas/schemas.go`

This is the main schemas file, defining core concepts like `Task`, `Finding`, and `ResultEnvelope`.

```go:Core Task Schemas:pkg/schemas/schemas.go
package schemas

import (
	"encoding/json"
	"fmt"
	"time"
)

// TaskType defines the valid types of tasks the engine can process.
type TaskType string

const (
	TaskAgentMission          TaskType = "AGENT_MISSION"
	TaskAnalyzeWebPageTaint   TaskType = "ANALYZE_WEB_PAGE_TAINT"
	TaskAnalyzeWebPageProtoPP TaskType = "ANALYZE_WEB_PAGE_PROTOPP"
	TaskTestRaceCondition     TaskType = "TEST_RACE_CONDITION"
	TaskTestAuthATO           TaskType = "TEST_AUTH_ATO"
	TaskTestAuthIDOR          TaskType = "TEST_AUTH_IDOR"
	TaskAnalyzeHeaders        TaskType = "ANALYZE_HEADERS"
	TaskAnalyzeJWT            TaskType = "ANALYZE_JWT"
)

// Severity defines the severity level of a finding for consistency.
type Severity string

const (
	SeverityCritical    Severity = "CRITICAL"
	SeverityHigh        Severity = "HIGH"
	SeverityMedium      Severity = "MEDIUM"
	SeverityLow         Severity = "LOW"
	SeverityInfo        Severity = "INFORMATIONAL"
)

// Task defines the unit of work to be performed by a worker.
type Task struct {
	ScanID     string      `json:"scan_id"`
	TaskID     string      `json:"task_id"`
	Type       TaskType    `json:"type"`
	TargetURL  string      `json:"target_url"`
	Parameters interface{} `json:"parameters,omitempty"`
}

// paramsFactory is a function type that returns a pointer to a new instance of a parameter struct.
type paramsFactory func() interface{}

// paramsRegistry maps TaskTypes to their corresponding factory functions.
var paramsRegistry = map[TaskType]paramsFactory{
	TaskAgentMission:          func() interface{} { return &AgentMissionParams{} },
	TaskAnalyzeWebPageTaint:   func() interface{} { return &TaintTaskParams{} },
	TaskAnalyzeWebPageProtoPP: func() interface{} { return &ProtoPollutionTaskParams{} },
	TaskTestAuthATO:           func() interface{} { return &ATOTaskParams{} },
	TaskTestAuthIDOR:          func() interface{} { return &IDORTaskParams{} },
	TaskAnalyzeJWT:            func() interface{} { return &JWTTaskParams{} },
	TaskTestRaceCondition:     func() interface{} { return &RaceConditionTaskParams{} },
	TaskAnalyzeHeaders:        func() interface{} { return &HeadersTaskParams{} },
}

// UnmarshalJSON provides custom deserialization logic for the Task struct.
func (t *Task) UnmarshalJSON(data []byte) error {
	type TaskAlias Task
	aux := struct {
		*TaskAlias
		Parameters json.RawMessage `json:"parameters,omitempty"`
	}{
		TaskAlias: (*TaskAlias)(t),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("failed to unmarshal base task structure: %w", err)
	}
	if len(aux.Parameters) == 0 || string(aux.Parameters) == "null" {
		return nil
	}
	factory, ok := paramsRegistry[t.Type]
	if !ok {
		return fmt.Errorf("unknown task type: %s", t.Type)
	}
	params := factory()
	if err := json.Unmarshal(aux.Parameters, params); err != nil {
		return fmt.Errorf("failed to unmarshal parameters for task type %s: %w", t.Type, err)
	}
	t.Parameters = params
	return nil
}

// ResultEnvelope is the container for data sent from workers to the central store.
type ResultEnvelope struct {
	ScanID    string          `json:"scan_id"`
	TaskID    string          `json:"task_id"`
	Timestamp time.Time       `json:"timestamp"`
	Findings  []Finding       `json:"findings"`
	KGUpdates *KGUpdates      `json:"kg_updates,omitempty"`
	Artifacts json.RawMessage `json:"artifacts,omitempty"`
}

// Finding represents a specific security vulnerability or observation.
type Finding struct {
	ID             string          `json:"id"`
	ScanID         string          `json:"-"`
	TaskID         string          `json:"task_id"`
	Timestamp      time.Time       `json:"timestamp"`
	Target         string          `json:"target"`
	Module         string          `json:"module"`
	Vulnerability  string          `json:"vulnerability"`
	Severity       Severity        `json:"severity"`
	Description    string          `json:"description"`
	Evidence       json.RawMessage `json:"evidence,omitempty"`
	Recommendation string          `json:"recommendation,omitempty"`
	CWE            string          `json:"cwe,omitempty"`
}

// KGUpdates represents the interconnected data discovered during analysis.
type KGUpdates struct {
	Nodes []NodeInput `json:"nodes"`
	Edges []EdgeInput `json:"edges"`
}
```eof

---
### `pkg/schemas/parameters.go`

And finally, the specific parameter structs for each task type.

```go:Task Parameter Schemas:pkg/schemas/parameters.go
package schemas

import "net/http"

// This file defines the specific parameter structures for each task type.

type AgentMissionParams struct {
	MissionBrief string `json:"mission_brief"`
}

type TaintTaskParams struct {
	InteractionDepth int    `json:"interaction_depth"`
	FocusSelector    string `json:"focus_selector,omitempty"`
}

type ProtoPollutionTaskParams struct{}

type ATOTaskParams struct {
	Usernames    []string `json:"usernames"`
	PasswordList []string `json:"password_list,omitempty"`
}

type IDORTaskParams struct {
	HTTPMethod  string      `json:"http_method"`
	HTTPBody    []byte      `json:"http_body,omitempty"`
	HTTPHeaders http.Header `json:"http_headers"`
}

type JWTTaskParams struct {
	Token             string `json:"token"`
	BruteForceEnabled bool   `json:"brute_force_enabled"`
}

type RaceConditionTaskParams struct {
	HTTPMethod  string `json:"http_method"`
	HTTPBody    []byte `json:"http_body,omitempty"`
	Concurrency int    `json:"concurrency"`
}

type HeadersTaskParams struct{}
```eof