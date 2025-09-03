// pkg/schemas/schemas.go
package schemas

import (
	"encoding/json"
	"fmt"
	"time"
)

// TaskType defines the valid types of tasks the engine can process.
type TaskType string

const (
	// Agent Tasks
	TaskAgentMission TaskType = "AGENT_MISSION"

	// Active Analysis Tasks
	TaskAnalyzeWebPageTaint   TaskType = "ANALYZE_WEB_PAGE_TAINT"
	TaskAnalyzeWebPageProtoPP TaskType = "ANALYZE_WEB_PAGE_PROTOPP"
	TaskTestRaceCondition     TaskType = "TEST_RACE_CONDITION"

	// Authentication Analysis Tasks
	TaskTestAuthATO  TaskType = "TEST_AUTH_ATO"
	TaskTestAuthIDOR TaskType = "TEST_AUTH_IDOR"

	// Passive and Static Analysis Tasks
	TaskAnalyzeHeaders TaskType = "ANALYZE_HEADERS"
	TaskAnalyzeJWT     TaskType = "ANALYZE_JWT"
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
	// ScanID identifies the overall scan operation this task belongs to.
	ScanID     string      `json:"scan_id"`
	TaskID     string      `json:"task_id"`
	Type       TaskType    `json:"type"`
	TargetURL  string      `json:"target_url"`
	Parameters interface{} `json:"parameters,omitempty"`
}

// paramsFactory is a function type that returns a pointer to a new instance of a parameter struct.
type paramsFactory func() interface{}

// paramsRegistry maps TaskTypes to their corresponding factory functions.
// This centralizes the mapping and enables dynamic unmarshalling.
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
	// Step 1: Use an optimized technique to avoid recursion and boilerplate.
	// Define an Alias of the Task type.
	type TaskAlias Task
	// Define an auxiliary struct that embeds a pointer to the alias (*TaskAlias)
	// and overrides the Parameters field to capture it as json.RawMessage.
	aux := struct {
		*TaskAlias
		Parameters json.RawMessage `json:"parameters,omitempty"`
	}{
		TaskAlias: (*TaskAlias)(t), // Point the embedded field to the receiver 't'.
	}

	// Unmarshal the data. This populates 't' directly (via the embedded pointer)
	// and captures the raw parameters, eliminating the need for manual field copying.
	if err := json.Unmarshal(data, &aux); err != nil {
		return fmt.Errorf("failed to unmarshal base task structure: %w", err)
	}

	// Step 2: Handle cases where parameters are missing or explicitly null.
	if len(aux.Parameters) == 0 || string(aux.Parameters) == "null" {
		// No parameters provided. t.Parameters remains nil.
		return nil
	}

	// Step 3: Use the registry to find the constructor for the specific TaskType.
	factory, ok := paramsRegistry[t.Type]
	if !ok {
		// Error Handling: Fail fast if the task type is unknown.
		return fmt.Errorf("unknown or unsupported task type encountered: %s", t.Type)
	}

	// Step 4: Create the parameter struct instance (as a pointer) and unmarshal.
	params := factory()
	if err := json.Unmarshal(aux.Parameters, params); err != nil {
		// Provide specific context about which type failed.
		return fmt.Errorf("failed to unmarshal parameters for task type %s: %w", t.Type, err)
	}

	// Step 5: Assign the pointer to the interface field.
	// This is efficient (no boxing/copying).
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
	ScanID         string          `json:"-"` // Excluded from user-facing JSON, used internally.
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
	Nodes []KGNode `json:"nodes"`
	Edges []KGEdge `json:"edges"`
}

// KGNode represents an entity for serialization.
type KGNode struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	// Use RawMessage to defer parsing of dynamic properties.
	Properties json.RawMessage `json:"properties"`
}

// KGEdge represents a relationship between two nodes for serialization.
type KGEdge struct {
	SourceID     string `json:"source_id"`
	TargetID     string `json:"target_id"`
	Relationship string `json:"relationship"`
	// Use RawMessage to defer parsing of dynamic properties.
	Properties json.RawMessage `json:"properties"`
	Timestamp  time.Time       `json:"timestamp"`
}