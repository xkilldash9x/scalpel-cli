package schemas

import (
	"encoding/json"
	"time"
	"fmt"
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
	SeverityInformational Severity = "INFORMATIONAL"
)

// Task defines the unit of work to be performed by a worker.
type Task struct {
	ScanID     string      `json:"scan_id"`
	TaskID     string      `json:"task_id"`
	Type       TaskType    `json:"type"`
	TargetURL  string      `json:"target_url"`
	Parameters interface{} `json:"parameters,omitempty"`
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

// -- Task Parameter Deserialization Logic --

// paramsFactory is a function type that returns a pointer to a new instance of a parameter struct.
type paramsFactory func() interface{}

// paramsRegistry maps TaskTypes to their corresponding factory functions.
var paramsRegistry = map[TaskType]paramsFactory{
	TaskAgentMission:        func() interface{} { return &AgentMissionParams{} },
	TaskAnalyzeWebPageTaint: func() interface{} { return &TaintTaskParams{} },
	TaskAnalyzeWebPageProtoPP: func() interface{} { return &ProtoPollutionTaskParams{} },
	TaskTestAuthATO:         func() interface{} { return &ATOTaskParams{} },
	TaskTestAuthIDOR:        func() interface{} { return &IDORTaskParams{} },
	TaskAnalyzeJWT:          func() interface{} { return &JWTTaskParams{} },
	TaskTestRaceCondition:   func() interface{} { return &RaceConditionTaskParams{} },
	TaskAnalyzeHeaders:      func() interface{} { return &HeadersTaskParams{} },
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
		return nil
	}

	params := factory()
	if err := json.Unmarshal(aux.Parameters, params); err != nil {
		return fmt.Errorf("failed to unmarshal parameters for task type %s: %w", t.Type, err)
	}

	t.Parameters = params
	return nil
}

// -- Placeholder Structs for Interface Contracts --
type Query struct{}
type NeighborsResult struct{}
type GraphExport struct{}