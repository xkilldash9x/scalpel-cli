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
	ScanID     string      `json:"scan_id"` // CRITICAL FIX: Added to track which scan this task belongs to.
	TaskID     string      `json:"task_id"`
	Type       TaskType    `json:"type"`
	TargetURL  string      `json:"target_url"`
	Parameters interface{} `json:"parameters,omitempty"`
}

// UnmarshalJSON provides custom deserialization logic for the Task struct,
// enabling the 'Parameters' field to be unmarshalled into the correct concrete struct
// based on the 'Type' field.
func (t *Task) UnmarshalJSON(data []byte) error {
	// Step 1: Unmarshal into a temporary struct to read the 'type' field.
	type temporaryTask struct {
		ScanID     string          `json:"scan_id"`
		TaskID     string          `json:"task_id"`
		Type       TaskType        `json:"type"`
		TargetURL  string          `json:"target_url"`
		Parameters json.RawMessage `json:"parameters"`
	}

	var temp temporaryTask
	if err := json.Unmarshal(data, &temp); err != nil {
		return fmt.Errorf("failed to unmarshal temporary task: %w", err)
	}

	// Step 2: Assign the known fields to the main struct.
	t.ScanID = temp.ScanID
	t.TaskID = temp.TaskID
	t.Type = temp.Type
	t.TargetURL = temp.TargetURL

	// Step 3: Switch on the task type to unmarshal parameters into the correct struct.
	switch t.Type {
	case TaskAgentMission:
		var params AgentMissionParams
		if err := json.Unmarshal(temp.Parameters, &params); err != nil {
			return fmt.Errorf("unmarshalling AgentMissionParams: %w", err)
		}
		t.Parameters = params
	case TaskAnalyzeWebPageTaint:
		var params TaintTaskParams
		if err := json.Unmarshal(temp.Parameters, &params); err != nil {
			return fmt.Errorf("unmarshalling TaintTaskParams: %w", err)
		}
		t.Parameters = params
	case TaskAnalyzeWebPageProtoPP:
		var params ProtoPollutionTaskParams
		if err := json.Unmarshal(temp.Parameters, &params); err != nil {
			return fmt.Errorf("unmarshalling ProtoPollutionTaskParams: %w", err)
		}
		t.Parameters = params
	case TaskTestAuthATO:
		var params ATOTaskParams
		if err := json.Unmarshal(temp.Parameters, &params); err != nil {
			return fmt.Errorf("unmarshalling ATOTaskParams: %w", err)
		}
		t.Parameters = params
	case TaskTestAuthIDOR:
		var params IDORTaskParams
		if err := json.Unmarshal(temp.Parameters, &params); err != nil {
			return fmt.Errorf("unmarshalling IDORTaskParams: %w", err)
		}
		t.Parameters = params
	case TaskAnalyzeJWT:
		var params JWTTaskParams
		if err := json.Unmarshal(temp.Parameters, &params); err != nil {
			return fmt.Errorf("unmarshalling JWTTaskParams: %w", err)
		}
		t.Parameters = params
	case TaskTestRaceCondition:
		var params RaceConditionTaskParams
		if err := json.Unmarshal(temp.Parameters, &params); err != nil {
			return fmt.Errorf("unmarshalling RaceConditionTaskParams: %w", err)
		}
		t.Parameters = params
	case TaskAnalyzeHeaders:
		var params HeadersTaskParams
		if err := json.Unmarshal(temp.Parameters, &params); err != nil {
			return fmt.Errorf("unmarshalling HeadersTaskParams: %w", err)
		}
		t.Parameters = params
	default:
		// If the type is unknown or has no parameters, leave them as nil.
		t.Parameters = nil
	}

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
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties"`
}

// KGEdge represents a relationship between two nodes for serialization.
type KGEdge struct {
	SourceID     string                 `json:"source_id"`
	TargetID     string                 `json:"target_id"`
	Relationship string                 `json:"relationship"`
	Properties   map[string]interface{} `json:"properties"`
	Timestamp    time.Time              `json:"timestamp"`
}
