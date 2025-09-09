package schemas

import "time"

// TaskType defines the type of task to be performed.
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

// Severity defines the severity level of a finding.
type Severity string

const (
	SeverityCritical      Severity = "CRITICAL"
	SeverityHigh          Severity = "HIGH"
	SeverityMedium        Severity = "MEDIUM"
	SeverityLow           Severity = "LOW"
	SeverityInformational Severity = "INFORMATIONAL"
)

// NodeType defines the type of a node in the knowledge graph.
type NodeType string

// RelationshipType defines the type of a relationship (edge) in the knowledge graph.
type RelationshipType string

// Vulnerability holds details about a specific vulnerability.
type Vulnerability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Finding represents a security finding.
type Finding struct {
	Vulnerability  Vulnerability     `json:"vulnerability"`
	Severity       Severity          `json:"severity"`
	Recommendation string            `json:"recommendation"`
	CWE            []string          `json:"cwe"`
	Properties     map[string]string `json:"properties"`
}

// ResultEnvelope contains the results of an analysis task.
type ResultEnvelope struct {
	TaskID    string    `json:"task_id"`
	Findings  []Finding `json:"findings"`
	Timestamp time.Time `json:"timestamp"`
}

// Node represents a node in the knowledge graph.
type Node struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Properties map[string]interface{} `json:"properties"`
	Status     string                 `json:"status"`
	CreatedAt  time.Time              `json:"created_at"`
	LastSeen   time.Time              `json:"last_seen"`
}

// Edge represents a relationship between two nodes in the knowledge graph.
type Edge struct {
	ID         string                 `json:"id"`
	From       string                 `json:"from"`
	To         string                 `json:"to"`
	Label      RelationshipType       `json:"label"`
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time              `json:"created_at"`
}

// NodeInput is used for creating or updating nodes.
type NodeInput struct {
	ID         string                 `json:"id"`
	Type       NodeType               `json:"type"`
	Properties map[string]interface{} `json:"properties"`
}

// EdgeInput is used for creating or updating edges.
type EdgeInput struct {
	From  string           `json:"from"`
	To    string           `json:"to"`
	Label RelationshipType `json:"label"`
}