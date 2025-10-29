package schemas

import (
	"encoding/json"
	"time"
)

// ObservationType defines the category of an observation made by an agent.
type ObservationType string

const (
	ObservationSystemState     ObservationType = "SYSTEM_STATE"
	ObservationCodebaseContext ObservationType = "CODEBASE_CONTEXT"
	ObservationEvolutionResult ObservationType = "EVOLUTION_RESULT"
)

// -- Canonical Knowledge Graph Data Model --

// NodeType defines the type of a node in the knowledge graph.
type NodeType string

const (
	NodeHost               NodeType = "HOST"
	NodeIPAddress          NodeType = "IP_ADDRESS"
	NodeURL                NodeType = "URL"
	NodeCookie             NodeType = "COOKIE"
	NodeHeader             NodeType = "HEADER"
	NodeTechnology         NodeType = "TECHNOLOGY"
	NodeVulnerability      NodeType = "VULNERABILITY"
	NodeAction             NodeType = "ACTION"
	NodeObservation        NodeType = "OBSERVATION"
	NodeTool               NodeType = "TOOL"
	NodeFile               NodeType = "FILE"
	NodeDomain             NodeType = "DOMAIN"
	NodeFunction           NodeType = "FUNCTION"
	NodeMission            NodeType = "MISSION"
	NodeImprovementAttempt NodeType = "IMPROVEMENT_ATTEMPT"
)

// RelationshipType defines the type of an edge between nodes.
type RelationshipType string

const (
	RelationshipResolvesTo     RelationshipType = "RESOLVES_TO"
	RelationshipLinksTo        RelationshipType = "LINKS_TO"
	RelationshipUses           RelationshipType = "USES"
	RelationshipHas            RelationshipType = "HAS"
	RelationshipExposes        RelationshipType = "EXPOSES"
	RelationshipExecuted       RelationshipType = "EXECUTED"
	RelationshipHasObservation RelationshipType = "HAS_OBSERVATION"
	RelationshipImports        RelationshipType = "IMPORTS"
	RelationshipHostsURL       RelationshipType = "HOSTS_URL"
	RelationshipHasSubdomain   RelationshipType = "HAS_SUBDOMAIN"
	RelationshipAttempted      RelationshipType = "ATTEMPTED"
)

// NodeStatus defines the state of a node, useful for tracking analysis progress.
type NodeStatus string

const (
	StatusNew        NodeStatus = "NEW"
	StatusProcessing NodeStatus = "PROCESSING"
	StatusAnalyzed   NodeStatus = "ANALYZED"
	StatusError      NodeStatus = "ERROR"
	StatusSuccess    NodeStatus = "SUCCESS"
	StatusFailure    NodeStatus = "FAILURE"
)

// Node represents a single entity in the Knowledge Graph.
type Node struct {
	ID         string          `json:"id"`
	Type       NodeType        `json:"type"`
	Label      string          `json:"label"`
	Status     NodeStatus      `json:"status"`
	Properties json.RawMessage `json:"properties"`
	CreatedAt  time.Time       `json:"created_at"`
	LastSeen   time.Time       `json:"last_seen"`
}

// Edge represents a directed, labeled relationship between two nodes.
type Edge struct {
	ID         string           `json:"id"`
	From       string           `json:"from"`
	To         string           `json:"to"`
	Type       RelationshipType `json:"type"`
	Label      string           `json:"label"`
	Properties json.RawMessage  `json:"properties"`
	CreatedAt  time.Time        `json:"created_at"`
	LastSeen   time.Time        `json:"last_seen"`
}

// Subgraph represents a localized view of the Knowledge Graph, used for context passing.
type Subgraph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// -- Knowledge Graph Property Schemas --

// FileNodeProperties defines the structured properties for a NodeFile.
type FileNodeProperties struct {
	FilePath string `json:"file_path"`
	Language string `json:"language"`
}

// FunctionNodeProperties defines the structured properties for a NodeFunction.
type FunctionNodeProperties struct {
	StartLine  int  `json:"start_line"`
	EndLine    int  `json:"end_line"`
	IsExported bool `json:"is_exported"`
}

// ImprovementAttemptProperties defines the structured properties for a NodeImprovementAttempt.
type ImprovementAttemptProperties struct {
	GoalObjective string                 `json:"goal_objective"`
	StrategyDesc  string                 `json:"strategy_description"`
	ActionType    string                 `json:"action_type"`
	ActionPayload map[string]interface{} `json:"action_payload"`
	OutcomeOutput string                 `json:"outcome_output"`
}

// -- Input Schemas for Bulk Operations --

// NodeInput is a helper struct for bulk inserting or updating nodes.
type NodeInput struct {
	ID         string          `json:"id"`
	Type       NodeType        `json:"type"`
	Label      string          `json:"label"`
	Status     NodeStatus      `json:"status"`
	Properties json.RawMessage `json:"properties"`
}

// EdgeInput is a helper struct for bulk inserting or updating edges.
type EdgeInput struct {
	ID         string           `json:"id"`
	From       string           `json:"from"`
	To         string           `json:"to"`
	Type       RelationshipType `json:"type"`
	Label      string           `json:"label"`
	Properties json.RawMessage  `json:"properties"`
}

// -- Communication & Result Schemas --

// KnowledgeGraphUpdate is a container for bulk updates to the Knowledge Graph.
type KnowledgeGraphUpdate struct {
	NodesToAdd []NodeInput `json:"nodes_to_add"`
	EdgesToAdd []EdgeInput `json:"edges_to_add"`
}
