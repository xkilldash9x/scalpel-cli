package schemas

import (
	"encoding/json"
	"time"
)

// ObservationType categorizes an observation made by an autonomous agent,
// providing context about what the information represents.
type ObservationType string

const (
	ObservationSystemState     ObservationType = "SYSTEM_STATE"     // An observation about the state of the system or environment.
	ObservationCodebaseContext ObservationType = "CODEBASE_CONTEXT" // An observation about the structure or content of the codebase.
	ObservationEvolutionResult ObservationType = "EVOLUTION_RESULT" // The result of a self-improvement or evolution attempt.
)

// -- Canonical Knowledge Graph Data Model --

// NodeType represents the specific type of an entity (node) in the knowledge graph.
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

// RelationshipType defines the semantic type of a relationship (edge) between
// two nodes in the knowledge graph.
type RelationshipType string

const (
	RelationshipResolvesTo     RelationshipType = "RESOLVES_TO"     // e.g., A HOST resolves to an IP_ADDRESS.
	RelationshipLinksTo        RelationshipType = "LINKS_TO"        // e.g., A URL links to another URL.
	RelationshipUses           RelationshipType = "USES"           // e.g., A HOST uses a TECHNOLOGY.
	RelationshipHas            RelationshipType = "HAS"            // e.g., A HOST has a COOKIE.
	RelationshipExposes        RelationshipType = "EXPOSES"        // e.g., A URL exposes a VULNERABILITY.
	RelationshipExecuted       RelationshipType = "EXECUTED"       // e.g., An AGENT executed a TOOL.
	RelationshipHasObservation RelationshipType = "HAS_OBSERVATION" // e.g., An ACTION has an OBSERVATION.
	RelationshipImports        RelationshipType = "IMPORTS"        // e.g., A FILE imports another FILE.
	RelationshipHostsURL       RelationshipType = "HOSTS_URL"       // e.g., A HOST hosts a URL.
	RelationshipHasSubdomain   RelationshipType = "HAS_SUBDOMAIN"  // e.g., A DOMAIN has a SUBDOMAIN.
	RelationshipAttempted      RelationshipType = "ATTEMPTED"      // e.g., A MISSION attempted an IMPROVEMENT_ATTEMPT.
)

// NodeStatus tracks the lifecycle state of a node within the knowledge graph,
// often used to manage analysis workflows. The values are lowercase to match the
// corresponding ENUM in the PostgreSQL database.
type NodeStatus string

const (
	StatusNew        NodeStatus = "new"        // The node has been discovered but not yet processed.
	StatusProcessing NodeStatus = "processing" // The node is currently being analyzed.
	StatusAnalyzed   NodeStatus = "analyzed"   // The node has been fully analyzed.
	StatusError      NodeStatus = "error"      // An error occurred during the analysis of the node.
	StatusSuccess    NodeStatus = "success"    // A process involving the node completed successfully.
	StatusFailure    NodeStatus = "failure"   // A process involving the node failed.
)

// Node represents a single entity or concept in the Knowledge Graph. Each node
// has a unique ID, a type, a label for display, and a set of properties that
// store detailed, structured information.
type Node struct {
	ID         string          `json:"id"`
	Type       NodeType        `json:"type"`
	Label      string          `json:"label"`
	Status     NodeStatus      `json:"status"`
	Properties json.RawMessage `json:"properties"` // Flexible JSONB field for type-specific data.
	CreatedAt  time.Time       `json:"created_at"`
	LastSeen   time.Time       `json:"last_seen"`
}

// Edge represents a directed, typed, and labeled relationship between two nodes
// in the Knowledge Graph. It connects a 'from' node to a 'to' node and can
// have its own set of properties.
type Edge struct {
	ID         string           `json:"id"`
	From       string           `json:"from"` // The ID of the source node.
	To         string           `json:"to"`   // The ID of the target node.
	Type       RelationshipType `json:"type"`
	Label      string           `json:"label"`
	Properties json.RawMessage  `json:"properties"`
	CreatedAt  time.Time        `json:"created_at"`
	LastSeen   time.Time        `json:"last_seen"`
}

// Subgraph represents a subset of the full Knowledge Graph, containing a
// collection of nodes and the edges that connect them. It is often used to pass
// relevant context to different parts of the system.
type Subgraph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// -- Knowledge Graph Property Schemas --

// FileNodeProperties contains the specific attributes for a node of type NodeFile.
type FileNodeProperties struct {
	FilePath string `json:"file_path"` // The full path to the file.
	Language string `json:"language"`  // The programming language of the file.
}

// FunctionNodeProperties contains the specific attributes for a node of type NodeFunction.
type FunctionNodeProperties struct {
	StartLine  int  `json:"start_line"`   // The starting line number of the function in the file.
	EndLine    int  `json:"end_line"`     // The ending line number of the function.
	IsExported bool `json:"is_exported"` // Whether the function is exported for external use.
}

// ImprovementAttemptProperties contains the specific attributes for a node of
// type NodeImprovementAttempt, capturing the details of a self-healing or
// evolution action.
type ImprovementAttemptProperties struct {
	GoalObjective string                 `json:"goal_objective"`      // The high-level goal being pursued.
	StrategyDesc  string                 `json:"strategy_description"` // The strategy devised to achieve the goal.
	ActionType    string                 `json:"action_type"`         // The specific type of action taken.
	ActionPayload map[string]interface{} `json:"action_payload"`      // The parameters and data used in the action.
	OutcomeOutput string                 `json:"outcome_output"`      // The result or output of the action.
}

// -- Input Schemas for Bulk Operations --

// NodeInput is a data structure used for efficiently adding or updating nodes
// in bulk. It contains all the necessary information to create a new node.
type NodeInput struct {
	ID         string          `json:"id"`
	Type       NodeType        `json:"type"`
	Label      string          `json:"label"`
	Status     NodeStatus      `json:"status"`
	Properties json.RawMessage `json:"properties"`
}

// EdgeInput is a data structure used for efficiently adding or updating edges
// in bulk. It defines a relationship between two nodes.
type EdgeInput struct {
	ID         string           `json:"id"`
	From       string           `json:"from"`
	To         string           `json:"to"`
	Type       RelationshipType `json:"type"`
	Label      string           `json:"label"`
	Properties json.RawMessage  `json:"properties"`
}

// -- Communication & Result Schemas --

// KnowledgeGraphUpdate serves as a container for a set of changes to be applied
// to the knowledge graph. It allows for batching node and edge additions into a
// single, atomic update.
type KnowledgeGraphUpdate struct {
	NodesToAdd []NodeInput `json:"nodes_to_add"`
	EdgesToAdd []EdgeInput `json:"edges_to_add"`
}
