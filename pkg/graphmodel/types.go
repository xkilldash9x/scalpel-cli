package graphmodel

import "time"

// NodeType defines the categories of entities in the graph.
type NodeType string

// RelationshipType defines the nature of the connection between nodes.
type RelationshipType string

// Constants for specific System Node IDs
// Using prefixes for system nodes prevents collision with asset IDs.
const (
	RootNodeID  = "SYSTEM:ROOT"
	OSINTNodeID = "SYSTEM:OSINT"
)

// Constants for Node Types (Entities)
const (
	// Metadata
	NodeTypeScanRoot   NodeType = "ScanRoot"
	NodeTypeDataSource NodeType = "DataSource"

	// Infrastructure Assets
	NodeTypeDomain    NodeType = "Domain"
	NodeTypeIPAddress NodeType = "IPAddress"
	NodeTypeURL       NodeType = "URL"
	NodeTypeBinary    NodeType = "Binary"

	// Application Components
	NodeTypeTechnology     NodeType = "Technology"
	NodeTypeAPIEndpoint    NodeType = "APIEndpoint"
	NodeTypeParameter      NodeType = "Parameter"
	NodeTypeBrowserStorage NodeType = "BrowserStorage"

	// Findings
	NodeTypeVulnerability NodeType = "Vulnerability"

	// Actors
	NodeTypeUserIdentity NodeType = "UserIdentity"

	// Agent Cognitive State
	NodeTypeMission     NodeType = "Mission"
	NodeTypeAction      NodeType = "Action"
	NodeTypeObservation NodeType = "Observation"
)

// Constants for Relationship Types (Edges)
const (
	// Structural
	RelationshipTypeLinksTo      RelationshipType = "LINKS_TO"
	RelationshipTypeRedirectsTo  RelationshipType = "REDIRECTS_TO"
	RelationshipTypeResolvesTo   RelationshipType = "RESOLVES_TO"
	RelationshipTypeHasParameter RelationshipType = "HAS_PARAMETER"
	RelationshipTypeContains     RelationshipType = "CONTAINS"

	// Operational
	RelationshipTypeUsesTechnology RelationshipType = "USES_TECHNOLOGY"
	RelationshipTypeDerivedFrom    RelationshipType = "DERIVED_FROM"
	RelationshipTypeDataFlowsTo    RelationshipType = "DATA_FLOWS_TO"

	// Findings
	RelationshipTypeAffects RelationshipType = "AFFECTS"

	// Agent Cognitive Relationships
	RelationshipTypeExecutesAction       RelationshipType = "EXECUTES_ACTION"
	RelationshipTypeGeneratesObservation RelationshipType = "GENERATES_OBSERVATION"
	RelationshipTypeInformsMission       RelationshipType = "INFORMS_MISSION"
	RelationshipTypeNextAction           RelationshipType = "NEXT_ACTION"
)

// Properties is a generic map for storing attributes.
// Note: Values must be comparable (no slices, maps, or functions) to be indexed efficiently.
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
	Timestamp    time.Time        `json:"timestamp"` // Timestamp of when the relationship was observed/updated.
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

// GraphExport is a structure for exporting the entire graph.
type GraphExport struct {
	Nodes []*Node `json:"nodes"`
	Edges []*Edge `json:"edges"`
}
