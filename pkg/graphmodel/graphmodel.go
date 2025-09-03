// File:         pkg/graphmodel/graphmodel.go
// Description:  This file contains the consolidated data models for the knowledge graph,
//               including critical cloning methods for concurrency safety.
//
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
// Consolidated from the former pkg/graphmodel/types.go
const (
	// Metadata
	NodeTypeScanRoot   NodeType = "ScanRoot"
	NodeTypeDataSource NodeType = "DataSource"

	// Infrastructure Assets
	NodeTypeDomain     NodeType = "Domain"
	NodeTypeIPAddress  NodeType = "IPAddress"
	NodeTypeURL        NodeType = "URL"
	NodeTypeBinary     NodeType = "Binary"
	NodeTypeIdentifier NodeType = "Identifier" // Fallback for IDs that don't match known patterns

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

	// Agent Artifacts
	NodeTypeTAOPolicyArtifact NodeType = "TAO_PolicyArtifact"
)

// Constants for Relationship Types (Edges)
// Consolidated from the former pkg/graphmodel/types.go
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
	RelationshipTypeNextAction           RelationshipType = "NEXT_ACTION" // Allows self-referencing edges

	// Agent Artifact Relationships
	RelationshipTypeGeneratesArtifact RelationshipType = "GENERATES_ARTIFACT"
	RelationshipTypeAppliesTo         RelationshipType = "APPLIES_TO"
)

// Properties is a generic map for storing attributes.
// Note: Values must be comparable (no slices, maps, or functions) to be indexed efficiently in the in-memory KG.
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

// GraphExport is a structure for exporting the entire graph or a subgraph.
type GraphExport struct {
	Nodes []*Node `json:"nodes"`
	Edges []*Edge `json:"edges"`
}

// --- Deep Copy and Cloning Methods ---

// DeepCopy creates a true copy of the Properties map.
// This is essential for preventing external modifications to internal graph state.
func (p Properties) DeepCopy() Properties {
	if p == nil {
		return nil
	}
	copy := make(Properties, len(p))
	for k, v := range p {
		// Assumes primitive, comparable values as required for indexing.
		copy[k] = v
	}
	return copy
}

// Clone creates a deep copy of a Node.
// CRITICAL FIX: This prevents data races by ensuring callers receive a copy
// of the node, not a pointer to the internal state of the in-memory graph.
func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}
	return &Node{
		ID:         n.ID,
		Type:       n.Type,
		Properties: n.Properties.DeepCopy(), // Crucial: Copy the properties map.
		CreatedAt:  n.CreatedAt,
		UpdatedAt:  n.UpdatedAt,
	}
}

// Clone creates a deep copy of an Edge.
// CRITICAL FIX: Prevents data races in the same way as the Node.Clone method.
func (e *Edge) Clone() *Edge {
	if e == nil {
		return nil
	}
	return &Edge{
		SourceID:     e.SourceID,
		TargetID:     e.TargetID,
		Relationship: e.Relationship,
		Properties:   e.Properties.DeepCopy(), // Crucial: Copy the properties map.
		Timestamp:    e.Timestamp,
	}
}
