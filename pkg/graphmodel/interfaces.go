package graphmodel

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/pkg/graphmodel"
)

// GraphStore defines the interface for interacting with the knowledge graph backend.
// It abstracts the storage implementation (in-memory, Postgres, etc.).
type GraphStore interface {
	// Writer operations
	AddNode(input graphmodel.NodeInput) (*graphmodel.Node, error)
	AddEdge(input graphmodel.EdgeInput) (*graphmodel.Edge, error)

	// Atomic operations (convenience methods that might use transactions or locks)
	RecordTechnology(assetId string, technologyName string, version string, source string, confidence float64, assetType graphmodel.NodeType) error
	RecordLink(sourceUrl string, targetUrl string, method string, depth int) error

	// Reader operations
	GetNodeByID(id string) (*graphmodel.Node, error)
	FindNodes(query graphmodel.Query) ([]*graphmodel.Node, error)
	GetNeighbors(nodeId string) (graphmodel.NeighborsResult, error)

	// Export and Contextualization
	ExportGraph() graphmodel.GraphExport
	// ExtractMissionSubgraph retrieves a localized subgraph relevant to the current mission.
	// This is critical for managing LLM context windows.
	ExtractMissionSubgraph(ctx context.Context, missionID string, lookbackSteps int) (graphmodel.GraphExport, error)

	// Utility
	InferAssetType(assetId string) graphmodel.NodeType
}
