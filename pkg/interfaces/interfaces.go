// -- pkg/interfaces/interfaces.go --
package interfaces

import (
	"context"
	"net/http"
	"net/url"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/graphmodel"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// -- KnowledgeGraph Interfaces (Segregated) --

// KnowledgeGraphReader defines read-only operations for the Knowledge Graph.
// Components that only need to query or export graph data should depend on this.
type KnowledgeGraphReader interface {
	GetNodeByID(id string) (*graphmodel.Node, error)
	FindNodes(query graphmodel.Query) ([]*graphmodel.Node, error)
	GetNeighbors(nodeId string) (graphmodel.NeighborsResult, error)
	ExportGraph() graphmodel.GraphExport
}

// KnowledgeGraphWriter defines write-only operations for the Knowledge Graph.
// Components that add or modify graph data (like analyzers) should depend on this.
type KnowledgeGraphWriter interface {
	AddNode(input graphmodel.NodeInput) (*graphmodel.Node, error)
	AddEdge(input graphmodel.EdgeInput) (*graphmodel.Edge, error)
	RecordTechnology(assetId string, technologyName string, version string, source string, confidence float64, assetType graphmodel.NodeType) error
	RecordLink(sourceUrl string, targetUrl string, method string, depth int) error
}

// KnowledgeGraph composes the reader and writer interfaces for components
// that require full read/write access to the graph.
type KnowledgeGraph interface {
	KnowledgeGraphReader
	KnowledgeGraphWriter
}

// -- Other Core Interfaces --

// HTTPClient defines a standardized interface for making HTTP requests.
type HTTPClient interface {
	Get(ctx context.Context, url string) (body []byte, statusCode int, err error)
	Do(req *http.Request) (*http.Response, error)
}

// ScopeManager defines the contract for determining if a URL is in scope.
type ScopeManager interface {
	IsInScope(u *url.URL) bool
	GetRootDomain() string
}

// TaskSubmitter provides a way for components to submit new tasks to the engine.
type TaskSubmitter interface {
	SubmitTask(task schemas.Task) error
}

// EventBus provides a generic pub/sub mechanism with robust error handling.
type EventBus interface {
	Publish(ctx context.-,-.Context, topic string, payload []byte) error
	// Subscribe registers a handler for a topic. The handler must return an error
	// to signal a processing failure, or nil for success.
	Subscribe(ctx context.Context, topic string, handler func(payload []byte) error) error
}

// LLMClient defines a standardized interface for interacting with LLMs.
type LLMClient interface {
	GenerateResponse(ctx context.Context, systemPrompt string, userPrompt string) (string, error)
}

// SessionManager defines the interface for the headless browser pool.
type SessionManager interface {
	InitializeSession(ctx context.Context) (browser.SessionContext, error)
	Shutdown(ctx context.Context) error
}
