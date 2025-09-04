package interfaces

import (
	"context"
	"net/http"
	
	"github.com/chromedp/cdproto/runtime"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// -- Core Service Interfaces --

// TaskEngine defines the contract for the task processing system.
type TaskEngine interface {
	Start(ctx context.Context)
	Stop()
	SubmitTask(task schemas.Task) error
}

// Store defines the interface for the central data persistence layer.
type Store interface {
	PersistData(ctx context.Context, envelope *schemas.ResultEnvelope) error
	Close()
}

// -- Browser Interaction Interfaces --

// SessionManager defines the contract for managing browser lifecycles.
type SessionManager interface {
	InitializeSession(taskCtx context.Context) (SessionContext, error)
	Shutdown(ctx context.Context) error
}

// SessionContext manages a single, isolated browser tab and its instrumentation.
type SessionContext interface {
	ID() string
	GetContext() context.Context
	InjectScriptPersistently(script string) error
	ExposeFunction(name string, function interface{}) error
	Navigate(url string) error
	Click(selector string) error
	Type(selector, text string) error
	Submit(selector string) error
	ScrollPage(direction string) error
	Interact(config schemas.InteractionConfig) error
	CollectArtifacts() (*schemas.Artifacts, error)
	Close(ctx context.Context) error
}

// Executor defines a lower-level interface for sending commands to the browser.
type Executor interface {
	Execute(ctx context.Context, command string, res interface{}, params ...interface{}) error
	Evaluate(ctx context.Context, expression string, result **runtime.RemoteObject) error
}

// -- Knowledge Graph Interfaces --

// KnowledgeGraph defines the interface for interacting with the graph database.
type KnowledgeGraph interface {
	AddNode(ctx context.Context, input schemas.NodeInput) (*schemas.Node, error)
	AddEdge(ctx context.Context, input schemas.EdgeInput) (*schemas.Edge, error)
	GetNodeByID(ctx context.Context, id string) (*schemas.Node, error)
	FindNodes(ctx context.Context, query schemas.Query) ([]*schemas.Node, error)
	GetNeighbors(ctx context.Context, nodeID string) (schemas.NeighborsResult, error)
	ExportGraph(ctx context.Context) (schemas.GraphExport, error)
}

// -- Discovery & Analysis Interfaces --

// DiscoveryEngine defines the contract for the asset discovery phase.
type DiscoveryEngine interface {
	Run(ctx context.Context, initialURL string) error
}

// HTTPClient defines a standard interface for making HTTP requests.
type HTTPClient interface {
	Get(ctx context.Context, url string) (body []byte, statusCode int, err error)
	Post(ctx context.Context, url string, contentType string, body []byte) (*http.Response, error)
}