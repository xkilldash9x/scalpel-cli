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

// -- KnowledgeGraph Interface --

// KnowledgeGraph defines the complete set of operations for interacting with the knowledge graph.
// It abstracts the underlying storage implementation (e.g., in-memory, Postgres), allowing
// different parts of the application to interact with the graph via a stable contract.
type KnowledgeGraph interface {
	// -- Write Operations --
	AddNode(input graphmodel.NodeInput) (*graphmodel.Node, error)
	AddEdge(input graphmodel.EdgeInput) (*graphmodel.Edge, error)

	// -- Atomic Write Operations --
	// These are convenience methods that handle transactional or multi-step logic.
	RecordTechnology(assetId string, technologyName string, version string, source string, confidence float64, assetType graphmodel.NodeType) error
	RecordLink(sourceUrl string, targetUrl string, method string, depth int) error

	// -- Read Operations --
	GetNodeByID(id string) (*graphmodel.Node, error)
	FindNodes(query graphmodel.Query) ([]*graphmodel.Node, error)
	GetNeighbors(nodeId string) (graphmodel.NeighborsResult, error)

	// -- Export and Contextualization --
	ExportGraph() graphmodel.GraphExport
	// ExtractMissionSubgraph retrieves a localized subgraph relevant to a specific mission,
	// which is critical for managing context windows for AI agents.
	ExtractMissionSubgraph(ctx context.Context, missionID string, lookbackSteps int) (graphmodel.GraphExport, error)

	// -- Utility Methods --
	InferAssetType(assetId string) graphmodel.NodeType
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
	Publish(ctx context.Context, topic string, payload []byte) error
	// Subscribe registers a handler for a topic. The handler must return an error
	// to signal a processing failure, or nil for success.
	Subscribe(ctx context.Context, topic string, handler func(payload []byte) error) error
}

// GenerationOptions holds parameters for controlling LLM generation.
type GenerationOptions struct {
	// Temperature controls the creativity of the response. Lower is more deterministic.
	Temperature float32
	// MaxTokens sets the maximum length of the generated response.
	MaxTokens int
	// ForceJSONFormat indicates to the LLM provider to enforce JSON output mode if available.
	ForceJSONFormat bool
}

// GenerationRequest encapsulates all inputs for a single LLM API call.
type GenerationRequest struct {
	SystemPrompt string
	UserPrompt   string
	Options      GenerationOptions
}

// LLMClient defines the interface for interacting with a Large Language Model.
// It abstracts the specific provider (e.g., Gemini, OpenAI) away from the agent logic.
type LLMClient interface {
	// GenerateResponse sends a structured request to the LLM and returns the text content.
	GenerateResponse(ctx context.Context, req GenerationRequest) (string, error)
}

// SessionManager defines the interface for the headless browser pool.
type SessionManager interface {
	InitializeSession(ctx context.Context) (browser.SessionContext, error)
	Shutdown(ctx context.Context) error
}