package schemas

import (
	"context"
	"encoding/json"
	"time"
)

// -- Store Interface --

// Store defines the interface for persisting and retrieving scan data.
// This allows the command logic to be decoupled from the concrete database implementation.
type Store interface {
	PersistData(ctx context.Context, data *ResultEnvelope) error
	GetFindingsByScanID(ctx context.Context, scanID string) ([]Finding, error)
}

// -- Engine Interfaces --

// DiscoveryEngine defines the interface for an engine that discovers potential tasks.
type DiscoveryEngine interface {
	Start(ctx context.Context, targets []string) (<-chan Task, error)
	Stop()
}

// TaskEngine defines the interface for an engine that executes tasks.
type TaskEngine interface {
	Start(ctx context.Context, taskChan <-chan Task)
	Stop()
}

// Orchestrator defines the interface for the scan orchestrator component.
type Orchestrator interface {
	StartScan(ctx context.Context, targets []string, scanID string) error
}

// -- Centralized Core Service Interfaces --

// KnowledgeGraphClient defines the canonical interface for interacting with the Knowledge Graph.
//
//go:generate mockery --name KnowledgeGraphClient --output ../../internal/mocks --outpkg mocks
type KnowledgeGraphClient interface {
	AddNode(ctx context.Context, node Node) error
	AddEdge(ctx context.Context, edge Edge) error
	GetNode(ctx context.Context, id string) (Node, error)
	// GetEdge retrieves an edge by its unique ID. Added for feature parity across implementations.
	GetEdge(ctx context.Context, id string) (Edge, error)
	GetEdges(ctx context.Context, nodeID string) ([]Edge, error)
	GetNeighbors(ctx context.Context, nodeID string) ([]Node, error)
	QueryImprovementHistory(ctx context.Context, goalObjective string, limit int) ([]Node, error)
}

// BrowserManager defines the canonical interface for managing browser processes and creating sessions.
type BrowserManager interface {
	NewAnalysisContext(
		sessionCtx context.Context,
		cfg interface{},
		persona Persona,
		taintTemplate string,
		taintConfig string,
		findingsChan chan<- Finding,
	) (SessionContext, error)
	Shutdown(ctx context.Context) error
}

// BrowserInteractor defines the canonical interface for high-level browser interactions.
type BrowserInteractor interface {
	NavigateAndExtract(ctx context.Context, url string) ([]string, error)
}

// SessionContext defines the interface for interacting with a specific browser session.
//
//go:generate mockery --name SessionContext --output ../../internal/mocks --outpkg mocks
type SessionContext interface {
	ID() string
	Navigate(ctx context.Context, url string) error
	Click(ctx context.Context, selector string) error
	Type(ctx context.Context, selector string, text string) error
	Submit(ctx context.Context, selector string) error
	ScrollPage(ctx context.Context, direction string) error
	WaitForAsync(ctx context.Context, milliseconds int) error
	ExposeFunction(ctx context.Context, name string, function interface{}) error
	InjectScriptPersistently(ctx context.Context, script string) error
	Interact(ctx context.Context, config InteractionConfig) error
	Close(ctx context.Context) error
	CollectArtifacts(ctx context.Context) (*Artifacts, error)
	AddFinding(ctx context.Context, finding Finding) error
	Sleep(ctx context.Context, d time.Duration) error
	DispatchMouseEvent(ctx context.Context, data MouseEventData) error
	SendKeys(ctx context.Context, keys string) error
	// DispatchStructuredKey handles pressing a structured key combination (like a shortcut).
	DispatchStructuredKey(ctx context.Context, data KeyEventData) error
	GetElementGeometry(ctx context.Context, selector string) (*ElementGeometry, error)
	ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error)
}

// HTTPClient defines the interface for making simple HTTP GET requests.
type HTTPClient interface {
	Get(ctx context.Context, url string) (body []byte, statusCode int, err error)
}

// -- LLM Client Schemas & Interface --

// ModelTier specifies a preference for performance vs. capability.
type ModelTier string

const (
	TierFast     ModelTier = "fast"
	TierPowerful ModelTier = "powerful"
)

type GenerationOptions struct {
	Temperature     float32 `json:"temperature"`
	ForceJSONFormat bool    `json:"force_json_format"`
	TopP            float32
	TopK            int
}

type GenerationRequest struct {
	SystemPrompt string            `json:"system_prompt"`
	UserPrompt   string            `json:"user_prompt"`
	Tier         ModelTier         `json:"tier"`
	Options      GenerationOptions `json:"options"`
}

// LLMClient defines the interface for interacting with a Large Language Model.
type LLMClient interface {
	Generate(ctx context.Context, req GenerationRequest) (string, error)
}

// -- OAST Schemas & Interface --

// OASTProvider is the contract for interacting with an OAST service.
type OASTProvider interface {
	GetInteractions(ctx context.Context, canaries []string) ([]OASTInteraction, error)
	GetServerURL() string
}

// OASTInteraction represents a detected interaction on the OAST server.
type OASTInteraction struct {
	Canary          string
	Protocol        string
	SourceIP        string
	InteractionTime time.Time
	RawRequest      string
}
