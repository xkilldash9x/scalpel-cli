package schemas

import (
	"context"
	"encoding/json"
	"time"
)

// -- Store Interface --

// Store defines a generic interface for a persistent storage system for scan
// data. This abstraction allows the application to be independent of the
// specific database implementation (e.g., PostgreSQL, in-memory).
type Store interface {
	// PersistData saves a collection of findings and other results from a task
	// to the data store.
	PersistData(ctx context.Context, data *ResultEnvelope) error
	// GetFindingsByScanID retrieves all findings associated with a specific scan ID.
	GetFindingsByScanID(ctx context.Context, scanID string) ([]Finding, error)
}

// -- Engine Interfaces --

// DiscoveryEngine is responsible for discovering new tasks from a set of initial
// targets. It could be a web crawler, a file system scanner, or any other
// mechanism that identifies units of work.
type DiscoveryEngine interface {
	// Start begins the discovery process and returns a channel from which new
	// Tasks can be read.
	Start(ctx context.Context, targets []string) (<-chan Task, error)
	// Stop gracefully terminates the discovery process.
	Stop()
}

// TaskEngine is responsible for executing a stream of tasks. It manages a pool
// of workers to process tasks concurrently.
type TaskEngine interface {
	// Start begins processing tasks from the provided channel.
	Start(ctx context.Context, taskChan <-chan Task)
	// Stop gracefully terminates the task execution engine.
	Stop()
}

// Orchestrator coordinates the entire scan process, from discovery to task
// execution and result processing. It's the central component that ties the
// different engines together.
type Orchestrator interface {
	// StartScan initiates a new scan for a given set of targets and a unique scan ID.
	StartScan(ctx context.Context, targets []string, scanID string) error
}

// -- Centralized Core Service Interfaces --

// KnowledgeGraphClient defines the standard interface for all interactions with
// the knowledge graph. It provides methods for adding, retrieving, and querying
// nodes and edges, abstracting the underlying graph database.
//
//go:generate mockery --name KnowledgeGraphClient --output ../../internal/mocks --outpkg mocks
type KnowledgeGraphClient interface {
	// AddNode adds a new node to the knowledge graph.
	AddNode(ctx context.Context, node Node) error
	// AddEdge adds a new edge between two nodes in the knowledge graph.
	AddEdge(ctx context.Context, edge Edge) error
	// GetNode retrieves a node by its unique ID.
	GetNode(ctx context.Context, id string) (Node, error)
	// GetEdge retrieves an edge by its unique ID.
	GetEdge(ctx context.Context, id string) (Edge, error)
	// GetEdges retrieves all edges connected to a specific node.
	GetEdges(ctx context.Context, nodeID string) ([]Edge, error)
	// GetNeighbors retrieves all nodes directly connected to a specific node.
	GetNeighbors(ctx context.Context, nodeID string) ([]Node, error)
	// QueryImprovementHistory searches for past self-improvement attempts related
	// to a specific objective.
	QueryImprovementHistory(ctx context.Context, goalObjective string, limit int) ([]Node, error)
}

// BrowserManager is responsible for the lifecycle of browser instances. It can
// launch new browser processes and create isolated sessions (contexts) for
// analysis.
type BrowserManager interface {
	// NewAnalysisContext creates a new, isolated browser session tailored for
	// security analysis, complete with a specified persona and taint tracking
	// configuration.
	NewAnalysisContext(
		sessionCtx context.Context,
		cfg interface{},
		persona Persona,
		taintTemplate string,
		taintConfig string,
		findingsChan chan<- Finding,
	) (SessionContext, error)
	// Shutdown gracefully terminates all browser instances managed by this manager.
	Shutdown(ctx context.Context) error
}

// BrowserInteractor provides a simplified, high-level interface for common
// browser interactions, such as navigating to a page and extracting all links.
type BrowserInteractor interface {
	// NavigateAndExtract loads a URL and returns a list of all discovered links.
	NavigateAndExtract(ctx context.Context, url string) ([]string, error)
}

// SessionContext defines the interface for controlling a single browser tab or
// session. It provides a rich set of methods for navigation, interaction,
// script execution, and artifact collection.
//
//go:generate mockery --name SessionContext --output ../../internal/mocks --outpkg mocks
type SessionContext interface {
	ID() string                                                                  // Returns the unique ID of the session.
	Navigate(ctx context.Context, url string) error                              // Navigates the session to a new URL.
	Click(ctx context.Context, selector string) error                            // Clicks on an element matching the selector.
	Type(ctx context.Context, selector string, text string) error                // Types text into an element.
	Submit(ctx context.Context, selector string) error                           // Submits a form.
	ScrollPage(ctx context.Context, direction string) error                      // Scrolls the page up or down.
	WaitForAsync(ctx context.Context, milliseconds int) error                    // Waits for a specified period.
	ExposeFunction(ctx context.Context, name string, function interface{}) error // Exposes a Go function to the browser's JS context.
	InjectScriptPersistently(ctx context.Context, script string) error           // Injects a script that persists across navigations.
	Interact(ctx context.Context, config InteractionConfig) error                // Executes a complex sequence of interactions.
	Close(ctx context.Context) error                                             // Closes the browser session.
	CollectArtifacts(ctx context.Context) (*Artifacts, error)                    // Gathers all available data (HAR, DOM, etc.).
	AddFinding(ctx context.Context, finding Finding) error                       // Reports a new finding discovered in this session.
	Sleep(ctx context.Context, d time.Duration) error                            // Pauses execution for a duration.
	DispatchMouseEvent(ctx context.Context, data MouseEventData) error           // Dispatches a low-level mouse event.
	SendKeys(ctx context.Context, keys string) error                             // Sends a sequence of keystrokes.
	// DispatchStructuredKey sends a key press event with modifiers (e.g., Ctrl+C).
	DispatchStructuredKey(ctx context.Context, data KeyEventData) error
	GetElementGeometry(ctx context.Context, selector string) (*ElementGeometry, error)             // Gets the geometry of an element.
	ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) // Executes a JavaScript snippet.
}

// HTTPClient provides a simple interface for making HTTP GET requests. It's used
// for basic network operations where the full power of a browser is not required.
type HTTPClient interface {
	// Get performs an HTTP GET request to the specified URL and returns the
	// response body, status code, and any error that occurred.
	Get(ctx context.Context, url string) (body []byte, statusCode int, err error)
}

// -- LLM Client Schemas & Interface --

// ModelTier allows for selecting a large language model based on a preference
// for speed versus advanced capabilities.
type ModelTier string

const (
	TierFast     ModelTier = "fast"     // Prefers a faster, potentially less capable model.
	TierPowerful ModelTier = "powerful" // Prefers a more capable, potentially slower model.
)

// GenerationOptions provides detailed parameters to control the text generation
// process of the LLM, such as creativity (temperature) and output format.
type GenerationOptions struct {
	Temperature     float64 `json:"temperature"`       // Controls randomness. Lower is more deterministic.
	ForceJSONFormat bool    `json:"force_json_format"` // If true, forces the model to output valid JSON.
	TopP            float64 `json:"top_p"`             // Nucleus sampling parameter.
	TopK            int     `json:"top_k"`             // Top-k sampling parameter.
}

// GenerationRequest encapsulates a complete request to the LLM, including the
// system and user prompts, the desired model tier, and generation options.
type GenerationRequest struct {
	SystemPrompt string            `json:"system_prompt"` // Instructions for the model's persona and task.
	UserPrompt   string            `json:"user_prompt"`   // The specific query or input from the user.
	Tier         ModelTier         `json:"tier"`          // The desired model tier (fast or powerful).
	Options      GenerationOptions `json:"options"`       // Advanced generation parameters.
}

// LLMClient defines a standard interface for interacting with a Large Language
// Model, abstracting the specifics of the underlying provider (e.g., Gemini).
type LLMClient interface {
	// Generate produces a text completion based on the provided request.
	Generate(ctx context.Context, req GenerationRequest) (string, error)
	// Close cleans up any resources held by the client (e.g., network connections, SDK resources).
	Close() error
}

// -- OAST Schemas & Interface --

// OASTProvider defines the interface for an Out-of-Band Application Security
// Testing service. It provides a way to check for interactions with a public
// server initiated by the target application.
type OASTProvider interface {
	// GetInteractions queries the OAST server for any interactions that match a
	// given list of canary tokens.
	GetInteractions(ctx context.Context, canaries []string) ([]OASTInteraction, error)
	// GetServerURL returns the public URL of the OAST server, which can be used
	// in payloads.
	GetServerURL() string
}

// OASTInteraction represents a single interaction (e.g., an HTTP request or DNS
// lookup) received by the OAST server.
type OASTInteraction struct {
	Canary          string    // The unique canary token that triggered the interaction.
	Protocol        string    // The protocol of the interaction (e.g., "HTTP", "DNS").
	SourceIP        string    // The IP address from which the interaction originated.
	InteractionTime time.Time // The timestamp of the interaction.
	RawRequest      string    // The raw request data, if available.
}
