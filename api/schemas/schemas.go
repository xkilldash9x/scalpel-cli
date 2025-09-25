// api/schemas.go
package schemas

import (
	"context"
	"encoding/json"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
)

// -- Task & Finding Schemas --

// TaskType defines the type of task to be executed by a module.
type TaskType string

const (
	TaskAgentMission          TaskType = "AGENT_MISSION"
	TaskAnalyzeWebPageTaint   TaskType = "ANALYZE_WEB_PAGE_TAINT"
	TaskAnalyzeWebPageProtoPP TaskType = "ANALYZE_WEB_PAGE_PROTOPP"
	TaskTestRaceCondition     TaskType = "TEST_RACE_CONDITION"
	TaskTestAuthATO           TaskType = "TEST_AUTH_ATO"
	TaskTestAuthIDOR          TaskType = "TEST_AUTH_IDOR"
	TaskAnalyzeHeaders        TaskType = "ANALYZE_HEADERS"
	TaskAnalyzeJWT            TaskType = "ANALYZE_JWT"
)

// Task represents a unit of work to be executed by the engine.
// This is central to how the system decouples discovery from execution.
type Task struct {
	TaskID     string      `json:"task_id"`
	ScanID     string      `json:"scan_id"`
	Type       TaskType    `json:"type"`
	TargetURL  string      `json:"target_url"`
	Parameters interface{} `json:"parameters"` // Holds task specific configuration.
}

// -- Task Parameter Definitions --

// ATOTaskParams defines parameters for the Account Takeover task.
type ATOTaskParams struct {
	Usernames []string `json:"usernames"`
}

// IDORTaskParams defines parameters for the IDOR task.
type IDORTaskParams struct {
	HTTPMethod  string            `json:"http_method"`
	HTTPBody    string            `json:"http_body"`
	HTTPHeaders map[string]string `json:"http_headers"`
}

// JWTTaskParams defines parameters for the JWT analysis task.
type JWTTaskParams struct {
	Token string `json:"token"`
}

// AgentMissionParams defines parameters for the Agent mission task.
type AgentMissionParams struct {
	MissionBrief string `json:"mission_brief"`
}

// Severity defines the severity level of a finding.
type Severity string

const (
	SeverityCritical      Severity = "CRITICAL"
	SeverityHigh          Severity = "HIGH"
	SeverityMedium        Severity = "MEDIUM"
	SeverityLow           Severity = "LOW"
	SeverityInformational Severity = "INFORMATIONAL"
)

// Vulnerability defines a general class of vulnerability.
type Vulnerability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Finding represents a specific instance of a vulnerability discovered during a scan.
type Finding struct {
	ID             string        `json:"id"`
	ScanID         string        `json:"scan_id"`
	TaskID         string        `json:"task_id"`
	Timestamp      time.Time     `json:"timestamp"`
	Target         string        `json:"target"`
	Module         string        `json:"module"`
	Vulnerability  Vulnerability `json:"vulnerability"`
	Severity       Severity      `json:"severity"`
	Description    string        `json:"description"`
	Evidence       string        `json:"evidence"`
	Recommendation string        `json:"recommendation"`
	CWE            []string      `json:"cwe,omitempty"`
}

// -- IAST (Interactive Application Security Testing) Schemas --

// ProbeType defines the category of the attack payload.
type ProbeType string

const (
	ProbeTypeXSS                ProbeType = "XSS"
	ProbeTypeSSTI               ProbeType = "SSTI" // Server-Side Template Injection
	ProbeTypeSQLi               ProbeType = "SQLI" // SQL Injection
	ProbeTypeCmdInjection       ProbeType = "CMD_INJECTION"
	ProbeTypeOAST               ProbeType = "OAST" // Out-of-Band Application Security Testing
	ProbeTypeDOMClobbering      ProbeType = "DOM_CLOBBERING"
	ProbeTypePrototypePollution ProbeType = "PROTOTYPE_POLLUTION"
	ProbeTypeGeneric            ProbeType = "GENERIC" // For generic data flow tracking.
)

// TaintSource identifies where the tainted data originated.
type TaintSource string

const (
	// Client side persistent storage
	SourceCookie         TaintSource = "COOKIE"
	SourceLocalStorage   TaintSource = "LOCAL_STORAGE"
	SourceSessionStorage TaintSource = "SESSION_STORAGE"

	// Client side transient sources
	SourceURLParam     TaintSource = "URL_PARAM"
	SourceHashFragment TaintSource = "HASH_FRAGMENT"
	SourceReferer      TaintSource = "REFERER"
	SourceHeader       TaintSource = "HEADER"
	SourceDOMInput     TaintSource = "DOM_INPUT" // Data entered via forms/interaction.
	SourceDOM          TaintSource = "DOM"       // Data read from existing DOM (e.g., window.name).

	// Communication channels
	SourceWebSocket   TaintSource = "WEB_SOCKET"   // Data received from server via WebSocket.
	SourcePostMessage TaintSource = "POST_MESSAGE" // Data received from other windows/workers.
)

// TaintSink identifies the dangerous function or property where tainted data landed.
type TaintSink string

const (
	// -- Execution Sinks --
	SinkEval                TaintSink = "EVAL"
	SinkFunctionConstructor TaintSink = "FUNCTION_CONSTRUCTOR"
	SinkSetTimeout          TaintSink = "SET_TIMEOUT"          // When a string is passed.
	SinkSetInterval         TaintSink = "SET_INTERVAL"         // When a string is passed.
	SinkEventHandler        TaintSink = "EVENT_HANDLER"        // e.g., element.onload, setAttribute('onclick', ...)

	// -- DOM Manipulation Sinks (XSS) --
	SinkInnerHTML          TaintSink = "INNER_HTML"
	SinkOuterHTML          TaintSink = "OUTER_HTML"
	SinkInsertAdjacentHTML TaintSink = "INSERT_ADJACENT_HTML"
	SinkDocumentWrite      TaintSink = "DOCUMENT_WRITE"

	// -- Resource & Navigation Sinks --
	SinkScriptSrc      TaintSink = "SCRIPT_SRC"
	SinkIframeSrc      TaintSink = "IFRAME_SRC"
	SinkIframeSrcDoc   TaintSink = "IFRAME_SRCDOC"
	SinkWorkerSrc      TaintSink = "WORKER_SRC"
	SinkEmbedSrc       TaintSink = "EMBED_SRC"
	SinkObjectData     TaintSink = "OBJECT_DATA"
	SinkBaseHref       TaintSink = "BASE_HREF"  // Can lead to script gadget hijacking
	SinkNavigation     TaintSink = "NAVIGATION" // e.g., location.href, window.open with javascript: URIs

	// -- Network/Exfiltration Sinks --
	SinkFetch             TaintSink = "FETCH_BODY"
	SinkFetchURL          TaintSink = "FETCH_URL"
	SinkXMLHTTPRequest    TaintSink = "XHR_BODY"
	SinkXMLHTTPRequestURL TaintSink = "XHR_URL"
	SinkWebSocketSend     TaintSink = "WEBSOCKET_SEND"
	SinkSendBeacon        TaintSink = "SEND_BEACON"

	// -- IPC (Inter-Process Communication) Sinks --
	SinkPostMessage       TaintSink = "POST_MESSAGE"
	SinkWorkerPostMessage TaintSink = "WORKER_POST_MESSAGE"

	// -- Style & CSS Sinks --
	SinkStyleCSS        TaintSink = "STYLE_CSS"      // e.g., element.style.cssText, can be used for data exfil/UI redressing
	SinkStyleInsertRule TaintSink = "STYLE_INSERT_RULE" // Can inject malicious CSS rules.

	// -- Special Confirmation Sinks (High Confidence) --
	SinkExecution               TaintSink = "EXECUTION_PROOF"
	SinkOASTInteraction         TaintSink = "OAST_INTERACTION"
	SinkPrototypePollution      TaintSink = "PROTOTYPE_POLLUTION_CONFIRMED"
)

// ObservationType defines the category of an observation made by an agent.
type ObservationType string

const (
	ObservationSystemState     ObservationType = "SYSTEM_STATE"
	ObservationCodebaseContext ObservationType = "CODEBASE_CONTEXT"
)

// -- Canonical Knowledge Graph Data Model --

// NodeType defines the type of a node in the knowledge graph.
type NodeType string

const (
	NodeHost          NodeType = "HOST"
	NodeIPAddress     NodeType = "IP_ADDRESS"
	NodeURL           NodeType = "URL"
	NodeCookie        NodeType = "COOKIE"
	NodeHeader        NodeType = "HEADER"
	NodeTechnology    NodeType = "TECHNOLOGY"
	NodeVulnerability NodeType = "VULNERABILITY"
	NodeAction        NodeType = "ACTION"
	NodeObservation   NodeType = "OBSERVATION"
	NodeTool          NodeType = "TOOL"
	NodeFile          NodeType = "FILE"
	NodeDomain        NodeType = "DOMAIN"
	// A new node type for a function in a codebase.
	NodeFunction NodeType = "FUNCTION"
	NodeMission  NodeType = "MISSION"
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
	// A new relationship type to denote that one function or file imports another.
	RelationshipImports      RelationshipType = "IMPORTS"
	RelationshipHostsURL     RelationshipType = "HOSTS_URL"
	RelationshipHasSubdomain RelationshipType = "HAS_SUBDOMAIN"
)

// NodeStatus defines the state of a node, useful for tracking analysis progress.
type NodeStatus string

const (
	StatusNew        NodeStatus = "NEW"
	StatusProcessing NodeStatus = "PROCESSING"
	StatusAnalyzed   NodeStatus = "ANALYZED"
	StatusError      NodeStatus = "ERROR"
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
	From       string           `json:"from"` // Source Node ID
	To         string           `json:"to"`   // Target Node ID
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
	From       string           `json:"from"` // Source Node ID
	To         string           `json:"to"`   // Target Node ID
	Type       RelationshipType `json:"type"`
	Label      string           `json:"label"`
	Properties json.RawMessage  `json:"properties"`
}

// -- Communication & Result Schemas --

// KnowledgeGraphUpdate is a container for bulk updates to the Knowledge Graph.
// It's used within a ResultEnvelope to send back new entities discovered by a task.
type KnowledgeGraphUpdate struct {
	NodesToAdd []NodeInput `json:"nodes_to_add"`
	EdgesToAdd []EdgeInput `json:"edges_to_add"`
}

// ResultEnvelope is the top level wrapper for all results from a single task.
type ResultEnvelope struct {
	ScanID    string                `json:"scan_id"`
	TaskID    string                `json:"task_id"`
	Timestamp time.Time             `json:"timestamp"`
	Findings  []Finding             `json:"findings"`
	KGUpdates *KnowledgeGraphUpdate `json:"kg_updates,omitempty"`
}

// -- Browser & Artifact Schemas --

// ClientHints defines the User-Agent Client Hints data.
type ClientHints struct {
	Platform        string                         `json:"platform"`
	PlatformVersion string                         `json:"platformVersion"`
	Architecture    string                         `json:"architecture"`
	Bitness         string                         `json:"bitness"`
	Mobile          bool                           `json:"mobile"`
	Brands          []*emulation.UserAgentBrandVersion `json:"brands"`
}

// Persona encapsulates all properties for a consistent browser fingerprint.
type Persona struct {
	UserAgent   string     `json:"userAgent"`
	Platform    string     `json:"platform"`
	Languages   []string   `json:"languages"`

	// Flattened ScreenProperties
	Width       int64 `json:"width"`
	Height      int64 `json:"height"`
	AvailWidth  int64 `json:"availWidth"`
	AvailHeight int64 `json:"availHeight"`
	ColorDepth  int64 `json:"colorDepth"`
	PixelDepth  int64 `json:"pixelDepth"`
	Mobile      bool  `json:"mobile"`

	Timezone        string       `json:"timezoneId"`
	Locale          string       `json:"locale"`
	ClientHintsData *ClientHints `json:"clientHintsData,omitempty"`
	NoiseSeed       int64        `json:"noiseSeed"`
}

// DefaultPersona provides a fallback persona if none is specified.
var DefaultPersona = Persona{
	UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	Platform:    "Win32",
	Languages:   []string{"en-US", "en"},
	Width:       1920,
	Height:      1080,
	AvailWidth:  1920,
	AvailHeight: 1040,
	ColorDepth:  24,
	PixelDepth:  24,
	Mobile:      false,
	Timezone:    "America/Los_Angeles",
	Locale:      "en-US",
}

// InteractionConfig defines parameters for the automated page interactor.
type InteractionConfig struct {
	MaxDepth              int               `json:"max_depth"`
	MaxInteractionsPerDepth int               `json:"max_interactions_per_depth"`
	InteractionDelayMs    int               `json:"interaction_delay_ms"`
	PostInteractionWaitMs int               `json:"post_interaction_wait_ms"`
	CustomInputData       map[string]string `json:"custom_input_data,omitempty"`
}

// ConsoleLog represents a single entry from the browser's console.
type ConsoleLog struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Text      string    `json:"text"`
	Source    string    `json:"source,omitempty"`
	URL       string    `json:"url,omitempty"`
	Line      int64     `json:"line,omitempty"`
}

// StorageState captures the state of browser storage at a point in time.
type StorageState struct {
	Cookies        []*network.Cookie `json:"cookies"`
	LocalStorage   map[string]string `json:"local_storage"`
	SessionStorage map[string]string `json:"session_storage"`
}

// Artifacts is a collection of all data gathered during a browser interaction.
type Artifacts struct {
	HAR         *HAR         `json:"har"`
	DOM         string       `json:"dom"`
	ConsoleLogs []ConsoleLog `json:"console_logs"`
	Storage     StorageState `json:"storage"`
}

// Credential holds a username and password pair.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// -- HAR (HTTP Archive) Schemas --

// HAR represents the root of the HTTP Archive format.
type HAR struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Pages   []Page  `json:"pages"`
	Entries []Entry `json:"entries"`
}

type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Page struct {
	StartedDateTime time.Time   `json:"startedDateTime"`
	ID              string      `json:"id"`
	Title           string      `json:"title"`
	PageTimings     PageTimings `json:"pageTimings"`
}

type PageTimings struct {
	OnContentLoad float64 `json:"onContentLoad"`
	OnLoad        float64 `json:"onLoad"`
}

type Entry struct {
	Pageref         string    `json:"pageref"`
	StartedDateTime time.Time `json:"startedDateTime"`
	Time            float64   `json:"time"`
	Request         Request   `json:"request"`
	Response        Response  `json:"response"`
	Cache           struct{}  `json:"cache"`
	Timings         Timings   `json:"timings"`
}

type Request struct {
	Method      string    `json:"method"`
	URL         string    `json:"url"`
	HTTPVersion string    `json:"httpVersion"`
	Cookies     []Cookie  `json:"cookies"`
	Headers     []NVPair  `json:"headers"`
	QueryString []NVPair  `json:"queryString"`
	PostData    *PostData `json:"postData,omitempty"`
	HeadersSize int64     `json:"headersSize"`
	BodySize    int64     `json:"bodySize"`
}

type Response struct {
	Status      int      `json:"status"`
	StatusText  string   `json:"statusText"`
	HTTPVersion string   `json:"httpVersion"`
	Cookies     []Cookie `json:"cookies"`
	Headers     []NVPair `json:"headers"`
	Content     Content  `json:"content"`
	RedirectURL string   `json:"redirectURL"`
	HeadersSize int64    `json:"headersSize"`
	BodySize    int64    `json:"bodySize"`
}

type Timings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	SSL     float64 `json:"ssl"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

type NVPair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Path     string    `json:"path"`
	Domain   string    `json:"domain"`
	Expires  time.Time `json:"expires"`
	HTTPOnly bool      `json:"httpOnly"`
	Secure   bool      `json:"secure"`
}

type PostData struct {
	MimeType string   `json:"mimeType"`
	Text     string   `json:"text"`
	Params   []NVPair `json:"params"`
}

type Content struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

// NewHAR creates and initializes a new HAR object with default values.
func NewHAR() *HAR {
	return &HAR{
		Log: HARLog{
			Version: "1.2",
			Creator: Creator{
				Name:    "Scalpel-CLI",
				Version: "2.0",
			},
			Entries: make([]Entry, 0),
		},
	}
}

// -- LLM Client Schemas & Interface --

// ModelTier specifies a preference for performance vs. capability.
type ModelTier string

const (
	TierFast     ModelTier = "fast"   // Optimized for speed and cost.
	TierPowerful ModelTier = "powerful" // Optimized for reasoning and accuracy.
)

type GenerationOptions struct {
	Temperature     float32 `json:"temperature"`
	ForceJSONFormat bool    `json:"force_json_format"`
	TopP            float32
	TopK            int
}

type GenerationRequest struct {
	SystemPrompt string          `json:"system_prompt"`
	UserPrompt   string          `json:"user_prompt"`
	Tier         ModelTier       `json:"tier"`
	Options      GenerationOptions `json:"options"`
}

// LLMClient defines the interface for interacting with a Large Language Model.
type LLMClient interface {
	Generate(ctx context.Context, req GenerationRequest) (string, error)
}

// -- Engine Interfaces --

// DiscoveryEngine defines the interface for an engine that discovers potential tasks.
type DiscoveryEngine interface {
	// Start kicks off the discovery process, returning a channel that will stream tasks.
	Start(ctx context.Context, targets []string) (<-chan Task, error)
	Stop()
}

// TaskEngine defines the interface for an engine that executes tasks.
type TaskEngine interface {
	// Start begins processing tasks from a channel.
	Start(ctx context.Context, taskChan <-chan Task)
	Stop()
}

// -- Centralized Core Service Interfaces --

// KnowledgeGraphClient defines the canonical interface for interacting with the Knowledge Graph.
// It uses the rich Node and Edge types for clarity and type safety.
type KnowledgeGraphClient interface {
	AddNode(ctx context.Context, node Node) error
	AddEdge(ctx context.Context, edge Edge) error
	GetNode(ctx context.Context, id string) (Node, error)
	GetEdges(ctx context.Context, nodeID string) ([]Edge, error)
	GetNeighbors(ctx context.Context, nodeID string) ([]Node, error)
}

// BrowserManager defines the canonical interface for managing browser processes and creating sessions.
// It requires a config.Config, so we must use an interface{} to avoid import cycles.
// The concrete implementation will perform a type assertion.
type BrowserManager interface {
	NewAnalysisContext(
		sessionCtx context.Context,
		cfg interface{}, // *config.Config
		persona Persona,
		taintTemplate string,
		taintConfig string,
		findingsChan chan<- Finding,
	) (SessionContext, error)
	Shutdown(ctx context.Context) error
}

// BrowserInteractor defines the canonical interface for high-level browser interactions within a single session.
type BrowserInteractor interface {
	NavigateAndExtract(ctx context.Context, url string) ([]string, error)
}

// SessionContext defines the interface for interacting with a specific browser session (tab).
// This is used by more advanced analyzers and agents that need fine-grained control.
type SessionContext interface {
	// ID returns the unique identifier for the session.
	ID() string
	Navigate(ctx context.Context, url string) error
	Click(selector string) error
	Type(selector string, text string) error
	Submit(selector string) error
	ScrollPage(direction string) error
	WaitForAsync(milliseconds int) error
	// GetContext returns the underlying context for the session, which is necessary
	// for executing raw CDP actions that require a context.
	GetContext() context.Context
	// ExposeFunction allows Go functions to be called from the browser's JavaScript context.
	ExposeFunction(ctx context.Context, name string, function interface{}) error
	// InjectScriptPersistently adds a script that will be executed on all new documents in the session.
	InjectScriptPersistently(ctx context.Context, script string) error
	// ExecuteScript runs a snippet of JavaScript in the current document.
	ExecuteScript(ctx context.Context, script string, res interface{}) error
	// Interact triggers the automated recursive interaction logic.
	Interact(ctx context.Context, config InteractionConfig) error
	// Close gracefully terminates the browser session.
	Close(ctx context.Context) error

	// FIX: Added CollectArtifacts to gather data like HAR logs and DOM state from the session.
	CollectArtifacts() (*Artifacts, error)
	// FIX: Added AddFinding to allow analyzers to report findings directly through the session.
	AddFinding(finding Finding) error
}

// HTTPClient defines the interface for making simple HTTP GET requests.
// This is used by passive discovery modules.
type HTTPClient interface {
	Get(ctx context.Context, url string) (body []byte, statusCode int, err error)
}

// OASTProvider is the contract for interacting with an OAST service.
type OASTProvider interface {
	// Fetches interactions since the last check for the given canaries.
	GetInteractions(ctx context.Context, canaries []string) ([]OASTInteraction, error)
	// Returns the base URL/domain for the OAST server to be used in payloads.
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
