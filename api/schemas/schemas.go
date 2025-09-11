package schemas

import (
	"context"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/google/uuid"
)

// -- Task & Finding Schemas --

// TaskType defines the type of task to be executed by a module.
type TaskType string

const (
	TaskAgentMission        TaskType = "AGENT_MISSION"
	TaskAnalyzeWebPageTaint TaskType = "ANALYZE_WEB_PAGE_TAINT"
	TaskAnalyzeWebPageProtoPP TaskType = "ANALYZE_WEB_PAGE_PROTOPP"
	TaskTestRaceCondition   TaskType = "TEST_RACE_CONDITION"
	TaskTestAuthATO         TaskType = "TEST_AUTH_ATO"
	TaskTestAuthIDOR        TaskType = "TEST_AUTH_IDOR"
	TaskAnalyzeHeaders      TaskType = "ANALYZE_HEADERS"
	TaskAnalyzeJWT          TaskType = "ANALYZE_JWT"
)

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
	TaskID         string        `json:"task_id"`
	Timestamp      time.Time     `json:"timestamp"`
	Target         string        `json:"target"` // The specific URL or asset where the finding was discovered.
	Module         string        `json:"module"` // The name of the module/engine that produced the finding.
	Vulnerability  Vulnerability `json:"vulnerability"`
	Severity       Severity      `json:"severity"`
	Description    string        `json:"description"`    // Specific details about this particular finding.
	Evidence       string        `json:"evidence"`       // Concrete evidence, like a request/response pair or log entry.
	Recommendation string        `json:"recommendation"` // Steps to mitigate or fix the vulnerability.
	CWE            []string      `json:"cwe,omitempty"`  // Associated CWEs.
}

// -- Canonical Knowledge Graph Data Model --

// NodeType defines the type of a node in the knowledge graph.
// Using a dedicated type enhances clarity and allows for compile time checks.
type NodeType string

// These provide a controlled vocabulary for node types.
const (
	NodeHost        NodeType = "HOST"
	NodeIPAddress   NodeType = "IP_ADDRESS"
	NodeURL         NodeType = "URL"
	NodeCookie      NodeType = "COOKIE"
	NodeHeader      NodeType = "HEADER"
	NodeTechnology  NodeType = "TECHNOLOGY"
	NodeVulnerability NodeType = "VULNERABILITY"
	NodeAction      NodeType = "ACTION"
	NodeObservation NodeType = "OBSERVATION"
	NodeTool        NodeType = "TOOL"
	NodeFile        NodeType = "FILE"
)

// RelationshipType defines the type of an edge between nodes in the knowledge graph.
type RelationshipType string

// These establish a formal set of relationship labels.
const (
	RelationshipResolvesTo     RelationshipType = "RESOLVES_TO"
	RelationshipLinksTo        RelationshipType = "LINKS_TO"
	RelationshipUses           RelationshipType = "USES"
	RelationshipHas            RelationshipType = "HAS"
	RelationshipExposes        RelationshipType = "EXPOSES"
	RelationshipExecuted       RelationshipType = "EXECUTED"
	RelationshipHasObservation RelationshipType = "HAS_OBSERVATION"
)

// Node represents a single entity, concept, or piece of data in the Knowledge Graph.
// This struct is the single, canonical representation for ALL nodes to be stored
// in the graph. It is intentionally generic to accommodate any type of information.
type Node struct {
	// A universally unique identifier for the node.
	ID uuid.UUID `json:"id"`
	// Type categorizes the node, using the predefined NodeType constants.
	Type NodeType `json:"type"`
	// A human readable label for the node.
	Label string `json:"label"`
	// An open map to store any additional properties or metadata associated with the node.
	Props map[string]interface{} `json:"props"`
}

// Edge represents a directed, labeled relationship between two nodes in the Knowledge Graph.
// This struct is the single, canonical representation for ALL edges.
type Edge struct {
	// A universally unique identifier for the edge.
	ID uuid.UUID `json:"id"`
	// The ID of the node where the edge originates.
	Source uuid.UUID `json:"source"`
	// The ID of the node where the edge terminates.
	Target uuid.UUID `json:"target"`
	// Describes the nature of the relationship, using predefined RelationshipType constants.
	Label RelationshipType `json:"label"`
	// An open map to store any additional properties, such as weights or timestamps.
	Props map[string]interface{} `json:"props"`
}

// KnowledgeGraphUpdate represents a batch of updates to be applied to the knowledge graph.
// It contains slices of the canonical Node and Edge structs.
type KnowledgeGraphUpdate struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// -- Communication & Result Schemas --

// ResultEnvelope is the top-level wrapper for all results produced by a single task.
type ResultEnvelope struct {
	ScanID    string                `json:"scan_id"`
	TaskID    string                `json:"task_id"`
	Timestamp time.Time             `json:"timestamp"`
	Findings  []Finding             `json:"findings"`
	KGUpdates *KnowledgeGraphUpdate `json:"kg_updates,omitempty"`
}

// -- Browser & Artifact Schemas --

// InteractionConfig defines the parameters for the automated page interactor.
type InteractionConfig struct {
	MaxDepth                int               `json:"max_depth"`
	MaxInteractionsPerDepth int               `json:"max_interactions_per_depth"`
	InteractionDelayMs      int               `json:"interaction_delay_ms"`
	PostInteractionWaitMs   int               `json:"post_interaction_wait_ms"`
	CustomInputData         map[string]string `json:"custom_input_data,omitempty"` // User provided data for specific inputs (key: 'id' or 'name' attribute).
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
	TierFast     ModelTier = "fast"     // Optimized for speed and cost.
	TierPowerful ModelTier = "powerful" // Optimized for reasoning and accuracy.
)

type GenerationOptions struct {
	Temperature     float32
	ForceJSONFormat bool
}

type GenerationRequest struct {
	SystemPrompt string
	UserPrompt   string
	Tier         ModelTier
	Options      GenerationOptions
}

// LLMClient defines the interface for interacting with a Large Language Model.
type LLMClient interface {
	Generate(ctx context.Context, req GenerationRequest) (string, error)
}

// -- Engine Interfaces --

// DiscoveryEngine defines the interface for an engine that discovers potential targets or tasks.
type DiscoveryEngine interface {
	// Start begins the discovery process, returning a channel that will stream findings.
	Start(ctx context.Context, targets string) (<-chan Finding, error)
	Stop()
}

// TaskEngine defines the interface for an engine that executes tasks based on findings.
type TaskEngine interface {
	// Start begins processing findings from a channel.
	Start(ctx context.Context, taskChan <-chan Finding)
	Stop()
}


