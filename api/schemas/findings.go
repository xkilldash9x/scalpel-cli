package schemas

import (
	"encoding/json"
	"time"
)

// -- Finding Schemas --

// Severity defines the severity level of a finding.
// Production Ready: Standardized to lowercase to match PostgreSQL ENUM conventions.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	// Renamed Informational to Info to match standard terminology and the DB ENUM.
	SeverityInfo Severity = "info"
)

// Finding represents a specific instance of a vulnerability discovered during a scan.
// Maps to the findings table.
type Finding struct {
	ID     string `json:"id"`
	ScanID string `json:"scan_id"`
	TaskID string `json:"task_id"`

	// ObservedAt is when the finding was discovered (maps to DB column observed_at).
	ObservedAt time.Time `json:"observed_at"` // Renamed from Timestamp

	Target string `json:"target"`
	Module string `json:"module"`

	// VulnerabilityName is the identifier for the type of vulnerability found (e.g., "Reflected XSS").
	// Maps to DB column vulnerability_name.
	VulnerabilityName string `json:"vulnerability_name"` // Replaces Vulnerability struct

	Severity    Severity `json:"severity"`
	Description string   `json:"description"`

	// Evidence holds structured proof of the vulnerability.
	// Production Ready: Changed Evidence from string to json.RawMessage to support structured JSONB storage.
	Evidence json.RawMessage `json:"evidence,omitempty"`

	Recommendation string   `json:"recommendation"`
	CWE            []string `json:"cwe,omitempty"` // Maps to TEXT[] in DB
}

// -- IAST (Interactive Application Security Testing) Schemas --
// Note: The Vulnerability struct from the original file was removed as it was flattened into Finding.

// ProbeType defines the category of the attack payload.
type ProbeType string

const (
	ProbeTypeXSS                ProbeType = "XSS"
	ProbeTypeSSTI               ProbeType = "SSTI"
	ProbeTypeSQLi               ProbeType = "SQLI"
	ProbeTypeCmdInjection       ProbeType = "CMD_INJECTION"
	ProbeTypeOAST               ProbeType = "OAST"
	ProbeTypeDOMClobbering      ProbeType = "DOM_CLOBBERING"
	ProbeTypePrototypePollution ProbeType = "PROTOTYPE_POLLUTION"
	ProbeTypeGeneric            ProbeType = "GENERIC"
)

// TaintSource identifies where the tainted data originated.
type TaintSource string

const (
	SourceCookie         TaintSource = "COOKIE"
	SourceLocalStorage   TaintSource = "LOCAL_STORAGE"
	SourceSessionStorage TaintSource = "SESSION_STORAGE"
	SourceURLParam       TaintSource = "URL_PARAM"
	SourceHashFragment   TaintSource = "HASH_FRAGMENT"
	SourceReferer        TaintSource = "REFERER"
	SourceHeader         TaintSource = "HEADER"
	SourceDOMInput       TaintSource = "DOM_INPUT"
	SourceDOM            TaintSource = "DOM"
	SourceWebSocket      TaintSource = "WEB_SOCKET"
	SourcePostMessage    TaintSource = "POST_MESSAGE"
)

// TaintSink identifies the dangerous function or property where tainted data landed.
type TaintSink string

const (
	SinkEval                TaintSink = "EVAL"
	SinkFunctionConstructor TaintSink = "FUNCTION_CONSTRUCTOR"
	SinkSetTimeout          TaintSink = "SET_TIMEOUT"
	SinkSetInterval         TaintSink = "SET_INTERVAL"
	SinkEventHandler        TaintSink = "EVENT_HANDLER"
	SinkInnerHTML           TaintSink = "INNER_HTML"
	SinkOuterHTML           TaintSink = "OUTER_HTML"
	SinkInsertAdjacentHTML  TaintSink = "INSERT_ADJACENT_HTML"
	SinkDocumentWrite       TaintSink = "DOCUMENT_WRITE"
	SinkScriptSrc           TaintSink = "SCRIPT_SRC"
	SinkIframeSrc           TaintSink = "IFRAME_SRC"
	SinkIframeSrcDoc        TaintSink = "IFRAME_SRCDOC"
	SinkWorkerSrc           TaintSink = "WORKER_SRC"
	SinkEmbedSrc            TaintSink = "EMBED_SRC"
	SinkObjectData          TaintSink = "OBJECT_DATA"
	SinkBaseHref            TaintSink = "BASE_HREF"
	SinkNavigation          TaintSink = "NAVIGATION"
	SinkFetch               TaintSink = "FETCH_BODY"
	SinkFetchURL            TaintSink = "FETCH_URL"
	SinkXMLHTTPRequest      TaintSink = "XHR_BODY"
	SinkXMLHTTPRequestURL   TaintSink = "XHR_URL"
	SinkWebSocketSend       TaintSink = "WEBSOCKET_SEND"
	SinkSendBeacon          TaintSink = "SEND_BEACON"
	SinkPostMessage         TaintSink = "POST_MESSAGE"
	SinkWorkerPostMessage   TaintSink = "WORKER_POST_MESSAGE"
	SinkStyleCSS            TaintSink = "STYLE_CSS"
	SinkStyleInsertRule     TaintSink = "STYLE_INSERT_RULE"
	SinkExecution           TaintSink = "EXECUTION_PROOF"
	SinkOASTInteraction     TaintSink = "OAST_INTERACTION"
	SinkPrototypePollution  TaintSink = "PROTOTYPE_POLLUTION_CONFIRMED"
)
