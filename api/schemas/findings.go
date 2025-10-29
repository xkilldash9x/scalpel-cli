package schemas

import (
	"time"
)

// -- Finding Schemas --

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
