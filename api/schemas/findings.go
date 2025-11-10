package schemas

import (
	"encoding/json"
	"time"
)

// -- Finding Schemas --

// Severity represents the severity level of a security finding, ranging from
// critical to informational. The values are lowercase to align with database ENUMs.
type Severity string

// Constants defining the standard severity levels for findings.
const (
	SeverityCritical Severity = "critical" // Represents a critical vulnerability.
	SeverityHigh     Severity = "high"     // Represents a high-severity vulnerability.
	SeverityMedium   Severity = "medium"   // Represents a medium-severity vulnerability.
	SeverityLow      Severity = "low"      // Represents a low-severity vulnerability.
	SeverityInfo     Severity = "info"     // Represents an informational finding.
)

// Finding encapsulates all the details of a single security vulnerability
// identified by a scan. It includes information about the vulnerability, its
// location, severity, and evidence. This struct maps directly to the `findings`
// table in the database.
type Finding struct {
	ID     string `json:"id"`     // Unique identifier for the finding.
	ScanID string `json:"scan_id"` // The ID of the scan that produced this finding.
	TaskID string `json:"task_id"` // The ID of the specific task that found this issue.

	// ObservedAt is the timestamp when the finding was discovered.
	ObservedAt time.Time `json:"observed_at"`

	Target string `json:"target"` // The target URL or resource where the vulnerability was found.
	Module string `json:"module"` // The name of the analysis module that reported the finding.

	// VulnerabilityName is a descriptive name for the type of vulnerability (e.g., "Reflected XSS").
	VulnerabilityName string `json:"vulnerability_name"`

	Severity    Severity `json:"severity"`    // The severity level of the finding.
	Description string   `json:"description"` // A detailed description of the vulnerability.

	// Evidence provides structured, machine-readable proof of the vulnerability,
	// stored as JSONB in the database.
	Evidence json.RawMessage `json:"evidence,omitempty"`

	Recommendation string   `json:"recommendation"`  // Suggested steps for remediation.
	CWE            []string `json:"cwe,omitempty"` // A list of relevant Common Weakness Enumeration (CWE) identifiers.
}

// -- IAST (Interactive Application Security Testing) Schemas --

// ProbeType categorizes the type of attack payload used in a taint analysis
// or active vulnerability check.
type ProbeType string

// Constants for different categories of attack probes.
const (
	ProbeTypeXSS                ProbeType = "XSS"                 // Cross-Site Scripting probes.
	ProbeTypeSSTI               ProbeType = "SSTI"                // Server-Side Template Injection probes.
	ProbeTypeSQLi               ProbeType = "SQLI"                // SQL Injection probes.
	ProbeTypeCmdInjection       ProbeType = "CMD_INJECTION"       // Command Injection probes.
	ProbeTypeOAST               ProbeType = "OAST"                // Out-of-Band Application Security Testing probes.
	ProbeTypeDOMClobbering      ProbeType = "DOM_CLOBBERING"      // DOM Clobbering probes.
	ProbeTypePrototypePollution ProbeType = "PROTOTYPE_POLLUTION" // Prototype Pollution probes.
	ProbeTypeGeneric            ProbeType = "GENERIC"             // Generic or uncategorized probes.
)

// TaintSource identifies the origin of untrusted or "tainted" data that is
// introduced into the application.
type TaintSource string

// Constants for various sources of tainted data in a web application.
const (
	SourceCookie         TaintSource = "COOKIE"          // Data from document.cookie.
	SourceLocalStorage   TaintSource = "LOCAL_STORAGE"   // Data from window.localStorage.
	SourceSessionStorage TaintSource = "SESSION_STORAGE" // Data from window.sessionStorage.
	SourceURLParam       TaintSource = "URL_PARAM"       // Data from URL query parameters.
	SourceHashFragment   TaintSource = "HASH_FRAGMENT"   // Data from the URL hash fragment.
	SourceReferer        TaintSource = "REFERER"         // Data from the Referer header.
	SourceHeader         TaintSource = "HEADER"          // Data from other HTTP headers.
	SourceDOMInput       TaintSource = "DOM_INPUT"       // Data from user input fields.
	SourceDOM            TaintSource = "DOM"             // Data from other DOM elements.
	SourceWebSocket      TaintSource = "WEB_SOCKET"      // Data from a WebSocket message.
	SourcePostMessage    TaintSource = "POST_MESSAGE"    // Data from a postMessage event.
)

// TaintSink represents a function, property, or location where tainted data
// could cause a security vulnerability if it is used without proper sanitization.
type TaintSink string

// Constants for various sinks where tainted data can lead to vulnerabilities.
const (
	SinkEval                TaintSink = "EVAL"                          // eval()
	SinkFunctionConstructor TaintSink = "FUNCTION_CONSTRUCTOR"        // new Function()
	SinkSetTimeout          TaintSink = "SET_TIMEOUT"                 // setTimeout()
	SinkSetInterval         TaintSink = "SET_INTERVAL"                // setInterval()
	SinkEventHandler        TaintSink = "EVENT_HANDLER"               // on* event handlers (e.g., onclick).
	SinkInnerHTML           TaintSink = "INNER_HTML"                  // element.innerHTML
	SinkOuterHTML           TaintSink = "OUTER_HTML"                  // element.outerHTML
	SinkInsertAdjacentHTML  TaintSink = "INSERT_ADJACENT_HTML"        // element.insertAdjacentHTML
	SinkDocumentWrite       TaintSink = "DOCUMENT_WRITE"              // document.write()
	SinkScriptSrc           TaintSink = "SCRIPT_SRC"                  // script.src
	SinkIframeSrc           TaintSink = "IFRAME_SRC"                  // iframe.src
	SinkIframeSrcDoc        TaintSink = "IFRAME_SRCDOC"               // iframe.srcdoc
	SinkWorkerSrc           TaintSink = "WORKER_SRC"                  // new Worker()
	SinkEmbedSrc            TaintSink = "EMBED_SRC"                   // embed.src
	SinkObjectData          TaintSink = "OBJECT_DATA"                 // object.data
	SinkBaseHref            TaintSink = "BASE_HREF"                   // base.href
	SinkNavigation          TaintSink = "NAVIGATION"                  // window.location, etc.
	SinkFetch               TaintSink = "FETCH_BODY"                  // fetch() body
	SinkFetchURL            TaintSink = "FETCH_URL"                   // fetch() URL
	SinkXMLHTTPRequest      TaintSink = "XHR_BODY"                    // XMLHttpRequest.send() body
	SinkXMLHTTPRequestURL   TaintSink = "XHR_URL"                     // XMLHttpRequest.open() URL
	SinkWebSocketSend       TaintSink = "WEBSOCKET_SEND"              // WebSocket.send()
	SinkSendBeacon          TaintSink = "SEND_BEACON"                 // navigator.sendBeacon()
	SinkPostMessage         TaintSink = "POST_MESSAGE"                // window.postMessage()
	SinkWorkerPostMessage   TaintSink = "WORKER_POST_MESSAGE"         // worker.postMessage()
	SinkStyleCSS            TaintSink = "STYLE_CSS"                   // style.textContent, etc.
	SinkStyleInsertRule     TaintSink = "STYLE_INSERT_RULE"           // style.insertRule()
	SinkExecution           TaintSink = "EXECUTION_PROOF"             // Confirmed JavaScript execution.
	SinkOASTInteraction     TaintSink = "OAST_INTERACTION"            // Confirmed out-of-band interaction.
	SinkPrototypePollution  TaintSink = "PROTOTYPE_POLLUTION_CONFIRMED" // Confirmed prototype pollution.
)
