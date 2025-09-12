package taint

import (
	"context"
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- Constants --

// JavaScript callback function names exposed by the Go analyzer to the browser.
const (
	JSCallbackSinkEvent      = "__scalpel_sink_event"
	JSCallbackExecutionProof = "__scalpel_execution_proof"
	// Callback for instrumentation or runtime errors in the JS shim.
	JSCallbackShimError = "__scalpel_shim_error"
)

// -- Core IAST Concepts --

// Event represents any message sent to the correlation engine.
type Event interface {
	isEvent()
}

// NOTE: TaintSource, TaintSink, and ProbeType constants have been moved to the
// 'api/schemas' package to act as the single source of truth for the framework.
// This file now references those canonical definitions.

// SanitizationLevel indicates if the payload was modified before reaching the sink.
type SanitizationLevel int

const (
	SanitizationNone    SanitizationLevel = iota // Payload arrived intact.
	SanitizationPartial                          // Canary found, but payload structure is broken (e.g., tags stripped, quotes escaped).
)

// -- Data Structures --

// ProbeDefinition is the blueprint for one of our attack payloads.
type ProbeDefinition struct {
	Type        schemas.ProbeType `json:"type" yaml:"type"`
	Payload     string            `json:"payload" yaml:"payload"`
	// Context is a hint about where we expect the payload to work best.
	Context     string `json:"context" yaml:"context"`
	Description string `json:"description" yaml:"description"`
}

// ActiveProbe is a specific instance of a probe injected into the application.
type ActiveProbe struct {
	Type      schemas.ProbeType
	Key       string // what param did we inject it into?
	Value     string // what was the full payload?
	Canary    string // the unique ID for this probe.
	Source    schemas.TaintSource // where did it come from?
	CreatedAt time.Time // Timestamp for expiration tracking.
}

// SinkEvent is reported by the browser shim when tainted data reaches a sink.
// JSON tags must match the JS shim output.
type SinkEvent struct {
	Type       schemas.TaintSink `json:"type"`
	Value      string            `json:"value"`
	Detail     string            `json:"detail"`
	StackTrace string            `json:"stack"` // JS stack trace.
}

func (SinkEvent) isEvent() {}

// ExecutionProofEvent is a message from the browser confirming a payload executed.
type ExecutionProofEvent struct {
	Canary     string `json:"canary"`
	StackTrace string `json:"stack"`
}

func (ExecutionProofEvent) isEvent() {}

// ShimErrorEvent is a message from the browser reporting an internal instrumentation error.
type ShimErrorEvent struct {
	Error      string `json:"error"`
	Location   string `json:"location"`
	StackTrace string `json:"stack"`
}

// OASTInteraction represents a detected interaction on the OAST server.
type OASTInteraction struct {
	Canary          string
	Protocol        string
	SourceIP        string
	InteractionTime time.Time
	RawRequest      string
}

func (OASTInteraction) isEvent() {}

// CorrelatedFinding links a source to a sink, representing a potential vulnerability.
// This is an internal type used by the correlation engine before being transformed
// into a final schemas.Finding for reporting.
type CorrelatedFinding struct {
	TaskID            string
	TargetURL         string
	Sink              schemas.TaintSink
	Origin            schemas.TaintSource
	Value             string // The value that reached the sink.
	Canary            string
	Probe             ActiveProbe
	Detail            string
	IsConfirmed       bool // True if confirmed via ExecutionProof, OAST, or definitive sinks.
	SanitizationLevel SanitizationLevel // Indicates if the payload was modified.
	StackTrace        string            // The relevant stack trace.
	OASTDetails       *OASTInteraction  // Details if confirmed via OAST.
}

// -- Interfaces --

// OASTProvider is the contract for interacting with an OAST service.
type OASTProvider interface {
	// Fetches interactions since the last check for the given canaries.
	GetInteractions(ctx context.Context, canaries []string) ([]OASTInteraction, error)
	// Returns the base URL/domain for the OAST server to be used in payloads.
	GetServerURL() string
}

// BrowserInteractor is the contract for controlling a browser instance.
type BrowserInteractor interface {
	InitializeSession(ctx context.Context) (SessionContext, error)
}

// SessionContext is the contract for a single, isolated browser tab/context.
type SessionContext interface {
	// Instrumentation
	InjectScriptPersistently(ctx context.Context, script string) error
	ExposeFunction(ctx context.Context, name string, function interface{}) error
	ExecuteScript(ctx context.Context, script string) error

	// Browser automation
	Navigate(ctx context.Context, url string) error
	WaitForAsync(ctx context.Context, milliseconds int) error
	Interact(ctx context.Context, config InteractionConfig) error

	// Cleanup
	Close() error
}

// ResultsReporter is the contract for reporting findings from the analysis.
type ResultsReporter interface {
	Report(finding CorrelatedFinding)
}

// -- Configuration --

// SinkDefinition holds the blueprint for how to hook a specific function in JavaScript.
type SinkDefinition struct {
	Name        string            `json:"Name" yaml:"name"` // e.g., "Element.prototype.innerHTML"
	Type        schemas.TaintSink `json:"Type" yaml:"type"`
	Setter      bool              `json:"Setter" yaml:"setter"`           // Is it a property setter or a function call?
	ArgIndex    int               `json:"ArgIndex" yaml:"arg_index"`      // Which function argument do we care about?
	// ConditionID refers to a predefined handler in the JS shim (CSP compliant).
	ConditionID string `json:"ConditionID,omitempty" yaml:"condition_id,omitempty"`
}

// InteractionConfig holds the settings for the browser interaction/crawling phase.
type InteractionConfig struct {
	MaxDepth                int `json:"max_depth" yaml:"max_depth"`
	MaxInteractionsPerDepth int `json:"max_interactions_per_depth" yaml:"max_interactions_per_depth"`
	InteractionDelayMs      int `json:"interaction_delay_ms" yaml:"interaction_delay_ms"`
	PostInteractionWaitMs   int `json:"post_interaction_wait_ms" yaml:"post_interaction_wait_ms"`
}

// Config holds all the settings for the Taint Analyzer.
type Config struct {
	TaskID string `json:"task_id" yaml:"task_id"`
	Target *url.URL
	// Probes and Sinks are now part of the configuration, allowing dynamic loading.
	Probes      []ProbeDefinition `json:"probes" yaml:"probes"`
	Sinks       []SinkDefinition  `json:"sinks" yaml:"sinks"`
	Interaction InteractionConfig `json:"interaction" yaml:"interaction"`
	AnalysisTimeout time.Duration `json:"analysis_timeout" yaml:"analysis_timeout"`

	// Performance/Robustness configurations.
	EventChannelBuffer      int           `json:"event_channel_buffer" yaml:"event_channel_buffer"`
	FinalizationGracePeriod time.Duration `json:"finalization_grace_period" yaml:"finalization_grace_period"`
	// How long probes remain active before expiring (crucial for SPAs).
	ProbeExpirationDuration time.Duration `json:"probe_expiration_duration" yaml:"probe_expiration_duration"`
	CleanupInterval         time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	OASTPollingInterval     time.Duration `json:"oast_polling_interval" yaml:"oast_polling_interval"`
}
---
// internal/analysis/active/taint/types.go
package taint

import (
	"fmt"
	"net/url"
	"time"
)

// Config holds the configuration for the Taint Analyzer.
type Config struct {
	TaskID                  string
	Target                  *url.URL
	Probes                  []ProbeDefinition
	Sinks                   []SinkDefinition
	AnalysisTimeout         time.Duration
	EventChannelBuffer      int
	FinalizationGracePeriod time.Duration
	ProbeExpirationDuration time.Duration
	CleanupInterval         time.Duration
	OASTPollingInterval     time.Duration
	Interaction             InteractionConfig
}

// InteractionConfig defines parameters for automated interaction during taint analysis.
// Mirrors schemas.InteractionConfig for convenience within the taint package.
type InteractionConfig struct {
	MaxDepth                int
	MaxInteractionsPerDepth int
	InteractionDelayMs      int
	PostInteractionWaitMs   int
}

// ProbeType categorizes the vulnerability class the probe is designed to detect.
// These are defined within the taint package, not schemas, as they are specific to this analyzer.
type ProbeType string

const (
	ProbeTypeXSS            ProbeType = "XSS"
	ProbeTypeSSTI           ProbeType = "SSTI"
	ProbeTypeSQLi           ProbeType = "SQLI"
	ProbeTypeCmdInjection   ProbeType = "CMD_INJECTION"
	ProbeTypeDOMClobbering  ProbeType = "DOM_CLOBBERING"
	ProbeTypeDataLeakage    ProbeType = "DATA_LEAKAGE"
)

// ProbeDefinition defines a specific payload and its characteristics.
type ProbeDefinition struct {
	Type    ProbeType
	Payload string
	// Context helps the JS shim understand where the payload is safe (e.g., HTML, JS string, Attribute).
	Context string
}

// TaintSource defines where the tainted data originated.
type TaintSource string

const (
	SourceURLParam      TaintSource = "URL_PARAM"
	SourceURLHash       TaintSource = "URL_HASH"
	SourceCookie        TaintSource = "COOKIE"
	SourceLocalStorage  TaintSource = "LOCAL_STORAGE"
	SourceSessionStorage TaintSource = "SESSION_STORAGE"
	SourceReferer       TaintSource = "REFERER"
	SourceDOMInput      TaintSource = "DOM_INPUT" // Data entered via interaction
)

// TaintSink defines the dangerous function or property where tainted data landed.
type TaintSink string

const (
	SinkInnerHTML           TaintSink = "innerHTML"
	SinkOuterHTML           TaintSink = "outerHTML"
	SinkDocumentWrite       TaintSink = "document.write"
	SinkEval                TaintSink = "eval"
	SinkFunctionConstructor TaintSink = "Function"
	SinkScriptSrc           TaintSink = "script.src"
	SinkIframeSrc           TaintSink = "iframe.src"
	SinkIframeSrcDoc        TaintSink = "iframe.srcdoc"
	SinkNavigation          TaintSink = "location/navigation"
	SinkFetch               TaintSink = "fetch"
	SinkFetch_URL           TaintSink = "fetch_url"
	SinkXMLHTTPRequest      TaintSink = "XMLHttpRequest.send"
	SinkXMLHTTPRequest_URL  TaintSink = "XMLHttpRequest_url"
	SinkWebSocketSend       TaintSink = "WebSocket.send"
	SinkSendBeacon          TaintSink = "navigator.sendBeacon"

	// Special meta sink indicating confirmed execution (e.g., alert() fired).
	SinkExecution TaintSink = "EXECUTION_PROOF"
)

// SinkDefinition defines how the JS shim should wrap a specific sink.
type SinkDefinition struct {
	Name TaintSink
	// Type can be 'property' (e.g., innerHTML) or 'function' (e.g., eval).
	Type string
	// Target specifies the object (e.g., 'Element.prototype', 'window').
	Target string
	// ArgumentIndex specifies which argument to monitor (for functions).
	ArgumentIndex int
}

// ActiveProbe tracks a probe that has been injected into the environment.
type ActiveProbe struct {
	Type      ProbeType
	Key       string // The key used (e.g., URL param name, Cookie name, Storage key).
	Value     string // The full payload injected.
	Canary    string // The unique canary string within the payload.
	Source    TaintSource
	CreatedAt time.Time
}

// -- Events (Browser -> Go) --

// Event interface allows different event types to be sent over the same channel.
type Event interface {
	EventType() string
}

// SinkEvent is reported when tainted data reaches a sink.
type SinkEvent struct {
	Type       TaintSink `json:"type"`
	Value      string    `json:"value"`
	Detail     string    `json:"detail"`
	Location   string    `json:"location"`
	StackTrace string    `json:"stack_trace"`
}

func (e SinkEvent) EventType() string { return "SINK_EVENT" }

// ExecutionProofEvent is reported when a payload successfully executes (e.g., XSS alert).
type ExecutionProofEvent struct {
	Canary string `json:"canary"`
}

func (e ExecutionProofEvent) EventType() string { return "EXECUTION_PROOF_EVENT" }

// ShimErrorEvent is reported when the instrumentation itself encounters an error.
type ShimErrorEvent struct {
	Error      string `json:"error"`
	Location   string `json:"location"`
	StackTrace string `json:"stack_trace"`
}

func (e ShimErrorEvent) EventType() string { return "SHIM_ERROR_EVENT" }

// -- Correlation Result --

// CorrelatedFinding represents a successfully correlated taint flow.
type CorrelatedFinding struct {
	TaskID      string
	TargetURL   string
	Sink        TaintSink
	Origin      TaintSource
	Value       string
	Canary      string
	Probe       ActiveProbe
	Detail      string
	StackTrace  string
	IsConfirmed bool // True if execution proof (e.g., XSS alert) was received.
}

// GenerateProbes provides a basic set of probes.
// This should eventually be loaded from configuration or a dedicated module.
func GenerateProbes() []ProbeDefinition {
	// Basic XSS probe utilizing the execution proof callback (assuming JSCallbackExecutionProof is defined globally or passed in)
	// We rely on analyzer.go to define JSCallbackExecutionProof and inject it here.
	// This is a placeholder implementation.
	xssPayload := fmt.Sprintf(`<img src=x onerror="window.scalpel_execution_proof && window.scalpel_execution_proof('{{.Canary}}')">`)

	return []ProbeDefinition{
		{Type: ProbeTypeXSS, Payload: xssPayload, Context: "HTML"},
		{Type: ProbeTypeDataLeakage, Payload: "secret_data_{{.Canary}}", Context: "Text"},
		// Add SSTI, SQLi, etc. probes here.
	}
}

type TaintSource string

const (
	SourceURLParam       TaintSource = "URL_PARAM"
	SourceURLHash        TaintSource = "URL_HASH"
	SourceCookie         TaintSource = "COOKIE"
	SourceLocalStorage   TaintSource = "LOCAL_STORAGE"
	SourceSessionStorage TaintSource = "SESSION_STORAGE"
	SourceBodyParam      TaintSource = "BODY_PARAM"
	SourceHeader         TaintSource = "HEADER"
	SourceReferer        TaintSource = "REFERER"
	SourceDOMInput       TaintSource = "DOM_INPUT" // Data entered via interaction
	SourcePostMessage    TaintSource = "POST_MESSAGE"
)

// ProbeType categorizes the vulnerability class a probe is designed to detect.
type ProbeType string

const (
	ProbeTypeXSS            ProbeType = "XSS"
	ProbeTypeSSTI           ProbeType = "SSTI"
	ProbeTypeSQLI           ProbeType = "SQLI"
	ProbeTypeCmdInjection   ProbeType = "CMD_INJECTION"
	ProbeTypeDOMClobbering  ProbeType = "DOM_CLOBBERING"
	ProbeTypeDataLeakage    ProbeType = "DATA_LEAKAGE"
	ProbeTypeOpenRedirect   ProbeType = "OPEN_REDIRECT"
	ProbeTypePrototypePollution ProbeType = "PROTOTYPE_POLLUTION"
)

// TaintSink defines a potentially dangerous function, property, or operation
// where tainted data could cause a security vulnerability.
type TaintSink string

const (
	// -- Meta Sinks (for internal tracking) --

	// SINK_EXECUTION_PROOF is a special sink triggered by an explicit callback
	// from an executed payload (e.g., an onerror handler), confirming code execution.
	SINK_EXECUTION_PROOF TaintSink = "EXECUTION_PROOF"

	// -- HTML & Script Injection Sinks --

	SINK_INNER_HTML                       TaintSink = "SINK_INNER_HTML"
	SINK_OUTER_HTML                       TaintSink = "SINK_OUTER_HTML"
	SINK_INSERT_ADJACENT_HTML             TaintSink = "SINK_INSERT_ADJACENT_HTML"
	SINK_DOCUMENT_WRITE                   TaintSink = "SINK_DOCUMENT_WRITE"
	SINK_IFRAME_SRCDOC                    TaintSink = "SINK_IFRAME_SRCDOC"
	SINK_RANGE_CREATE_CONTEXTUAL_FRAGMENT TaintSink = "SINK_RANGE_CREATE_CONTEXTUAL_FRAGMENT"

	// -- Code Execution Sinks --

	SINK_EVAL                 TaintSink = "SINK_EVAL"
	SINK_FUNCTION_CONSTRUCTOR TaintSink = "SINK_FUNCTION_CONSTRUCTOR"
	SINK_SET_TIMEOUT_STRING   TaintSink = "SINK_SET_TIMEOUT_STRING"
	SINK_SET_INTERVAL_STRING  TaintSink = "SINK_SET_INTERVAL_STRING"

	// -- URL, Redirect, and Navigation Sinks --

	SINK_LOCATION         TaintSink = "SINK_LOCATION"
	SINK_LOCATION_ASSIGN  TaintSink = "SINK_LOCATION_ASSIGN"
	SINK_LOCATION_REPLACE TaintSink = "SINK_LOCATION_REPLACE"
	SINK_WINDOW_OPEN      TaintSink = "SINK_WINDOW_OPEN"
	SINK_A_HREF_JAVASCRIPT TaintSink = "SINK_A_HREF_JAVASCRIPT" // For javascript: URIs

	// -- Resource Loading & Inclusion Sinks --

	SINK_SCRIPT_SRC  TaintSink = "SINK_SCRIPT_SRC"
	SINK_IFRAME_SRC  TaintSink = "SINK_IFRAME_SRC"
	SINK_EMBED_SRC   TaintSink = "SINK_EMBED_SRC"
	SINK_OBJECT_DATA TaintSink = "SINK_OBJECT_DATA"
	SINK_BASE_HREF   TaintSink = "SINK_BASE_HREF"

	// -- Attribute & Style Injection Sinks --

	// SINK_SET_ATTRIBUTE_DANGEROUS covers attributes like 'src', 'href', 'formaction', etc.
	SINK_SET_ATTRIBUTE_DANGEROUS TaintSink = "SINK_SET_ATTRIBUTE_DANGEROUS"
	// SINK_ON_EVENT_HANDLER covers assignment to properties like 'onclick', 'onerror', etc.
	SINK_ON_EVENT_HANDLER        TaintSink = "SINK_ON_EVENT_HANDLER"

	// -- Data Exfiltration Sinks --

	SINK_FETCH_URL            TaintSink = "SINK_FETCH_URL"
	SINK_XHR_OPEN_URL         TaintSink = "SINK_XHR_OPEN_URL"
	SINK_XHR_SEND_DATA        TaintSink = "SINK_XHR_SEND_DATA"
	SINK_WEBSOCKET_URL        TaintSink = "SINK_WEBSOCKET_URL"
	SINK_WEBSOCKET_SEND_DATA  TaintSink = "SINK_WEBSOCKET_SEND_DATA"
	SINK_NAVIGATOR_SEND_BEACON TaintSink = "SINK_NAVIGATOR_SEND_BEACON"
	SINK_DOCUMENT_COOKIE      TaintSink = "SINK_DOCUMENT_COOKIE"
	SINK_POST_MESSAGE_DATA    TaintSink = "SINK_POST_MESSAGE_DATA"

	// -- DOM Clobbering Sinks --
	// This sink is for when an element's 'id' or 'name' attribute, if tainted,
	// could overwrite a global variable.
	SINK_DOM_CLOBBERING TaintSink = "SINK_DOM_CLOBBERING"
)
