// pkg/analysis/active/taint/types.go
package taint

import (
	"context"
	"net/url"
	"time"
)

// -- Constants --

// JavaScript callback function names exposed by the Go analyzer to the browser.
const (
	JSCallbackSinkEvent      = "__scalpel_sink_event"
	JSCallbackExecutionProof = "__scalpel_execution_proof"
	// ENHANCEMENT: Callback for instrumentation or runtime errors in the JS shim.
	JSCallbackShimError = "__scalpel_shim_error"
)

// -- Core IAST Concepts --

// Event represents any message sent to the correlation engine.
type Event interface {
	isEvent()
}

// TaintSource is where the sketchy data comes from.
type TaintSource string

const (
	SourceURLParam       TaintSource = "URL_PARAMETER"
	SourceHashFragment   TaintSource = "HASH_FRAGMENT"
	SourceCookie         TaintSource = "COOKIE"
	SourceHeader         TaintSource = "HEADER"
	SourceBody           TaintSource = "BODY"
	SourceLocalStorage   TaintSource = "LOCAL_STORAGE"
	SourceSessionStorage TaintSource = "SESSION_STORAGE"
	SourcePostMessage    TaintSource = "POST_MESSAGE"   // Taint arriving via window.postMessage
	SourceWorkerMessage  TaintSource = "WORKER_MESSAGE" // Taint arriving from a Web Worker
)

// TaintSink is where the sketchy data ends up.
type TaintSink string

const (
	// Execution/DOM Sinks
	SinkEval                TaintSink = "EVAL"
	SinkFunctionConstructor TaintSink = "FUNCTION_CONSTRUCTOR"
	SinkInnerHTML           TaintSink = "INNER_HTML"
	SinkOuterHTML           TaintSink = "OUTER_HTML"
	SinkDocumentWrite       TaintSink = "DOCUMENT_WRITE"
	SinkIframeSrcDoc        TaintSink = "IFRAME_SRCDOC"

	// High confidence signals
	SinkExecution          TaintSink = "EXECUTION_PROOF"
	SinkOASTInteraction    TaintSink = "OAST_INTERACTION"    // Confirmed via Out-of-Band callback
	SinkPrototypePollution TaintSink = "PROTOTYPE_POLLUTION" // Confirmed pollution of Object.prototype

	// Resource/Navigation Sinks
	SinkScriptSrc  TaintSink = "SCRIPT_SRC"
	SinkIframeSrc  TaintSink = "IFRAME_SRC"
	SinkNavigation TaintSink = "NAVIGATION"
	SinkWorkerSrc  TaintSink = "WORKER_SRC"

	// Network/Exfiltration Sinks
	SinkWebSocketSend      TaintSink = "WEBSOCKET_SEND"
	SinkXMLHTTPRequest     TaintSink = "XHR_SEND"
	SinkXMLHTTPRequest_URL TaintSink = "XHR_URL"
	SinkFetch              TaintSink = "FETCH_BODY"
	SinkFetch_URL          TaintSink = "FETCH_URL"
	SinkSendBeacon         TaintSink = "SEND_BEACON"

	// Inter-Process Communication (IPC) Sinks
	SinkPostMessage       TaintSink = "POST_MESSAGE"        // Taint leaving via window.postMessage
	SinkWorkerPostMessage TaintSink = "WORKER_POST_MESSAGE" // Taint being sent to a Web Worker
)

// ProbeType is the category for the attack vector.
type ProbeType string

const (
	ProbeTypeXSS                ProbeType = "XSS"
	ProbeTypeSSTI               ProbeType = "SSTI"
	ProbeTypeSQLi               ProbeType = "SQLI"
	ProbeTypeCmdInjection       ProbeType = "CMD_INJECTION"
	ProbeTypeGeneric            ProbeType = "GENERIC"
	ProbeTypeDOMClobbering      ProbeType = "DOM_CLOBBERING"
	// ENHANCEMENT: Probes specifically designed to pollute object prototypes.
	ProbeTypePrototypePollution ProbeType = "PROTOTYPE_POLLUTION"
	// ENHANCEMENT: Probes relying on Out-of-Band callbacks (Blind XSS, SSRF).
	ProbeTypeOAST ProbeType = "OAST"
)

// SanitizationLevel indicates if the payload was modified before reaching the sink.
type SanitizationLevel int

const (
	SanitizationNone    SanitizationLevel = iota // Payload arrived intact.
	SanitizationPartial                          // Canary found, but payload structure is broken (e.g., tags stripped, quotes escaped).
)

// -- Data Structures --

// ProbeDefinition is the blueprint for one of our attack payloads.
type ProbeDefinition struct {
	Type        ProbeType `json:"type" yaml:"type"`
	Payload     string    `json:"payload" yaml:"payload"`
	// Context is a hint about where we expect the payload to work best.
	Context     string `json:"context" yaml:"context"`
	Description string `json:"description" yaml:"description"`
}

// ActiveProbe is a specific instance of a probe injected into the application.
type ActiveProbe struct {
	Type      ProbeType
	Key       string      // what param did we inject it into?
	Value     string      // what was the full payload?
	Canary    string      // the unique ID for this probe.
	Source    TaintSource // where did it come from?
	CreatedAt time.Time   // Timestamp for expiration tracking.
}

// SinkEvent is reported by the browser shim when tainted data reaches a sink.
// JSON tags must match the JS shim output.
type SinkEvent struct {
	Type       TaintSink `json:"type"`
	Value      string    `json:"value"`
	Detail     string    `json:"detail"`
	StackTrace string    `json:"stack"` // JS stack trace.
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

// CorrelatedFinding links a source to a sink, representing a vulnerability.
type CorrelatedFinding struct {
	TaskID            string
	TargetURL         string
	Sink              TaintSink
	Origin            TaintSource
	Value             string // The value that reached the sink.
	Canary            string
	Probe             ActiveProbe
	Detail            string
	IsConfirmed       bool              // True if confirmed via ExecutionProof, OAST, or definitive sinks (e.g., Prototype Pollution).
	SanitizationLevel SanitizationLevel // Indicates if the payload was modified.
	StackTrace        string            // The relevant stack trace.
	OASTDetails       *OASTInteraction  // Details if confirmed via OAST.
}

// -- Interfaces --

// its the contract for interacting with an OAST service.
type OASTProvider interface {
	//  fetches interactions since the last check for the given canaries.
	GetInteractions(ctx context.Context, canaries []string) ([]OASTInteraction, error)
	//  returns the base URL/domain for the OAST server to be used in payloads.
	GetServerURL() string
}

// contract for controlling a browser.
type BrowserInteractor interface {
	InitializeSession(ctx context.Context) (SessionContext, error)
}

// contract for a single, isolated browser tab.
type SessionContext interface {
	// instrumentation stuff
	InjectScriptPersistently(ctx context.Context, script string) error
	ExposeFunction(ctx context.Context, name string, function interface{}) error
	ExecuteScript(ctx context.Context, script string) error

	// driving the browser
	Navigate(ctx context.Context, url string) error
	WaitForAsync(ctx context.Context, milliseconds int) error
	Interact(ctx context.Context, config InteractionConfig) error

	// cleanup
	Close() error
}

//  how we phone home with any cool findings.
type ResultsReporter interface {
	Report(finding CorrelatedFinding)
}

// -- Configuration --

// the blueprint for how to hook a specific function in JS.
type SinkDefinition struct {
	Name        string    `json:"Name" yaml:"name"`                   // e.g., "Element.prototype.innerHTML"
	Type        TaintSink `json:"Type" yaml:"type"`
	Setter      bool      `json:"Setter" yaml:"setter"`               // is it a property setter or a function call?
	ArgIndex    int       `json:"ArgIndex" yaml:"arg_index"`          // which function argument do we care about?
	// ConditionID refers to a predefined handler in the JS shim (CSP compliant).
	ConditionID string    `json:"ConditionID,omitempty" yaml:"condition_id,omitempty"`
}

//  holds the settings for the browser interaction/crawling phase.
type InteractionConfig struct {
	MaxDepth                int `json:"max_depth" yaml:"max_depth"`
	MaxInteractionsPerDepth int `json:"max_interactions_per_depth" yaml:"max_interactions_per_depth"`
	InteractionDelayMs      int `json:"interaction_delay_ms" yaml:"interaction_delay_ms"`
	PostInteractionWaitMs   int `json:"post_interaction_wait_ms" yaml:"post_interaction_wait_ms"`
}

// Config is all the settings for the Taint Analyzer.
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
	// STATE MANAGEMENT: How long probes remain active before expiring (crucial for SPAs).
	ProbeExpirationDuration time.Duration `json:"probe_expiration_duration" yaml:"probe_expiration_duration"`
	CleanupInterval         time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	OASTPollingInterval     time.Duration `json:"oast_polling_interval" yaml:"oast_polling_interval"`
}
