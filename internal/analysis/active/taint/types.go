// internal/analysis/active/taint/types.go
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