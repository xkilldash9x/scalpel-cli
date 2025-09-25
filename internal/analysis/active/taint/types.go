// package taint defines the core data structures, constants, and interfaces
// used throughout the IAST analysis system.
package taint

import (
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Constants defining the names of Go functions exposed to the browser's
// JavaScript environment. These create the callback bridge from the JS shim
// back to the Go analyzer.
const (
	JSCallbackSinkEvent      = "__scalpel_sink_event"
	JSCallbackExecutionProof = "__scalpel_execution_proof"
	JSCallbackShimError      = "__scalpel_shim_error"
)

// Event is the base interface for all data flowing into the correlation engine.
// It enables the use of a single channel for different event types.
type Event interface {
	isEvent()
}

// SanitizationLevel indicates whether a payload was modified by the application
// before reaching a sink.
type SanitizationLevel int

const (
	// SanitizationNone indicates the payload reached the sink intact.
	SanitizationNone SanitizationLevel = iota
	// SanitizationPartial indicates the canary was found, but the payload's
	// structure was modified (e.g., HTML tags stripped, quotes escaped).
	SanitizationPartial
)

// ProbeDefinition defines the blueprint for an attack vector, including its type,
// payload template, and context.
type ProbeDefinition struct {
	Type        schemas.ProbeType `json:"type" yaml:"type"`
	Payload     string            `json:"payload" yaml:"payload"`
	Context     string            `json:"context" yaml:"context"`
	Description string            `json:"description" yaml:"description"`
}

// ActiveProbe represents a specific, tracked instance of a ProbeDefinition that
// has been injected into the target application.
type ActiveProbe struct {
	Type      schemas.ProbeType
	Key       string // The name/key used for injection (e.g., URL parameter name, cookie name).
	Value     string // The full payload after template substitution.
	Canary    string // The unique identifier for this specific probe instance.
	Source    schemas.TaintSource
	CreatedAt time.Time
}

// SinkEvent is reported by the JS shim when a tainted value is passed to an
// instrumented function or property (a "sink").
type SinkEvent struct {
	Type       schemas.TaintSink `json:"type"`
	Value      string            `json:"value"` // The tainted value observed at the sink.
	Detail     string            `json:"detail"`  // Additional context, like the function or property name.
	StackTrace string            `json:"stack"`
}

func (SinkEvent) isEvent() {}

// ExecutionProofEvent is reported by the JS shim when a payload's canary is
// executed directly as JavaScript, confirming a vulnerability.
type ExecutionProofEvent struct {
	Canary     string `json:"canary"`
	StackTrace string `json:"stack"`
}

func (ExecutionProofEvent) isEvent() {}

// ShimErrorEvent is used to report internal errors from the JavaScript shim
// back to the Go backend for debugging.
type ShimErrorEvent struct {
	Error      string `json:"error"`
	Location   string `json:"location"`
	StackTrace string `json:"stack"`
}

func (ShimErrorEvent) isEvent() {}


// OASTInteraction represents a confirmed out-of-band callback received by the
// OAST provider. It implements the Event interface to be processed by the
// correlation engine.
type OASTInteraction struct {
	Canary          string
	Protocol        string
	SourceIP        string
	InteractionTime time.Time
	RawRequest      string
}

func (OASTInteraction) isEvent() {}

// CorrelatedFinding is the final output of the analysis engine, representing a
// detected or confirmed vulnerability.
type CorrelatedFinding struct {
	TaskID            string
	TargetURL         string
	Sink              schemas.TaintSink
	Origin            schemas.TaintSource
	Value             string // The value observed at the sink.
	Canary            string
	Probe             ActiveProbe
	Detail            string
	IsConfirmed       bool // True if confirmed by execution proof or OAST.
	SanitizationLevel SanitizationLevel
	StackTrace        string
	OASTDetails       *OASTInteraction // Details if confirmed via OAST.
}

// OASTProvider is an alias for the canonical OASTProvider interface, used to
// decouple the analyzer from the specific implementation.
type OASTProvider schemas.OASTProvider

// SessionContext is an alias for the canonical SessionContext interface.
type SessionContext schemas.SessionContext

// ResultsReporter defines the interface for reporting findings. The Report
// method must be thread-safe as it may be called concurrently by multiple
// correlation workers.
type ResultsReporter interface {
	Report(finding CorrelatedFinding)
}

// SinkDefinition defines how a specific JavaScript function or property should
// be instrumented by the JS shim.
type SinkDefinition struct {
	Name        string            `json:"Name" yaml:"name"` // Full property path (e.g., "Element.prototype.innerHTML").
	Type        schemas.TaintSink `json:"Type" yaml:"type"` // The canonical sink type.
	Setter      bool              `json:"Setter" yaml:"setter"`     // True if this is a property setter (e.g., innerHTML), false for a function call.
	ArgIndex    int               `json:"ArgIndex" yaml:"arg_index"`  // The argument index to inspect for taint (for function calls).
	ConditionID string            `json:"ConditionID,omitempty" yaml:"condition_id,omitempty"` // An optional ID for a JS-side pre-condition check.
}

// Config holds all operational parameters for a single taint analysis task.
type Config struct {
	TaskID      string   `json:"task_id" yaml:"task_id"`
	Target      *url.URL
	Probes      []ProbeDefinition `json:"probes" yaml:"probes"`
	Sinks       []SinkDefinition  `json:"sinks" yaml:"sinks"`
	Interaction schemas.InteractionConfig `json:"interaction" yaml:"interaction"`

	// AnalysisTimeout is the total maximum duration for the entire analysis.
	AnalysisTimeout time.Duration `json:"analysis_timeout" yaml:"analysis_timeout"`

	// -- Performance & Concurrency Tuning --

	// CorrelationWorkers controls the number of goroutines processing events concurrently.
	CorrelationWorkers int `json:"correlation_workers" yaml:"correlation_workers"`
	// EventChannelBuffer is the size of the buffer for the main events channel.
	EventChannelBuffer int `json:"event_channel_buffer" yaml:"event_channel_buffer"`
	// FinalizationGracePeriod is the extra time to wait for async events after probing finishes.
	FinalizationGracePeriod time.Duration `json:"finalization_grace_period" yaml:"finalization_grace_period"`
	// ProbeExpirationDuration is the TTL for active probes to prevent memory leaks.
	ProbeExpirationDuration time.Duration `json:"probe_expiration_duration" yaml:"probe_expiration_duration"`
	// CleanupInterval is the frequency at which the expired probe cleanup task runs.
	CleanupInterval time.Duration `json:"cleanup_interval" yaml:"cleanup_interval"`
	// OASTPollingInterval is the frequency at which the OAST provider is checked for interactions.
	OASTPollingInterval time.Duration `json:"oast_polling_interval" yaml:"oast_polling_interval"`
}