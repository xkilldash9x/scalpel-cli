// File: internal/analysis/active/taint/types.go

// Package taint implements the core logic for Interactive Application Security Testing (IAST)
// using dynamic taint analysis within a browser environment.
package taint

import (
	"context"
	"net/url"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Constants defining the names of Go functions exposed to the browser's JavaScript environment.
const (
	JSCallbackSinkEvent      = "__scalpel_sink_event"
	JSCallbackExecutionProof = "__scalpel_execution_proof"
	JSCallbackShimError      = "__scalpel_shim_error"
)

// ----------------------------------------------------------------------------
// Interfaces
// ----------------------------------------------------------------------------

// Event is the marker interface for all data flowing into the correlation engine (polymorphism).
type Event interface {
	isEvent()
}

// OASTProvider defines the interface required for OAST integration.
type OASTProvider interface {
	GetInteractions(ctx context.Context, canaries []string) ([]schemas.OASTInteraction, error)
	GetServerURL() string
}

// SessionContext is a local alias for the canonical schemas.SessionContext interface.
type SessionContext schemas.SessionContext

// ResultsReporter defines the interface for reporting findings.
// CRITICAL: Implementations must be thread-safe.
type ResultsReporter interface {
	// Report persists a correlated finding. It accepts a context for robust error handling (e.g., database timeouts).
	Report(ctx context.Context, finding CorrelatedFinding) error
}

// ----------------------------------------------------------------------------
// Configuration and Definitions
// ----------------------------------------------------------------------------

// Config holds all operational parameters for a single taint analysis task.
type Config struct {
	TaskID      string
	Target      *url.URL
	Probes      []ProbeDefinition
	Sinks       []SinkDefinition
	Interaction schemas.InteractionConfig

	// AnalysisTimeout is the maximum duration for the entire analysis task.
	AnalysisTimeout time.Duration

	// Tuning holds parameters for optimizing performance, concurrency, and timing.
	Tuning TuningConfig
}

// TuningConfig holds low-level parameters for optimizing the analysis engine.
type TuningConfig struct {
	// CorrelationWorkers controls the number of concurrent goroutines processing events.
	CorrelationWorkers int
	// EventChannelBuffer controls the size of the buffer for the main events channel (backpressure control).
	EventChannelBuffer int
	// FinalizationGracePeriod is the time to wait for async events after probing finishes.
	FinalizationGracePeriod time.Duration
	// ProbeExpirationDuration is the TTL for active probes.
	ProbeExpirationDuration time.Duration
	// CleanupInterval is the frequency of the expired probe cleanup routine.
	CleanupInterval time.Duration
	// OASTPollingInterval is the frequency of checking the OAST provider.
	OASTPollingInterval time.Duration
}

// ProbeDefinition defines the blueprint for an attack vector.
type ProbeDefinition struct {
	Type        schemas.ProbeType
	Payload     string // Template string, e.g., {{.Canary}}, {{.OASTServer}}.
	Context     string
	Description string
}

// SinkDefinition defines how a specific JavaScript function or property should be instrumented.
type SinkDefinition struct {
	Name        string            `json:"Name"` // Full path (e.g., "Element.prototype.innerHTML").
	Type        schemas.TaintSink `json:"Type"`
	Setter      bool              `json:"Setter"`
	ArgIndex    int               `json:"ArgIndex"`
	ConditionID string            `json:"ConditionID,omitempty"` // Optional JS-side precondition ID.
}

// ----------------------------------------------------------------------------
// Internal State Tracking
// ----------------------------------------------------------------------------

// ActiveProbe represents a specific, tracked instance of an injected probe.
type ActiveProbe struct {
	Type      schemas.ProbeType
	Key       string // Injection point identifier (e.g., URL param name).
	Value     string // The actual payload injected.
	Canary    string
	Source    schemas.TaintSource
	CreatedAt time.Time
}

// ----------------------------------------------------------------------------
// Event Types (Implementing the Event interface)
// ----------------------------------------------------------------------------

// SinkEvent is reported by the JS shim when tainted data reaches a sink.
type SinkEvent struct {
	Type       schemas.TaintSink `json:"type"`
	Value      string            `json:"value"`
	Detail     string            `json:"detail"`
	StackTrace string            `json:"stack"`
}

func (SinkEvent) isEvent() {}

// ExecutionProofEvent is reported when a payload successfully executes as JavaScript.
type ExecutionProofEvent struct {
	Canary     string `json:"canary"`
	StackTrace string `json:"stack"`
}

func (ExecutionProofEvent) isEvent() {}

// ShimErrorEvent reports internal errors from the JavaScript instrumentation.
type ShimErrorEvent struct {
	Error      string `json:"error"`
	Location   string `json:"location"`
	StackTrace string `json:"stack"`
}

func (ShimErrorEvent) isEvent() {}

// OASTInteraction represents a confirmed out-of-band callback.
type OASTInteraction struct {
	Canary          string
	Protocol        string
	SourceIP        string
	InteractionTime time.Time
	RawRequest      string
}

func (OASTInteraction) isEvent() {}

// ----------------------------------------------------------------------------
// Results and Findings
// ----------------------------------------------------------------------------

// SanitizationLevel indicates whether a payload was modified before reaching a sink.
type SanitizationLevel int

const (
	// SanitizationNone indicates the payload reached the sink intact.
	SanitizationNone SanitizationLevel = iota
	// SanitizationPartial indicates the canary survived, but the payload structure was altered.
	SanitizationPartial
)

// CorrelatedFinding is the output of the analysis, linking a source to a sink event.
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
	OASTDetails       *OASTInteraction
}
