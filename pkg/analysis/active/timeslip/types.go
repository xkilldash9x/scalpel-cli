// pkg/analysis/active/timeslip/types.go
package timeslip

import (
	"bytes"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/network"
)

// Define custom error types for better classification.
var (
	ErrH2Unsupported       = errors.New("H2 strategy failed: server did not utilize HTTP/2 (downgraded or unsupported)")
	ErrPipeliningRejected  = errors.New("pipelining rejected by server (connection closed during write)")
	ErrTargetUnreachable   = errors.New("target unreachable or timed out")
	ErrConfigurationError  = errors.New("configuration or input data error")
	ErrPayloadMutationFail = errors.New("payload mutation failed")
)

// RaceStrategy defines the technique used to induce the race condition.
type RaceStrategy string

const (
	H1Concurrent     RaceStrategy = "H1_CONCURRENT"
	H1SingleByteSend RaceStrategy = "H1_SINGLE_BYTE_SEND"
	H2Multiplexing   RaceStrategy = "H2_MULTIPLEXING"
	AsyncGraphQL     RaceStrategy = "ASYNC_GRAPHQL_BATCH"
)

// RaceCandidate defines the target request to be used in the race condition test.
type RaceCandidate struct {
	Method    string
	URL       string
	Headers   http.Header
	// Body may contain template variables like {{UUID}} or {{NONCE}}.
	Body      []byte
	IsGraphQL bool
}

// SuccessCondition defines customizable rules for determining if an operation was successful.
type SuccessCondition struct {
	// StatusCodes: If empty, defaults to 2xx/3xx.
	StatusCodes []int `json:"status_codes,omitempty"`
	// BodyRegex: Must match the response body.
	BodyRegex string `json:"body_regex,omitempty"`
	// HeaderRegex: Must match at least one response header (Key: Value).
	HeaderRegex string `json:"header_regex,omitempty"`

	// Compiled regexes (unexported).
	bodyRx   *regexp.Regexp
	headerRx *regexp.Regexp
}

// Config holds the configuration parameters for the TimeSlip analysis.
type Config struct {
	Concurrency     int           `json:"concurrency"`
	Timeout         time.Duration `json:"timeout"`
	IgnoreTLSErrors bool          `json:"ignore_tls_errors"`
	ThresholdMs     int           `json:"threshold_ms"`

	// Success defines the conditions for a successful operation.
	Success SuccessCondition `json:"success_conditions"`

	// RequestJitter adds a random delay (up to this duration) before sending each request.
	RequestJitter time.Duration `json:"request_jitter,omitempty"`
	// ConnectionDelay (H1Concurrent only) adds a delay during initialization to prime connections.
	ConnectionDelay time.Duration `json:"connection_delay,omitempty"`
	// ExpectedSuccesses defines the maximum number of successful operations expected.
	// If nil or <= 0, defaults to 1 (standard TOCTOU assumption).
	ExpectedSuccesses int `json:"expected_successes,omitempty"`
}

// RaceResponse is the result from a single operation within a race attempt.
type RaceResponse struct {
	*network.ParsedResponse
	// Fingerprint is the composite hash (Status+Headers+Body) used for comparison.
	Fingerprint string
	Error       error
	StreamID    uint32

	// IsSuccess indicates whether the specific action succeeded (determined by the SuccessOracle).
	IsSuccess bool

	// SpecificBody holds the response body relevant to this operation.
	SpecificBody []byte
}

// RaceResult is the collection of all responses from a single race attempt strategy.
type RaceResult struct {
	Strategy  RaceStrategy
	Responses []*RaceResponse
	Duration  time.Duration
}

// ResponseStatistics holds statistical data about the response times.
type ResponseStatistics struct {
	MinDurationMs int64   `json:"min_duration_ms"`
	MaxDurationMs int64   `json:"max_duration_ms"`
	AvgDurationMs float64 `json:"avg_duration_ms"`
	MedDurationMs float64 `json:"med_duration_ms"`
	StdDevMs      float64 `json:"std_dev_ms"`
	TimingDeltaMs int64   `json:"timing_delta_ms"`
}

// AnalysisResult is the final assessment of the race attempt.
type AnalysisResult struct {
	Vulnerable      bool
	Strategy        RaceStrategy
	Details         string
	// Confidence level (0.0 to 1.0).
	Confidence      float64
	SuccessCount    int
	UniqueResponses map[string]int

	// Stats provides detailed timing analysis.
	Stats ResponseStatistics
}

// --- sync.Pool Implementation for Performance Optimization ---

const maxResponseBodyBytes = 2 * 1024 * 1024 // 2 MB limit

// bufferPool is used to reuse bytes.Buffer objects, reducing GC pressure.
var bufferPool = sync.Pool{
	New: func() interface{} {
		// Pre-allocate a reasonable size buffer (e.g., 4KB).
		b := new(bytes.Buffer)
		b.Grow(4096)
		return b
	},
}

// getBuffer retrieves a buffer from the pool.
func getBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

// putBuffer returns a buffer to the pool. The buffer is reset before being put back.
func putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	// Optimization: Avoid returning excessively large buffers to the pool if they grew significantly.
	if buf.Cap() < 64*1024 { // 64KB limit
		bufferPool.Put(buf)
	}
	// Otherwise, let GC handle it.
}
