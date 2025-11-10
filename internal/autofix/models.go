// internal/autofix/models.go
package autofix

import "time"

// PostMortem is a structured report that captures all relevant information about
// an application crash, including the panic message, stack trace, and the HTTP
// request that likely triggered it.
type PostMortem struct {
	IncidentID        string       `json:"incident_id"`
	CrashTime         time.Time    `json:"crash_time"`
	PanicMessage      string       `json:"panic_message"`
	FilePath          string       `json:"file_path"` // Relative to the project root.
	LineNumber        int          `json:"line_number"`
	FullStackTrace    string       `json:"full_stack_trace"`
	TriggeringRequest *DASTRequest `json:"triggering_request,omitempty"`
}

// DASTRequest represents an HTTP request captured from a dynamic analysis
// tool's log, which can be correlated with a crash to identify the trigger.
type DASTRequest struct {
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	RawRequest string    `json:"raw_request,omitempty"`
}

// AnalysisResult encapsulates the output from the Analyzer component. It includes
// the LLM's explanation of the bug, a proposed patch, and a confidence score.
type AnalysisResult struct {
	Explanation string  `json:"explanation"`
	RootCause   string  `json:"root_cause"`
	Confidence  float64 `json:"confidence"` // A score from 0.0 to 1.0.
	Patch       string  `json:"patch"`      // The patch in unified diff format.
}
