// internal/autofix/models.go
package autofix

import "time"

// PostMortem is the structured report generated when a crash is detected and correlated.
type PostMortem struct {
	IncidentID        string       `json:"incident_id"`
	CrashTime         time.Time    `json:"crash_time"`
	PanicMessage      string       `json:"panic_message"`
	// FilePath should ideally be relative to the project root for consistency.
	FilePath          string       `json:"file_path"`
	LineNumber        int          `json:"line_number"`
	FullStackTrace    string       `json:"full_stack_trace"`
	TriggeringRequest *DASTRequest `json:"triggering_request,omitempty"`
}

// DASTRequest captures the last recorded request from a dynamic analysis tool's log.
type DASTRequest struct {
	Timestamp  time.Time `json:"timestamp"`
	Method     string    `json:"method"`
	URL        string    `json:"url"`
	RawRequest string    `json:"raw_request,omitempty"`
}

// AnalysisResult holds the outcome of the AI's code review and the proposed fix.
type AnalysisResult struct {
	Explanation string  `json:"explanation"`
	RootCause   string  `json:"root_cause"`
	// Confidence score (0.0 to 1.0) provided by the LLM.
	Confidence float64 `json:"confidence"`
	// Patch in standard 'git diff' (unified) format.
	Patch      string  `json:"patch"`
}