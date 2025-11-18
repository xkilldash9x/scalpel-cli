// File: internal/analysis/core/taint_defs.go
package core

// TaintSource represents a potential entry point for user controlled data.
type TaintSource string

// TaintSink represents a dangerous function or property where tainted data could lead to a vulnerability.
type TaintSink string

// SinkType categorizes the impact of a taint sink.
type SinkType string

const (
	SinkTypeExecution          SinkType = "Code Execution"
	SinkTypeHTMLInjection      SinkType = "DOM XSS (HTML Injection)"
	SinkTypeURLRedirection     SinkType = "Open Redirect/URL Manipulation"
	SinkTypeCookieManipulation SinkType = "Cookie Manipulation"
	SinkTypeAttributeInjection SinkType = "DOM XSS (Attribute Injection)"
	SinkTypeDataLeak           SinkType = "Data Leakage"
)

// Known Taint Sources (DOM/Browser APIs)
const (
	SourceLocationHash     TaintSource = "location.hash"
	SourceLocationSearch   TaintSource = "location.search"
	SourceLocationHref     TaintSource = "location.href"
	SourceDocumentCookie   TaintSource = "document.cookie"
	SourceDocumentReferrer TaintSource = "document.referrer"
	SourceWindowName       TaintSource = "window.name"
	SourceLocalStorage     TaintSource = "localStorage.getItem"
	SourceSessionStorage   TaintSource = "sessionStorage.getItem"
	SourcePostMessageData  TaintSource = "message.data"
	SourceUnknown          TaintSource = "unknown_source" // Used when propagating taint without a clear origin
)

// SinkDefinition provides metadata about a specific sink.
type SinkDefinition struct {
	Name        string    `json:"Name" yaml:"name"`                                    // Full property path (e.g., "Element.prototype.innerHTML").
	Type        TaintSink `json:"Type" yaml:"type"`                                    // The canonical sink type.
	Setter      bool      `json:"Setter" yaml:"setter"`                                // True if this is a property setter.
	ArgIndex    int       `json:"ArgIndex" yaml:"arg_index"`                           // The argument index to inspect for taint (for function calls).
	ConditionID string    `json:"ConditionID,omitempty" yaml:"condition_id,omitempty"` // An optional ID for a JS-side pre-condition.
}
