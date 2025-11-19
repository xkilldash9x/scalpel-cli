// File: internal/analysis/core/definitions.go
package core

import (
	"net/http"
	// Added imports for taint definitions
	"strings"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- Identifier Definitions --

// IdentifierType provides a classification for different kinds of resource
// identifiers found in HTTP requests, such as numeric IDs or UUIDs.
type IdentifierType string

// IdentifierLocation specifies the exact part of an HTTP request where an
// identifier was discovered.
type IdentifierLocation string

const (
	TypeUnknown   IdentifierType = "Unknown"
	TypeNumericID IdentifierType = "NumericID"
	TypeUUID      IdentifierType = "UUID"
	TypeObjectID  IdentifierType = "ObjectID" // e.g., MongoDB ObjectID
	TypeBase64    IdentifierType = "Base64"
)

const (
	LocationURLPath    IdentifierLocation = "URLPath"
	LocationQueryParam IdentifierLocation = "QueryParam"
	LocationJSONBody   IdentifierLocation = "JSONBody"
	LocationHeader     IdentifierLocation = "Header"
)

// ObservedIdentifier provides a structured representation of a potential
// resource identifier discovered within an HTTP request, detailing its value,
// type, and precise location.
type ObservedIdentifier struct {
	Value     string
	Type      IdentifierType
	Location  IdentifierLocation
	Key       string // The key for headers, query params, or the JSON path.
	PathIndex int    // The index for URL path segments.
}

// -- Taint Analysis Definitions (Shared between Static and Dynamic) --
// (Step 1: Moved from javascript/definitions.go and taint/probes.go)

// TaintSource represents a potential entry point for user controlled data (used primarily in SAST reporting).
type TaintSource string

// TaintSink represents a specific function or property name identified statically (used primarily in SAST reporting).
type TaintSink string

// SinkType categorizes the impact of a taint sink (used primarily in SAST reporting).
type SinkType string

// SinkType constants
const (
	SinkTypeExecution          SinkType = "Code Execution"
	SinkTypeHTMLInjection      SinkType = "DOM XSS (HTML Injection)"
	SinkTypeURLRedirection     SinkType = "Open Redirect/URL Manipulation"
	SinkTypeCookieManipulation SinkType = "Cookie Manipulation"
	SinkTypeAttributeInjection SinkType = "DOM XSS (Attribute Injection)"
	SinkTypeDataLeak           SinkType = "Data Leakage"
	SinkTypeUnknown            SinkType = "Unknown"
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

// SinkDefinition provides the blueprint for instrumenting (IAST) or analyzing (SAST) a single JavaScript sink.
// It unifies the definitions previously split between taint/types.go and javascript/definitions.go.
// (Step 1: Moved and adapted from taint/types.go SinkDefinition)
type SinkDefinition struct {
	// Full property path (e.g., "Element.prototype.innerHTML").
	Name string `json:"Name" yaml:"name"`
	// The canonical sink type (e.g., SinkInnerHTML). Used for correlation.
	Type schemas.TaintSink `json:"Type" yaml:"type"`

	// -- Instrumentation Details (IAST) --

	// True if this is a property setter.
	Setter bool `json:"Setter" yaml:"setter"`
	// The argument index to inspect for taint (for function calls).
	ArgIndex int `json:"ArgIndex" yaml:"arg_index"`
	// An optional ID for a JS-side pre-condition (e.g. "IS_STRING_ARG0").
	ConditionID string `json:"ConditionID,omitempty" yaml:"condition_id,omitempty"`
}

// -- Unified Sink List --

// DefaultSinks provides the unified list of JavaScript sinks.
// (Step 1: Moved from taint/probes.go)
func DefaultSinks() []SinkDefinition {
	return []SinkDefinition{
		// -- Execution Sinks (High Risk) --
		{Name: "eval", Type: schemas.SinkEval, Setter: false, ArgIndex: 0}, // Global eval
		// setTimeout/setInterval are only dangerous if the first argument is a string.
		{Name: "setTimeout", Type: schemas.SinkEval, Setter: false, ArgIndex: 0, ConditionID: "IS_STRING_ARG0"},
		{Name: "setInterval", Type: schemas.SinkEval, Setter: false, ArgIndex: 0, ConditionID: "IS_STRING_ARG0"},
		// Function constructor sinks
		{Name: "Function", Type: schemas.SinkFunctionConstructor, Setter: false, ArgIndex: 0},
		{Name: "Function.prototype.constructor", Type: schemas.SinkFunctionConstructor, Setter: false, ArgIndex: 0},

		// -- DOM Manipulation & HTML Rendering Sinks --
		{Name: "document.write", Type: schemas.SinkDocumentWrite, Setter: false, ArgIndex: 0},
		{Name: "document.writeln", Type: schemas.SinkDocumentWrite, Setter: false, ArgIndex: 0},

		// These apply to standard DOM and Shadow DOM elements due to prototype inheritance.
		{Name: "Element.prototype.innerHTML", Type: schemas.SinkInnerHTML, Setter: true},
		{Name: "Element.prototype.outerHTML", Type: schemas.SinkOuterHTML, Setter: true},
		{Name: "Element.prototype.insertAdjacentHTML", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 1},

		// DOMParser sink
		{Name: "DOMParser.prototype.parseFromString", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 0},

		// jQuery sinks (Common sources of DOM XSS)
		{Name: "jQuery.prototype.html", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.append", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.prepend", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.after", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.before", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.replaceWith", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.globalEval", Type: schemas.SinkEval, Setter: false, ArgIndex: 0},
		{Name: "jQuery.parseHTML", Type: schemas.SinkInnerHTML, Setter: false, ArgIndex: 0},

		// -- Navigation Sinks (Open Redirect / Protocol-based XSS / SPA Routing) --
		/*
			FIX: Instrument Location.prototype instead of the 'location' instance (e.g., window.location).
			Browsers lock down the 'location' object instance ([LegacyUnforgeable] attributes in WebIDL),
			preventing modification of its methods/properties directly on the instance.
			Instrumenting the prototype is allowed and effective across modern browsers.
		*/
		// Instrumenting the 'href' setter on the prototype covers both `location.href = X` and `location = X`.
		{Name: "Location.prototype.href", Type: schemas.SinkNavigation, Setter: true},
		{Name: "Location.prototype.assign", Type: schemas.SinkNavigation, Setter: false, ArgIndex: 0},
		{Name: "Location.prototype.replace", Type: schemas.SinkNavigation, Setter: false, ArgIndex: 0},

		{Name: "open", Type: schemas.SinkNavigation, Setter: false, ArgIndex: 0}, // Global open (window.open)

		// History API (SPA Navigation/DOM XSS vectors) - Added for increased effectiveness in SPAs.
		// The URL is the 3rd argument (index 2).
		{Name: "History.prototype.pushState", Type: schemas.SinkNavigation, Setter: false, ArgIndex: 2},
		{Name: "History.prototype.replaceState", Type: schemas.SinkNavigation, Setter: false, ArgIndex: 2},

		// -- Resource Loading Sinks --
		{Name: "HTMLScriptElement.prototype.src", Type: schemas.SinkScriptSrc, Setter: true},
		{Name: "HTMLIFrameElement.prototype.src", Type: schemas.SinkIframeSrc, Setter: true},
		{Name: "HTMLIFrameElement.prototype.srcdoc", Type: schemas.SinkIframeSrcDoc, Setter: true},

		// -- Data Exfiltration / Network Sinks --
		{Name: "WebSocket.prototype.send", Type: schemas.SinkWebSocketSend, Setter: false, ArgIndex: 0},

		// navigator.sendBeacon (Arg 1 is the data)
		{Name: "navigator.sendBeacon", Type: schemas.SinkSendBeacon, Setter: false, ArgIndex: 1, ConditionID: "SEND_BEACON_DATA_EXISTS"},

		// XHR: Body (send) or URL (open)
		{Name: "XMLHttpRequest.prototype.send", Type: schemas.SinkXMLHTTPRequest, Setter: false, ArgIndex: 0, ConditionID: "XHR_SEND_DATA_EXISTS"},
		{Name: "XMLHttpRequest.prototype.open", Type: schemas.SinkXMLHTTPRequestURL, Setter: false, ArgIndex: 1},

		// Fetch: URL (arg 0) or Body (arg 1) - Handled dynamically in JS Shim
		{Name: "fetch", Type: schemas.SinkFetchURL, Setter: false, ArgIndex: 0},
		{Name: "fetch", Type: schemas.SinkFetch, Setter: false, ArgIndex: 1},

		// -- Inter-Process Communication (IPC) Sinks --

		// window.postMessage (Taint flowing to other windows/iframes)
		// Note: We instrument Window.prototype, but this might fail in some environments if Window is not exposed globally or is locked down.
		// It generally works in standard browser contexts.
		{Name: "Window.prototype.postMessage", Type: schemas.SinkPostMessage, Setter: false, ArgIndex: 0},
		// Worker.postMessage (Taint flowing to Web Workers)
		{Name: "Worker.prototype.postMessage", Type: schemas.SinkWorkerPostMessage, Setter: false, ArgIndex: 0},
		// DedicatedWorkerGlobalScope.postMessage (Taint flowing from Worker back to main thread)
		{Name: "DedicatedWorkerGlobalScope.prototype.postMessage", Type: schemas.SinkPostMessage, Setter: false, ArgIndex: 0},
	}
}

// GetSinkType maps the canonical schemas.TaintSink (used by IAST) to the broader SinkType (used by SAST).
// This helper is crucial for correlation between the two engines (Step 5).
func GetSinkType(canonical schemas.TaintSink) SinkType {
	switch canonical {
	case schemas.SinkEval, schemas.SinkFunctionConstructor, schemas.SinkScriptSrc, schemas.SinkExecution:
		return SinkTypeExecution
	case schemas.SinkInnerHTML, schemas.SinkOuterHTML, schemas.SinkDocumentWrite, schemas.SinkIframeSrcDoc:
		return SinkTypeHTMLInjection
	case schemas.SinkNavigation, schemas.SinkIframeSrc, schemas.SinkWorkerSrc:
		// IframeSrc/WorkerSrc can be navigation or execution depending on protocol, we categorize broadly here.
		return SinkTypeURLRedirection
	case schemas.SinkWebSocketSend, schemas.SinkXMLHTTPRequest, schemas.SinkXMLHTTPRequestURL, schemas.SinkFetch, schemas.SinkFetchURL, schemas.SinkSendBeacon, schemas.SinkPostMessage, schemas.SinkWorkerPostMessage, schemas.SinkOASTInteraction:
		return SinkTypeDataLeak
	default:
		// Fallback heuristics based on string matching for robustness
		if strings.Contains(string(canonical), "HTML") {
			return SinkTypeHTMLInjection
		}
		if strings.Contains(string(canonical), "ATTRIBUTE") {
			return SinkTypeAttributeInjection
		}
		return SinkTypeUnknown
	}
}

// -- General Analysis Definitions --

// Removed deprecated types: SeverityLevel, Status, AnalysisResult, Evidence.
// Analyzers should use the canonical schemas defined in api/schemas.

// SerializedResponse provides a JSON-safe representation of an HTTP response,
// intended for embedding within the `Evidence` field of a finding. It ensures
// the response body is stored as a string.
type SerializedResponse struct {
	StatusCode int         `json:"status_code"`
	Headers    http.Header `json:"headers"`
	Body       string      `json:"body"`
}

// Reporter defines a standard, thread-safe interface for components that can
// publish the results of an analysis, such as writing them to a database or a file.
type Reporter interface {
	// Write takes a `ResultEnvelope`, which can contain findings and/or
	// knowledge graph updates, and persists it.
	Write(envelope *schemas.ResultEnvelope) error
}

// --- Static Analysis Helpers (Moved from javascript/definitions.go) ---
// These helpers are specific to how the static analyzer interprets the AST paths.

// knownPropertySources is a map for quick lookup of recognized sources accessed via properties.
var knownPropertySources = map[string]TaintSource{
	string(SourceLocationHash):     SourceLocationHash,
	string(SourceLocationSearch):   SourceLocationSearch,
	string(SourceLocationHref):     SourceLocationHref,
	string(SourceDocumentCookie):   SourceDocumentCookie,
	string(SourceDocumentReferrer): SourceDocumentReferrer,
	string(SourceWindowName):       SourceWindowName,
	// Including variations with "window." prefixes
	"window.location.hash":   SourceLocationHash,
	"window.location.search": SourceLocationSearch,
	"window.location.href":   SourceLocationHref,
}

// knownFunctionSources defines sources accessed via function calls.
var knownFunctionSources = map[string]TaintSource{
	"localStorage.getItem":          SourceLocalStorage,
	"sessionStorage.getItem":        SourceSessionStorage,
	"window.localStorage.getItem":   SourceLocalStorage,
	"window.sessionStorage.getItem": SourceSessionStorage,
}

// knownSanitizers defines functions known to safely encode or clean data.
var knownSanitizers = map[string]bool{
	"encodeURI":          true,
	"encodeURIComponent": true,
	"JSON.stringify":     true,
	"parseInt":           true,
	"parseFloat":         true,
	"Number":             true,
	"DOMPurify.sanitize": true,
}

// CheckIfPropertySource checks if a property access path matches a known source.
func CheckIfPropertySource(path []string) (TaintSource, bool) {
	if len(path) == 0 {
		return "", false
	}
	pathStr := strings.Join(path, ".")
	if source, ok := knownPropertySources[pathStr]; ok {
		return source, true
	}
	return "", false
}

// CheckIfFunctionSource checks if a function call path matches a known source.
func CheckIfFunctionSource(path []string) (TaintSource, bool) {
	if len(path) == 0 {
		return "", false
	}
	pathStr := strings.Join(path, ".")
	if source, ok := knownFunctionSources[pathStr]; ok {
		return source, true
	}
	return "", false
}

// CheckIfSanitizer checks if a function call path matches a known sanitizer.
func CheckIfSanitizer(path []string) bool {
	if len(path) == 0 {
		return false
	}
	pathStr := strings.Join(path, ".")
	if knownSanitizers[pathStr] {
		return true
	}
	// Check global function name fallback
	funcName := path[len(path)-1]
	return knownSanitizers[funcName]
}
