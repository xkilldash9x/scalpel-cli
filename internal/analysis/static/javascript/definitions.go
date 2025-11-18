// Filename: javascript/definitions.go
// Package javascript provides static analysis capabilities for client side JavaScript.
// This file contains the definitions of known taint sources, sinks, and sanitizers.
package javascript

import "strings"

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
	Name TaintSink
	Type SinkType
	// For function calls, specifies which argument indices are sensitive.
	TaintedArgs []int
}

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
	// "window.name" is removed here because it is already covered by string(SourceWindowName)
}

// knownFunctionSources defines sources accessed via function calls.
var knownFunctionSources = map[string]TaintSource{
	"localStorage.getItem":          SourceLocalStorage,
	"sessionStorage.getItem":        SourceSessionStorage,
	"window.localStorage.getItem":   SourceLocalStorage,
	"window.sessionStorage.getItem": SourceSessionStorage,
}

// knownSinkPropertyPaths defines sinks accessed via property assignment.
// Level 1.2: Context-aware sink definitions.
var knownSinkPropertyPaths = map[string]SinkDefinition{
	// -- High Specificity Paths --

	// Execution Sinks (Approximation based on common names)
	"script.src":  {Name: "script.src", Type: SinkTypeExecution},
	"embed.src":   {Name: "embed.src", Type: SinkTypeExecution},
	"object.data": {Name: "object.data", Type: SinkTypeExecution},

	// URL/Redirect Sinks
	"location.href":        {Name: "location.href", Type: SinkTypeURLRedirection},
	"window.location.href": {Name: "window.location.href", Type: SinkTypeURLRedirection},

	// Cookie Sink
	"document.cookie": {Name: "document.cookie", Type: SinkTypeCookieManipulation},

	// Attribute Injection
	"a.href":      {Name: "a.href", Type: SinkTypeAttributeInjection},
	"form.action": {Name: "form.action", Type: SinkTypeAttributeInjection},
	"iframe.src":  {Name: "iframe.src", Type: SinkTypeHTMLInjection}, // Can be data: or javascript:

	// Data Leakage
	"img.src": {Name: "img.src", Type: SinkTypeDataLeak},

	// -- Generic Property Names (Fallbacks) --

	"innerHTML": {Name: "innerHTML", Type: SinkTypeHTMLInjection},
	"outerHTML": {Name: "outerHTML", Type: SinkTypeHTMLInjection},

	// Generic 'src' or 'href' fallbacks if context is completely unknown.
	"src":  {Name: "src", Type: SinkTypeAttributeInjection},
	"href": {Name: "href", Type: SinkTypeAttributeInjection},
}

// knownSinkFunctions defines sinks accessed via function calls (e.g., eval(...)).
var knownSinkFunctions = map[string]SinkDefinition{
	// Execution
	"eval":        {Name: "eval", Type: SinkTypeExecution, TaintedArgs: []int{0}},
	"setTimeout":  {Name: "setTimeout", Type: SinkTypeExecution, TaintedArgs: []int{0}},
	"setInterval": {Name: "setInterval", Type: SinkTypeExecution, TaintedArgs: []int{0}},
	"Function":    {Name: "Function", Type: SinkTypeExecution, TaintedArgs: []int{0}}, // For 'new Function()'

	// HTML Injection
	"document.write":   {Name: "document.write", Type: SinkTypeHTMLInjection, TaintedArgs: []int{0}},
	"document.writeln": {Name: "document.writeln", Type: SinkTypeHTMLInjection, TaintedArgs: []int{0}},

	// URL Redirection
	"location.assign":         {Name: "location.assign", Type: SinkTypeURLRedirection, TaintedArgs: []int{0}},
	"window.location.assign":  {Name: "window.location.assign", Type: SinkTypeURLRedirection, TaintedArgs: []int{0}},
	"location.replace":        {Name: "location.replace", Type: SinkTypeURLRedirection, TaintedArgs: []int{0}},
	"window.location.replace": {Name: "window.location.replace", Type: SinkTypeURLRedirection, TaintedArgs: []int{0}},
	"window.open":             {Name: "window.open", Type: SinkTypeURLRedirection, TaintedArgs: []int{0}},
	"open":                    {Name: "open", Type: SinkTypeURLRedirection, TaintedArgs: []int{0}},
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

// CheckIfSinkProperty checks if a property access path matches a known sink property.
// Level 1.2: Updated to use the full path for context awareness.
func CheckIfSinkProperty(path []string) (SinkDefinition, bool) {
	if len(path) == 0 {
		return SinkDefinition{}, false
	}

	// 1. Check the full path (e.g., "script.src")
	fullPath := strings.Join(path, ".")
	if def, ok := knownSinkPropertyPaths[fullPath]; ok {
		return def, true
	}

	// 2. Fallback to just the property name (e.g., "innerHTML")
	propName := path[len(path)-1]
	if def, ok := knownSinkPropertyPaths[propName]; ok {
		return def, true
	}

	return SinkDefinition{}, false
}

// CheckIfSinkFunction checks if a function call path matches a known sink function.
func CheckIfSinkFunction(path []string) (SinkDefinition, bool) {
	if len(path) == 0 {
		return SinkDefinition{}, false
	}

	// 1. Check the full path (e.g., "document.write")
	pathStr := strings.Join(path, ".")
	if def, ok := knownSinkFunctions[pathStr]; ok {
		return def, true
	}

	// 2. Check the specific name (e.g., "eval", "setTimeout") if it's a global function call.
	funcName := path[len(path)-1]
	if def, ok := knownSinkFunctions[funcName]; ok {
		return def, true
	}

	return SinkDefinition{}, false
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
