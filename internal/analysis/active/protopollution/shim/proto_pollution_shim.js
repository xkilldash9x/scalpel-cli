// -- pkg/analysis/active/protopollution/analyzer.go --
package protopollution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

const (
	jsCallbackName = "__scalpel_protopollution_proof"
)

// Analyzer checks for client-side prototype pollution vulnerabilities using an advanced shim.
type Analyzer struct {
	logger      *zap.Logger
	browser     browser.SessionManager
	findingChan chan schemas.Finding
	canary      string
	taskID      string
}

// PollutionProofEvent is the data sent from the JS shim when pollution is detected.
type PollutionProofEvent struct {
	Source string `json:"source"`
	Canary string `json:"canary"`
}

// NewAnalyzer creates a new prototype pollution analyzer.
func NewAnalyzer(logger *zap.Logger, browserManager browser.SessionManager) *Analyzer {
	return &Analyzer{
		logger:      logger.Named("protopollution_analyzer"),
		browser:     browserManager,
		findingChan: make(chan schemas.Finding, 5), // Buffer for multiple potential findings
		canary:      uuid.New().String()[:8],
	}
}

// Analyze performs the prototype pollution check.
func (a *Analyzer) Analyze(ctx context.Context, taskID, targetURL string) ([]schemas.Finding, error) {
	a.taskID = taskID
	session, err := a.browser.InitializeSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not initialize browser session: %w", err)
	}
	defer session.Close(ctx)

	// Expose the Go function that the JS shim will call upon success.
	if err := session.ExposeFunction(jsCallbackName, a.handlePollutionProof); err != nil {
		return nil, fmt.Errorf("failed to expose proof function: %w", err)
	}

	// Generate and inject the specialized JS shim.
	shimScript, err := a.generateShim()
	if err != nil {
		return nil, fmt.Errorf("failed to generate pp shim: %w", err)
	}
	if err := session.InjectScriptPersistently(shimScript); err != nil {
		return nil, fmt.Errorf("failed to inject pp shim: %w", err)
	}

	// Navigate to the target and wait for async events.
	a.logger.Info("Navigating and monitoring for prototype pollution", zap.String("target", targetURL))
	if err := session.Navigate(targetURL); err != nil {
		// This could be a navigation to a page that triggers pollution via URL params.
		// A non-fatal error is fine here.
		a.logger.Debug("Navigation completed (or failed gracefully)", zap.String("target", targetURL), zap.Error(err))
	}

	// Wait for a reasonable time for asynchronous events (like fetch/XHR) to complete.
	select {
	case <-time.After(8 * time.Second):
		a.logger.Info("Monitoring period finished.", zap.String("target", targetURL))
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	
	close(a.findingChan)
	var findings []schemas.Finding
	for f := range a.findingChan {
		f.Target = targetURL
		findings = append(findings, f)
	}

	return findings, nil
}

// handlePollutionProof is the callback function triggered from the browser.
func (a *Analyzer) handlePollutionProof(event PollutionProofEvent) {
	if event.Canary != a.canary {
		a.logger.Warn("Received pollution proof with mismatched canary.", zap.String("expected", a.canary), zap.String("got", event.Canary))
		return
	}

	vulnerability := "Client-Side Prototype Pollution"
	cwe := "CWE-1321" // Prototype Pollution
	severity := schemas.SeverityHigh
	
	// Make the finding more specific based on the reported vector.
	if strings.Contains(event.Source, "DOM_Clobbering") {
		vulnerability = "DOM Clobbering"
		cwe = "CWE-1339" // DOM Clobbering
		severity = schemas.SeverityMedium
	}
	
	a.logger.Warn("Potential vulnerability detected!", zap.String("type", vulnerability), zap.String("vector", event.Source))

	desc := fmt.Sprintf(
		"A client-side vulnerability related to object prototypes was detected via the '%s' vector. This can allow an attacker to add or modify properties of all objects, potentially leading to Cross-Site Scripting (XSS), Denial of Service (DoS), or application logic bypasses.",
		event.Source,
	)
	evidence, _ := json.Marshal(event)

	finding := schemas.Finding{
		ID:             uuid.New().String(),
		TaskID:         a.taskID,
		Timestamp:      time.Now().UTC(),
		Module:         "PrototypePollutionAnalyzer",
		Vulnerability:  vulnerability,
		Severity:       severity,
		Description:    desc,
		Evidence:       evidence,
		Recommendation: "Audit client-side JavaScript for unsafe recursive merge functions, property definition by path, and cloning logic. Sanitize user input before parsing as JSON or using it in object-merge operations. Consider freezing Object.prototype (`Object.freeze(Object.prototype)`) as a defense-in-depth measure.",
		CWE:            cwe,
	}
	
	select {
	case a.findingChan <- finding:
	default:
		a.logger.Warn("Finding channel was full or closed, could not report finding.")
	}
}

// generateShim prepares the JavaScript payload with the dynamic canary.
func (a *Analyzer) generateShim() (string, error) {
	// The shim content is now a constant in this file.
	tmpl, err := template.New("pp_shim").Parse(ProtoPollutionShim)
	if err != nil {
		return "", err
	}
	data := struct {
		Canary       string
		CallbackName string
	}{
		Canary:       a.canary,
		CallbackName: jsCallbackName,
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// ProtoPollutionShim holds the complete, unabridged content of your advanced JS shim.
const ProtoPollutionShim = `
(function(scope) {
    'use strict';
    const sandbox = scope.scalpelSandbox = scope.scalpelSandbox || {};
    if (sandbox.ppGlobalInstrumentationDone) return;

    let pollutionCanary = '{{.Canary}}';
    let detectionCallbackName = '{{.CallbackName}}';
    let domObserver = null;
    const globalListenerTracker = new WeakMap();

    sandbox.initializeProtoPollution = function(canary, callbackName) {
        if (pollutionCanary) {
            cleanupPreviousRun();
        }
        pollutionCanary = canary;
        detectionCallbackName = callbackName;
        setupPrototypeTrap();
        if (!sandbox.ppGlobalInstrumentationDone) {
            instrumentEventListeners();
            instrumentWebSockets();
            instrumentFetch();
            instrumentXHR();
            sandbox.ppGlobalInstrumentationDone = true;
        }
        monitorDOMClobbering();
    };

    function cleanupPreviousRun() {
        if (pollutionCanary) {
            try {
                delete Object.prototype[pollutionCanary];
            } catch (e) {
                console.warn("[Scalpel PP Shim] Failed to clean up previous canary.", e);
            }
        }
        if (domObserver) {
            domObserver.disconnect();
            domObserver = null;
        }
    }

    function setupPrototypeTrap() {
        try {
            Object.defineProperty(Object.prototype, pollutionCanary, {
                get: function() {
                    if (this !== scope) {
                        notifyBackend("Object.prototype_access");
                    }
                    return 'polluted_by_scalpel';
                },
                configurable: true
            });
        } catch (e) {
            console.warn("[Scalpel PP Shim] Could not define canary property on Object.prototype.", e);
        }
    }

    function notifyBackend(source) {
        if (typeof scope[detectionCallbackName] === 'function') {
            setTimeout(() => {
                try {
                    scope[detectionCallbackName]({
                        source: source,
                        canary: pollutionCanary
                    });
                    console.warn(` + "`[Scalpel PP Shim] Potential pollution vector detected via ${source}`" + `);
                } catch (e) {
                    console.error("[Scalpel PP Shim] Failed to notify backend.", e);
                }
            }, 0);
        }
    }

    function instrumentEventListeners() {
        const originalAddEventListener = EventTarget.prototype.addEventListener;
        const originalRemoveEventListener = EventTarget.prototype.removeEventListener;
        EventTarget.prototype.addEventListener = function(type, listener, options) {
            if (type !== 'message' || typeof listener !== 'function') {
                return originalAddEventListener.call(this, type, listener, options);
            }
            if (!globalListenerTracker.has(this)) {
                globalListenerTracker.set(this, new Map());
            }
            const targetMap = globalListenerTracker.get(this);
            let wrappedListener = targetMap.get(listener);
            if (!wrappedListener) {
                wrappedListener = function(event) {
                    if (event && event.data) {
                        checkForPollutionPatterns(event.data, 'postMessage');
                    }
                    return listener.apply(this, arguments);
                };
                targetMap.set(listener, wrappedListener);
            }
            return originalAddEventListener.call(this, type, wrappedListener, options);
        };
        EventTarget.prototype.removeEventListener = function(type, listener, options) {
            if (type !== 'message' || typeof listener !== 'function' || !globalListenerTracker.has(this)) {
                return originalRemoveEventListener.call(this, type, listener, options);
            }
            const targetMap = globalListenerTracker.get(this);
            const wrappedListener = targetMap.get(listener);
            if (wrappedListener) {
                return originalRemoveEventListener.call(this, type, wrappedListener, options);
            }
            return originalRemoveEventListener.call(this, type, listener, options);
        };
    }

    function instrumentFetch() {
        if (!scope.fetch) return;
        const originalFetch = scope.fetch;
        scope.fetch = function(...args) {
            return originalFetch.apply(this, args).then(response => {
                const clonedResponse = response.clone();
                const contentType = response.headers.get('Content-Type');
                if (contentType && contentType.includes('application/json')) {
                    clonedResponse.text().then(data => {
                        checkForPollutionPatterns(data, 'Fetch_Response');
                    }).catch(() => {});
                }
                return response;
            });
        };
    }

    function instrumentXHR() {
        if (!scope.XMLHttpRequest) return;
        const originalSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(...args) {
            const xhr = this;
            xhr.addEventListener('load', function() {
                if (xhr.readyState === 4 && xhr.status >= 200 && xhr.status < 400) {
                    try {
                        const contentType = xhr.getResponseHeader('Content-Type');
                        if ((xhr.responseType === "" || xhr.responseType === "text") && contentType && contentType.includes('application/json')) {
                            const responseText = xhr.responseText;
                            if (responseText) {
                                checkForPollutionPatterns(responseText, 'XHR_Response');
                            }
                        }
                    } catch (e) {}
                }
            });
            return originalSend.apply(this, args);
        };
    }

    function instrumentWebSockets() {
        if (!scope.WebSocket) return;
        const OriginalWebSocket = scope.WebSocket;
        const protoOnMessageDesc = Object.getOwnPropertyDescriptor(WebSocket.prototype, 'onmessage');
        const WebSocketProxy = new Proxy(OriginalWebSocket, {
            construct(target, args) {
                const wsInstance = Reflect.construct(target, args);
                const onMessageListenerMap = new WeakMap();
                const addedListeners = new WeakMap();
                if (protoOnMessageDesc && protoOnMessageDesc.set) {
                    Object.defineProperty(wsInstance, 'onmessage', {
                        set: function(appListener) {
                            if (typeof appListener !== 'function') {
                                return protoOnMessageDesc.set.call(this, appListener);
                            }
                            const wrappedListener = function(event) {
                                if (event && event.data) {
                                    checkForPollutionPatterns(event.data, 'WebSocket_onmessage');
                                }
                                return appListener.apply(this, arguments);
                            };
                            onMessageListenerMap.set(this, appListener);
                            return protoOnMessageDesc.set.call(this, wrappedListener);
                        },
                        get: function() {
                            return onMessageListenerMap.get(this) || protoOnMessageDesc.get.call(this);
                        },
                        configurable: true
                    });
                }
                const originalWSAddEventListener = wsInstance.addEventListener;
                wsInstance.addEventListener = function(type, listener, options) {
                    if (type !== 'message' || typeof listener !== 'function') {
                        return originalWSAddEventListener.call(this, type, listener, options);
                    }
                    let wrappedListener = addedListeners.get(listener);
                    if (!wrappedListener) {
                        wrappedListener = function(event) {
                            if (event && event.data) {
                                checkForPollutionPatterns(event.data, 'WebSocket_Listener');
                            }
                            return listener.apply(this, arguments);
                        };
                        addedListeners.set(listener, wrappedListener);
                    }
                    return originalWSAddEventListener.call(this, type, wrappedListener, options);
                };
                const originalWSRemoveEventListener = wsInstance.removeEventListener;
                wsInstance.removeEventListener = function(type, listener, options) {
                    if (type !== 'message' || typeof listener !== 'function') {
                        return originalWSRemoveEventListener.call(this, type, listener, options);
                    }
                    const wrappedListener = addedListeners.get(listener);
                    if (wrappedListener) {
                        return originalWSRemoveEventListener.call(this, type, wrappedListener, options);
                    }
                    return originalWSRemoveEventListener.call(this, type, listener, options);
                };
                return wsInstance;
            }
        });
        scope.WebSocket = WebSocketProxy;
        scope.WebSocket.prototype = OriginalWebSocket.prototype;
        Object.keys(OriginalWebSocket).forEach(key => {
            if (!(key in WebSocketProxy)) {
                const descriptor = Object.getOwnPropertyDescriptor(OriginalWebSocket, key);
                if (descriptor) {
                    Object.defineProperty(WebSocketProxy, key, descriptor);
                }
            }
        });
    }

    function checkForPollutionPatterns(data, source) {
        if (typeof data !== 'string' || data.length < 10) return;
        if (!data.includes('__proto__') && !data.includes('constructor')) {
            return;
        }
        try {
            let foundProto = false;
            const parsed = JSON.parse(data, (key, value) => {
                if (key === '__proto__') {
                    foundProto = true;
                }
                return value;
            });
            if (foundProto) {
                notifyBackend(source + "_json_proto_key");
            }
            if (parsed && typeof parsed === 'object' && Object.prototype.hasOwnProperty.call(parsed, 'constructor')) {
                const constructorPart = parsed['constructor'];
                if (constructorPart && typeof constructorPart === 'object' && Object.prototype.hasOwnProperty.call(constructorPart, 'prototype')) {
                    notifyBackend(source + "_json_constructor_key");
                }
            }
        } catch (e) {}
    }

    function monitorDOMClobbering() {
        if (!scope.MutationObserver) return;
        const checkClobbering = () => {
            if (Object.hasOwn(scope, pollutionCanary) && scope[pollutionCanary] !== 'polluted_by_scalpel') {
                const clobberer = scope[pollutionCanary];
                if (clobberer instanceof Element || clobberer instanceof HTMLCollection) {
                    notifyBackend("DOM_Clobbering");
                }
            }
        };
        domObserver = new MutationObserver(() => {
            checkClobbering();
        });
        const observeDOM = () => {
            if (document.documentElement) {
                domObserver.observe(document.documentElement, {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeFilter: ['id', 'name']
                });
                checkClobbering();
            } else {
                setTimeout(observeDOM, 50);
            }
        };
        observeDOM();
    }

    // Initialize with default values, which will be overwritten by Go.
    sandbox.initializeProtoPollution('defaultCanary', 'defaultCallback');
})(window);
`
