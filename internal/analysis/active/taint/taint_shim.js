// internal/analysis/active/taint/taint_shim.js
(function(scope) {
    'use strict';

    // Prevent re-instrumentation
    if (scope.__SCALPEL_TAINT_INSTRUMENTED__) return;
    scope.__SCALPEL_TAINT_INSTRUMENTED__ = true;

    // Configuration injected by the Go backend via text/template
    const CONFIG = {
        // @ts-ignore - This is a Go template placeholder that will be replaced with a valid JSON object.
        Sinks: {{.SinksJSON}},
        SinkCallbackName: "{{.SinkCallbackName}}",
        ProofCallbackName: "{{.ProofCallbackName}}",
        ErrorCallbackName: "{{.ErrorCallbackName}}",
        CanaryPrefix: "SCALPEL",
        // Property name used specifically for Prototype Pollution probes.
        PollutionCheckProperty: "scalpelPolluted",
        // Flag for exposing internals during unit testing (set via global variable before loading)
        IsTesting: scope.__SCALPEL_TEST_MODE__ || false
    };

    // Determine the context (Main Window or Web Worker)
    const IS_WORKER = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;
    const CONTEXT_NAME = IS_WORKER ? "Worker" : "Window";

    // FIX: Explicitly use scope.console to ensure we use the instrumented environment's console (e.g., JSDOM during testing).
    const logger = {
        warn: (...args) => scope.console.warn(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args),
        error: (...args) => scope.console.error(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args),
        log: (...args) => scope.console.log(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args)
    };

    // Predefined condition handlers for CSP compatibility.
    const ConditionHandlers = {
        'IS_STRING_ARG0': (args) => typeof args[0] === 'string',
        'SEND_BEACON_DATA_EXISTS': (args) => args.length > 1 && args[1] != null,
        'XHR_SEND_DATA_EXISTS': (args) => args.length > 0 && args[0] != null,
    };

    // Set to track instrumented objects (Prototypes, Shadow Roots, Functions) to avoid infinite recursion/re-instrumentation.
    const instrumentedCache = new WeakSet();

    /**
     * ROBUSTNESS: Reports internal instrumentation errors back to the Go backend.
     */
    function reportShimError(error, location, stack = null) {
        const callback = scope[CONFIG.ErrorCallbackName];
        if (typeof callback === 'function') {
            // Execute asynchronously
            setTimeout(() => {
                try {
                    const errorStack = stack || (error instanceof Error ? error.stack : getStackTrace());
                    callback({
                        error: String(error),
                        location: String(location),
                        stack: errorStack
                    });
                } catch (e) {
                    logger.error("Failed to call backend error callback.", e);
                }
            }, 0);
        } else {
            logger.error(`Shim Error at ${location}:`, error);
        }
    }

    /**
     * Captures the current stack trace.
     */
    function getStackTrace() {
        try {
            const err = new Error();
            if (err.stack) {
                // Clean up the stack trace to remove the shim's internal functions.
                // Slicing 3 usually removes the Error creation, the capture function, and the instrumented wrapper.
                return err.stack.split('\n').slice(3).join('\n');
            }
        } catch (e) {
            // Ignore errors during stack trace generation.
        }
        return "Could not capture stack trace.";
    }

    // FIX: Added function to capture page context for better correlation and FP reduction.
    /**
     * Captures the current page context (URL and Title).
     * Handles differences between Window and Worker contexts.
     */
    function getPageContext() {
        let url = "N/A (Unknown Context)";
        let title = "N/A";

        if (!IS_WORKER) {
            // Main Window Context
            try {
                // Use scope.document for robustness (e.g., JSDOM environment).
                if (scope.document && scope.document.location) {
                    url = scope.document.location.href;
                    // Title might not be available immediately if the DOM is still loading.
                    title = scope.document.title || "N/A (Loading)";
                } else {
                    // Fallback to scope.location if document is unavailable (e.g. about:blank before navigation)
                    if (scope.location) {
                        url = scope.location.href;
                    } else {
                        url = "N/A (No Document or Location)";
                    }
                }
            } catch (e) {
                // Security exceptions might occur (e.g. sandboxed iframes).
                // We report the error but still return a status string for the callback.
                reportShimError(e, "getPageContext access error (Window)");
                url = "N/A (Security Exception)";
                title = "N/A (Security Exception)";
            }
        } else {
            // Web Worker Context
            try {
                // In a worker, 'self.location' (scope.location) exists and refers to the worker script URL.
                if (scope.location) {
                    url = scope.location.href;
                }
                title = "N/A (Worker Context)";
            } catch (e) {
                // Defensive catch.
                reportShimError(e, "getPageContext access error (Worker)");
                url = "N/A (Security Exception - Worker)";
            }
        }
        return { url, title };
    }


    /**
     * Checks if a value contains the canary prefix, indicating it's tainted.
     * Implements deep checking with cycle detection and depth limits.
     */
    function isTainted(value, depth = 0, seen = new WeakSet()) {
        const MAX_DEPTH = 4; // Limit recursion depth for performance and robustness.

        // FIX: Check depth limit first to ensure strict boundary compliance and prevent excessive recursion.
        // Previously, string checks occurred before depth checks, allowing detection at depth > MAX_DEPTH.
        if (depth > MAX_DEPTH) {
            return false;
        }

        if (typeof value === 'string') {
            return value.includes(CONFIG.CanaryPrefix);
        }

        // Simplified check since depth is already handled above.
        if (typeof value !== 'object' || value === null) {
            return false;
        }

        if (seen.has(value)) return false;
        seen.add(value);

        // Handle Arrays and specialized iterable objects (URLSearchParams, FormData)
        // ROBUSTNESS: Use scope.* to ensure we use the correct global objects in both Window/Worker contexts and test environments.
        if (Array.isArray(value) ||
            (typeof scope.URLSearchParams !== 'undefined' && value instanceof scope.URLSearchParams) ||
            (typeof scope.FormData !== 'undefined' && value instanceof scope.FormData)) {

            const iterator = (typeof value.values === 'function') ? value.values() : value;
            for (const val of iterator) {
                if (isTainted(val, depth + 1, seen)) {
                    return true;
                }
            }
            return false;
        }

        // Handle generic objects
        try {
            const keys = Reflect.ownKeys(value);
            for (const key of keys) {
                try {
                    const propValue = value[key];
                    if (isTainted(propValue, depth + 1, seen)) {
                        return true;
                    }
                } catch (e) {
                    // Ignore errors accessing properties
                }
            }
        } catch (e) {
            // Cannot inspect object properties
        }
        return false;
    }


    /**
     * Reports a detected sink event to the Go backend.
     */
    function reportSink(type, value, detail) {
        const callback = scope[CONFIG.SinkCallbackName];
        if (typeof callback === 'function') {
            const stack = getStackTrace();
            // FIX: Capture page context for FP reduction.
            const context = getPageContext();

            // Asynchronous reporting to minimize impact on application performance.
            setTimeout(() => {
                try {
                    let stringValue;
                    // Handle complex types before reporting.
                    // ROBUSTNESS: Use scope.Request.
                    if (typeof scope.Request !== 'undefined' && value instanceof scope.Request) {
                        stringValue = value.url; // For FETCH_URL sink when Request object is used
                    } else if (typeof value === 'object' && value !== null) {
                        try {
                            // Attempt JSON stringify for objects/arrays/FormData etc.
                            stringValue = JSON.stringify(value);
                        } catch (e) {
                            stringValue = String(value);
                        }
                    } else {
                        stringValue = String(value);
                    }

                    // The callback expects an object argument matching the SinkEvent struct.
                    callback({
                        type: type,
                        value: stringValue,
                        detail: detail,
                        stack: stack,
                        // FIX: Add page context fields (matching Go struct JSON tags).
                        page_url: context.url,
                        page_title: context.title
                    });
                    logger.warn(`Taint flow detected: ${detail} (${type})`);
                } catch (e) {
                    reportShimError(e, "reportSink callback execution");
                }
            }, 0);
        }
    }

    /**
     * Overrides the execution proof callback to capture stack trace.
     */
    function initializeExecutionProofCallback() {
        const originalCallback = scope[CONFIG.ProofCallbackName];
        if (typeof originalCallback !== 'function') {
            logger.error("Backend execution proof callback not exposed correctly.");
            return;
        }

        // Replace the exposed Go function (which is a direct binding) with a JS wrapper.
        scope[CONFIG.ProofCallbackName] = function(canary) {
            const stack = getStackTrace();
            // FIX: Capture page context for FP reduction.
            const context = getPageContext();
            
            logger.warn(`Execution Proof triggered! Canary: ${canary}`);
            try {
                // The Go callback expects an object matching the ExecutionProofEvent struct.
                originalCallback({
                    canary: String(canary),
                    stack: stack,
                    // FIX: Add page context fields (matching Go struct JSON tags).
                    page_url: context.url,
                    page_title: context.title
                });
            } catch (e) {
                reportShimError(e, "initializeExecutionProofCallback wrapper execution");
            }
        };
    }

    /**
     * Resolves a nested property path (e.g., "Element.prototype.innerHTML") on a given object.
     */
    function resolvePath(path, root = scope) {
// ... (The remaining content of taint_shim.js remains unchanged up to the end of the file) ...
// ...
    initialize();

    // Expose internals for testing if in test mode
    if (CONFIG.IsTesting) {
        scope.__SCALPEL_INTERNALS__ = {
            isTainted: isTainted,
            resolvePath: resolvePath,
            CONFIG: CONFIG,
            ConditionHandlers: ConditionHandlers,
            getStackTrace: getStackTrace,
            // FIX: Expose getPageContext for testing
            getPageContext: getPageContext
        };
    }

})(self); // Use 'self' which refers to the global scope in both Window and Worker contexts.