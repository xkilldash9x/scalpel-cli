//Filename: taint_shim.js
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
        // VULN-FIX: These names are randomized per session by the Go backend.
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

    // --- VULN-FIX START: Capture Callbacks in Closure ---
    // Immediately capture the callback functions from the global scope into a local,
    // closure-scoped variable. This prevents DOM Clobbering that occurs after the
    // shim has initialized from affecting the shim's own reporting mechanisms.
    const SinkCallback = scope[CONFIG.SinkCallbackName];
    const ProofCallback = scope[CONFIG.ProofCallbackName];
    const ErrorCallback = scope[CONFIG.ErrorCallbackName];

    // Validate that the callbacks were exposed correctly. If not, the analysis is blind.
    // Use the raw console.error as our own ErrorCallback might be the one that's broken.
    if (typeof SinkCallback !== 'function' || typeof ProofCallback !== 'function' || typeof ErrorCallback !== 'function') {
        scope.console.error("[Scalpel] Critical Error: Backend callbacks not exposed correctly or were clobbered before shim initialization. Analysis may be ineffective.");
        // Abort initialization as the shim cannot function without its callbacks.
        return;
    }
    // --- VULN-FIX END ---


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
        // VULN-FIX: Use the closure-scoped `ErrorCallback` instead of re-resolving from the global scope.
        const callback = ErrorCallback;
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
            // This case should theoretically not be reached due to the initial check, but is kept for robustness.
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
        // VULN-FIX: Use the closure-scoped `SinkCallback` instead of re-resolving from the global scope.
        const callback = SinkCallback;
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
        // VULN-FIX: Use the closure-scoped `ProofCallback` as the original function to wrap.
        const originalCallback = ProofCallback;
        if (typeof originalCallback !== 'function') {
            // This case should not be reached due to the initial check, but is kept for robustness.
            logger.error("Backend execution proof callback not exposed correctly.");
            return;
        }

        // Replace the exposed Go function (which is a direct binding) with a JS wrapper.
        // This is necessary because the XSS payload can only call the global function directly (using the randomized name).
        // Our wrapper adds the stack trace before calling the real (captured) callback.
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
     * Returns an object containing the resolved object, its base, the property name, and the full path.
     */
    function resolvePath(path, root = scope) {
        const parts = path.split('.');
        let current = root;
        const resolvedPath = [];

        for (const part of parts) {
            if (current === null || typeof current === 'undefined') {
                return null;
            }
            
            try {
                // Check if the property exists on the object or its prototype chain.
                if (part in current) {
                    current = current[part];
                    resolvedPath.push(part);
                } else {
                    // ROBUSTNESS: Special handling for specific global objects if direct lookup failed.
                    // This helps when the environment might not have them directly on the scope object initially (e.g., 'document' during early load in some environments).
                    if (!IS_WORKER && root === scope) {
                        if (part === 'document' && typeof document !== 'undefined') {
                            current = document;
                            resolvedPath.push('document');
                            continue;
                        }
                        if (part === 'navigator' && typeof navigator !== 'undefined') {
                            current = navigator;
                            resolvedPath.push('navigator');
                            continue;
                        }
                    }
                    return null; // Property not found in the chain
                }
            } catch (e) {
                // Accessing certain properties might throw (e.g., cross-origin restrictions).
                reportShimError(e, `resolvePath access error: ${path} at ${part}`);
                return null;
            }
        }

        // Calculate the base object (the object containing the final property)
        let base = root;
        for(let i = 0; i < resolvedPath.length - 1; i++) {
            base = base[resolvedPath[i]];
        }

        return {
            object: current,
            base: base,
            propertyName: parts[parts.length - 1],
            fullPath: resolvedPath.join('.')
        };
    }

    /**
     * Creates a wrapper function for instrumenting function call sinks.
     */
    function createFunctionWrapper(originalFunction, sinkDef) {
        // Optimization: Check if the function is already instrumented (by checking if we wrapped it previously).
        if (instrumentedCache.has(originalFunction)) {
            return originalFunction;
        }

        const wrapper = function(...args) {
            // Check pre-conditions if defined (e.g., setTimeout with string arg).
            if (sinkDef.ConditionID) {
                const handler = ConditionHandlers[sinkDef.ConditionID];
                if (handler && !handler(args)) {
                    return originalFunction.apply(this, args);
                }
            }

            // Special handling for the `fetch` sink to inspect both URL and Body.
            // This combines the logic for both FETCH_URL and FETCH sinks.
            if (sinkDef.Name === 'fetch') {
                // Arg 0 (URL or Request object)
                if (isTainted(args[0])) {
                    // We report FETCH_URL regardless of which specific sink definition triggered this wrapper.
                    reportSink("FETCH_URL", args[0], "fetch(url/request)");
                }

                // Arg 1 (Options object, check body)
                if (args.length > 1 && args[1] && typeof args[1] === 'object' && args[1].body) {
                    if (isTainted(args[1].body)) {
                        reportSink("FETCH", args[1].body, "fetch(options.body)");
                    }
                }
            } else {
                // Standard argument inspection.
                const taintedArg = args[sinkDef.ArgIndex];
                if (isTainted(taintedArg)) {
                    const detail = `${sinkDef.Name}(arg${sinkDef.ArgIndex})`;
                    reportSink(sinkDef.Type, taintedArg, detail);
                }
            }

            // Call the original function.
            return originalFunction.apply(this, args);
        };

        // ROBUSTNESS: Mimic original function properties (toString, prototype) to avoid detection or breakage.
        try {
            Object.setPrototypeOf(wrapper, Object.getPrototypeOf(originalFunction));
            wrapper.toString = function() { return originalFunction.toString(); };
            if (originalFunction.prototype) {
                wrapper.prototype = originalFunction.prototype;
            }
            // Copy static properties if any
            Object.getOwnPropertyNames(originalFunction).forEach(prop => {
                if (!wrapper.hasOwnProperty(prop)) {
                    try {
                        Object.defineProperty(wrapper, prop, Object.getOwnPropertyDescriptor(originalFunction, prop));
                    } catch (e) {
                        // Ignore errors copying properties
                    }
                }
            });
        } catch (e) {
            // Best effort mimicry, might fail on some built-ins.
        }
        
        instrumentedCache.add(wrapper);
        return wrapper;
    }

    /**
     * Creates wrapper functions (getter/setter) for instrumenting property assignment sinks.
     */
    function createPropertyWrappers(originalDescriptor, sinkDef) {
        const wrappers = { ...originalDescriptor };

        if (originalDescriptor.set) {
            wrappers.set = function(value) {
                if (isTainted(value)) {
                    const detail = `${sinkDef.Name} = value`;
                    reportSink(sinkDef.Type, value, detail);
                }
                return originalDescriptor.set.call(this, value);
            };
            
             // ROBUSTNESS: Mimic original setter properties.
             try {
                Object.setPrototypeOf(wrappers.set, Object.getPrototypeOf(originalDescriptor.set));
                wrappers.set.toString = function() { return originalDescriptor.set.toString(); };
            } catch (e) {
                // Best effort mimicry.
            }

        } else if (originalDescriptor.writable) {
            // Handle properties defined with 'value' and 'writable: true' (less common for built-in sinks).
            logger.warn("Instrumenting writable data property without a native setter:", sinkDef.Name);
            // This requires redefining the property as an accessor, which is complex to manage the underlying value reliably across all contexts.
            // For core sinks like innerHTML, the 'set' path is standard and sufficient.
        }
       
        return wrappers;
    }

    /**
     * Instruments a single sink based on its definition.
     */
    function instrumentSink(sinkDef) {
        // 1. Resolve the path to the object containing the property/function (the base object).
        // E.g., for "Element.prototype.innerHTML", we need "Element.prototype".
        const pathParts = sinkDef.Name.split('.');
        const propertyName = pathParts.pop();
        const basePath = pathParts.join('.');

        let targetBase;

        if (basePath) {
            const resolvedBase = resolvePath(basePath);
            if (resolvedBase && resolvedBase.object) {
                targetBase = resolvedBase.object;
            }
        } else {
            // It's a global function/property (e.g., 'eval', 'fetch').
            targetBase = scope;
        }


        if (!targetBase || (typeof targetBase !== 'object' && typeof targetBase !== 'function')) {
            // This is expected for APIs not supported by the browser (e.g., jQuery not loaded, or very old browser).
            // We log it but do not report it as an error to the backend to reduce noise.
            logger.log("Skipping sink: Base object not found or invalid type.", sinkDef.Name);
            return;
        }

        // 2. Get the existing property descriptor from the base object.
        const descriptor = Object.getOwnPropertyDescriptor(targetBase, propertyName);

        if (!descriptor) {
            // Property doesn't exist directly on the base object (it might be inherited, but instrumentation happens on the definition).
            logger.log("Skipping sink: Property descriptor not found on base object.", sinkDef.Name);
            return;
        }

        // Check if the property is configurable. If not, we cannot instrument it.
        if (!descriptor.configurable) {
            // This is common for security-sensitive properties in modern browsers.
            logger.warn("Cannot instrument non-configurable property:", sinkDef.Name);
            return;
        }

        // 3. Create and apply the appropriate wrapper(s).
        try {
            if (sinkDef.Setter) {
                // Instrumenting a property setter (e.g., innerHTML).
                const wrappers = createPropertyWrappers(descriptor, sinkDef);
                Object.defineProperty(targetBase, propertyName, wrappers);
                logger.log(`Instrumented property setter: ${sinkDef.Name}`);
            } else {
                // Instrumenting a function call (e.g., document.write, eval).
                // Functions can be defined via 'value' (data descriptor) or 'get' (accessor descriptor).
                const originalFunction = descriptor.value || (descriptor.get && descriptor.get.call(targetBase));
                
                if (typeof originalFunction === 'function') {
                    const wrapper = createFunctionWrapper(originalFunction, sinkDef);
                    
                    // If the descriptor used 'value', update it.
                    if ('value' in descriptor) {
                        descriptor.value = wrapper;
                        Object.defineProperty(targetBase, propertyName, descriptor);
                    } else if ('get' in descriptor) {
                        // If it used 'get', we wrap the getter to return the wrapped function.
                        Object.defineProperty(targetBase, propertyName, {
                            ...descriptor,
                            get: () => wrapper
                        });
                    } else {
                        logger.warn("Function found but descriptor structure unexpected (no value or get):", sinkDef.Name);
                    }
                    
                    logger.log(`Instrumented function: ${sinkDef.Name}`);
                } else {
                    logger.warn("Target is not a function, but sink definition expects it to be:", sinkDef.Name);
                }
            }
        } catch (error) {
            // Instrumentation can fail due to various browser security restrictions or complex object states.
            reportShimError(error, `instrumentSink failure: ${sinkDef.Name}`);
        }
    }

    /**
     * Implements the detection logic for Prototype Pollution vulnerabilities.
     * Checks if Object.prototype has been polluted with the specific property.
     */
    function checkPrototypePollution() {
        try {
            // Check if the specific property exists on the Object.prototype itself.
            if (Object.prototype.hasOwnProperty(CONFIG.PollutionCheckProperty)) {
                const pollutedValue = Object.prototype[CONFIG.PollutionCheckProperty];
                
                // Validate that the value looks like one of our canaries.
                if (typeof pollutedValue === 'string' && pollutedValue.includes(CONFIG.CanaryPrefix)) {
                    logger.warn("Prototype Pollution Detected!", pollutedValue);
                    
                    // Report the confirmation back to the backend.
                    // We use the specific SinkPrototypePollution type.
                    // The 'value' is the canary itself, and 'detail' is the property name.
                    reportSink("PROTOTYPE_POLLUTION", pollutedValue, CONFIG.PollutionCheckProperty);
                    
                    // Clean up the prototype to prevent interference with the application and subsequent probes.
                    try {
                        delete Object.prototype[CONFIG.PollutionCheckProperty];
                    } catch (cleanupError) {
                        reportShimError(cleanupError, "checkPrototypePollution cleanup failure");
                    }
                }
            }
        } catch (error) {
            reportShimError(error, "checkPrototypePollution execution failure");
        }
    }


    /**
     * Initializes the instrumentation process.
     */
    function initialize() {
        logger.log("Initializing Taint Analysis Shim...");

        // 1. Initialize the execution proof callback wrapper first.
        initializeExecutionProofCallback();

        // 2. Instrument all defined sinks.
        const groupedSinks = {};
        CONFIG.Sinks.forEach(sink => {
            // Group sinks by name. This ensures that functions like 'fetch' (which have multiple sink definitions for different arguments) are only instrumented once.
            // The createFunctionWrapper handles the logic for all arguments internally.
            if (!groupedSinks[sink.Name]) {
                groupedSinks[sink.Name] = sink;
            }
        });

        Object.values(groupedSinks).forEach(instrumentSink);

        // 3. Set up Prototype Pollution detection.
        // We check periodically as pollution might happen asynchronously via various libraries after page load.
        const pollutionCheckInterval = setInterval(checkPrototypePollution, 500);

        // Stop checking after a reasonable time (e.g., 30 seconds) to minimize long-term overhead.
        setTimeout(() => {
            clearInterval(pollutionCheckInterval);
            logger.log("Stopped periodic Prototype Pollution checks.");
        }, 30000);

        // Also check immediately after initialization and on standard page load events.
        checkPrototypePollution();
        if (!IS_WORKER && scope.addEventListener) {
            scope.addEventListener('load', checkPrototypePollution);
            scope.addEventListener('DOMContentLoaded', checkPrototypePollution);
        }
        

        logger.log("Taint Analysis Shim initialized.");
    }

    // Start the initialization process.
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