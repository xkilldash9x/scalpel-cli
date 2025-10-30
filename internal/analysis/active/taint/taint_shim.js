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
                        stack: stack
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
            logger.warn(`Execution Proof triggered! Canary: ${canary}`);
            try {
                // The Go callback expects an object matching the ExecutionProofEvent struct.
                originalCallback({
                    canary: String(canary),
                    stack: stack
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
        const parts = path.split('.');
        let current = root;

        try {
            for (let i = 0; i < parts.length - 1; i++) {
                // Use Reflect.get for safer property access.
                current = Reflect.get(current, parts[i]);
                if (current === undefined || current === null) {
                    // Handle cases like jQuery not loaded, or APIs not present in the context.
                    return null;
                }
            }
            return {
                parent: current,
                key: parts[parts.length - 1]
            };
        } catch (e) {
            // Catch errors during property access (e.g., security policy violations, cross-origin iframes).
            reportShimError(e, `resolvePath access error for ${path}`);
            return null;
        }
    }

    /**
     * Instruments a function call.
     * FIX: Now accepts an array of sink definitions (sinkDefs) to handle multiple sinks on the same function (e.g., fetch URL and Body).
     */
    function instrumentFunction(parent, key, sinkDefs) {
        const originalFunc = parent[key];
        // The check remains the same: we only want to instrument a specific function implementation once.
        if (typeof originalFunc !== 'function' || instrumentedCache.has(originalFunc)) return;

        // All sinkDefs in the array have the same Name.
        const functionName = sinkDefs[0].Name;

        const wrapper = function(...args) {
            
            // FIX: Iterate over all sink definitions for this function
            for (const sinkDef of sinkDefs) {
                // ROBUSTNESS: Use try-catch inside the loop to ensure one failing definition doesn't stop others.
                try {
                    // Default assignment
                    let valueToInspect = args[sinkDef.ArgIndex];

                    // --- Specialized Argument Handlers (Pre-processing) ---

                    // 1. Fetch Handlers (fetch)
                    if (functionName === 'fetch') {
                        
                        // A. FETCH_BODY (ArgIndex 1)
                        if (sinkDef.ArgIndex === 1) {
                            // Check if options (arg 1) exists, is an object, and has a non-null/undefined body.
                            if (args.length > 1 && args[1] && typeof args[1] === 'object' && args[1].body != null) {
                                // Inspect the body property of the options object (arg 1).
                                valueToInspect = args[1].body;
                            } else {
                                // Body is missing or options object is missing. Skip this specific sink check.
                                continue;
                            }
                        } 
                        // B. FETCH_URL (ArgIndex 0)
                        else if (sinkDef.ArgIndex === 0) {
                            if (args.length > 0) {
                                // Inspect the URL (arg 0). Handle both string and Request object.
                                // ROBUSTNESS: Use scope.Request.
                                if (typeof scope.Request !== 'undefined' && args[0] instanceof scope.Request) {
                                    valueToInspect = args[0].url;
                                } else {
                                    valueToInspect = args[0];
                                }
                            } else {
                                 // fetch requires args, but defensively skip.
                                 continue;
                            }
                        }
                    }

                    // 2. SendBeacon Data (ArgIndex 1)
                    // ROBUSTNESS: Explicitly check if data exists, otherwise skip this sink definition.
                    else if (sinkDef.Type === 'SEND_BEACON' && sinkDef.ArgIndex === 1) {
                         if (args.length > 1 && args[1] != null) {
                             valueToInspect = args[1];
                         } else {
                             // If checking the data argument but it's missing, skip.
                             continue;
                         }
                    }

                    // --- Taint Check and Reporting ---
                    
                    if (isTainted(valueToInspect)) {
                        let conditionsMet = true;
                        if (sinkDef.ConditionID) {
                            try {
                                const handler = ConditionHandlers[sinkDef.ConditionID];
                                if (handler) {
                                    conditionsMet = handler(args);
                                } else {
                                    reportShimError(`Unknown ConditionID: ${sinkDef.ConditionID}`, `instrumentFunction ${functionName}`);
                                    conditionsMet = false; // Fail closed
                                }
                            } catch (e) {
                                reportShimError(e, `Error evaluating condition for ${functionName}. ConditionID: ${sinkDef.ConditionID}`);
                                conditionsMet = false; // Assume condition failed if evaluation errors.
                            }
                        }

                        if (conditionsMet) {
                            reportSink(sinkDef.Type, valueToInspect, functionName);
                        }
                    }
                } catch (e) {
                     // Report error specific to this sink definition.
                    reportShimError(e, `Error during instrumentation wrapper of function ${functionName} (Type: ${sinkDef.Type})`);
                }
            } // End of loop over sinkDefs

            // Call the original function using Reflect.apply for robustness.
            return Reflect.apply(originalFunc, this, args);
        };

        // Preserve original properties and prototype chain to avoid breaking frameworks.
        try {
            Object.setPrototypeOf(wrapper, originalFunc);
            if (originalFunc.prototype) {
                wrapper.prototype = originalFunc.prototype;
            }
            // Copy own properties (static methods, etc.)
            Object.getOwnPropertyNames(originalFunc).forEach(prop => {
                if (prop !== 'prototype' && prop !== 'name' && prop !== 'length') {
                    try {
                        Object.defineProperty(wrapper, prop, Object.getOwnPropertyDescriptor(originalFunc, prop));
                    } catch (e) {
                        // Ignore errors defining properties (e.g. non-configurable properties)
                    }
                }
            });
 
            // Replace the original function with the wrapper.
            parent[key] = wrapper;
            instrumentedCache.add(wrapper);
            instrumentedCache.add(originalFunc); // Also add original to cache for safety
        } catch (e) {
            reportShimError(e, `Could not fully restore prototype chain or define property for ${functionName}`);
        }
    }


    /**
     * Instruments a property setter.
     * FIX: Now accepts an array of sink definitions (sinkDefs).
     */
    function instrumentSetter(parent, key, sinkDefs) {
        let descriptor = Object.getOwnPropertyDescriptor(parent, key);
        let target = parent;

        // If not found on the object itself, look up the prototype chain.
        // This is necessary for properties like innerHTML which exist on Element.prototype.
        if (!descriptor || !descriptor.set) {
            let proto = Object.getPrototypeOf(parent);
            while (proto) {
                descriptor = Object.getOwnPropertyDescriptor(proto, key);
                if (descriptor && descriptor.set) {
                    target = proto;
                    break;
                }
                proto = Object.getPrototypeOf(proto);
            }
        }

        if (!descriptor || !descriptor.set || instrumentedCache.has(descriptor.set)) {
            return;
        }

        const originalSet = descriptor.set;
        const setterName = sinkDefs[0].Name;

        descriptor.set = function(value) {
            let tainted = false;
            try {
                tainted = isTainted(value);
            } catch (e) {
                reportShimError(e, `Error during taint check for setter ${setterName}`);
                // Proceed to call original setter even if taint check fails.
            }

            if (tainted) {
                // Report for every matching sink definition.
                for (const sinkDef of sinkDefs) {
                    // ROBUSTNESS: Use try-catch inside the loop.
                    try {
                        // Add condition checking for completeness, although rare for setters.
                        let conditionsMet = true;
                        if (sinkDef.ConditionID) {
                             try {
                                const handler = ConditionHandlers[sinkDef.ConditionID];
                                if (handler) {
                                    // Pass the setter value as the arguments array.
                                    conditionsMet = handler([value]);
                                } else {
                                    reportShimError(`Unknown ConditionID: ${sinkDef.ConditionID}`, `instrumentSetter ${setterName}`);
                                    conditionsMet = false;
                                }
                            } catch (e) {
                                reportShimError(e, `Error evaluating condition for ${setterName}. ConditionID: ${sinkDef.ConditionID}`);
                                conditionsMet = false;
                            }
                        }

                        if (conditionsMet) {
                             reportSink(sinkDef.Type, value, setterName);
                        }
                    } catch (e) {
                        reportShimError(e, `Error during reporting wrapper of setter ${setterName} (Type: ${sinkDef.Type})`);
                    }
                }
            }
            
            // Call the original setter with the correct context ('this').
            return originalSet.call(this, value);
        };

        instrumentedCache.add(descriptor.set);
        
        try {
            // Redefine the property on the target (object or prototype).
            Object.defineProperty(target, key, descriptor);
        } catch (e) {
            // This can fail if the property is non-configurable.
            reportShimError(e, `Failed to define property for setter ${setterName}. Property might be non-configurable.`);
        }
    }

    /**
     * Applies instrumentation for all defined sinks to a specific root object (e.g., Global Scope, Prototype).
     * FIX: Now takes the groupedSinks Map.
     */
    function applyInstrumentation(root, groupedSinks) {
        // Safety check to prevent redundant instrumentation on the same object/prototype.
        // Also check if groupedSinks map is valid.
        if (!root || instrumentedCache.has(root) || !groupedSinks) return;

        // Mark the root as processed early to prevent recursion issues if sinks reference the root itself.
        instrumentedCache.add(root);

        // FIX: Iterate over the grouped sinks map.
        groupedSinks.forEach((sinkDefs, sinkName) => {
            try {
                // Resolve the path relative to the root.
                const resolved = resolvePath(sinkName, root);

                if (!resolved || !resolved.parent) {
                    // Expected for APIs not present (e.g., jQuery not loaded, API not supported in Worker).
                    return;
                }

                const {
                    parent,
                    key
                } = resolved;

                // Check if the resolved parent matches the intended root context.
                // This is complex, especially with prototypes. We rely on resolvePath finding the correct prototype chain.

                // We assume all definitions for the same name have the same 'Setter' value.
                // Check ensures sinkDefs is not empty (it shouldn't be if grouped correctly).
                const isSetter = sinkDefs.length > 0 && sinkDefs[0].Setter;

                if (isSetter) {
                    instrumentSetter(parent, key, sinkDefs);
                } else {
                    instrumentFunction(parent, key, sinkDefs);
                }
            } catch (e) {
                // Use a generic name if root.constructor.name is unavailable
                const rootName = root.constructor ? root.constructor.name : "UnknownRoot";
                reportShimError(e, `Failed to instrument sink ${sinkName} on root ${rootName}`);
            }
        });
    }

    /**
     * SHADOW DOM SUPPORT:
     * Global instrumentation applied during initialization covers APIs used within the Shadow DOM
     * (e.g., Element.prototype.innerHTML), provided the configuration uses absolute paths.
     * Explicitly overriding attachShadow to dynamically instrument Shadow Roots is therefore redundant.
     */

    /**
     * Helper function to instrument addEventListener on various prototypes (EventTarget, Window, etc.).
     * FIX: This addresses inconsistencies across environments (like JSDOM) where patching
     * EventTarget.prototype alone might not successfully intercept window.addEventListener.
     */
    function instrumentEventListener(prototype) {
        if (!prototype || typeof prototype.addEventListener !== 'function') return;

        const originalAddEventListener = prototype.addEventListener;

        // FIX: Prevent re-instrumentation using the existing cache. The previous implementation bypassed this.
        if (instrumentedCache.has(originalAddEventListener)) return;

        const wrapper = function(type, listener, options) {
            let listenerToUse = listener;
            // Check for 'message' events (IPC/postMessage)
            if (type === 'message' && typeof listener === 'function') {
                listenerToUse = function(event) {
                    // Check if the data property is tainted
                    if (isTainted(event.data)) {
                        // Log the flow. We rely on subsequent sinks to catch the actual vulnerability.
                        logger.log("Tainted data received via postMessage/onmessage", event.origin);
                    }
                    // Call the original listener robustly
                    return Reflect.apply(listener, this, [event]);
                };
            }
            // Call the original addEventListener robustly
            return Reflect.apply(originalAddEventListener, this, [type, listenerToUse, options]);
        };

        prototype.addEventListener = wrapper;
        instrumentedCache.add(wrapper);
        instrumentedCache.add(originalAddEventListener);
    }
    
    /**
     * WEB WORKER SUPPORT: Instruments the creation and communication of Web Workers.
     */
    function instrumentWebWorkers() {
        // 1. Instrument Worker Creation (Main thread only)
        if (!IS_WORKER && typeof Worker !== 'undefined') {
            const OriginalWorker = Worker;
            const WorkerWrapper = function(url, options) {

                if (isTainted(String(url))) {
                    reportSink("WORKER_SRC", String(url), "new Worker()");
                }

                // Create the worker instance.
                const worker = new OriginalWorker(url, options);

                // We rely on the browser driver's persistent injection (which runs this shim in all contexts) 
                // to self-instrument the WorkerGlobalScope.
                logger.log("New worker created. Relying on persistent injection for worker context.");

                return worker;
            };
            // Restore prototype chain
            WorkerWrapper.prototype = OriginalWorker.prototype;
            Object.setPrototypeOf(WorkerWrapper, OriginalWorker);

            // Override the global Worker constructor
            scope.Worker = WorkerWrapper;
        }

        // 2. Instrument Worker Context (Worker thread only)
        if (IS_WORKER) {
            // applyInstrumentation(self) handles DedicatedWorkerGlobalScope.postMessage and other sinks (fetch, XHR).
            logger.log("IAST Shim initialized within Web Worker context.");
        }

       // 3. Instrument addEventListener to track incoming 'message' events (IPC Taint Flow)

        // Instrument the base EventTarget.prototype
        if (typeof scope.EventTarget !== 'undefined') {
            instrumentEventListener(scope.EventTarget.prototype);
        }

        // FIX: Explicitly instrument specific prototypes known to be targets for 'message' events.
        if (!IS_WORKER) {
            // Instrument Window.prototype (for window.addEventListener) - Crucial for JSDOM compatibility.
            if (typeof scope.Window !== 'undefined') {
                instrumentEventListener(scope.Window.prototype);
            }
            // *** START FIX ***
            // Explicitly patch the global 'window' object as well for JSDOM compatibility.
            if (typeof scope.addEventListener === 'function') {
                 instrumentEventListener(scope); // 'scope' is 'self', which is 'window' here
            }
            // *** END FIX ***
        } else {
             // Instrument WorkerGlobalScope.prototype (for self.addEventListener in workers)
             if (typeof scope.WorkerGlobalScope !== 'undefined') {
                instrumentEventListener(scope.WorkerGlobalScope.prototype);
             }
        }
   }

    /**
     * PROTOTYPE POLLUTION DETECTION: Checks if Object.prototype has been polluted by our probes.
     */
    function checkPrototypePollution() {
        // This check is relevant in both Window and Worker contexts.
        try {
            // Check if the specific property used in our probes exists on Object.prototype.
            if (Object.prototype.hasOwnProperty(CONFIG.PollutionCheckProperty)) {
                const pollutedValue = Object.prototype[CONFIG.PollutionCheckProperty];

                if (isTainted(pollutedValue)) {
                    logger.warn(`Prototype Pollution detected! Property: ${CONFIG.PollutionCheckProperty}, Value: ${pollutedValue}`);

                    // Report this as a confirmed finding. The 'value' field will contain the Canary.
                    reportSink('PROTOTYPE_POLLUTION', pollutedValue, CONFIG.PollutionCheckProperty);

                    // Clean up the prototype to avoid interfering with the application logic.
                    try {
                        delete Object.prototype[CONFIG.PollutionCheckProperty];
                    } catch (e) {
                        reportShimError(e, "Prototype Pollution cleanup failed");
                    }
                }
            }
        } catch (e) {
            reportShimError(e, "Error during Prototype Pollution check");
        }
    }

    /**
     * Initializes the instrumentation process.
     */
    function initialize() {
        // Wrap the entire initialization in a try-catch block for maximum robustness.
        try {
            // FIX: 1. Pre-process Sinks Configuration: Group sinks by Name.
            const GroupedSinks = new Map();
            
            // Robustness: Check if CONFIG.Sinks is actually an array before processing.
            if (Array.isArray(CONFIG.Sinks)) {
                CONFIG.Sinks.forEach(sinkDef => {
                    if (!GroupedSinks.has(sinkDef.Name)) {
                        GroupedSinks.set(sinkDef.Name, []);
                    }
                    GroupedSinks.get(sinkDef.Name).push(sinkDef);
                });
            } else if (CONFIG.Sinks && (typeof CONFIG.Sinks === 'object' || (typeof CONFIG.Sinks === 'string' && CONFIG.Sinks.length > 0))) {
                 // Report error if SinksJSON was provided but invalid (e.g., a string or object instead of an array).
                 // The original code relied on the global try/catch catching "forEach is not a function". Explicit checking is better.
                 throw new Error("CONFIG.Sinks is not a valid array.");
            }
            // If CONFIG.Sinks is null, undefined, or an empty string, we proceed with an empty GroupedSinks map.

            // 2. Set up the execution proof callback wrapper.
            initializeExecutionProofCallback();

            // 3. Apply instrumentation based on the configuration.
            // We assume configuration paths (sinkDef.Name) are absolute (relative to the global scope).
            applyInstrumentation(scope, GroupedSinks); // FIX: Pass the grouped sinks map.

            // NOTE: Removed redundant calls to applyInstrumentation on specific prototypes (e.g. Element.prototype).
            // If prototypes need instrumentation, they should be specified in the config (e.g., "Element.prototype.innerHTML").
            
            // 4. Instrument advanced features.
            instrumentWebWorkers();
            // 5. Check for Prototype Pollution.
            // We delay this check slightly to allow the application code that causes the pollution (e.g., JSON parsing on load) to execute.
            setTimeout(checkPrototypePollution, 1500);
            // Also check again later.
            setTimeout(checkPrototypePollution, 5000);

            logger.log("IAST Instrumentation initialized successfully.");

        } catch (e) {
            reportShimError(e, "Fatal error during IAST Shim initialization");
        }
    }

    initialize();

    // Expose internals for testing if in test mode
    if (CONFIG.IsTesting) {
        scope.__SCALPEL_INTERNALS__ = {
            isTainted: isTainted,
            resolvePath: resolvePath,
            CONFIG: CONFIG,
            ConditionHandlers: ConditionHandlers,
            getStackTrace: getStackTrace
        };
    }

})(self); // Use 'self' which refers to the global scope in both Window and Worker contexts.