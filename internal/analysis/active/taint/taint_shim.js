// File: internal/analysis/active/taint/taint_shim.js

/**
 * Scalpel IAST Instrumentation Shim
 *
 * This script is injected into the browser context (both main window and workers)
 * to perform dynamic taint analysis by instrumenting sensitive JavaScript APIs (sinks).
 * It implements robust techniques for taint tracking, prototype preservation, and cross-context communication.
 */
(function(scope) {
    'use strict';

    // Prevent re-instrumentation in the same context.
    if (scope.__SCALPEL_TAINT_INSTRUMENTED__) return;
    scope.__SCALPEL_TAINT_INSTRUMENTED__ = true;

    // Configuration injected by the Go backend via text/template.
    const CONFIG = {
        // SinksJSON is replaced with a valid JSON array of SinkDefinition objects.
        // @ts-ignore
        Sinks: {{.SinksJSON}},
        SinkCallbackName: "{{.SinkCallbackName}}",
        ProofCallbackName: "{{.ProofCallbackName}}",
        ErrorCallbackName: "{{.ErrorCallbackName}}",
        CanaryPrefix: "SCALPEL",
        // Property name used specifically for Prototype Pollution detection probes.
        PollutionCheckProperty: "scalpelPolluted",
        // Flag for exposing internals during unit testing (set via global variable).
        IsTesting: scope.__SCALPEL_TEST_MODE__ || false
    };

    // Determine the execution context (Main Window or Web Worker).
    const IS_WORKER = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;
    const CONTEXT_NAME = IS_WORKER ? "Worker" : "Window";

    // ROBUSTNESS: Explicitly use scope.console to ensure we use the instrumented environment's console.
    const logger = {
        warn: (...args) => scope.console.warn(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args),
        error: (...args) => scope.console.error(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args),
        log: (...args) => scope.console.log(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args)
    };

    // Predefined condition handlers for specialized sink logic.
    const ConditionHandlers = {
        'IS_STRING_ARG0': (args) => typeof args[0] === 'string', // e.g., setTimeout(string)
        'SEND_BEACON_DATA_EXISTS': (args) => args.length > 1 && args[1] != null,
        'XHR_SEND_DATA_EXISTS': (args) => args.length > 0 && args[0] != null,
    };

    // WeakSet to track instrumented objects to avoid infinite recursion/re-instrumentation.
    const instrumentedCache = new WeakSet();

    /**
     * ROBUSTNESS: Reports internal instrumentation errors back to the Go backend asynchronously.
     */
    function reportShimError(error, location, stack = null) {
        const callback = scope[CONFIG.ErrorCallbackName];
        if (typeof callback === 'function') {
            // Execute asynchronously to avoid blocking the main application flow.
            setTimeout(() => {
                try {
                    const errorStack = stack || (error instanceof Error ? error.stack : getStackTrace());
                    callback({
                        error: String(error),
                        location: String(location),
                        stack: errorStack
                    });
                } catch (e) {
                    logger.error("Failed to execute backend error callback.", e);
                }
            }, 0);
        } else {
            logger.error(`Shim Error at ${location}:`, error);
        }
    }

    /**
     * Captures and cleans the current stack trace.
     */
    function getStackTrace() {
        try {
            const err = new Error();
            if (err.stack) {
                // Remove internal shim functions from the trace.
                return err.stack.split('\n').slice(3).join('\n');
            }
        } catch (e) {}
        return "Could not capture stack trace.";
    }

    /**
     * Checks if a value is tainted (contains the canary prefix).
     * Implements deep inspection with cycle detection and depth limits.
     */
    function isTainted(value, depth = 0, seen = new WeakSet()) {
        const MAX_DEPTH = 5; // Increased depth for complex objects.

        // Check depth limit first.
        if (depth > MAX_DEPTH) {
            return false;
        }

        if (typeof value === 'string') {
            return value.includes(CONFIG.CanaryPrefix);
        }

        if (typeof value !== 'object' || value === null) {
            return false;
        }

        // Cycle detection.
        if (seen.has(value)) return false;
        seen.add(value);

        // Handle Iterables (Arrays, URLSearchParams, FormData).
        // ROBUSTNESS: Use scope.* to ensure we use the correct global objects.
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

        // Handle generic objects.
        try {
            // Use Reflect.ownKeys to include non-enumerable and symbol properties.
            const keys = Reflect.ownKeys(value);
            for (const key of keys) {
                try {
                    // Use Reflect.get for safer property access.
                    const propValue = Reflect.get(value, key);
                    if (isTainted(propValue, depth + 1, seen)) {
                        return true;
                    }
                } catch (e) {
                    // Ignore errors accessing restricted properties.
                }
            }
        } catch (e) {
            // Cannot inspect object (e.g., cross-origin).
        }
        return false;
    }


    /**
     * Reports a detected sink event to the Go backend asynchronously.
     */
    function reportSink(type, value, detail) {
        const callback = scope[CONFIG.SinkCallbackName];
        if (typeof callback === 'function') {
            const stack = getStackTrace();
            setTimeout(() => {
                try {
                    let stringValue;
                    // Handle complex types before reporting.
                    
                    // Handle Request objects (e.g., in Fetch API).
                    // ROBUSTNESS: Use scope.Request.
                    if (typeof scope.Request !== 'undefined' && value instanceof scope.Request) {
                        stringValue = value.url;
                    } else if (typeof value === 'object' && value !== null) {
                        try {
                            stringValue = JSON.stringify(value);
                        } catch (e) {
                            stringValue = String(value); // Fallback for circular structures.
                        }
                    } else {
                        stringValue = String(value);
                    }

                    // Callback expects an object matching the SinkEvent struct.
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
     * Overrides the execution proof callback to capture the stack trace upon execution.
     */
    function initializeExecutionProofCallback() {
        const originalCallback = scope[CONFIG.ProofCallbackName];
        if (typeof originalCallback !== 'function') {
            logger.error("Backend execution proof callback not exposed correctly.");
            return;
        }

        scope[CONFIG.ProofCallbackName] = function(canary) {
            const stack = getStackTrace();
            logger.warn(`Execution Proof triggered! Canary: ${canary}`);
            try {
                // Callback expects an object matching the ExecutionProofEvent struct.
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
     * Resolves a nested property path (e.g., "Element.prototype.innerHTML") on a root object.
     */
    function resolvePath(path, root = scope) {
        const parts = path.split('.');
        let current = root;

        try {
            for (let i = 0; i < parts.length - 1; i++) {
                current = Reflect.get(current, parts[i]);
                if (current === undefined || current === null) {
                    // Path does not exist (e.g., jQuery not loaded).
                    return null;
                }
            }
            return {
                parent: current,
                key: parts[parts.length - 1]
            };
        } catch (e) {
            reportShimError(e, `resolvePath access error for ${path}`);
            return null;
        }
    }

    /**
     * Instruments a function call.
     * Accepts an array of sink definitions (sinkDefs) to handle multiple sinks on the same function (e.g., fetch).
     */
    function instrumentFunction(parent, key, sinkDefs) {
        const originalFunc = parent[key];
        if (typeof originalFunc !== 'function' || instrumentedCache.has(originalFunc)) return;

        const functionName = sinkDefs[0].Name;

        const wrapper = function(...args) {
            
            // Iterate over all sink definitions for this function.
            for (const sinkDef of sinkDefs) {
                // Use try-catch inside the loop for robustness.
                try {
                    let valueToInspect = args[sinkDef.ArgIndex];

                    // --- Specialized Argument Handlers (Pre-processing) ---

                    // 1. Fetch API Handlers
                    if (functionName === 'fetch') {
                        // A. FETCH_BODY (ArgIndex 1)
                        if (sinkDef.ArgIndex === 1) {
                            if (args.length > 1 && args[1] && typeof args[1] === 'object' && args[1].body != null) {
                                valueToInspect = args[1].body;
                            } else {
                                continue; // Body missing, skip this sink check.
                            }
                        } 
                        // B. FETCH_URL (ArgIndex 0)
                        else if (sinkDef.ArgIndex === 0) {
                            if (args.length > 0) {
                                // Handle Request object input.
                                if (typeof scope.Request !== 'undefined' && args[0] instanceof scope.Request) {
                                    valueToInspect = args[0].url;
                                } else {
                                    valueToInspect = args[0];
                                }
                            } else {
                                 continue;
                            }
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
                                    conditionsMet = false;
                                }
                            } catch (e) {
                                reportShimError(e, `Error evaluating condition for ${functionName}. ConditionID: ${sinkDef.ConditionID}`);
                                conditionsMet = false;
                            }
                        }

                        if (conditionsMet) {
                            reportSink(sinkDef.Type, valueToInspect, functionName);
                        }
                    }
                } catch (e) {
                    reportShimError(e, `Error during instrumentation wrapper of function ${functionName} (Type: ${sinkDef.Type})`);
                }
            }

            // Call the original function robustly.
            return Reflect.apply(originalFunc, this, args);
        };

        // STEALTH & COMPATIBILITY: Preserve original properties and prototype chain.
        try {
            Object.setPrototypeOf(wrapper, originalFunc);
            if (originalFunc.prototype) {
                wrapper.prototype = originalFunc.prototype;
            }
            // Copy static properties.
            Object.getOwnPropertyNames(originalFunc).forEach(prop => {
                if (prop !== 'prototype' && prop !== 'name' && prop !== 'length') {
                    try {
                         const descriptor = Object.getOwnPropertyDescriptor(originalFunc, prop);
                         if (descriptor) {
                             Object.defineProperty(wrapper, prop, descriptor);
                         }
                    } catch (e) {
                        // Ignore errors for non-configurable properties.
                    }
                }
            });

            // Replace the original function robustly.
            try {
                const originalDescriptor = Object.getOwnPropertyDescriptor(parent, key);
                Object.defineProperty(parent, key, {
                    value: wrapper,
                    writable: originalDescriptor?.writable ?? true,
                    configurable: originalDescriptor?.configurable ?? true,
                    enumerable: originalDescriptor?.enumerable ?? false
                });
            } catch (e) {
                // Fallback for non-configurable properties.
                parent[key] = wrapper;
            }
            
            instrumentedCache.add(wrapper);
            instrumentedCache.add(originalFunc);
        } catch (e) {
            reportShimError(e, `Could not fully restore prototype chain or define property for ${functionName}`);
        }
    }


    /**
     * Instruments a property setter (e.g., innerHTML).
     */
    function instrumentSetter(parent, key, sinkDefs) {
        let descriptor = Object.getOwnPropertyDescriptor(parent, key);
        let target = parent;

        // If not found on the object, look up the prototype chain.
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
            }

            if (tainted) {
                // Report for every matching sink definition.
                for (const sinkDef of sinkDefs) {
                    try {
                        // Condition checking logic (same as instrumentFunction)
                        let conditionsMet = true; 
                        if (sinkDef.ConditionID) {
                             try {
                                const handler = ConditionHandlers[sinkDef.ConditionID];
                                if (handler) {
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
            
            // Call the original setter with the correct context.
            return Reflect.apply(originalSet, this, [value]);
        };

        instrumentedCache.add(descriptor.set);
        instrumentedCache.add(originalSet); // Add original setter to cache
        
        try {
            Object.defineProperty(target, key, descriptor);
        } catch (e) {
            reportShimError(e, `Failed to define property for setter ${setterName}. Property might be non-configurable.`);
        }
    }

    /**
     * Applies instrumentation based on the groupedSinks Map.
     */
    function applyInstrumentation(root, groupedSinks) {
        if (!root || instrumentedCache.has(root) || !groupedSinks) return;
        instrumentedCache.add(root);

        groupedSinks.forEach((sinkDefs, sinkName) => {
            try {
                const resolved = resolvePath(sinkName, root);
                if (!resolved || !resolved.parent) return;

                const { parent, key } = resolved;
                const isSetter = sinkDefs.length > 0 && sinkDefs[0].Setter;

                if (isSetter) {
                    instrumentSetter(parent, key, sinkDefs);
                } else {
                    instrumentFunction(parent, key, sinkDefs);
                }
            } catch (e) {
                const rootName = (root.constructor && root.constructor.name) ? root.constructor.name : "UnknownRoot";
                reportShimError(e, `Failed to instrument sink ${sinkName} on root ${rootName}`);
            }
        });
    }

    /**
     * Instruments addEventListener to track incoming 'message' events (IPC Taint Flow).
     */
    function instrumentEventListener(target) {
        // Target can be a prototype (e.g., EventTarget.prototype) or a global object (e.g., window).
        if (!target || typeof target.addEventListener !== 'function') return;
        const originalAddEventListener = target.addEventListener;
        if (instrumentedCache.has(originalAddEventListener)) return;

        const wrapper = function(type, listener, options) {
            let listenerToUse = listener;

            if (type === 'message' && typeof listener === 'function') {
                listenerToUse = function(event) {
                    if (isTainted(event.data)) {
                        logger.log("Tainted data received via postMessage/onmessage from origin:", event.origin);
                    }
                    return Reflect.apply(listener, this, [event]);
                };
            }
            return Reflect.apply(originalAddEventListener, this, [type, listenerToUse, options]);
        };

        target.addEventListener = wrapper;
        instrumentedCache.add(wrapper);
        instrumentedCache.add(originalAddEventListener);
    }
    
    /**
     * WEB WORKER SUPPORT: Instruments Worker creation and communication.
     */
    function instrumentWebWorkers() {
        // 1. Instrument Worker Creation (Main thread only)
        if (!IS_WORKER && typeof Worker !== 'undefined') {
            const OriginalWorker = Worker;
            const WorkerWrapper = function(url, options) {
                const urlString = String(url);
                if (isTainted(urlString)) {
                    reportSink("WORKER_SRC", urlString, "new Worker()");
                }
                // Rely on persistent injection to instrument the worker context itself.
                return new OriginalWorker(url, options);
            };
            WorkerWrapper.prototype = OriginalWorker.prototype;
            Object.setPrototypeOf(WorkerWrapper, OriginalWorker);
            scope.Worker = WorkerWrapper;
        }

       // 2. Instrument addEventListener for IPC tracking (All contexts)
       if (typeof scope.EventTarget !== 'undefined' && scope.EventTarget.prototype) {
            instrumentEventListener(scope.EventTarget.prototype);
       }

       // Explicitly instrument specific targets for robustness across environments (e.g., JSDOM).
       if (!IS_WORKER) {
            if (typeof scope.Window !== 'undefined' && scope.Window.prototype) {
                instrumentEventListener(scope.Window.prototype);
            }
            if (typeof scope.addEventListener === 'function') {
                 instrumentEventListener(scope); // Instrument the global window/self object directly.
            }
       } else {
            if (typeof scope.WorkerGlobalScope !== 'undefined' && scope.WorkerGlobalScope.prototype) {
                instrumentEventListener(scope.WorkerGlobalScope.prototype);
            }
            if (typeof scope.addEventListener === 'function') {
                 instrumentEventListener(scope); // Instrument the worker global scope directly.
            }
       }
   }

    /**
     * PROTOTYPE POLLUTION DETECTION: Actively checks if Object.prototype has been polluted.
     */
    function checkPrototypePollution() {
        try {
            if (Object.prototype.hasOwnProperty(CONFIG.PollutionCheckProperty)) {
                const pollutedValue = Object.prototype[CONFIG.PollutionCheckProperty];

                if (isTainted(pollutedValue)) {
                    logger.warn(`Prototype Pollution detected! Property: ${CONFIG.PollutionCheckProperty}`);
                    reportSink('PROTOTYPE_POLLUTION_CONFIRMED', pollutedValue, CONFIG.PollutionCheckProperty);

                    // Clean up the prototype.
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
     * Main initialization function.
     */
    function initialize() {
        // Global try-catch for maximum robustness.
        try {
            // 1. Group sinks by Name for efficient instrumentation.
            const GroupedSinks = new Map();
            
            if (Array.isArray(CONFIG.Sinks)) {
                CONFIG.Sinks.forEach(sinkDef => {
                    if (!GroupedSinks.has(sinkDef.Name)) {
                        GroupedSinks.set(sinkDef.Name, []);
                    }
                    GroupedSinks.get(sinkDef.Name).push(sinkDef);
                });
            } else if (CONFIG.Sinks && (typeof CONFIG.Sinks === 'object' || (typeof CONFIG.Sinks === 'string' && CONFIG.Sinks.length > 0))) {
                 throw new Error("CONFIG.Sinks is not a valid array.");
            }

            // 2. Setup execution proof wrapper.
            initializeExecutionProofCallback();

            // 3. Apply core instrumentation.
            applyInstrumentation(scope, GroupedSinks); 
            
            // 4. Instrument advanced features (IPC, Workers).
            instrumentWebWorkers();

            // 5. Schedule Prototype Pollution checks (delayed to allow app initialization).
            setTimeout(checkPrototypePollution, 1500);
            setTimeout(checkPrototypePollution, 5000);

            logger.log("IAST Instrumentation initialized successfully.");

        } catch (e) {
            reportShimError(e, "Fatal error during IAST Shim initialization");
        }
    }

    initialize();

    // Expose internals for unit testing if enabled.
    if (CONFIG.IsTesting) {
        scope.__SCALPEL_INTERNALS__ = {
            isTainted: isTainted,
            resolvePath: resolvePath,
            CONFIG: CONFIG,
            ConditionHandlers: ConditionHandlers,
            getStackTrace: getStackTrace
        };
    }

})(self); // 'self' refers to the global scope in both Window and Worker contexts.