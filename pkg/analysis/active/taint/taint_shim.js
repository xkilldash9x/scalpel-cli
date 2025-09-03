// pkg/analysis/active/taint/taint_shim.js
(function(scope) {
    'use strict';

    // Prevent re-instrumentation
    if (scope.__SCALPEL_TAINT_INSTRUMENTED__) return;
    scope.__SCALPEL_TAINT_INSTRUMENTED__ = true;

    // Configuration injected by the Go backend via text/template
    const CONFIG = {
        Sinks: {{.SinksJSON}},
        SinkCallbackName: "{{.SinkCallbackName}}",
        ProofCallbackName: "{{.ProofCallbackName}}",
        ErrorCallbackName: "{{.ErrorCallbackName}}",
        CanaryPrefix: "SCALPEL",
        // Property name used specifically for Prototype Pollution probes.
        PollutionCheckProperty: "scalpelPolluted"
    };

    // Determine the context (Main Window or Web Worker)
    const IS_WORKER = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope;
    const CONTEXT_NAME = IS_WORKER ? "Worker" : "Window";

    const logger = {
        warn: (...args) => console.warn(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args),
        error: (...args) => console.error(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args),
        log: (...args) => console.log(`[Scalpel Taint Shim - ${CONTEXT_NAME}]`, ...args)
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
        const MAX_DEPTH = 4; // Limit recursion depth for performance.

        if (typeof value === 'string') {
            return value.includes(CONFIG.CanaryPrefix);
        }

        if (typeof value !== 'object' || value === null || depth > MAX_DEPTH) {
            return false;
        }

        // Cycle detection
        if (seen.has(value)) return false;
        seen.add(value);

        // Handle Arrays and specialized iterable objects (URLSearchParams, FormData)
        if (Array.isArray(value) ||
            (typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams) ||
            (typeof FormData !== 'undefined' && value instanceof FormData)) {

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
                    if (typeof Request !== 'undefined' && value instanceof Request) {
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
     */
    function instrumentFunction(parent, key, sinkDef) {
        const originalFunc = parent[key];
        if (typeof originalFunc !== 'function' || instrumentedCache.has(originalFunc)) return;

        const wrapper = function(...args) {
            try {
                let valueToInspect = args[sinkDef.ArgIndex];

                // --- Specialized Argument Handlers (Pre-processing) ---

                // 1. Fetch Handlers (fetch)
                if (sinkDef.Name === 'fetch' && typeof Request !== 'undefined') {
                    if (sinkDef.Type === 'FETCH_BODY' && sinkDef.ArgIndex === 1 && args.length > 1 && args[1] && args[1].body) {
                        // Inspect the body property of the options object (arg 1).
                        valueToInspect = args[1].body;
                    } else if (sinkDef.Type === 'FETCH_URL' && sinkDef.ArgIndex === 0 && args.length > 0) {
                        // Inspect the URL (arg 0). Handle both string and Request object.
                        if (args[0] instanceof Request) {
                            valueToInspect = args[0].url;
                        } else {
                            valueToInspect = args[0];
                        }
                    }
                }

                // 2. SendBeacon Data (ArgIndex 1)
                else if (sinkDef.Type === 'SEND_BEACON' && sinkDef.ArgIndex === 1 && args.length > 1) {
                    valueToInspect = args[1];
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
                                reportShimError(`Unknown ConditionID: ${sinkDef.ConditionID}`, `instrumentFunction ${sinkDef.Name}`);
                                conditionsMet = false; // Fail closed
                            }
                        } catch (e) {
                            reportShimError(e, `Error evaluating condition for ${sinkDef.Name}. ConditionID: ${sinkDef.ConditionID}`);
                            conditionsMet = false; // Assume condition failed if evaluation errors.
                        }
                    }

                    if (conditionsMet) {
                        reportSink(sinkDef.Type, valueToInspect, sinkDef.Name);
                    }
                }
            } catch (e) {
                reportShimError(e, `Error during instrumentation wrapper of function ${sinkDef.Name}`);
            }

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
            reportShimError(e, `Could not fully restore prototype chain or define property for ${sinkDef.Name}`);
        }
    }


    /**
     * Instruments a property setter.
     */
    function instrumentSetter(parent, key, sinkDef) {
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

        descriptor.set = function(value) {
            try {
                if (isTainted(value)) {
                    reportSink(sinkDef.Type, value, sinkDef.Name);
                }
            } catch (e) {
                reportShimError(e, `Error during instrumentation wrapper of setter ${sinkDef.Name}`);
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
            reportShimError(e, `Failed to define property for setter ${sinkDef.Name}. Property might be non-configurable.`);
        }
    }

    /**
     * Applies instrumentation for all defined sinks to a specific root object (e.g., Global Scope, Prototype).
     */
    function applyInstrumentation(root) {
        // Safety check to prevent redundant instrumentation on the same object/prototype.
        if (!root || instrumentedCache.has(root)) return;

        // Mark the root as processed early to prevent recursion issues if sinks reference the root itself.
        instrumentedCache.add(root);

        CONFIG.Sinks.forEach(sinkDef => {
            try {
                // Resolve the path relative to the root.
                const resolved = resolvePath(sinkDef.Name, root);

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

                if (sinkDef.Setter) {
                    instrumentSetter(parent, key, sinkDef);
                } else {
                    instrumentFunction(parent, key, sinkDef);
                }

            } catch (e) {
                // Use a generic name if root.constructor.name is unavailable
                const rootName = root.constructor ? root.constructor.name : "UnknownRoot";
                reportShimError(e, `Failed to instrument sink ${sinkDef.Name} on root ${rootName}`);
            }
        });
    }

    /**
     * SHADOW DOM SUPPORT: Instruments the creation of Shadow Roots.
     */
    function instrumentShadowDOM() {
        if (IS_WORKER || typeof Element === 'undefined' || !Element.prototype.attachShadow) return;

        const originalAttachShadow = Element.prototype.attachShadow;
        Element.prototype.attachShadow = function(options) {
            const shadowRoot = originalAttachShadow.call(this, options);

            try {
                // Apply instrumentation to the ShadowRoot itself (e.g. shadowRoot.innerHTML).
                applyInstrumentation(shadowRoot);
                // Global prototypes are already instrumented by initialize().
                // We do not need a MutationObserver here.
            } catch (e) {
                reportShimError(e, "Error during Shadow DOM instrumentation (attachShadow)");
            }

            return shadowRoot;
        };
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

        // 3. Instrument EventTarget.addEventListener to track incoming 'message' events (IPC Taint Flow)
        if (typeof EventTarget !== 'undefined' && EventTarget.prototype.addEventListener) {
            const originalAddEventListener = EventTarget.prototype.addEventListener;
            EventTarget.prototype.addEventListener = function(type, listener, options) {
                let listenerToUse = listener;
                if (type === 'message' && typeof listener === 'function') {
                    listenerToUse = function(event) {
                        // Check if the data property is tainted
                        if (isTainted(event.data)) {
                            // Log the flow. We rely on subsequent sinks to catch the actual vulnerability if the data is used unsafely.
                            logger.log("Tainted data received via postMessage/onmessage", event.origin);
                        }
                        return listener.call(this, event);
                    };
                }
                return originalAddEventListener.call(this, type, listenerToUse, options);
            };
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
            // 1. Set up the execution proof callback wrapper.
            initializeExecutionProofCallback();

            // 2. Apply instrumentation to the current global scope (Window or Worker) and core prototypes.
            applyInstrumentation(scope);
            if (typeof Object !== 'undefined' && Object.prototype) applyInstrumentation(Object.prototype);
            if (typeof Function !== 'undefined' && Function.prototype) applyInstrumentation(Function.prototype);
            if (typeof Element !== 'undefined' && Element.prototype) applyInstrumentation(Element.prototype);
            if (typeof HTMLElement !== 'undefined' && HTMLElement.prototype) applyInstrumentation(HTMLElement.prototype);
            if (typeof Window !== 'undefined' && Window.prototype) applyInstrumentation(Window.prototype);


            // 3. Instrument advanced features.
            instrumentShadowDOM();
            instrumentWebWorkers();

            // 4. Check for Prototype Pollution.
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

})(self); // Use 'self' which refers to the global scope in both Window and Worker contexts.
