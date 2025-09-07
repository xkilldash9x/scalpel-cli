// pkg/browser/shim/taint_shim.js
/*
    Pinnacle Unified Runtime (Taint Shim)
    This is the JavaScript payload responsible for client-side taint analysis instrumentation.
    It is dynamically configured by the Go host via string replacement.
*/
(function() {
    'use strict';

    // Initialization Guard: Prevent re-instrumentation on the same page/frame.
    if (window.__SCALPEL_INSTRUMENTED__) {
        return;
    }

    // --- Configuration Injection ---
    // The Go backend replaces the placeholder /*{{SCALPEL_SINKS_CONFIG}}*/ with the actual JSON configuration array.
    const sinks = /*{{SCALPEL_SINKS_CONFIG}}*/;

    // Fallback and validation if injection failed or config is invalid.
    if (typeof sinks === 'undefined' || !Array.isArray(sinks)) {
        console.error("Scalpel Taint Shim: Configuration injection failed or invalid. Disabling instrumentation.");
        return;
    }

    if (sinks.length === 0) {
        // Configuration is valid but empty.
        console.log("Scalpel Taint Shim: No sinks configured.");
        return;
    }

    window.__SCALPEL_INSTRUMENTED__ = true;
    console.log("Scalpel Taint Shim Initialized. Monitoring " + sinks.length + " sinks.");

    // -- Taint Definition --
    // Standardized canary prefix.
    const canaryPrefix = 'SCALPEL_TAINT_CANARY';

    /**
     * Checks if the provided value contains the taint canary.
     */
    function isTainted(value) {
        // We primarily care about strings reaching sinks.
        if (typeof value !== 'string') {
            return false;
        }
        return value.includes(canaryPrefix);
    }

    // -- Reporting Mechanism --
    /**
     * Bridge back to Go. Must be defined in Go code using ExposeFunction("__scalpel_sink_event").
     * The Go implementation (using chromedp.Expose) handles the serialization automatically.
     */
    function reportSink(type, value, detail) {
        if (typeof window.__scalpel_sink_event === 'function') {
            try {
                window.__scalpel_sink_event({
                    type: type,
                    value: String(value), // Ensure it's a string for transport.
                    detail: detail
                });
                console.log(`SCALPEL SINK TRIGGERED: type=${type}, detail=${detail}`);
            } catch (e) {
                console.error("Scalpel Taint Shim: Error during reporting callback.", e);
            }
        } else {
            // This should only happen if the Go side failed to expose the function before this script ran.
            console.error("Scalpel Taint Shim: Go callback (__scalpel_sink_event) not found.");
        }
    }

    // -- Instrumentation Logic --

    /**
     * Resolves a nested object path string (e.g., "Element.prototype.innerHTML") starting from the window object.
     * Returns the parent object and the property name if found.
     */
    function resolveObjectPath(path) {
        if (!path) return { parent: null, propName: '' };

        const parts = path.split('.');
        // The last part is the property we want to instrument.
        const propName = parts.pop();
        
        let parent = window;

        // Traverse the remaining parts to find the parent object.
        for (const part of parts) {
            // Ensure the current object is traversable (not null/undefined, and is an object or function).
            if (parent === null || (typeof parent !== 'object' && typeof parent !== 'function')) {
                 return { parent: null, propName: '' };
            }

            // Check existence (including prototype chain) before access.
            if (part in parent) {
                try {
                    // Robustness: Accessing properties can throw (e.g., cross-origin security exceptions).
                    parent = parent[part];
                } catch (e) {
                    console.debug(`Scalpel: Error accessing property ${part} during traversal.`, e);
                    return { parent: null, propName: '' };
                }
            } else {
                return { parent: null, propName: '' };
            }
        }

        // Final validation on the resolved parent and property existence.
        if ((typeof parent !== 'object' && typeof parent !== 'function') || parent === null || !(propName in parent)) {
            return { parent: null, propName: '' };
        }

        return { parent, propName };
    }


    sinks.forEach(sink => {
        try {
            const { parent, propName } = resolveObjectPath(sink.Name);

            if (!parent) {
                // console.debug(`Scalpel: Could not resolve object path for ${sink.Name}.`);
                return;
            }

            const original = parent[propName];

            if (sink.Setter) {
                // Instrumenting a property setter (e.g., element.innerHTML = '...').

                // We must look up the descriptor on the prototype chain.
                let currentProto = parent;
                let descriptor = null;
                while (currentProto && !descriptor) {
                    descriptor = Object.getOwnPropertyDescriptor(currentProto, propName);
                    if (!descriptor) {
                        try {
                             currentProto = Object.getPrototypeOf(currentProto);
                        } catch (e) {
                            currentProto = null; // Handle potential errors getting prototype (e.g., cross-origin objects)
                        }
                    }
                }

                // Check if a setter exists.
                if (descriptor && descriptor.set) {
                    const originalSetter = descriptor.set;

                    // Define the new setter on the object where the descriptor was found.
                    const targetObject = currentProto || parent;

                    Object.defineProperty(targetObject, propName, {
                        set: function(newValue) {
                            let shouldReport = true;
                            // Conditions allow dynamic evaluation (e.g., 'newValue.length > 10').
                            if (sink.Conditions && sink.Conditions.trim() !== "") {
                                try {
                                    // Evaluate the condition. We assume the configuration source is trusted.
                                    shouldReport = new Function('newValue', `return ${sink.Conditions}`)(newValue);
                                } catch (e) {
                                    console.error(`Scalpel: Error evaluating condition for ${sink.Name}: ${sink.Conditions}`, e);
                                    shouldReport = true; // Default to report if evaluation fails
                                }
                            }

                            if (shouldReport && isTainted(newValue)) {
                                reportSink(sink.Type || 'Setter', newValue, sink.Name);
                            }
                            // Call the original setter using the correct 'this' context.
                            return originalSetter.call(this, newValue);
                        },
                        configurable: true // Allow redefinition
                    });
                }

            } else if (typeof original === 'function') {
                // Instrumenting a function call (e.g., window.eval('...')).

                // Replace the function on the parent object.
                parent[propName] = function(...args) {
                    // Check arguments for taint.
                    args.forEach((arg, index) => {
                        if (isTainted(arg)) {
                            reportSink(sink.Type || 'FunctionCall', arg, `${sink.Name} (Arg ${index})`);
                        }
                    });
                    // Call the original function using the correct 'this' context.
                    return original.apply(this, args);
                };

                // Stealth: Try to maintain the original function's properties.
                try {
                    // Use bind to ensure 'this' context if toString itself is called unusually
                    parent[propName].toString = original.toString.bind(original);

                    // AVOID Object.setPrototypeOf for performance reasons.

                    // Copy descriptors (includes name, length, and others).
                    // This might still fail for some native/host objects, but is safer than setPrototypeOf.
                    Object.defineProperties(parent[propName], Object.getOwnPropertyDescriptors(original));
                } catch (e) {
                    // May fail for some native functions, not critical.
                }
            }

        } catch (e) {
            // Catch-all for errors during instrumentation (e.g., permission errors).
            console.error(`Scalpel: Failed to instrument sink ${sink.Name}:`, e);
        }
    });
})();