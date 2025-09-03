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
        const parts = path.split('.');
        let obj = window;
        let parent = null;
        let propName = '';

        for (let i = 0; i < parts.length; i++) {
            propName = parts[i];

            // Check if the current object is traversable.
            if (obj === undefined || obj === null) {
                return { parent: null, propName: '' };
            }

            if (i < parts.length - 1) {
                // Navigate deeper
                // Use 'in' operator to check prototype chain as well, which is often needed for browser APIs.
                if (propName in obj) {
                     parent = obj;
                     obj = obj[propName];
                } else {
                    // Path does not exist.
                    return { parent: null, propName: '' };
                }
            } else {
                // At the last part, the current object is the container (parent) of the target property.
                parent = obj;
            }
        }

        // The target property/function name is the last part
        propName = parts[parts.length - 1];

        // Final validation.
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
                    parent[propName].toString = () => original.toString();
                    if (Object.getPrototypeOf(original)) {
                        Object.setPrototypeOf(parent[propName], Object.getPrototypeOf(original));
                    }
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
