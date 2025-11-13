(function(scope) {
    'use strict';
    // This sandbox is used to prevent re-instrumentation if the script is injected multiple times.
    const sandbox = scope.scalpelSandbox = scope.scalpelSandbox || {};
    if (sandbox.ppGlobalInstrumentationDone) return;

    // These placeholders are replaced by the Go analyzer before injection.
    let pollutionCanary = '{{SCALPEL_CANARY}}';
    let detectionCallbackName = '{{SCALPEL_CALLBACK_NAME}}';

    // Immediately capture the callback function into a local variable. This is the defense-in-depth
    // measure against DOM Clobbering. Even if an element overwrites the global `window[detectionCallbackName]`,
    // our shim will still hold a reference to the original function.
    const callback = scope[detectionCallbackName];

    let domObserver = null;

    /**
     * Sets up a trap on Object.prototype to detect when the canary property is accessed.
     * This is the primary detection mechanism for prototype pollution.
     */
    function setupPrototypeTrap() {
        try {
            Object.defineProperty(Object.prototype, pollutionCanary, {
                get: function() {
                    // We ignore access on the global window object itself.
                    if (this !== scope) {
                        notifyBackend("Object.prototype_access", "Direct access to polluted Object.prototype");
                    }
                    return 'polluted_by_scalpel';
                },
                // Must be configurable to allow cleanup between tests or runs.
                configurable: true
            });
        } catch (e) {
            console.warn("[Scalpel PP Shim] Could not define canary property on Object.prototype.", e);
        }
    }

    /**
     * Sends a notification back to the Go analyzer when a potential vulnerability is found.
     * @param {string} source - The source of the potential pollution (e.g., 'Fetch_Response').
     * @param {string} vector - A more detailed description or the actual malicious payload.
     */
    function notifyBackend(source, vector) {
        // Use the locally captured callback function, not the global one.
        if (typeof callback === 'function') {
            const stack = new Error().stack;
            // Use setTimeout to avoid blocking the main thread.
            setTimeout(() => {
                try {
                    callback({
                        source: source,
                        canary: pollutionCanary,
                        vector: vector || "N/A",
                        stackTrace: stack
                    });
                } catch (e) {
                    console.error("[Scalpel PP Shim] Failed to notify backend.", e);
                }
            }, 0);
        }
    }

    /**
     * Instruments the native fetch API to inspect JSON responses for pollution vectors.
     */
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

    /**
     * Instruments XMLHttpRequest to inspect JSON responses for pollution vectors.
     */
    function instrumentXHR() {
        if (!scope.XMLHttpRequest) return;
        const originalSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(...args) {
            this.addEventListener('load', function() {
                if (this.readyState === 4 && this.status >= 200 && this.status < 400) {
                    try {
                        const contentType = this.getResponseHeader('Content-Type');
                        if ((this.responseType === "" || this.responseType === "text") && contentType && contentType.includes('application/json')) {
                            if (this.responseText) {
                                checkForPollutionPatterns(this.responseText, 'XHR_Response');
                            }
                        }
                    } catch (e) { /* ignored */ }
                }
            });
            return originalSend.apply(this, args);
        };
    }


    /**
     * Recursively checks a parsed JSON object for keys that could cause pollution.
     * @param {object} obj - The object to check.
     * @returns {string|null} - The detected pollution vector, or null if none found.
     */
    function findPollutionVector(obj) {
        for (const key in obj) {
            if (key === '__proto__') return `__proto__`;
            if (key === 'constructor' && obj[key] && typeof obj[key] === 'object' && 'prototype' in obj[key]) {
                 return `constructor.prototype`;
            }
            if (typeof obj[key] === 'object' && obj[key] !== null) {
                const nestedVector = findPollutionVector(obj[key]);
                if (nestedVector) return `${key}.${nestedVector}`;
            }
        }
        return null;
    }


    /**
     * Parses a string of data and checks the resulting object for pollution vectors.
     * @param {string} data - The raw string data (usually from a network response).
     * @param {string} source - The source of the data.
     */
    function checkForPollutionPatterns(data, source) {
        if (typeof data !== 'string' || data.length < 10) return;
        // Quick check to avoid parsing JSON unnecessarily.
        if (!data.includes('__proto__') && !data.includes('constructor')) {
            return;
        }

        try {
            const parsed = JSON.parse(data);
            const vector = findPollutionVector(parsed);
            if (vector) {
                notifyBackend(source + "_JSON_payload", vector);
            }
        } catch (e) { /* Malformed JSON is ignored */ }
    }


    /**
     * Monitors the DOM for elements that could cause DOM Clobbering, which can be
     * a vector for prototype pollution.
     */
    function monitorDOMClobbering() {
        if (!scope.MutationObserver) return;
        const checkClobbering = () => {
            // Check if the canary has been overwritten on the window object by a DOM element.
            if (Object.hasOwn(scope, pollutionCanary) && scope[pollutionCanary] instanceof Element) {
                notifyBackend("DOM_Clobbering", `Element with id='${pollutionCanary}'`);
            }
        };

        domObserver = new MutationObserver(checkClobbering);
        // Start observing as soon as the document element is available.
        const observe = () => {
            if (document.documentElement) {
                domObserver.observe(document.documentElement, {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeFilter: ['id', 'name'] // We only care about attributes that can clobber globals.
                });
                checkClobbering(); // Initial check on load.
            } else {
                setTimeout(observe, 50); // Retry if DOM is not ready.
            }
        };
        observe();
    }

    // --- Main Execution ---
    setupPrototypeTrap();
    instrumentFetch();
    instrumentXHR();
    monitorDOMClobbering();
    sandbox.ppGlobalInstrumentationDone = true;

})(window);
