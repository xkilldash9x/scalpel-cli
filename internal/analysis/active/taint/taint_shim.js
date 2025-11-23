//Filename: taint_shim.js
// internal/analysis/active/taint/taint_shim.js
(function(scope) {
    'use strict';

    // Configuration injected by the Go backend via text/template
    // We define CONFIG early because cleanup might need it.
    const CONFIG = {
        // @ts-ignore - This is a Go template placeholder that will be replaced with a valid JSON object.
        Sinks: {{.SinksJSON}},
        // VULN-FIX: These names are randomized per session by the Go backend.
        SinkCallbackName: "{{.SinkCallbackName}}",
        
        // VULN-FIX (Timing): Separate names for the JS wrapper (payload target) and the Go backend handle.
        ProofCallbackName: "{{.ProofCallbackName}}",
        BackendProofCallbackName: "{{.BackendProofCallbackName}}",

        ErrorCallbackName: "{{.ErrorCallbackName}}",
        CanaryPrefix: "SCALPEL",
        // Property name used for Prototype Pollution probes (Write detection, Access trap, and DOM Clobbering).
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

    // TEST-FIX: Array to store functions that should be executed when the shim is unloaded or reloaded.
    let cleanupFunctions = [];

    // MERGE: Identifier used to tag the Prototype Pollution access trap getter/setter functions.
    const PP_TRAP_IDENTIFIER = Symbol("ScalpelPPTrap");

    // ROBUSTNESS: Expose symbol globally so zombie intervals from previous test runs (if any) recognize the new trap.
    scope.__SCALPEL_PP_SYMBOL__ = PP_TRAP_IDENTIFIER;


    /**
     * TEST-FIX: Cleans up resources, observers, intervals, and modifications made by the shim.
     * Essential for stability in test environments (like JSDOM) to prevent crashes between tests.
     */
    function cleanup() {
        if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;
        logger.log("Performing shim cleanup...");

        // 1. Clear Intervals
        if (scope.__SCALPEL_POLLUTION_CHECK_INTERVAL__) {
            clearInterval(scope.__SCALPEL_POLLUTION_CHECK_INTERVAL__);
            scope.__SCALPEL_POLLUTION_CHECK_INTERVAL__ = null;
        }

        // 2. Disconnect Observers
        [
            '__SCALPEL_CLOBBERING_OBSERVER__',
            '__SCALPEL_CSTI_OBSERVER__',
            '__SCALPEL_BASE_TAG_OBSERVER__'
        ].forEach(observerName => {
            if (scope[observerName]) {
                try {
                    scope[observerName].disconnect();
                } catch (e) {
                    logger.error(`Error disconnecting observer ${observerName}:`, e);
                }
                scope[observerName] = null;
            }
        });

        // 3. Run specific cleanup functions (e.g., remove event listeners, restore prototypes)
        // Execute in reverse order of registration to properly unwrap stacked instrumentations.
        cleanupFunctions.reverse().forEach(fn => {
            try {
                fn();
            } catch (e) {
                logger.error("Error during cleanup function execution:", e);
            }
        });
        cleanupFunctions = [];

        // 4. Attempt to clean up Object.prototype trap
        try {
            const propertyName = CONFIG.PollutionCheckProperty;
            // Check if the property exists and if it's our specific trap
            const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, propertyName);
            // Use the current symbol instance for comparison
            if (descriptor && descriptor.get && descriptor.get[PP_TRAP_IDENTIFIER]) {
                 delete Object.prototype[propertyName];
            }
        } catch (e) {
            // This might fail if the prototype is frozen, but we try our best.
            logger.error("Error during prototype trap cleanup:", e);
        }

        // 5. Reset instrumentation flag - MUST BE LAST
        // This flag is used by async callbacks (setTimeout, Promises, Observers) to check if the context is still valid.
        scope.__SCALPEL_TAINT_INSTRUMENTED__ = false;

        // Clear shared caches to allow re-instrumentation in tests
        if (scope.instrumentedCache) scope.instrumentedCache.clear();
        if (scope.listenerWrapperMap) scope.listenerWrapperMap = new WeakMap();
    }

    // Cleanup previous shim instances if re-initializing (e.g. in tests)
    if (scope.__SCALPEL_TAINT_INSTRUMENTED__) {
        if (CONFIG.IsTesting) {
            // If we are testing, we must clean up the previous instance before continuing.
            logger.log("Re-initialization detected in test mode. Cleaning up previous instance.");
            cleanup();
        } else {
            // In production, we avoid re-instrumenting.
            return;
        }
    }
    
    // Set the flag immediately.
    scope.__SCALPEL_TAINT_INSTRUMENTED__ = true;


    // FIX: Flag to prevent recursive triggering of the PP access trap during reporting.
    let isReporting = false;

    // --- VULN-FIX START: Capture Callbacks in Closure ---
    const SinkCallback = scope[CONFIG.SinkCallbackName];
    // VULN-FIX (Timing): Capture the backend handle, not the JS wrapper name.
    const BackendProofCallback = scope[CONFIG.BackendProofCallbackName];
    const ErrorCallback = scope[CONFIG.ErrorCallbackName];

    // VULN-FIX (Timing): Check the BackendProofCallback handle.
    if (typeof SinkCallback !== 'function' || typeof BackendProofCallback !== 'function' || typeof ErrorCallback !== 'function') {
        scope.console.error("[Scalpel] Critical Error: Backend callbacks not exposed correctly or were clobbered before shim initialization. Analysis may be ineffective.");
        // Allow continuation in test mode even if callbacks are mocked/missing, but stop in production.
        if (!CONFIG.IsTesting) {
             return;
        }
    }
    // --- VULN-FIX END ---


    // Predefined condition handlers for CSP compatibility.
    const ConditionHandlers = {
        'IS_STRING_ARG0': (args) => typeof args[0] === 'string',
        'SEND_BEACON_DATA_EXISTS': (args) => args.length > 1 && args[1] != null,
        'XHR_SEND_DATA_EXISTS': (args) => args.length > 0 && args[0] != null,
    };

    // Set to track instrumented objects to avoid infinite recursion.
    const instrumentedCache = new WeakSet();

    // NEW: Map to track original listeners and their wrappers for removeEventListener compatibility.
    const listenerWrapperMap = new WeakMap();

    // #################################################################################################
    // #                                     Heuristics and Utilities                                  #
    // #################################################################################################

    // --- 1. Luhn Algorithm Validator (NEW) ---

    /**
     * Checks if a potential credit card number passes the Luhn algorithm (Mod 10).
     * This filters out pattern matches that are mathematically invalid, reducing false positives.
     */
    function isValidLuhn(value) {
        // Remove all non-digits (spaces, dashes)
        const clean = value.replace(/\D/g, '');
        
        // Basic length check (PANs are typically 13-19 digits).
        if (clean.length < 13 || clean.length > 19) {
            return false;
        }

        let sum = 0;
        let shouldDouble = false;

        // Loop backwards through the digits
        for (let i = clean.length - 1; i >= 0; i--) {
            let digit = parseInt(clean.charAt(i), 10);

            if (shouldDouble) {
                // Double the digit
                digit *= 2;
                // If the result is > 9, subtract 9 (equivalent to summing the digits of the result)
                if (digit > 9) {
                    digit -= 9;
                }
            }

            sum += digit;
            // Toggle the flag for the next digit
            shouldDouble = !shouldDouble;
        }

        // The number is valid if the sum is divisible by 10.
        return (sum % 10) === 0;
    }


    // --- 2. Sensitive Data Patterns (UPDATED) ---
    const SECRET_PATTERNS = [
        // JWT/Bearer tokens
        /Bearer\s+ey[a-zA-Z0-9\-_]+\.ey[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/i,
        // Generic API Keys (high entropy heuristic)
        /[a-f0-9]{32,}/i,
        // AWS Keys
        /AKIA[0-9A-Z]{16}/,
        // Slack Tokens
        /xox[pbaors]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-f0-9]{32}/,
        // Note: Credit Card regex removed from here to be handled separately with Luhn validation
    ];

    // The modernized and comprehensive regex for detection (Visa, Master, Amex, Discover, Diners Club).
    // Handles spaces and dashes as separators. Must be kept in sync with scanner.go.
    // Global flag (/g) is essential for checking all matches in the input using matchAll or exec loop.
    const CC_REGEX = /\b(?:4[0-9]{3}(?:[- ]?[0-9]{4}){2}(?:[- ]?[0-9]{1,4})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)(?:[- ]?[0-9]{4}){3}|3[47][0-9]{2}(?:[- ]?[0-9]{6})[- ]?[0-9]{5}|6(?:011|5[0-9]{2}|4[4-9][0-9])(?:[- ]?[0-9]{4}){3}|3(?:0[0-5]|[68][0-9])[0-9](?:[- ]?[0-9]{6})[- ]?[0-9]{4})\b/g;


    /**
     * Checks if a string contains sensitive information (API keys, tokens, or validated Credit Cards).
     */
    function isSensitive(data) {
        if (typeof data !== 'string' || data.length < 10) return false;
        try {
            // 1. Check generic secret patterns
            for (const pattern of SECRET_PATTERNS) {
                if (pattern.test(data)) {
                    return true;
                }
            }

            // 2. Check Credit Card with Luhn Validation
            // We use matchAll (if available) or exec loop to handle potential multiple CCs in a single string.

            if (typeof data.matchAll === 'function') {
                const ccMatches = data.matchAll(CC_REGEX);
                for (const match of ccMatches) {
                      // The regex ensures the format is correct, isValidLuhn ensures the math is correct
                    if (isValidLuhn(match[0])) {
                        return true;
                    }
                }
            } else {
                // Fallback for older environments
                CC_REGEX.lastIndex = 0; // Reset regex state before starting the search
                let match;
                while ((match = CC_REGEX.exec(data)) !== null) {
                    if (isValidLuhn(match[0])) {
                        return true;
                    }
                }
            }

        } catch (e) {
             reportShimError(e, "isSensitive execution failure");
        }
        return false;
    }

    // --- 3. CSTI Patterns ---
    const TEMPLATE_PATTERNS = [
        /\{\{.*\}\}/, // Angular, Vue, Mustache, etc.
        // Add more framework syntax if needed (e.g., <%= ... %>)
    ];

    function containsTemplateSyntax(data) {
        if (typeof data !== 'string') return false;
        try {
            for (const pattern of TEMPLATE_PATTERNS) {
                if (pattern.test(data)) {
                    return true;
                }
            }
        } catch (e) {
             reportShimError(e, "containsTemplateSyntax execution failure");
        }
        return false;
    }

   // --- 4. Dangling Markup Heuristics ---
    function looksLikeHTML(data) {
        if (typeof data !== 'string') return false;
        const strData = String(data);
        // Basic length heuristic: URLs shorter than 50 are unlikely to contain significant exfiltrated data.
        if (strData.length < 50) return false;

        try {
            // Check for common HTML tags or attributes often found in exfiltrated data
            if (strData.includes('<div') || strData.includes('<span') || strData.includes('<input') || strData.includes('token=')) {
                return true;
            }
            // Check for excessive newlines which often occur in dangling markup exfiltration
            if ((strData.match(/\n/g) || []).length > 5) {
                return true;
            }
        } catch (e) {
            reportShimError(e, "looksLikeHTML execution failure");
        }
        return false;
    }

    /**
     * ROBUSTNESS: Reports internal instrumentation errors back to the Go backend.
     */
    function reportShimError(error, location, stack = null) {
        const callback = ErrorCallback;
        if (typeof callback === 'function') {
            setTimeout(() => {
                // TEST-FIX: Check if the context is still valid before executing async callback.
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                const previousReportingState = isReporting;
                isReporting = true;

                try {
                    const errorStack = stack || (error instanceof Error ? error.stack : getStackTrace());
                    const report = Object.create(null);
                    report.error = String(error);
                    report.location = String(location);
                    report.stack = errorStack;

                    callback(report);
                } catch (e) {
                    logger.error("Failed to call backend error callback.", e);
                } finally {
                    isReporting = previousReportingState;
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
                return err.stack.split('\n').slice(3).join('\n');
            }
        } catch (e) {}
        return "Could not capture stack trace.";
    }

    /**
     * Captures the current page context (URL and Title).
     */
    function getPageContext() {
        let url = "N/A (Unknown Context)";
        let title = "N/A";

        if (!IS_WORKER) {
            try {
                if (scope.document && scope.document.location) {
                    url = scope.document.location.href;
                    title = scope.document.title || "N/A (Loading)";
                } else {
                    if (scope.location) {
                        url = scope.location.href;
                    } else {
                        url = "N/A (No Document or Location)";
                    }
                }
            } catch (e) {
                reportShimError(e, "getPageContext access error (Window)");
                url = "N/A (Security Exception)";
                title = "N/A (Security Exception)";
            }
        } else {
            try {
                if (scope.location) {
                    url = scope.location.href;
                }
                title = "N/A (Worker Context)";
            } catch (e) {
                reportShimError(e, "getPageContext access error (Worker)");
                url = "N/A (Security Exception - Worker)";
            }
        }
        return { url, title };
    }

    // #################################################################################################
    // #                                     Taint Detection & Reporting                               #
    // #################################################################################################

    /**
     * Checks if a value contains the canary prefix, indicating it's tainted.
     */
    function isTainted(value, depth = 0, seen = new WeakSet()) {
        const MAX_DEPTH = 4;

        if (depth > MAX_DEPTH) {
            return false;
        }

        if (typeof value === 'string') {
            return value.includes(CONFIG.CanaryPrefix);
        }

        if (typeof value !== 'object' || value === null) {
            return false;
        }

        // --- TEST-FIX START: Prevent deep inspection of Host Objects ---
        // Deep inspection of Host Objects (like DOM Nodes or the global scope itself)
        // can cause instability (crashes) in simulated environments like JSDOM/Jest
        // (e.g., Assertion failed: isolate_data) and is generally irrelevant for tracking application data taint.
        try {
            if (value === scope) {
                return false;
            }
            // Check if it's a DOM Node (only relevant in Window context)
            if (!IS_WORKER && typeof scope.Node !== 'undefined' && value instanceof scope.Node) {
                return false;
            }
        } catch (e) {
            // Ignore potential security exceptions during checks (e.g., cross-origin access)
        }
        // --- TEST-FIX END ---

        if (seen.has(value)) return false;
        seen.add(value);

        if (Array.isArray(value) ||
            (typeof scope.URLSearchParams !== 'undefined' && value instanceof scope.URLSearchParams) ||
            (typeof scope.FormData !== 'undefined' && value instanceof scope.FormData) ||
            (typeof scope.Set !== 'undefined' && value instanceof scope.Set) ||
            (typeof scope.Map !== 'undefined' && value instanceof scope.Map)) {

            const iterator = (typeof value.values === 'function') ? value.values() : value;
            for (const val of iterator) {
                if (isTainted(val, depth + 1, seen)) {
                    return true;
                }
            }
            return false;
        }

        if (typeof scope.Request !== 'undefined' && value instanceof scope.Request) {
            if (isTainted(value.url, depth + 1, seen)) {
                return true;
            }
        }

        try {
            const keys = Reflect.ownKeys(value);
            for (const key of keys) {
                try {
                    const propValue = value[key];
                    if (isTainted(propValue, depth + 1, seen)) {
                        return true;
                    }
                } catch (e) {}
            }
        } catch (e) {}
        return false;
    }


    /**
     * Reports a detected sink event to the Go backend.
     */
    function reportSink(type, value, detail) {
        const callback = SinkCallback;
        if (typeof callback === 'function') {
            const stack = getStackTrace();
            const context = getPageContext();

            setTimeout(() => {
                // TEST-FIX: Check if the context is still valid before executing async callback.
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                const previousReportingState = isReporting;
                isReporting = true;

                try {
                    let stringValue;
                    if (typeof scope.Request !== 'undefined' && value instanceof scope.Request) {
                        stringValue = value.url;
                    } else if (typeof value === 'object' && value !== null) {
                        try {
                            stringValue = JSON.stringify(value);
                        } catch (e) {
                            stringValue = String(value);
                        }
                    } else {
                        stringValue = String(value);
                    }

                    // Truncate excessively long values to prevent reporting overload
                    if (stringValue.length > 2048) {
                        stringValue = stringValue.substring(0, 2048) + "...(truncated)";
                    }

                    const report = Object.create(null);
                    report.type = type;
                    report.value = stringValue;
                    report.detail = detail;
                    report.stack = stack;
                    report.page_url = context.url;
                    report.page_title = context.title;

                    callback(report);
                    logger.warn(`Event detected: ${detail} (${type})`);

                } catch (e) {
                    reportShimError(e, "reportSink callback execution");
                } finally {
                    isReporting = previousReportingState;
                }
            }, 0);
        }
    }

    /**
     * VULN-FIX (Timing): Initializes the JavaScript wrapper function that payloads will call.
     * This wrapper captures the context (stack/URL) and then calls the actual Go backend handle.
     */
    function initializeExecutionProofCallback() {
        // VULN-FIX (Timing): Use the BackendProofCallback captured in the closure.
        const backendCallback = BackendProofCallback;
        
        if (typeof backendCallback !== 'function') {
            // Don't log error if in testing mode and callback is missing (might be intentional)
            if (!CONFIG.IsTesting) {
                 logger.error("Backend execution proof callback handle not exposed correctly.");
            }
            return;
        }

        // Define the JS wrapper on the global scope using the name payloads expect (CONFIG.ProofCallbackName).
        scope[CONFIG.ProofCallbackName] = function(canary) {
            const stack = getStackTrace();
            const context = getPageContext();

            const previousReportingState = isReporting;
            isReporting = true;

            try {
                logger.warn(`Execution Proof triggered! Canary: ${canary}`);

                const proof = Object.create(null);
                proof.canary = String(canary);
                proof.stack = stack;
                proof.page_url = context.url;
                proof.page_title = context.title;

                // Call the actual Go backend handle.
                backendCallback(proof);
            } catch (e) {
                reportShimError(e, "initializeExecutionProofCallback wrapper execution");
            } finally {
                isReporting = previousReportingState;
            }
        };
    }

    // #################################################################################################
    // #                                Taint Flow Instrumentation (Core)                              #
    // #################################################################################################

    function resolvePath(path, root = scope) {
        const parts = path.split('.');
        let current = root;
        const resolvedPath = [];

        for (const part of parts) {
            if (current === null || typeof current === 'undefined') {
                return null;
            }

            try {
                if (part in current) {
                    current = current[part];
                    resolvedPath.push(part);
                } else {
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
                    return null;
                }
            } catch (e) {
                reportShimError(e, `resolvePath access error: ${path} at ${part}`);
                return null;
            }
        }

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

    function createFunctionWrapper(originalFunction, sinkDef) {
        if (instrumentedCache.has(originalFunction)) {
            return originalFunction;
        }

        const wrapper = function(...args) {
            if (sinkDef.ConditionID) {
                const handler = ConditionHandlers[sinkDef.ConditionID];
                if (handler && !handler(args)) {
                    return originalFunction.apply(this, args);
                }
            }

            if (sinkDef.Name === 'fetch') {
                if (isTainted(args[0])) {
                    // Use the Type defined in the config, or fallback to FETCH_URL
                    const sinkType = sinkDef.Type || "FETCH_URL";
                    reportSink(sinkType, args[0], "fetch(url/request)");
                }
                if (args.length > 1 && args[1] && typeof args[1] === 'object' && args[1].body) {
                    if (isTainted(args[1].body)) {
                        reportSink("FETCH_BODY", args[1].body, "fetch(options.body)");
                    }
                }
            } else {
                const taintedArg = args[sinkDef.ArgIndex];
                if (isTainted(taintedArg)) {
                    const detail = `${sinkDef.Name}(arg${sinkDef.ArgIndex})`;
                    reportSink(sinkDef.Type, taintedArg, detail);
                }
            }
            return originalFunction.apply(this, args);
        };

        try {
            Object.setPrototypeOf(wrapper, Object.getPrototypeOf(originalFunction));
            wrapper.toString = function() { return originalFunction.toString(); };
            if (originalFunction.prototype) {
                wrapper.prototype = originalFunction.prototype;
            }
            Object.getOwnPropertyNames(originalFunction).forEach(prop => {
                if (!wrapper.hasOwnProperty(prop)) {
                    try {
                        Object.defineProperty(wrapper, prop, Object.getOwnPropertyDescriptor(originalFunction, prop));
                    } catch (e) {}
                }
            });
        } catch (e) {}

        instrumentedCache.add(wrapper);
        return wrapper;
    }

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

             try {
                Object.setPrototypeOf(wrappers.set, Object.getPrototypeOf(originalDescriptor.set));
                wrappers.set.toString = function() { return originalDescriptor.set.toString(); };
            } catch (e) {}

        } else if (originalDescriptor.writable) {
            logger.warn("Instrumenting writable data property without a native setter:", sinkDef.Name);
        }

        return wrappers;
    }

    function instrumentSink(sinkDef) {
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
            targetBase = scope;
        }

        if (!targetBase || (typeof targetBase !== 'object' && typeof targetBase !== 'function')) {
            logger.log("Skipping sink: Base object not found or invalid type.", sinkDef.Name);
            return;
        }

        const descriptor = Object.getOwnPropertyDescriptor(targetBase, propertyName);

        if (!descriptor) {
            logger.log("Skipping sink: Property descriptor not found on base object.", sinkDef.Name);
            return;
        }

        if (!descriptor.configurable) {
            logger.warn("Cannot instrument non-configurable property:", sinkDef.Name);
            return;
        }

        try {
            if (sinkDef.Setter) {
                const wrappers = createPropertyWrappers(descriptor, sinkDef);
                Object.defineProperty(targetBase, propertyName, wrappers);
                logger.log(`Instrumented property setter: ${sinkDef.Name}`);
            } else {
                const originalFunction = descriptor.value || (descriptor.get && descriptor.get.call(targetBase));

                if (typeof originalFunction === 'function') {
                    const wrapper = createFunctionWrapper(originalFunction, sinkDef);

                    if ('value' in descriptor) {
                        descriptor.value = wrapper;
                        Object.defineProperty(targetBase, propertyName, descriptor);
                    } else if ('get' in descriptor) {
                        Object.defineProperty(targetBase, propertyName, {
                            ...descriptor,
                            get: () => wrapper
                        });
                    } else {
                        logger.warn("Function found but descriptor structure unexpected (no value or get):", sinkDef.Name);
                    }

                    logger.log(`Instrumented function: ${sinkDef.Name}`);
                } else {
                    // Log if not testing, as mocks might temporarily replace functions during tests.
                    if (!CONFIG.IsTesting) {
                         logger.warn("Target is not a function, but sink definition expects it to be:", sinkDef.Name);
                    }
                }
            }
        } catch (error) {
            reportShimError(error, `instrumentSink failure: ${sinkDef.Name}`);
        }
    }

    // #################################################################################################
    // #                          Advanced Vulnerability Detection (New Features)                      #
    // #################################################################################################

function instrumentPostMessage() {
        // 1. Definitions & Setup
        // define scope based on environment
        const scope = typeof globalThis !== 'undefined' ? globalThis : window;
        
        // Ensure we have the maps (using scope for consistency across modules)
        if (!scope.instrumentedCache) scope.instrumentedCache = new Set();
        if (!scope.listenerWrapperMap) scope.listenerWrapperMap = new WeakMap();

        // Safety check for EventTarget
        if (!scope.EventTarget || !scope.EventTarget.prototype) return;

        const originalAddEventListener = scope.EventTarget.prototype.addEventListener;
        const originalRemoveEventListener = scope.EventTarget.prototype.removeEventListener;

        // Prevent double-instrumentation
        if (scope.instrumentedCache.has(originalAddEventListener)) return;

        // --- 2. The Robust Window Check (Crucial for JSDOM) ---
        const isGlobalWindow = (ctx) => {
            if (!ctx) return false;

            // Check 1: Direct equality (Standard browser behavior)
            if (ctx === scope) return true;

            try {
                // Check 2: JSDOM FIX (The crucial addition)
                // In JSDOM, 'ctx' (this) is often the internal WindowImpl.
                // WindowImpl.window points to the WindowProxy (scope).
                if (ctx.window === scope) return true;

                // Check 3: Standard circular reference fallback
                if (ctx.window === ctx) return true;
                
                // Check 4: Brittle JSDOM Check by constructor name (Fallback)
                if (ctx.constructor && ctx.constructor.name === 'Window' && !('nodeType' in ctx)) {
                    return true;
                }

                // Check 5: Standard Browser Check by toStringTag
                const toStringTag = Object.prototype.toString.call(ctx);
                if (toStringTag === '[object Window]' || toStringTag === '[object DOMWindow]') {
                    return true;
                }

                return false;
            } catch (e) {
                // Accessing ctx.window might throw in cross-origin scenarios (e.g. iframes)
                return false;
            }
        };

        // --- 3. Add Event Listener Wrapper ---
        const addWrapper = function(type, listener, options) {
            const isFunction = typeof listener === 'function';
            const isObjectHandler = typeof listener === 'object' && listener !== null && typeof listener.handleEvent === 'function';

            // Filter: Must be 'message' event, must be a function or object handler, must be on the Window
            if (type !== 'message' || (!isFunction && !isObjectHandler) || !isGlobalWindow(this)) {
                return originalAddEventListener.call(this, type, listener, options);
            }

            // Prevent double-wrapping
            if (scope.listenerWrapperMap.has(listener)) {
                const existingWrapper = scope.listenerWrapperMap.get(listener);
                return originalAddEventListener.call(this, type, existingWrapper, options);
            }

            const wrappedListener = function(event) {
                let originAccessed = false;
                
                // Proxy the event to detect property access
                const eventProxy = new Proxy(event, {
                    get(target, prop, receiver) {
                        if (prop === 'origin') originAccessed = true;
                        return Reflect.get(target, prop, receiver);
                    }
                });

                try {
                    // Execute the original listener with the proxied event
                    if (isFunction) {
                        listener.call(this, eventProxy);
                    } else {
                        listener.handleEvent(eventProxy);
                    }
                } catch (e) {
                    throw e;
                } finally {
                    // Post-execution check
                    if (!originAccessed) {
                        const val = (event && event.origin) ? event.origin : "N/A";
                        
                        // FIX: Call the internal reportSink closure directly.
                        // This handles the async scheduling and uses the correct SinkCallback (mockSinkCallback).
                        reportSink(
                            "POSTMESSAGE_MISSING_ORIGIN_CHECK", 
                            val, 
                            "postMessage listener missing check for event.origin"
                        );
                    }
                }
            };

            scope.listenerWrapperMap.set(listener, wrappedListener);
            return originalAddEventListener.call(this, type, wrappedListener, options);
        };

        // --- 4. Remove Event Listener Wrapper ---
        const removeWrapper = function(type, listener, options) {
            const isFunction = typeof listener === 'function';
            const isObjectHandler = typeof listener === 'object' && listener !== null && typeof listener.handleEvent === 'function';

            if (type === 'message' && (isFunction || isObjectHandler) && isGlobalWindow(this)) {
                if (scope.listenerWrapperMap.has(listener)) {
                    const wrappedListener = scope.listenerWrapperMap.get(listener);
                    return originalRemoveEventListener.call(this, type, wrappedListener, options);
                }
            }
            return originalRemoveEventListener.call(this, type, listener, options);
        };

        // --- 5. Apply Overrides ---
        // We modify the prototype so all future instances (and current ones) are affected
        scope.EventTarget.prototype.addEventListener = addWrapper;
        scope.EventTarget.prototype.removeEventListener = removeWrapper;

        // Register cleanup for EventTarget.prototype modifications
        cleanupFunctions.push(() => {
             try {
                if (scope.EventTarget.prototype.addEventListener === addWrapper) {
                    scope.EventTarget.prototype.addEventListener = originalAddEventListener;
                }
                if (scope.EventTarget.prototype.removeEventListener === removeWrapper) {
                    scope.EventTarget.prototype.removeEventListener = originalRemoveEventListener;
                }
             } catch(e) {
                 logger.error("Error restoring EventTarget.prototype listeners:", e);
             }
        });

        // JSDOM/Environment FIX: Ensure window.addEventListener is also updated if it did not inherit the change.
        // This check detects if window has its own property that masks the prototype, OR if inheritance failed.
        if (scope.addEventListener !== addWrapper) {
            const originalWindowAddEvent = scope.addEventListener;
            const originalWindowRemoveEvent = scope.removeEventListener;

            try {
                Object.defineProperty(scope, 'addEventListener', {
                    value: addWrapper,
                    writable: true,
                    configurable: true
                });
                Object.defineProperty(scope, 'removeEventListener', {
                    value: removeWrapper,
                    writable: true,
                    configurable: true
                });

                // Register cleanup to restore window-specific methods
                cleanupFunctions.push(() => {
                    try {
                        if (scope.addEventListener === addWrapper && originalWindowAddEvent) {
                             Object.defineProperty(scope, 'addEventListener', {
                                value: originalWindowAddEvent,
                                writable: true,
                                configurable: true
                             });
                        }
                        if (scope.removeEventListener === removeWrapper && originalWindowRemoveEvent) {
                             Object.defineProperty(scope, 'removeEventListener', {
                                value: originalWindowRemoveEvent,
                                writable: true,
                                configurable: true
                             });
                        }
                    } catch (e) {
                        logger.error("Error restoring window.addEventListener during cleanup:", e);
                    }
                });

            } catch (e) {
                // Ignore if we can't redefine (e.g. non-configurable)
            }
        }

        // Mark as instrumented
        scope.instrumentedCache.add(originalAddEventListener);
        scope.instrumentedCache.add(originalRemoveEventListener);
    }
    
    // --- 2. Sensitive Data Leaking (Storage Inspector) (UPDATED) ---
    function instrumentStorage() {
        // Storage APIs are generally not available in Service Workers.
        if (IS_WORKER || !scope.Storage || !scope.Storage.prototype.setItem) return;

        const originalSetItem = scope.Storage.prototype.setItem;

        // Check if already instrumented
        if (instrumentedCache.has(originalSetItem)) return;

        try {
            const wrapper = function(key, value) {
                let sensitiveFoundInKey = false;
                // Storage APIs convert keys and values to strings.
                const strKey = String(key);
                const strValue = String(value);

                // Check for sensitive data using the updated isSensitive (includes Luhn validation for CCs)
                if (isSensitive(strKey)) {
                    // The type SENSITIVE_STORAGE_WRITE is handled specifically by the backend analyzer.
                    reportSink("SENSITIVE_STORAGE_WRITE", strKey, "Sensitive pattern detected in storage key");
                    sensitiveFoundInKey = true;
                }
                if (isSensitive(strValue)) {
                    // Avoid duplicate reports if key and value are the same and both sensitive
                    if (!sensitiveFoundInKey || strKey !== strValue) {
                         reportSink("SENSITIVE_STORAGE_WRITE", strValue, "Sensitive pattern detected in storage value");
                    }
                }

                return originalSetItem.call(this, key, value);
            };

             try {
                Object.setPrototypeOf(wrapper, Object.getPrototypeOf(originalSetItem));
                wrapper.toString = function() { return originalSetItem.toString(); };
            } catch (e) {}

            // Apply wrapper to the Storage prototype (affects both localStorage and sessionStorage)
            scope.Storage.prototype.setItem = wrapper;
            instrumentedCache.add(originalSetItem);

            // TEST-FIX: Add cleanup function
            cleanupFunctions.push(() => {
                if (scope.Storage && scope.Storage.prototype && scope.Storage.prototype.setItem === wrapper) {
                    scope.Storage.prototype.setItem = originalSetItem;
                }
            });

            logger.log("Instrumented Storage.setItem for sensitive data leakage.");

        } catch (e) {
            reportShimError(e, "instrumentStorage failure");
        }
    }

    // --- 3. Client-Side Template Injection (CSTI) / Framework Gadgets ---

    /**
     * JSDOM-FIX (Issues 2 & 3): Helper function to recursively check a node for CSTI patterns,
     * while handling JSDOM race conditions for attributes.
     * @param {Node} node - The DOM node to check.
     * @param {WeakMap<Element, Set<string>> | null} subsequentlyModifiedAttributes - Map of attributes to ignore.
     */
    function checkNodeForCSTI(node, subsequentlyModifiedAttributes = null) {
        // 1. Check Text Content (Issue 2: Ensure traversal reaches text nodes)
        if (node.nodeType === Node.TEXT_NODE) {
            if (isTainted(node.textContent) && containsTemplateSyntax(node.textContent)) {
                // Use a generic detail message covering both direct addition and element traversal.
                reportSink("FRAMEWORK_INJECTION", node.textContent, "Tainted template syntax injected into DOM (Text Node/Element)");
            }
        }
        // 2. Check Attributes and Recurse
        else if (node.nodeType === Node.ELEMENT_NODE) {
            // Check attributes on the element itself
            if (node.attributes) {
                const ignoredAttributes = subsequentlyModifiedAttributes && subsequentlyModifiedAttributes.get(node);

                for (const attr of node.attributes) {
                    // JSDOM-FIX (Issue 3): Skip attributes that were modified later in the same mutation batch.
                    // These will be handled by the 'attributes' mutation handler, preventing duplicates/misclassification.
                    if (ignoredAttributes && ignoredAttributes.has(attr.name)) {
                        continue;
                    }

                    if (isTainted(attr.value) && containsTemplateSyntax(attr.value)) {
                        // Clarify that this report is for the initial state of the attribute upon element addition.
                        reportSink("FRAMEWORK_INJECTION", attr.value, `Tainted template syntax injected into DOM (Attribute Initial: ${attr.name})`);
                    }
                }
            }
            // Recurse into children (Issue 2)
            if (node.childNodes) {
                // Pass the map down during recursion
                // Use Array.from for safety if iterating over a live NodeList during callbacks.
                try {
                    Array.from(node.childNodes).forEach(child => checkNodeForCSTI(child, subsequentlyModifiedAttributes));
                } catch (e) {
                    reportShimError(e, "checkNodeForCSTI recursion failure");
                }
            }
        }
    }


    function monitorCSTI() {
        if (IS_WORKER || !scope.MutationObserver || !scope.document) return;

        // We use a general MutationObserver approach to detect the outcome (injection into DOM), 
        // as framework-specific hooks (like Vue.compile) are often brittle across versions.

        try {
            const cstiObserver = new scope.MutationObserver((mutations) => {
                // TEST-FIX: Prevent execution if the context is being torn down
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                try {
                    // JSDOM-FIX (Issue 3): Pre-process mutations to handle race conditions.
                    // Identify attributes modified subsequently in the same batch to avoid reporting them during childList processing.
                    const subsequentlyModifiedAttributes = new WeakMap();
                    let hasChildList = false;

                    // Optimization: Only run this logic if necessary (requires WeakMap and Set)
                    if (scope.WeakMap && scope.Set) {
                        try {
                            for (const mutation of mutations) {
                                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                                    hasChildList = true;
                                } else if (mutation.type === 'attributes' && hasChildList) {
                                    // If we are processing an attribute mutation AND there was a preceding childList in this batch.
                                    const target = mutation.target;
                                    if (!subsequentlyModifiedAttributes.has(target)) {
                                        subsequentlyModifiedAttributes.set(target, new Set());
                                    }
                                    subsequentlyModifiedAttributes.get(target).add(mutation.attributeName);
                                }
                            }
                        } catch (e) {
                            reportShimError(e, "monitorCSTI mutation pre-processing failure");
                        }
                    }

                    for (const mutation of mutations) {
                        if (mutation.type === 'childList') {
                            // JSDOM-FIX (Issue 2): Use recursive checker for deep inspection.
                            // JSDOM-FIX (Issue 3): Pass the map of ignored attributes.
                            mutation.addedNodes.forEach(node => {
                                checkNodeForCSTI(node, subsequentlyModifiedAttributes);
                            });
                        } else if (mutation.type === 'characterData') {
                             // Check changes to existing text nodes
                            if (isTainted(mutation.target.textContent) && containsTemplateSyntax(mutation.target.textContent)) {
                                reportSink("FRAMEWORK_INJECTION", mutation.target.textContent, "Tainted template syntax injected into DOM (Character Data Mutation)");
                            }
                        }
                        else if (mutation.type === 'attributes') {
                            // Check changes to attributes on existing elements
                            // This correctly handles the attributes skipped by checkNodeForCSTI due to the race condition fix.
                            const attrValue = mutation.target.getAttribute(mutation.attributeName);
                            if (isTainted(attrValue) && containsTemplateSyntax(attrValue)) {
                                 reportSink("FRAMEWORK_INJECTION", attrValue, `Tainted template syntax injected into DOM (Attribute Mutation: ${mutation.attributeName})`);
                            }
                        }
                    }
                } catch (e) {
                    reportShimError(e, "monitorCSTI observer callback execution");
                }
            });

            const observe = () => {
                // TEST-FIX: Stop recursive observation attempts if context is torn down
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                if (scope.document && scope.document.documentElement) {
                    cstiObserver.observe(scope.document.documentElement, {
                        childList: true,
                        subtree: true,
                        attributes: true,
                        characterData: true,
                    });
                    logger.log("CSTI (Client-Side Template Injection) monitor initialized.");
                } else {
                    setTimeout(observe, 50);
                }
            };
            observe();

            // TEST-FIX: Store observer for cleanup
            scope.__SCALPEL_CSTI_OBSERVER__ = cstiObserver;

        } catch (e) {
            reportShimError(e, "monitorCSTI initialization");
        }
    }

    // --- 4. Dangling Markup Detection (Data Exfiltration) ---
    
    function instrumentNetworkForDanglingMarkup() {
        // 4.1 Hook Image (via HTMLImageElement.prototype.src)
        if (!IS_WORKER && typeof scope.HTMLImageElement !== 'undefined') {
            try {
                const imgProto = scope.HTMLImageElement.prototype;
                const descriptor = Object.getOwnPropertyDescriptor(imgProto, 'src');

                if (descriptor && descriptor.set && descriptor.configurable) {
                    // Check if already instrumented by this instance
                    if (instrumentedCache.has(descriptor.set)) return;

                    const originalSet = descriptor.set;

                    const wrapper = function(value) {
                        if (looksLikeHTML(value)) {
                            reportSink("DANGLING_MARKUP_EXFILTRATION", String(value), "Image.src contains potential raw HTML (Dangling Markup)");
                        }
                        return originalSet.call(this, value);
                    };

                    try {
                        Object.setPrototypeOf(wrapper, Object.getPrototypeOf(originalSet));
                        wrapper.toString = function() { return originalSet.toString(); };
                    } catch (e) {}

                    Object.defineProperty(imgProto, 'src', {
                        ...descriptor,
                        set: wrapper
                    });
                    instrumentedCache.add(descriptor.set);

                    // TEST-FIX: Add cleanup function
                    cleanupFunctions.push(() => {
                        try {
                            const currentDescriptor = Object.getOwnPropertyDescriptor(imgProto, 'src');
                            if (currentDescriptor && currentDescriptor.set === wrapper) {
                                Object.defineProperty(imgProto, 'src', descriptor);
                            }
                        } catch (e) {
                            logger.error("Error restoring Image.src during cleanup:", e);
                        }
                    });

                    logger.log("Instrumented HTMLImageElement.prototype.src for Dangling Markup detection.");
                }
            } catch (e) {
                reportShimError(e, "instrumentNetworkForDanglingMarkup (Image) failure");
            }
        }

        // 4.2 Hook XMLHttpRequest.open
        if (scope.XMLHttpRequest && scope.XMLHttpRequest.prototype && scope.XMLHttpRequest.prototype.open) {
            const originalOpen = scope.XMLHttpRequest.prototype.open;

            // Check if already instrumented
            if (instrumentedCache.has(originalOpen)) return;

            try {
                const wrapper = function(method, url, async, user, password) {
                    if (looksLikeHTML(url)) {
                        reportSink("DANGLING_MARKUP_EXFILTRATION", String(url), "XHR.open URL contains potential raw HTML (Dangling Markup)");
                    }
                    return originalOpen.apply(this, arguments);
                };

                 try {
                    Object.setPrototypeOf(wrapper, Object.getPrototypeOf(originalOpen));
                    wrapper.toString = function() { return originalOpen.toString(); };
                } catch (e) {}

                scope.XMLHttpRequest.prototype.open = wrapper;
                instrumentedCache.add(originalOpen);

                // TEST-FIX: Add cleanup function
                cleanupFunctions.push(() => {
                    if (scope.XMLHttpRequest && scope.XMLHttpRequest.prototype && scope.XMLHttpRequest.prototype.open === wrapper) {
                        scope.XMLHttpRequest.prototype.open = originalOpen;
                    }
                });

                logger.log("Instrumented XMLHttpRequest.open for Dangling Markup detection.");

            } catch (e) {
                reportShimError(e, "instrumentNetworkForDanglingMarkup (XHR) failure");
            }
        }

        // 4.3 Hook Fetch (integrated into instrumentFetchAdvanced below)
    }


    // --- 5. Base Tag Hijacking ---
    function monitorBaseTagHijacking() {
        if (IS_WORKER || !scope.MutationObserver || !scope.document) return;

        try {
            const baseTagObserver = new scope.MutationObserver((mutations) => {
                // TEST-FIX: Prevent execution if the context is being torn down
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;
                try {
                    for (const mutation of mutations) {
                        if (mutation.type === 'childList') {
                            mutation.addedNodes.forEach(node => {
                                // Check if the added node is a <base> tag
                                if (node.nodeName === 'BASE') {
                                    const href = node.getAttribute('href') || 'N/A (No href)';
                                    reportSink("BASE_TAG_HIJACK", href, "Dynamic injection of <base> tag detected.");
                                }
                            });
                        }
                    }
                } catch (e) {
                     reportShimError(e, "monitorBaseTagHijacking observer callback execution");
                }
            });

            const observeHead = () => {
                // TEST-FIX: Stop recursive observation attempts if context is torn down
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                // document.head might not be available immediately if the script loads early
                if (scope.document && scope.document.head) {
                    baseTagObserver.observe(scope.document.head, {
                        childList: true,
                        subtree: false // Only monitor direct children of <head>
                    });
                    logger.log("Base Tag Hijacking monitor initialized.");
                } else {
                    setTimeout(observeHead, 50);
                }
            };
            observeHead();

            // TEST-FIX: Store observer for cleanup
            scope.__SCALPEL_BASE_TAG_OBSERVER__ = baseTagObserver;

        } catch (e) {
            reportShimError(e, "monitorBaseTagHijacking initialization");
        }
    }


    // #################################################################################################
    // #                     Prototype Pollution & DOM Clobbering (Merged Features)                    #
    // #################################################################################################

    function checkForPollutionPatterns(data, source) {
        if (typeof data !== 'string' || data.length < 10) return;
        if (!data.includes('__proto__') && !data.includes('constructor')) {
            return;
        }

        let foundVector = null;

        try {
            JSON.parse(data, function(key, value) {
                if (foundVector) return value;

                if (key === '__proto__') {
                    foundVector = '__proto__';
                } else if (key === 'constructor' && value && typeof value === 'object') {
                   try {
                        if (Object.prototype.hasOwnProperty.call(value, 'prototype')) {
                            foundVector = 'constructor.prototype';
                        }
                   } catch (e) {}
                }
                return value;
            });

            if (foundVector) {
                reportSink("POTENTIAL_PP_VECTOR", foundVector, `${source}_JSON_payload`);
            }
        } catch (e) {}
    }

    // VULN-FIX: Combines PP detection and Dangling Markup detection for Fetch.
    function instrumentFetchAdvanced() {
        if (!scope.fetch) return;
        // Use the potentially already instrumented fetch (e.g., by Taint Flow wrapper)
        const originalFetch = scope.fetch;
        
        // Check if this specific advanced wrapper has already been applied by this shim instance
        // We use a specific flag here because instrumentedCache might contain the wrapper from instrumentSink,
        // but we want to ensure the advanced logic is applied exactly once.
        if (originalFetch.__SCALPEL_ADVANCED_INSTRUMENTED__) return;

        const wrapper = function(...args) {
            // --- 4. Dangling Markup Check ---
            try {
                let url = "";
                if (typeof args[0] === 'string') {
                    url = args[0];
                } else if (typeof scope.Request !== 'undefined' && args[0] instanceof scope.Request) {
                    url = args[0].url;
                }

                if (looksLikeHTML(url)) {
                    reportSink("DANGLING_MARKUP_EXFILTRATION", String(url), "Fetch URL contains potential raw HTML (Dangling Markup)");
                }
            } catch (e) {
                reportShimError(e, "instrumentFetchAdvanced dangling markup check failure");
            }

            // --- Prototype Pollution Check (Existing Logic) ---
            return originalFetch.apply(this, args).then(response => {
                // TEST-FIX: Ensure context is still valid during async processing
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                try {
                    if (typeof scope.Response !== 'undefined' && response instanceof scope.Response) {
                        // FIX: Case-insensitive check for Content-Type.
                        const contentType = 
                            response.headers.get('Content-Type') || 
                            response.headers.get('content-type');

                        if (contentType && contentType.includes('application/json')) {
                            const clonedResponse = response.clone();
                            clonedResponse.text().then(data => {
                                // TEST-FIX: Final check before reporting
                                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;
                                checkForPollutionPatterns(data, 'Fetch_Response');
                            }).catch(e => {});
                        }
                    }
                } catch (e) {
                    reportShimError(e, "instrumentFetchAdvanced response processing");
                }
                return response;
            }).catch(error => {
                throw error;
            });
        };

         try {
            Object.setPrototypeOf(wrapper, Object.getPrototypeOf(originalFetch));
            wrapper.toString = function() { return originalFetch.toString(); };
             Object.getOwnPropertyNames(originalFetch).forEach(prop => {
                if (!wrapper.hasOwnProperty(prop)) {
                    try {
                        Object.defineProperty(wrapper, prop, Object.getOwnPropertyDescriptor(originalFetch, prop));
                    } catch (e) {}
                }
            });
        } catch (e) {}

        wrapper.__SCALPEL_ADVANCED_INSTRUMENTED__ = true;
        scope.fetch = wrapper;

        // TEST-FIX: Add cleanup function.
        cleanupFunctions.push(() => {
            if (scope.fetch === wrapper) {
                scope.fetch = originalFetch;
            }
        });

        logger.log("Instrumented Fetch for PP vectors and Dangling Markup.");
    }

    function instrumentXHRForPP() {
        if (!scope.XMLHttpRequest || !scope.XMLHttpRequest.prototype) return;
        const XHRProto = scope.XMLHttpRequest.prototype;
        // Use the current XHRProto.send, which might already be instrumented by other tools.
        const originalSend = XHRProto.send;

        // Check if already instrumented by this specific wrapper
        if (originalSend.__SCALPEL_PP_INSTRUMENTED__) return;

        const wrapper = function(...args) {
            try {
                // We must use the addEventListener present on the instance, which might be the native one or another wrapper.
                const instanceAddEventListener = this.addEventListener;
                
                if (typeof instanceAddEventListener === 'function') {
                    instanceAddEventListener.call(this, 'load', function() {
                        // TEST-FIX: Ensure context is still valid when the load event fires
                        if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                        if (this.readyState === 4 && this.status >= 200 && this.status < 400) {
                            try {
                                const contentType = this.getResponseHeader('Content-Type');
                                if ((this.responseType === "" || this.responseType === "text") && contentType && contentType.includes('application/json')) {
                                    if (this.responseText) {
                                        checkForPollutionPatterns(this.responseText, 'XHR_Response');
                                    }
                                }
                            } catch (e) {}
                        }
                    });
                }
            } catch (e) {
                reportShimError(e, "instrumentXHRForPP event listener setup");
            }
            return originalSend.apply(this, args);
        };

         try {
            Object.setPrototypeOf(wrapper, Object.getPrototypeOf(originalSend));
            wrapper.toString = function() { return originalSend.toString(); };
        } catch (e) {}

        wrapper.__SCALPEL_PP_INSTRUMENTED__ = true;

        try {
            XHRProto.send = wrapper;

            // TEST-FIX: Add cleanup function
            cleanupFunctions.push(() => {
                if (scope.XMLHttpRequest && scope.XMLHttpRequest.prototype && scope.XMLHttpRequest.prototype.send === wrapper) {
                    scope.XMLHttpRequest.prototype.send = originalSend;
                }
            });

            logger.log("Instrumented XHR.send for PP vectors.");
        } catch (error) {
            reportShimError(error, "instrumentXHRForPP application failure");
        }
    }

    // --- 2. Prototype Access Trap (Usage Detection) & Write Detection ---

    function setupPrototypeAccessTrap() {
        const propertyName = CONFIG.PollutionCheckProperty;
        try {
            const existingDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, propertyName);
            // Check if the existing trap belongs to this specific shim instance (using the symbol identity)
            if (existingDescriptor && existingDescriptor.get && existingDescriptor.get[PP_TRAP_IDENTIFIER]) {
                logger.log("Prototype Access Trap already set up by this instance.");
                return;
            }

            if (Object.prototype.hasOwnProperty(propertyName)) {
                // If it exists but isn't our trap, it might be pollution or another tool.
                logger.warn("Prototype property existed before trap setup. Running immediate check.");
                checkPrototypePollution();
                // We return here because checkPrototypePollution will attempt to clean up and re-call setupPrototypeAccessTrap if successful.
                return;
            }

            const trapGetter = function() {
                // TEST-FIX: If the context is dead, accessing 'this' or global scope can crash V8.
                // We rely on the instrumentation flag as a heuristic for context validity.
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) {
                    return 'scalpel_trap_activated_zombie_context';
                }

                if (isReporting) {
                    return 'scalpel_trap_activated_ignored';
                }

                if (this === null || typeof this === 'undefined' || (typeof this !== 'object' && typeof this !== 'function')) {
                    return 'scalpel_trap_activated_benign';
                }

                let isGlobal = false;
                if (this === scope) {
                    isGlobal = true;
                } 
                
                if (!isGlobal) {
                    try {
                        const type = Object.prototype.toString.call(this);
                        if (type === '[object Window]' || type === '[object WorkerGlobalScope]') {
                            isGlobal = true;
                        }
                    } catch (e) {}
                }

                if (!isGlobal) {
                    try {
                        if (IS_WORKER) {
                            if (typeof this.self !== 'undefined' && this.self === this) {
                                isGlobal = true;
                            }
                        } else {
                            if (
                                (typeof this.window !== 'undefined' && this.window === this) ||
                                (typeof this.self !== 'undefined' && this.self === this)
                               ) {
                                isGlobal = true;
                            }
                        }
                    } catch (e) {}
                }
                
                if (!isGlobal) {
                    reportSink("PROTOTYPE_POLLUTION_ACCESS", propertyName, "Access to polluted Object.prototype property detected");
                }
                return 'scalpel_trap_activated';
            };

            const trapSetter = function(value) {
                // TEST-FIX: Check context validity
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                try {
                    Object.defineProperty(Object.prototype, propertyName, {
                        value: value,
                        writable: true,
                        configurable: true,
                        enumerable: true
                    });
                    setTimeout(checkPrototypePollution, 0);
                } catch (e) {
                    reportShimError(e, "setupPrototypeAccessTrap setter redefine failure");
                }
            };

            trapGetter[PP_TRAP_IDENTIFIER] = true;
            trapSetter[PP_TRAP_IDENTIFIER] = true;

            Object.defineProperty(Object.prototype, propertyName, {
                get: trapGetter,
                set: trapSetter,
                configurable: true,
                enumerable: false
            });
            logger.log(`Setup Prototype Access/Write Trap on property: ${propertyName}`);
        } catch (e) {
            reportShimError(e, "setupPrototypeAccessTrap failure");
        }
    }

    // --- 3. DOM Clobbering Monitor ---

    function monitorDOMClobbering() {
        if (IS_WORKER || !scope.MutationObserver || !scope.document) return;

        const propertyName = CONFIG.PollutionCheckProperty;

        const checkClobbering = () => {
            // TEST-FIX: Prevent execution if the context is being torn down
            if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

            try {
                if (Object.prototype.hasOwnProperty.call(scope, propertyName)) {
                    const value = scope[propertyName];
                    if ((typeof scope.Element !== 'undefined' && value instanceof scope.Element) ||
                        (typeof scope.HTMLCollection !== 'undefined' && value instanceof scope.HTMLCollection && value.length > 0)) {

                        const detail = (typeof scope.HTMLCollection !== 'undefined' && value instanceof scope.HTMLCollection) ? "HTMLCollection" : `Element <${value.tagName}>`;
                        reportSink("DOM_CLOBBERING", propertyName, `Global variable clobbered by ${detail}`);
                    }
                }
            } catch (e) {
                reportShimError(e, "monitorDOMClobbering checkClobbering execution");
            }
        };

        try {
            const domObserver = new scope.MutationObserver(checkClobbering);

            const observe = () => {
                // TEST-FIX: Stop recursive observation attempts if context is torn down
                if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

                if (scope.document && scope.document.documentElement) {
                    domObserver.observe(scope.document.documentElement, {
                        childList: true,
                        subtree: true,
                        attributes: true,
                        attributeFilter: ['id', 'name']
                    });
                    checkClobbering();
                    logger.log("DOM Clobbering monitor initialized.");
                } else {
                    setTimeout(observe, 50);
                }
            };
            observe();

            // TEST-FIX: Store observer for cleanup
            scope.__SCALPEL_CLOBBERING_OBSERVER__ = domObserver;

        } catch (e) {
            reportShimError(e, "monitorDOMClobbering initialization");
        }
    }

    // --- 4. Active Pollution Confirmation (Write Detection Logic) ---

    function checkPrototypePollution() {
        // TEST-FIX: Crucial check for intervals/timeouts to prevent execution in dead contexts.
        if (!scope.__SCALPEL_TAINT_INSTRUMENTED__) return;

        try {
            const propertyName = CONFIG.PollutionCheckProperty;

            if (Object.prototype.hasOwnProperty(propertyName)) {
                const descriptor = Object.getOwnPropertyDescriptor(Object.prototype, propertyName);

                // ROBUSTNESS: Use the current global symbol (which points to the symbol of the active shim instance)
                // to check if the property is still our trap.
                const currentTrapSymbol = scope.__SCALPEL_PP_SYMBOL__ || PP_TRAP_IDENTIFIER;

                if (descriptor && (
                        (descriptor.get && descriptor.get[currentTrapSymbol]) ||
                        (descriptor.set && descriptor.set[currentTrapSymbol])
                    )) {
                    return;
                }

                let pollutedValue;
                try {
                    pollutedValue = Object.prototype[propertyName];
                } catch (e) {
                    reportShimError(e, "checkPrototypePollution value access failure");
                    return;
                }

                if (isTainted(pollutedValue)) {
                    logger.warn("Prototype Pollution Detected (Write Confirmation)!", pollutedValue);
                    reportSink("PROTOTYPE_POLLUTION", pollutedValue, propertyName);

                    try {
                        delete Object.prototype[propertyName];
                        setupPrototypeAccessTrap();
                    } catch (cleanupError) {
                        reportShimError(cleanupError, "checkPrototypePollution cleanup/re-arm failure");
                    }
                }
            }
        } catch (error) {
            reportShimError(error, "checkPrototypePollution execution failure");
        }
    }

    // #################################################################################################
    // #                                          Initialization                                       #
    // #################################################################################################

    function initialize() {
        logger.log("Initializing Taint Analysis Shim...");

        // Note: Cleanup of the previous instance is now handled at the very top of the script.

        initializeExecutionProofCallback();

        // 1. Core Taint Flow Instrumentation
        
        // Capture originals before Core Taint Flow instrumentation for reliable cleanup registration later.
        const originalFetch = scope.fetch;
        const originalXHRProto = (scope.XMLHttpRequest && scope.XMLHttpRequest.prototype) ? scope.XMLHttpRequest.prototype : null;
        const originalXHROpen = originalXHRProto ? originalXHRProto.open : null;
        const originalXHRSend = originalXHRProto ? originalXHRProto.send : null;
        
        const groupedSinks = Object.create(null);
        if (Array.isArray(CONFIG.Sinks)) {
            CONFIG.Sinks.forEach(sink => {
                if (!groupedSinks[sink.Name]) {
                    groupedSinks[sink.Name] = sink;
                }
            });
            Object.values(groupedSinks).forEach(instrumentSink);
        } else if (!CONFIG.IsTesting) {
             logger.error("CONFIG.Sinks is invalid or missing. Core Taint Flow disabled.");
        }
       

        // 2. Advanced Network Instrumentation (PP, Dangling Markup)
        // Note: Initialization order matters. Advanced wrappers wrap the functions potentially already wrapped by instrumentSink.
        // The cleanupFunctions registration within these ensures proper unwrapping.
        instrumentFetchAdvanced(); // Handles PP and Dangling Markup for Fetch
        instrumentXHRForPP();      // Handles PP for XHR.send
        instrumentNetworkForDanglingMarkup(); // Handles Dangling Markup for Image.src and XHR.open

        // 3. Prototype Pollution (Traps)
        setupPrototypeAccessTrap();
        
        // 4. Advanced Vulnerability Detection (API Hooks & Observers)
        instrumentPostMessage();
        instrumentStorage();
        monitorCSTI();
        monitorBaseTagHijacking();
        monitorDOMClobbering();

        // 5. Periodic Checks (PP Write confirmation)
        // The interval callback (checkPrototypePollution) now checks context validity.
        const pollutionCheckInterval = setInterval(checkPrototypePollution, 500);
        
        // TEST-FIX: Store the interval ID on the scope so it can be cleared on cleanup.
        scope.__SCALPEL_POLLUTION_CHECK_INTERVAL__ = pollutionCheckInterval;

        setTimeout(() => {
            // Check if this specific interval is still the active one before clearing
            if (scope.__SCALPEL_POLLUTION_CHECK_INTERVAL__ === pollutionCheckInterval) {
                 clearInterval(pollutionCheckInterval);
                 scope.__SCALPEL_POLLUTION_CHECK_INTERVAL__ = null;
                 logger.log("Stopped periodic Prototype Pollution checks.");
            }
        }, 30000);

        // 6. Event-based Checks
        // Use the native window.addEventListener here (EventTarget.prototype is instrumented by postMessage logic,
        // but 'load'/'DOMContentLoaded' are unrelated).
        if (!IS_WORKER && window.addEventListener) {
            // TEST-FIX: Capture listeners so they can be removed during cleanup to prevent JSDOM crashes.
            const loadListener = () => checkPrototypePollution();
            const domContentLoadedListener = () => checkPrototypePollution();

            window.addEventListener('load', loadListener);
            window.addEventListener('DOMContentLoaded', domContentLoadedListener);

            // Store cleanup actions
            cleanupFunctions.push(() => {
                if (window.removeEventListener) {
                    window.removeEventListener('load', loadListener);
                    window.removeEventListener('DOMContentLoaded', domContentLoadedListener);
                }
            });
        }

        logger.log("Taint Analysis Shim initialized.");
    }

    initialize();

    // Expose internals for unit testing
    if (CONFIG.IsTesting) {
        const internals = Object.create(null);
        internals.isTainted = isTainted;
        internals.resolvePath = resolvePath;
        internals.CONFIG = CONFIG;
        internals.ConditionHandlers = ConditionHandlers;
        internals.getStackTrace = getStackTrace;
        internals.getPageContext = getPageContext;
        internals.checkForPollutionPatterns = checkForPollutionPatterns;
        internals.checkPrototypePollution = checkPrototypePollution;
        internals.PP_TRAP_IDENTIFIER = PP_TRAP_IDENTIFIER;
        // NEW: Expose utilities for testing
        internals.isSensitive = isSensitive;
        internals.isValidLuhn = isValidLuhn; // Expose the new validator
        internals.CC_REGEX = CC_REGEX;       // Expose the comprehensive regex
        internals.containsTemplateSyntax = containsTemplateSyntax;
        internals.looksLikeHTML = looksLikeHTML;
        // TEST-FIX: Expose the cleanup function
        internals.cleanup = cleanup;
        // Expose CSTI helper for specific tests (optional)
        internals.checkNodeForCSTI = checkNodeForCSTI;

        scope.__SCALPEL_INTERNALS__ = internals;
    }

})(self);