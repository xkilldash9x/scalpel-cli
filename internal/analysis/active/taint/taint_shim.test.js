// internal/analysis/active/taint/taint_shim.test.js
/** @testEnvironment jsdom */

const fs = require('fs');
const path = require('path');

// --- Test Constants ---
// Mocked Go template variables
const MOCK_CONFIG = {
    SinkCallbackName: "__scalpel_sink_event",
    ProofCallbackName: "__scalpel_execution_proof",
    ErrorCallbackName: "__scalpel_shim_error",
    IsTesting: "true" // Enable testing mode to expose internals
};

// This MUST match the canary prefix in your shim's CONFIG
const TAINT_PREFIX = 'SCALPEL';
// A sample tainted string for testing
const TAINTED_STRING = `${TAINT_PREFIX}_payload_abc`;
// A sample clean string for testing
const CLEAN_STRING = "clean_payload_xyz";

const LOG_PREFIX = "[Scalpel Taint Shim - Window]";

/**
 * Helper function to load the shim into the JSDOM environment.
 * It reads the shim template, injects mock config, and executes it.
 *
 * @param {Array|string} sinksConfig - The sinks config array for testing.
 */
function loadShim(sinksConfig) {
    // Read the *Go template* file
    const template = fs.readFileSync(path.join(__dirname, 'taint_shim.js'), 'utf8');

    let sinksJSON;
    if (typeof sinksConfig === 'string') {
        // Handle special test cases for invalid JSON
        sinksJSON = sinksConfig;
    } else {
        // Default to '[]' just like your Go code
        sinksJSON = (sinksConfig && sinksConfig.length > 0) ? JSON.stringify(sinksConfig) : '[]';
    }

    // Simulate the Go template execution by replacing all placeholders
    const script = template
        .replace('{{.SinksJSON}}', sinksJSON)
        .replace('{{.SinkCallbackName}}', MOCK_CONFIG.SinkCallbackName)
        .replace('{{.ProofCallbackName}}', MOCK_CONFIG.ProofCallbackName)
        .replace('{{.ErrorCallbackName}}', MOCK_CONFIG.ErrorCallbackName)
        // Use regex to handle Go template syntax like {{.IsTesting | default false}}
        // This is replaced by the __SCALPEL_TEST_MODE__ global, but we still need to clean up the template tag.
        .replace(/{{.IsTesting.*}}/g, 'false'); // Default to false, test mode is set globally

    // Execute the script in the global context
    try {
        new Function('self', script)(window); // Pass 'window' as 'self'
    } catch (e) {
        console.error("Error evaluating shim script:", e);
    }
}

// --- Mocks for Fetch API (JSDOM compatibility) ---

// Minimal MockRequest implementation (as JSDOM doesn't provide it globally)
class MockRequest {
    constructor(url, options) {
        this.url = url;
        this.method = (options && options.method) || 'GET';
        this.body = (options && options.body) || null;
    }
}

// Minimal MockResponse implementation
class MockResponse {
    constructor(body = '{}', init = { status: 200 }) {
        this.body = body;
        this.status = init.status;
    }
}

// --- Test Suite ---

describe('Scalpel Taint Shim (Advanced)', () => {

    // --- Mocks and Spies ---
    let consoleLogSpy;
    let consoleErrorSpy;
    let originalDocWrite;
    let originalInnerHTMLDescriptor;
    // Define mocks locally for cleaner access in tests
    let mockSinkCallback;
    let mockProofCallback;
    let mockErrorCallback;

    // Setup before each test
    beforeEach(() => {
        // Enable test mode for the shim

        // Polyfill Request and Response in JSDOM scope if they don't exist
        if (!window.Request) window.Request = MockRequest;
        if (!window.Response) window.Response = MockResponse;
        window.__SCALPEL_TEST_MODE__ = true;

        // Reset the instrumentation guard
        window.__SCALPEL_TAINT_INSTRUMENTED__ = false;

        // Mock the Go callback functions
        mockSinkCallback = jest.fn();
        mockProofCallback = jest.fn();
        mockErrorCallback = jest.fn();
        window[MOCK_CONFIG.SinkCallbackName] = mockSinkCallback;
        window[MOCK_CONFIG.ProofCallbackName] = mockProofCallback;
        window[MOCK_CONFIG.ErrorCallbackName] = mockErrorCallback;

        // Spy on console messages
        consoleLogSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
        consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        // Mock a real function (document.write)
        originalDocWrite = document.write;
        document.write = jest.fn();

        // Mock a real property setter (innerHTML)
        originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: jest.fn(function(value) {
                originalInnerHTMLDescriptor.set.call(this, value);
            }),
            get: originalInnerHTMLDescriptor.get,
            configurable: true,
        });
    });

    // Cleanup after each test
    afterEach(() => {
        jest.restoreAllMocks();
        document.write = originalDocWrite;
        Object.defineProperty(Element.prototype, 'innerHTML', originalInnerHTMLDescriptor);

        // Clean up global state
        delete window[MOCK_CONFIG.SinkCallbackName];
        delete window[MOCK_CONFIG.ProofCallbackName];
        delete window[MOCK_CONFIG.ErrorCallbackName];
        delete window.__SCALPEL_TAINT_INSTRUMENTED__;
        delete window.__SCALPEL_TEST_MODE__;
        delete window.__SCALPEL_INTERNALS__;

        // Clean up polyfills if we added them
        if (window.Request === MockRequest) delete window.Request;
        if (window.Response === MockResponse) delete window.Response;
    });

    // --- Test Cases ---

    describe('Loading and Configuration', () => {
        it('should set __SCALPEL_TAINT_INSTRUMENTED__ guard', () => {
            loadShim([{ Name: "document.write", Type: "DOM_SINK" }]);
            expect(window.__SCALPEL_TAINT_INSTRUMENTED__).toBe(true);
        });

        it('should not run twice if already instrumented', () => {
            loadShim([{ Name: "document.write", Type: "DOM_SINK" }]); // First load
            expect(consoleLogSpy).toHaveBeenCalledWith(
                LOG_PREFIX,
                expect.stringContaining("IAST Instrumentation initialized successfully.")
            );
            consoleLogSpy.mockClear();

            loadShim([{ Name: "document.write", Type: "DOM_SINK" }]); // Second load
            expect(consoleLogSpy).not.toHaveBeenCalled();
        });

        // Error reporting is async (setTimeout 0), so the test must be async.
        it('should log an error for invalid (non-array) config', (done) => {
            loadShim('"this is not an array"'); // Pass invalid JSON

            // Wait for the async error report
            setTimeout(() => {
                expect(mockErrorCallback).toHaveBeenCalledWith(
                    expect.objectContaining({
                        error: expect.stringContaining("CONFIG.Sinks.forEach is not a function"),
                        location: "Fatal error during IAST Shim initialization"
                    })
                );
                done();
            }, 10);
        });

        it('should log "IAST Instrumentation initialized" for a valid config', () => {
            loadShim([{ Name: "document.write", Type: "DOM_SINK", Setter: false, ArgIndex: 0 }]);
            expect(consoleLogSpy).toHaveBeenCalledWith(
                LOG_PREFIX,
                expect.stringContaining("IAST Instrumentation initialized successfully.")
            );
        });
    });

    describe('Function Instrumentation (e.g., document.write)', () => {
        const fnConfig = [{
            Name: "document.write",
            Type: "DOM_SINK",
            Setter: false,
            ArgIndex: 0
        }];

        it('should call reportSink for a tainted argument', (done) => {
            loadShim(fnConfig);
            document.write(TAINTED_STRING);

            // Reporting is async (setTimeout), so we must wait
            setTimeout(() => {
                expect(mockSinkCallback).toHaveBeenCalledTimes(1);
                expect(mockSinkCallback).toHaveBeenCalledWith(
                    expect.objectContaining({
                        type: "DOM_SINK",
                        value: TAINTED_STRING,
                        detail: "document.write"
                    })
                );
                done();
            }, 10); // 10ms should be enough
        });

        it('should call the original function after reporting', () => {
            const originalMock = document.write;
            loadShim(fnConfig);
            document.write(TAINTED_STRING);
            expect(originalMock).toHaveBeenCalledTimes(1);
            expect(originalMock).toHaveBeenCalledWith(TAINTED_STRING);
        });

        it('should NOT call reportSink for a clean argument', (done) => {
            loadShim(fnConfig);
            document.write(CLEAN_STRING);

            setTimeout(() => {
                expect(mockSinkCallback).not.toHaveBeenCalled();
                done();
            }, 10);
        });
    });

    describe('Setter Instrumentation (e.g., innerHTML)', () => {
        const setterConfig = [{
            Name: "Element.prototype.innerHTML",
            Type: "XSS_SINK",
            Setter: true
        }];

        let el;
        let originalSetterMock;

        beforeEach(() => {
            originalSetterMock = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set;
            el = document.createElement('div');
        });

        it('should call reportSink for a tainted value', (done) => {
            loadShim(setterConfig);
            el.innerHTML = TAINTED_STRING;

            setTimeout(() => {
                expect(mockSinkCallback).toHaveBeenCalledTimes(1);
                expect(mockSinkCallback).toHaveBeenCalledWith(
                    expect.objectContaining({
                        type: "XSS_SINK",
                        value: TAINTED_STRING,
                        detail: "Element.prototype.innerHTML"
                    })
                );
                done();
            }, 10);
        });

        it('should call the original setter after reporting', () => {
            loadShim(setterConfig);
            el.innerHTML = TAINTED_STRING;
            expect(originalSetterMock).toHaveBeenCalledTimes(1);
            expect(el.innerHTML).toBe(TAINTED_STRING);
        });
    });

    describe('Prototype Pollution Detection', () => {
        // Use Jest fake timers to speed up the tests (checks occur at 1500ms and 5000ms)
        beforeEach(() => {
            jest.useFakeTimers();
        });

        afterEach(() => {
            // Ensure cleanup even if test fails
            if (Object.prototype.hasOwnProperty("scalpelPolluted")) {
                delete Object.prototype.scalpelPolluted;
            }
            jest.useRealTimers();
        });

        it('should detect and report prototype pollution at the first check (1500ms)', () => {
            // Simulate pollution
            Object.prototype.scalpelPolluted = `${TAINT_PREFIX}_POLLUTED`;
            
            loadShim([]); // Load the shim

            // Fast-forward time past the first check
            jest.advanceTimersByTime(1501);

            // Reporting is async, so advance timers again to clear the setTimeout(0)
            jest.advanceTimersByTime(1); 

            expect(mockSinkCallback).toHaveBeenCalledWith(
                expect.objectContaining({
                    type: "PROTOTYPE_POLLUTION",
                    value: `${TAINT_PREFIX}_POLLUTED`,
                    detail: "scalpelPolluted"
                })
            );
            // Check that it cleaned up after itself
            expect(Object.prototype.hasOwnProperty("scalpelPolluted")).toBe(false);
        });

        it('should detect pollution occurring after the first check (at 5000ms)', () => {
            loadShim([]);

            // Fast-forward past the first check
            jest.advanceTimersByTime(1501);
            expect(mockSinkCallback).not.toHaveBeenCalled();

            // Pollute now
            Object.prototype.scalpelPolluted = `${TAINT_PREFIX}_LATE`;

            // Fast-forward past the second check
            jest.advanceTimersByTime(3500); // 1501 + 3500 = 5001ms

            // Reporting is async, so advance timers again to clear the setTimeout(0)
            jest.advanceTimersByTime(1);

            expect(mockSinkCallback).toHaveBeenCalledWith(
                expect.objectContaining({ type: "PROTOTYPE_POLLUTION", value: `${TAINT_PREFIX}_LATE` })
            );
            expect(Object.prototype.hasOwnProperty("scalpelPolluted")).toBe(false);
        });
    });

    // --- Increased Coverage Suites ---

    describe('Taint Detection (isTainted)', () => {
        let isTainted;

        beforeEach(() => {
            loadShim([]); // Load shim (relies on __SCALPEL_TEST_MODE__ set in global beforeEach)
            if (window.__SCALPEL_INTERNALS__) {
                isTainted = window.__SCALPEL_INTERNALS__.isTainted;
            } else {
                throw new Error("Shim internals not exposed for testing.");
            }
        });

        it('should detect taint in simple strings', () => {
            expect(isTainted(TAINTED_STRING)).toBe(true);
            expect(isTainted(CLEAN_STRING)).toBe(false);
        });

        it('should not detect taint in non-string primitives', () => {
            expect(isTainted(123)).toBe(false);
            expect(isTainted(null)).toBe(false);
            expect(isTainted(undefined)).toBe(false);
            expect(isTainted(true)).toBe(false);
        });

        it('should detect taint in arrays (deep)', () => {
            expect(isTainted([CLEAN_STRING, TAINTED_STRING])).toBe(true);
            expect(isTainted([CLEAN_STRING, [1, TAINTED_STRING]])).toBe(true);
            expect(isTainted([CLEAN_STRING, 123])).toBe(false);
        });

        it('should detect taint in objects (deep)', () => {
            expect(isTainted({ a: CLEAN_STRING, b: TAINTED_STRING })).toBe(true);
            expect(isTainted({ a: { b: { c: TAINTED_STRING } } })).toBe(true);
            expect(isTainted({ a: CLEAN_STRING })).toBe(false);
        });

        it('should handle cycles in objects robustly', () => {
            const obj = { a: CLEAN_STRING };
            obj.b = obj;
            expect(() => isTainted(obj)).not.toThrow();
            expect(isTainted(obj)).toBe(false);

            const objTainted = { a: CLEAN_STRING, c: TAINTED_STRING }; // Taint is at root
            objTainted.b = objTainted;
            expect(isTainted(objTainted)).toBe(true);
        });

        it('should respect depth limit (MAX_DEPTH=4)', () => {
            // Taint at depth 4 should be found (Root=0, l1=1, l2=2, l3=3, l4=4)
            const deepTaintedOk = { l1: { l2: { l3: { l4: TAINTED_STRING } } } };
            expect(isTainted(deepTaintedOk)).toBe(true);

            // Taint at depth 5 should NOT be found
            const deepTaintedTooFar = { l1: { l2: { l3: { l4: { l5: TAINTED_STRING } } } } };
            expect(isTainted(deepTaintedTooFar)).toBe(false);
        });

        it('should detect taint in URLSearchParams (Iterable)', () => {
            const paramsTainted = new URLSearchParams();
            paramsTainted.append('q', TAINTED_STRING);
            expect(isTainted(paramsTainted)).toBe(true);

            const paramsClean = new URLSearchParams();
            paramsClean.append('q', CLEAN_STRING);
            expect(isTainted(paramsClean)).toBe(false);
        });

        it('should detect taint in FormData (Iterable)', () => {
            const formDataTainted = new FormData();
            formDataTainted.append('file', TAINTED_STRING);
            expect(isTainted(formDataTainted)).toBe(true);

            const formDataClean = new FormData();
            formDataClean.append('file', CLEAN_STRING);
            expect(isTainted(formDataClean)).toBe(false);
        });
    });

    describe('Execution Proof Callback', () => {
        it('should wrap the backend callback and add stack trace', () => {
            loadShim([]);

            const canary = "UNIQUE_CANARY_123";
            // Call the wrapper
            window[MOCK_CONFIG.ProofCallbackName](canary);

            // Check if the mock (original backend callback) was called by the wrapper
            expect(mockProofCallback).toHaveBeenCalledTimes(1);
            expect(mockProofCallback).toHaveBeenCalledWith(
                expect.objectContaining({
                    canary: canary,
                    stack: expect.any(String) // Check that a stack trace was added
                })
            );
        });
    });

    describe('Specialized Sink Handlers (e.g., fetch)', () => {
        const fetchConfig = [
            { Name: "fetch", Type: "FETCH_URL", Setter: false, ArgIndex: 0 },
            { Name: "fetch", Type: "FETCH_BODY", Setter: false, ArgIndex: 1 }
        ];

         // Mock global fetch
         // Use window.Response which might be the native or the MockResponse
        const mockFetch = jest.fn(() => Promise.resolve(new window.Response()));

        beforeEach(() => {
            window.fetch = mockFetch;
            loadShim(fetchConfig);
        });

        afterEach(() => {
            delete window.fetch;
        });

        it('should detect tainted URL (String argument)', (done) => {
            const taintedUrl = `http://example.com/?q=${TAINTED_STRING}`;
            fetch(taintedUrl);

            setTimeout(() => {
                expect(mockSinkCallback).toHaveBeenCalledTimes(1);
                expect(mockSinkCallback).toHaveBeenCalledWith(expect.objectContaining({
                    type: "FETCH_URL",
                    value: taintedUrl,
                    detail: "fetch"
                }));
                // Ensure the original (mocked) fetch was called correctly
                expect(mockFetch).toHaveBeenCalledWith(taintedUrl);
                done();
            }, 10);
        });

        it('should detect tainted URL (Request object)', (done) => {
            const taintedUrl = `http://example.com/?q=${TAINTED_STRING}`;
            // Use window.Request which might be the native or the MockRequest
            const request = new window.Request(taintedUrl);
            fetch(request);

            setTimeout(() => {
                expect(mockSinkCallback).toHaveBeenCalledTimes(1);
                expect(mockSinkCallback).toHaveBeenCalledWith(expect.objectContaining({
                    type: "FETCH_URL",
                    // The shim extracts the URL from the Request object for reporting
                    value: taintedUrl,
                    detail: "fetch"
                }));
                expect(mockFetch).toHaveBeenCalledWith(request);
                done();
            }, 10);
        });

        // *** START FIX ***
        // Changed test to be async and await the fetch call.
        it('should detect tainted Body', async () => {
            const cleanUrl = "http://example.com/";
            await fetch(cleanUrl, { method: 'POST', body: TAINTED_STRING });

            // Wait for the async reportSink (setTimeout 0) to complete
            // Give it 10ms to be safe and avoid race conditions.
            await new Promise(res => setTimeout(res, 10));
            // *** END FIX ***

            expect(mockSinkCallback).toHaveBeenCalledTimes(1);
            expect(mockSinkCallback).toHaveBeenCalledWith(expect.objectContaining({
                type: "FETCH_BODY",
                value: TAINTED_STRING,
                detail: "fetch"
            }));
        });

        it('should NOT report body sink if body is missing (validates specialized handler logic)', (done) => {
            const cleanUrl = "http://example.com/";
            // Options object exists, but no 'body' property.
            fetch(cleanUrl, { method: 'GET', headers: { 'X-Test': '1' } });

            setTimeout(() => {
                // The specialized handler should set valueToInspect=null, preventing report.
                expect(mockSinkCallback).not.toHaveBeenCalled();
                done();
            }, 10);
        });
    });

    describe('Conditional Sinks (e.g., setTimeout)', () => {
        const conditionalConfig = [{
            Name: "setTimeout",
            Type: "EVAL_SINK",
            Setter: false,
            ArgIndex: 0,
            ConditionID: "IS_STRING_ARG0"
        }];

        beforeEach(() => {
            jest.useFakeTimers(); // Use fake timers for setTimeout
            loadShim(conditionalConfig);
        });
        
        afterEach(() => {
            jest.useRealTimers();
        });

        // This test is synchronous because we use fake timers.
        it('should report sink if condition (IS_STRING_ARG0) is met (Tainted String)', () => {
            // FIX: Use a valid JS expression containing the taint.
            // The original TAINTED_STRING ("SCALPEL_payload_abc") caused a ReferenceError when evaluated by setTimeout.
            const executableTaintedString = `'${TAINTED_STRING}'`; // A string literal
            setTimeout(executableTaintedString, 10);
            
            // Advance timers to trigger setTimeout and the async report
            jest.advanceTimersByTime(20); 

            expect(mockSinkCallback).toHaveBeenCalledTimes(1);
            expect(mockSinkCallback).toHaveBeenCalledWith(expect.objectContaining({ type: "EVAL_SINK", value: executableTaintedString }));
        });

        it('should NOT report sink if condition is NOT met (Function)', () => {
            const taintedFunc = () => console.log(TAINTED_STRING);
            setTimeout(taintedFunc, 10);

            jest.advanceTimersByTime(20);

            expect(mockSinkCallback).not.toHaveBeenCalled();
        });
    });
    
    // Note: Shadow DOM testing in JSDOM is limited, but we test the instrumentation of attachShadow itself.
    // The *real* test is that Element.prototype.innerHTML was already instrumented.
    describe('Shadow DOM Instrumentation', () => {
        const shadowConfig = [{
            Name: "Element.prototype.innerHTML",
            Type: "XSS_SINK_SHADOW",
            Setter: true
        }];

        it('should instrument sinks within a newly created Shadow Root', (done) => {
            if (typeof Element.prototype.attachShadow !== 'function') {
                console.warn("Skipping Shadow DOM test: JSDOM environment does not support Shadow DOM.");
                done();
                return;
            }

            loadShim(shadowConfig);

            const host = document.createElement('div');
            document.body.appendChild(host);
            const shadowRoot = host.attachShadow({ mode: 'open' });

            const shadowEl = document.createElement('p');
            shadowRoot.appendChild(shadowEl);

            // Test the sink on an element inside the shadow DOM
            shadowEl.innerHTML = TAINTED_STRING;

            setTimeout(() => {
                expect(mockSinkCallback).toHaveBeenCalledTimes(1);
                expect(mockSinkCallback).toHaveBeenCalledWith(expect.objectContaining({
                    type: "XSS_SINK_SHADOW",
                    detail: "Element.prototype.innerHTML"
                }));
                document.body.removeChild(host);
                done();
            }, 10);
        });
    });
    
    describe('IPC Taint Flow (addEventListener)', () => {

        beforeEach(() => {
            loadShim([]); // IPC instrumentation is always active
        });

        it('should wrap "message" listeners to check for tainted data', () => {
            const listener = jest.fn();
            window.addEventListener('message', listener);
            consoleLogSpy.mockClear(); // Clear logs from initialization

            // Dispatch a message event with tainted data
            const taintedEvent = new MessageEvent('message', {
                data: TAINTED_STRING,
                origin: 'http://attacker.com'
            });
            window.dispatchEvent(taintedEvent);

            // The original listener should still be called
            expect(listener).toHaveBeenCalledWith(taintedEvent);

            // The shim should log that tainted data was received
            expect(consoleLogSpy).toHaveBeenCalledWith(
                LOG_PREFIX,
                "Tainted data received via postMessage/onmessage",
                'http://attacker.com'
            );
        });
    });

});