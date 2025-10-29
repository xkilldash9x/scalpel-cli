// internal/analysis/active/taint/taint_shim.test.js
/** @testEnvironment jsdom */

const fs = require('fs');
const path = require('path');

// --- Test Constants ---
// Mocked Go template variables
const MOCK_CALLBACKS = {
    SinkCallbackName: "__scalpel_sink_event",
    ProofCallbackName: "__scalpel_execution_proof",
    ErrorCallbackName: "__scalpel_shim_error",
};

// This MUST match the canary prefix in your shim's CONFIG
const TAINT_PREFIX = 'SCALPEL';
// A sample tainted string for testing
const TAINTED_STRING = `${TAINT_PREFIX}_payload_abc`;
// A sample clean string for testing
const CLEAN_STRING = "clean_payload_xyz";

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
        .replace('{{.SinkCallbackName}}', MOCK_CALLBACKS.SinkCallbackName)
        .replace('{{.ProofCallbackName}}', MOCK_CALLBACKS.ProofCallbackName)
        .replace('{{.ErrorCallbackName}}', MOCK_CALLBACKS.ErrorCallbackName);

    // Execute the script in the global context
    try {
        new Function('self', script)(window); // Pass 'window' as 'self'
    } catch (e) {
        console.error("Error evaluating shim script:", e);
    }
}

// --- Test Suite ---

describe('Scalpel Taint Shim (Advanced)', () => {

    // --- Mocks and Spies ---
    let consoleLogSpy;
    let consoleErrorSpy;
    let originalDocWrite;
    let originalInnerHTMLDescriptor;

    // Setup before each test
    beforeEach(() => {
        // Reset the instrumentation guard
        window.__SCALPEL_TAINT_INSTRUMENTED__ = false;

        // Mock the Go callback functions
        window[MOCK_CALLBACKS.SinkCallbackName] = jest.fn();
        window[MOCK_CALLBACKS.ProofCallbackName] = jest.fn();
        window[MOCK_CALLBACKS.ErrorCallbackName] = jest.fn();

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
        delete window[MOCK_CALLBACKS.SinkCallbackName];
        delete window[MOCK_CALLBACKS.ProofCallbackName];
        delete window[MOCK_CALLBACKS.ErrorCallbackName];
        delete window.__SCALPEL_TAINT_INSTRUMENTED__;
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
                expect.stringContaining("IAST Instrumentation initialized successfully.")
            );
            consoleLogSpy.mockClear();

            loadShim([{ Name: "document.write", Type: "DOM_SINK" }]); // Second load
            expect(consoleLogSpy).not.toHaveBeenCalled();
        });

        it('should log an error for invalid (non-array) config', () => {
            loadShim('"this is not an array"'); // Pass invalid JSON
            // The new shim doesn't log an error, it just fails initialization
            // We should check that the error callback was hit
            expect(window[MOCK_CALLBACKS.ErrorCallbackName]).toHaveBeenCalledWith(
                expect.objectContaining({
                    error: expect.stringContaining("CONFIG.Sinks.forEach is not a function"),
                    location: "Failed to instrument sink document.write"
                })
            );
        });

        it('should log "IAST Instrumentation initialized" for a valid config', () => {
            loadShim([{ Name: "document.write", Type: "DOM_SINK", Setter: false, ArgIndex: 0 }]);
            expect(consoleLogSpy).toHaveBeenCalledWith(
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
                expect(window[MOCK_CALLBACKS.SinkCallbackName]).toHaveBeenCalledTimes(1);
                expect(window[MOCK_CALLBACKS.SinkCallbackName]).toHaveBeenCalledWith(
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
                expect(window[MOCK_CALLBACKS.SinkCallbackName]).not.toHaveBeenCalled();
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
                expect(window[MOCK_CALLBACKS.SinkCallbackName]).toHaveBeenCalledTimes(1);
                expect(window[MOCK_CALLBACKS.SinkCallbackName]).toHaveBeenCalledWith(
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
        it('should detect and report prototype pollution', (done) => {
            // Simulate pollution
            Object.prototype.scalpelPolluted = `${TAINT_PREFIX}_POLLUTED`;
            
            loadShim([]); // Load the shim

            // The check is async, so we must wait longer
            setTimeout(() => {
                expect(window[MOCK_CALLBACKS.SinkCallbackName]).toHaveBeenCalledWith(
                    expect.objectContaining({
                        type: "PROTOTYPE_POLLUTION",
                        value: `${TAINT_PREFIX}_POLLUTED`,
                        detail: "scalpelPolluted"
                    })
                );
                // Check that it cleaned up after itself
                expect(Object.prototype.hasOwnProperty("scalpelPolluted")).toBe(false);
                done();
            }, 1510); // Wait just over the 1500ms timeout in the shim
        });
    });

});