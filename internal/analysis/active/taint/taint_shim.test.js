// internal/analysis/active/taint/taint_shim.test.js
/** @testEnvironment jsdom */

const fs = require('fs');
const path = require('path');

// --- Test Constants ---
const MOCK_CONFIG = {
    SinkCallbackName: "__scalpel_sink_event",
    ProofCallbackName: "__scalpel_execution_proof",
    ErrorCallbackName: "__scalpel_shim_error",
    IsTesting: "true"
};

const TAINT_PREFIX = 'SCALPEL';
const TAINTED_STRING = `${TAINT_PREFIX}_payload_abc`;
const CLEAN_STRING = "clean_payload_xyz";
const LOG_PREFIX = "[Scalpel Taint Shim - Window]";

/**
 * Helper to load the shim.
 */
function loadShim(sinksConfig) {
    const template = fs.readFileSync(path.join(__dirname, 'taint_shim.js'), 'utf8');
    let sinksJSON = (sinksConfig && typeof sinksConfig === 'object') ? JSON.stringify(sinksConfig) : (sinksConfig || '[]');

    const script = template
        .replace('{{.SinksJSON}}', sinksJSON)
        .replace('{{.SinkCallbackName}}', MOCK_CONFIG.SinkCallbackName)
        .replace('{{.ProofCallbackName}}', MOCK_CONFIG.ProofCallbackName)
        .replace('{{.ErrorCallbackName}}', MOCK_CONFIG.ErrorCallbackName)
        .replace(/{{.IsTesting.*}}/g, 'false');

    try {
        new Function('self', script)(window);
    } catch (e) {
        console.error("Error evaluating shim script:", e);
    }
}

// --- Mocks for Fetch API ---
// VULN-FIX: Use WeakMap to simulate internal slots. 
// Real Request objects store data in internal slots, not own properties. 
// This ensures Reflect.ownKeys(req) is empty, accurately matching browser behavior for taint checking.
const _reqPrivates = new WeakMap();

class MockRequest {
    constructor(url, options) {
        _reqPrivates.set(this, {
            url: url,
            method: (options && options.method) || 'GET',
            body: (options && options.body) || null
        });
    }
    get url() { return _reqPrivates.get(this).url; }
    get method() { return _reqPrivates.get(this).method; }
    get body() { return _reqPrivates.get(this).body; }
}

class MockResponse {
    constructor(body = '{}', init = { status: 200 }) {
        this.body = body;
        this.status = init.status;
    }
}

describe('Scalpel Taint Shim (Robustness Suite)', () => {
    let consoleLogSpy, consoleErrorSpy;
    let mockSinkCallback, mockProofCallback, mockErrorCallback;
    let originalDocWrite, originalInnerHTMLDescriptor;

    beforeEach(() => {
        if (!window.Request) window.Request = MockRequest;
        if (!window.Response) window.Response = MockResponse;
        window.__SCALPEL_TEST_MODE__ = true;
        window.__SCALPEL_TAINT_INSTRUMENTED__ = false;

        mockSinkCallback = jest.fn();
        mockProofCallback = jest.fn();
        mockErrorCallback = jest.fn();
        window[MOCK_CONFIG.SinkCallbackName] = mockSinkCallback;
        window[MOCK_CONFIG.ProofCallbackName] = mockProofCallback;
        window[MOCK_CONFIG.ErrorCallbackName] = mockErrorCallback;

        consoleLogSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
        consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        originalDocWrite = document.write;
        document.write = jest.fn();

        originalInnerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: jest.fn(function(value) { originalInnerHTMLDescriptor.set.call(this, value); }),
            get: originalInnerHTMLDescriptor.get,
            configurable: true,
        });
    });

    afterEach(() => {
        jest.restoreAllMocks();
        document.write = originalDocWrite;
        Object.defineProperty(Element.prototype, 'innerHTML', originalInnerHTMLDescriptor);
        
        delete window[MOCK_CONFIG.SinkCallbackName];
        delete window[MOCK_CONFIG.ProofCallbackName];
        delete window[MOCK_CONFIG.ErrorCallbackName];
        delete window.__SCALPEL_TAINT_INSTRUMENTED__;
        delete window.__SCALPEL_TEST_MODE__;
        delete window.__SCALPEL_INTERNALS__;
        if (window.Request === MockRequest) delete window.Request;
    });

    // --- NEW: Context Capture Robustness ---
    describe('Context Capture (getPageContext)', () => {
        it('should capture correct URL and Title in Window context', () => {
            // JSDOM default URL is about:blank or configured via testEnvironmentOptions
            Object.defineProperty(document, 'title', { value: 'Test Page Title', writable: true });
            
            loadShim([]);
            const getPageContext = window.__SCALPEL_INTERNALS__.getPageContext;
            const ctx = getPageContext();

            expect(ctx.url).toBe(window.location.href);
            expect(ctx.title).toBe("Test Page Title");
        });

        it('should handle missing document gracefully (simulating early load/worker)', () => {
            loadShim([]);
            const getPageContext = window.__SCALPEL_INTERNALS__.getPageContext;

            // Temporarily hide document
            const originalDoc = window.document;
            delete window.document;

            const ctx = getPageContext();
            
            // Should fallback to location or return N/A, but NOT throw
            expect(ctx).toBeDefined();
            expect(ctx.url).toBeDefined();
            
            window.document = originalDoc;
        });
    });

    // --- NEW: Path Resolution Robustness ---
    describe('Path Resolution (resolvePath)', () => {
        let resolvePath;
        beforeEach(() => {
            loadShim([]);
            resolvePath = window.__SCALPEL_INTERNALS__.resolvePath;
        });

        it('should resolve deep existing paths', () => {
            window.A = { B: { C: { D: "Target" } } };
            const result = resolvePath("A.B.C.D");
            expect(result).not.toBeNull();
            expect(result.object).toBe("Target");
            expect(result.base).toBe(window.A.B.C);
            expect(result.propertyName).toBe("D");
        });

        it('should return null for non-existent paths safely', () => {
            const result = resolvePath("A.NonExistent.C");
            expect(result).toBeNull();
        });

        it('should resolve global objects via implicit scope or direct name', () => {
            // 'document' is on window, but resolvePath has special handling
            const res1 = resolvePath("document");
            expect(res1.object).toBe(document);

            const res2 = resolvePath("navigator");
            expect(res2.object).toBe(navigator);
        });

        it('should handle properties that throw on access (Security/CORS)', () => {
            // Mock a property that throws
            Object.defineProperty(window, 'RestrictedProp', {
                get: () => { throw new Error("Security Exception"); },
                configurable: true
            });

            // Should verify reporting of shim error, but mainly ensure it returns null and doesn't crash shim
            const result = resolvePath("RestrictedProp.sub");
            expect(result).toBeNull();
        });
    });

    // --- ENHANCED: Taint Detection ---
    describe('Taint Detection (isTainted) - Advanced Structures', () => {
        let isTainted;
        beforeEach(() => {
            loadShim([]);
            isTainted = window.__SCALPEL_INTERNALS__.isTainted;
        });

        it('should detect taint in Sets', () => {
            const s = new Set();
            s.add("clean");
            s.add(TAINTED_STRING);
            expect(isTainted(s)).toBe(true);
        });

        it('should detect taint in Maps (Values)', () => {
            const m = new Map();
            m.set("key", TAINTED_STRING);
            expect(isTainted(m)).toBe(true);
        });

        it('should detect taint in Maps (Keys) - if iterated', () => {
            const m = new Map();
            m.set(TAINTED_STRING, "value");
            // Expected: False, because we only check values() for iterables
            expect(isTainted(m)).toBe(false); 
        });

        it('should handle mixed nested Map/Set/Array', () => {
            const complex = new Map();
            const s = new Set();
            s.add([1, { deep: TAINTED_STRING }]);
            complex.set("inner", s);
            
            expect(isTainted(complex)).toBe(true);
        });

        // FIX VERIFICATION TEST
        it('should detect taint in Request objects (Prototype Accessors)', () => {
            // This test validates that isTainted correctly accesses properties that are not "own" properties
            // but are exposed via getters on the prototype (simulating Web API objects like Request).
            const req = new window.Request(TAINTED_STRING);
            
            // Ensure our Mock is behaving like a browser object (hidden internal slot)
            expect(Reflect.ownKeys(req)).not.toContain('url');
            expect(req.url).toBe(TAINTED_STRING);

            expect(isTainted(req)).toBe(true);
        });
    });
});
