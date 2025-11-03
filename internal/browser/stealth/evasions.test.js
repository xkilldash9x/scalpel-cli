// internal/browser/stealth/evasions_test.js
// In-browser unit test suite for evasions.js

// Simple in-browser test runner framework
const ScalpelTestRunner = {
    tests: [],
    results: [],
    define(name, testFunc) {
        this.tests.push({ name, testFunc });
    },
    run() {
        this.results = [];
        console.log("Starting Scalpel Stealth Evasion Tests...");
        // Use Promise.all to handle async tests gracefully
        const promises = this.tests.map(async (test) => {
            try {
                // Execute the test function (supports async functions)
                await test.testFunc();
                this.results.push({ name: test.name, status: 'PASS' });
            } catch (error) {
                // Capture stack trace for better debugging in Go runner.
                this.results.push({ name: test.name, status: 'FAIL', error: error.message, stack: error.stack });
                console.error(`FAIL: ${test.name}`, error);
            }
        });

        Promise.all(promises).then(() => {
            console.log("Tests finished.");
            // Expose results globally so the Go test can retrieve them (via polling)
            window.SCALPEL_TEST_RESULTS = this.results;
        });
    }
};

// Simple assertion library
const assert = {
    equal(actual, expected, message) {
        if (actual !== expected) {
            throw new Error(`${message}: Expected ${expected}, but got ${actual}`);
        }
    },
    isTrue(condition, message) {
        if (!condition) {
            throw new Error(message);
        }
    },
    isFalse(condition, message) {
        if (condition) {
            throw new Error(message);
        }
    },
    // Helper for asynchronous exception testing (useful if APIs return Promises that reject)
    // Also handles synchronous exceptions thrown by the API implementations (like Permissions validation).
    async throwsAsync(asyncFunc, expectedErrorType, message) {
        try {
            await asyncFunc();
            throw new Error(`${message}: Expected an exception but none was thrown.`);
        } catch (error) {
            if (error.message.includes('Expected an exception but none was thrown')) {
                throw error; // Rethrow if assertion failed (no exception occurred)
            }
            if (expectedErrorType && !(error instanceof expectedErrorType)) {
                 throw new Error(`${message}: Expected error type ${expectedErrorType.name}, but got ${error.name}. Error: ${error.message}`);
            }
        }
    }
};

// --- Tests Definitions ---

ScalpelTestRunner.define('Evasion: Webdriver Flag Removal', () => {
    assert.isFalse(navigator.webdriver, 'navigator.webdriver should be false');
});

ScalpelTestRunner.define('Evasion: window.chrome simulation and masking', () => {
    assert.isTrue(window.chrome !== undefined, 'window.chrome should be defined');
    assert.isTrue(window.chrome.runtime !== undefined, 'window.chrome.runtime should be defined');
    
    // Test Masking
    assert.equal(window.chrome.runtime.connect.toString(), 'function connect() { [native code] }', 'window.chrome.runtime.connect masking failed');
    
    // Test Double Masking
    assert.equal(window.chrome.runtime.connect.toString.toString(), 'function toString() { [native code] }', 'window.chrome.runtime.connect double masking failed');
});

ScalpelTestRunner.define('Persona Application: Navigator Properties', () => {
    const persona = window.SCALPEL_PERSONA;
    // Use camelCase for assertions (e.g., userAgent)
    assert.isTrue(persona !== undefined && persona.userAgent !== undefined, 'Persona data should be available');
    
    assert.equal(navigator.userAgent, persona.userAgent, 'UserAgent mismatch');
    assert.equal(navigator.platform, persona.platform, 'Platform mismatch');

    // Check derived properties (Robustness improvement)
    const expectedAppVersion = persona.userAgent.replace(/^Mozilla\//, '');
    assert.equal(navigator.appVersion, expectedAppVersion, 'appVersion mismatch');

    // Check languages array
    assert.equal(navigator.languages.join(','), persona.languages.join(','), 'Languages mismatch');
    // Check singular language property (Robustness improvement)
    assert.equal(navigator.language, persona.languages[0], 'Primary language mismatch');

    assert.isTrue(Object.isFrozen(navigator.languages), 'Languages array should be frozen');
});

ScalpelTestRunner.define('Persona Application: Screen Properties (DPR/ColorDepth Clarity)', () => {
    const persona = window.SCALPEL_PERSONA;
    // Use camelCase for assertions (e.g., width, availWidth, colorDepth, pixelDepth)
    assert.equal(window.screen.width, persona.width, 'Screen width mismatch');
    assert.equal(window.screen.height, persona.height, 'Screen height mismatch');
    
    assert.equal(window.screen.availWidth, persona.availWidth, 'Screen availWidth mismatch');
    assert.equal(window.screen.availHeight, persona.availHeight, 'Screen availHeight mismatch');
    
    // Verify ColorDepth and PixelDepth interpretation (Robustness fix).
    // screen.colorDepth and screen.pixelDepth should match Persona.colorDepth.
    assert.equal(window.screen.colorDepth, persona.colorDepth, 'Screen colorDepth mismatch');
    assert.equal(window.screen.pixelDepth, persona.colorDepth, 'Screen pixelDepth mismatch');

    // Verify Device Pixel Ratio (DPR). This is set via CDP override using Persona.pixelDepth.
    const expectedDPR = persona.pixelDepth || 1.0;
    assert.equal(window.devicePixelRatio, expectedDPR, 'Device Pixel Ratio (DPR) mismatch');

    assert.equal(window.outerWidth, persona.width, 'window.outerWidth mismatch');
    assert.equal(window.outerHeight, persona.height, 'window.outerHeight mismatch');
});

ScalpelTestRunner.define('Evasion: Permissions API spoofing and masking (Async)', async () => {
    if (navigator.permissions && navigator.permissions.query && window.PermissionStatus) {
        
        // 1. Check functionality
        const result = await navigator.permissions.query({ name: 'notifications' });
        const expectedState = (window.Notification && Notification.permission === 'default') ? 'prompt' : Notification.permission;
        assert.equal(result.state, expectedState, 'Permissions API notification state mismatch');
        assert.isTrue(result instanceof PermissionStatus, 'Result should be an instance of PermissionStatus');

        // 2. Check masking (toString override)
        assert.equal(navigator.permissions.query.toString(), 'function query() { [native code] }', 'Permissions query function masking failed');

        // 2.5 Check Double Masking
        assert.equal(navigator.permissions.query.toString.toString(), 'function toString() { [native code] }', 'Permissions query double masking failed');

        // 3. Check input validation (robustness improvements)
        await assert.throwsAsync(() => navigator.permissions.query(), TypeError, 'Calling query() without arguments');
        await assert.throwsAsync(() => navigator.permissions.query(null), TypeError, 'Calling query(null)');
        await assert.throwsAsync(() => navigator.permissions.query({}), TypeError, 'Calling query({}) without name');

    } else {
        console.warn("Skipping Permissions API test: API or PermissionStatus not available.");
    }
});

ScalpelTestRunner.define('Evasion: WebGL Spoofing', () => {
    const persona = window.SCALPEL_PERSONA;
    // Use camelCase for assertions (e.g., webGLVendor, webGLRenderer)
    if (!persona.webGLVendor || !persona.webGLRenderer) {
        console.warn("Skipping WebGL test: No WebGL data in persona.");
        return;
    }

    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

    if (!gl) {
        // This can happen in certain headless environments.
        console.warn("Skipping WebGL test: WebGL context creation failed.");
        return;
    }

    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (debugInfo) {
        assert.equal(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL), persona.webGLVendor, 'WebGL Vendor mismatch');
        assert.equal(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL), persona.webGLRenderer, 'WebGL Renderer mismatch');
    }

    // Check masking
    assert.equal(gl.getParameter.toString(), 'function getParameter() { [native code] }', 'WebGL getParameter masking failed');
    assert.equal(gl.getParameter.toString.toString(), 'function toString() { [native code] }', 'WebGL getParameter double masking failed');
});


// Run the tests automatically when the script loads
ScalpelTestRunner.run();