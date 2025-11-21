// internal/browser/stealth/evasions_test.js
// In-browser unit test suite for evasions.js

// Simple in-browser test runner framework
const ScalpelTestRunner = {
    tests: [],
    results: [],
    define(name, testFunc) {
        this.tests.push({ name, testFunc });
    },
    // Fix for Race Condition (Bug 3): Run tests sequentially
    async run() {
        this.results = [];
        console.log("Starting Scalpel Stealth Evasion Tests...");
        
        for (const test of this.tests) {
            try {
                // Execute the test function (supports async functions)
                // Await guarantees sequential execution, preventing interference between tests
                // that modify global state (like window.Notification).
                await test.testFunc();
                this.results.push({ name: test.name, status: 'PASS' });
            } catch (error) {
                // Capture stack trace for better debugging in Go runner.
                this.results.push({ name: test.name, status: 'FAIL', error: error.message, stack: error.stack });
                console.error(`FAIL: ${test.name}`, error);
            }
        }

        console.log("Tests finished.");
        // Expose results globally so the Go test can retrieve them (via polling)
        window.SCALPEL_TEST_RESULTS = this.results;
    }
};

// Simple assertion library
const assert = {
    equal(actual, expected, message) {
        if (actual !== expected) {
            throw new Error(`${message}: Expected ${expected}, but got ${actual}`);
        }
    },
    // Added notEqual assertion (For Bug 6)
    notEqual(actual, expected, message) {
        if (actual === expected) {
            throw new Error(`${message}: Expected value not to be ${expected}, but it was.`);
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

// Constants for assertions
const NATIVE_TOSTRING = 'function toString() { [native code] }';

// --- Tests Definitions ---

ScalpelTestRunner.define('Evasion: Webdriver Flag Removal', () => {
    assert.isFalse(navigator.webdriver, 'navigator.webdriver should be false');
});

// (Test for Bug 1: Infinite Masking)
ScalpelTestRunner.define('Evasion: window.chrome simulation and masking (Infinite Masking)', () => {
    assert.isTrue(window.chrome !== undefined, 'window.chrome should be defined');
    assert.isTrue(window.chrome.runtime !== undefined, 'window.chrome.runtime should be defined');
    
    const targetFunc = window.chrome.runtime.connect;

    // Test Masking (L1)
    assert.equal(targetFunc.toString(), 'function connect() { [native code] }', 'L1 masking failed');
    
    // Test Double Masking (L2)
    assert.equal(targetFunc.toString.toString(), NATIVE_TOSTRING, 'L2 masking failed');

    // Test Triple Masking (L3)
    assert.equal(targetFunc.toString.toString.toString(), NATIVE_TOSTRING, 'L3 masking failed');
    
    // Test Quadruple Masking (L4)
    assert.equal(targetFunc.toString.toString.toString.toString(), NATIVE_TOSTRING, 'L4 masking failed');
});

ScalpelTestRunner.define('Persona Application: Navigator Properties', () => {
    const persona = window.SCALPEL_PERSONA;
    // Use camelCase for assertions (e.g., userAgent)
    assert.isTrue(persona !== undefined && persona.userAgent !== undefined, 'Persona data should be available');
    
    assert.equal(navigator.userAgent, persona.userAgent, 'UserAgent mismatch');
    
    // We check platform only if it was provided, allowing Go logic (Bug 5) to handle derivation if empty.
    // The Go test runner (js_test.go) provides an explicit platform, so we verify it here.
    if (persona.platform) {
        assert.equal(navigator.platform, persona.platform, 'Platform mismatch');
    }

    // Check derived properties (Robustness improvement)
    const expectedAppVersion = persona.userAgent.replace(/^Mozilla\//, '');
    assert.equal(navigator.appVersion, expectedAppVersion, 'appVersion mismatch');

    // Check languages array
    assert.equal(navigator.languages.join(','), persona.languages.join(','), 'Languages mismatch');
    // Check singular language property (Robustness improvement)
    assert.equal(navigator.language, persona.languages[0], 'Primary language mismatch');

    assert.isTrue(Object.isFrozen(navigator.languages), 'Languages array should be frozen');
});

ScalpelTestRunner.define('Persona Application: Screen and Window Properties', () => {
    const persona = window.SCALPEL_PERSONA;

    assert.equal(window.screen.width, persona.width, 'Screen width mismatch');
    assert.equal(window.screen.height, persona.height, 'Screen height mismatch');
    
    // Handle potential default values if not provided in persona (js_test.go provides them)
    const expectedAvailWidth = persona.availWidth || persona.width;
    const expectedAvailHeight = persona.availHeight || persona.height;

    assert.equal(window.screen.availWidth, expectedAvailWidth, 'Screen availWidth mismatch');
    assert.equal(window.screen.availHeight, expectedAvailHeight, 'Screen availHeight mismatch');
    
    // Verify ColorDepth and PixelDepth interpretation.
    const expectedColorDepth = persona.colorDepth || 24;
    assert.equal(window.screen.colorDepth, expectedColorDepth, 'Screen colorDepth mismatch');
    assert.equal(window.screen.pixelDepth, expectedColorDepth, 'Screen pixelDepth mismatch');

    // Verify Device Pixel Ratio (DPR).
    const expectedDPR = persona.pixelDepth || 1.0;
    assert.equal(window.devicePixelRatio, expectedDPR, 'Device Pixel Ratio (DPR) mismatch');

    // Verify Window Dimensions (Test for Bug 3)
    assert.equal(window.outerWidth, persona.width, 'window.outerWidth mismatch');
    assert.equal(window.outerHeight, persona.height, 'window.outerHeight mismatch');
    assert.equal(window.innerWidth, persona.width, 'window.innerWidth mismatch');
    assert.equal(window.innerHeight, persona.height, 'window.innerHeight mismatch');
});

ScalpelTestRunner.define('Evasion: Permissions API (Masking, Structure, Functionality)', async () => {
    if (navigator.permissions && navigator.permissions.query && window.PermissionStatus) {
        
        // 1. Check functionality
        const result = await navigator.permissions.query({ name: 'notifications' });
        
        // Determine expected state robustly (handles missing Notification API, related to Bug 2)
        let expectedState = 'prompt'; 
        if (window.Notification) {
            expectedState = (Notification.permission === 'default') ? 'prompt' : Notification.permission;
        }

        assert.equal(result.state, expectedState, 'Permissions API notification state mismatch');
        assert.isTrue(result instanceof PermissionStatus, 'Result should be an instance of PermissionStatus');

        const targetFunc = navigator.permissions.query;

        // 2. Check masking (Test for Bug 1)
        assert.equal(targetFunc.toString(), 'function query() { [native code] }', 'Permissions L1 masking failed');
        assert.equal(targetFunc.toString.toString(), NATIVE_TOSTRING, 'Permissions L2 masking failed');
        assert.equal(targetFunc.toString.toString.toString(), NATIVE_TOSTRING, 'Permissions L3 masking failed');


        // 3. Check input validation
        await assert.throwsAsync(() => navigator.permissions.query(), TypeError, 'Calling query() without arguments');
        await assert.throwsAsync(() => navigator.permissions.query(null), TypeError, 'Calling query(null)');
        await assert.throwsAsync(() => navigator.permissions.query({}), TypeError, 'Calling query({}) without name');

        // 4. Check structural integrity (Test for Bug 4)
        // Native behavior: state is a getter on prototype, not an own property.
        // Even with the Proxy fix, the Proxy should forward getOwnPropertyDescriptor to the target,
        // which has no own property. This MUST still pass.
        const descriptor = Object.getOwnPropertyDescriptor(result, 'state');
        assert.equal(descriptor, undefined, 'PermissionStatus object should not have an own property "state"');

        // 5. Verify prototype restoration (Test for Bug 4)
        const protoDescriptor = Object.getOwnPropertyDescriptor(PermissionStatus.prototype, 'state');
        assert.isTrue(protoDescriptor && typeof protoDescriptor.get === 'function', 'Prototype descriptor missing or invalid');
        // Check if the getter is masked (native functions usually are)
        assert.isTrue(protoDescriptor.get.toString().includes('[native code]'), 'Prototype getter seems modified (not restored to native)');

    } else {
        console.warn("Skipping Permissions API test: API or PermissionStatus not available.");
    }
});

// TEST FOR BUG 1 (PERSISTENCE)
ScalpelTestRunner.define('Evasion: Permissions API - Persistence of Spoof', async () => {
    if (navigator.permissions && navigator.permissions.query && window.Notification) {
        
        // This test verifies that the spoofed result PERSISTS even after the prototype restoration.
        // We force a mismatch: spoofed = 'granted', native/internal = 'prompt'.
        
        const originalNotificationPermission = Object.getOwnPropertyDescriptor(window.Notification, 'permission');
        // Mock Notification.permission to be 'granted'
        Object.defineProperty(window.Notification, 'permission', { value: 'granted', configurable: true });

        try {
            // Call query. The evasion logic sees Notification.permission='granted' and spoofs the result.
            const result = await navigator.permissions.query({ name: 'notifications' });
            
            // At this point, the prototype hook in evasions.js should have been restored.
            // If the bug exists (no Proxy), result.state will access native getter -> internal slot -> 'prompt'.
            // If fixed (Proxy), result.state will use the Proxy trap -> 'granted'.
            
            assert.equal(result.state, 'granted', 'PermissionStatus.state did not persist the spoofed value after query resolution');
            
        } finally {
            // Clean up
            if (originalNotificationPermission) {
                Object.defineProperty(window.Notification, 'permission', originalNotificationPermission);
            } else {
                // Fallback for cleanup if descriptor was missing (unlikely)
                 delete window.Notification.permission; 
            }
        }
    }
});

// (Test for Bug 2: Missing Notification API handling)
ScalpelTestRunner.define('Evasion: Permissions API - Robustness (Missing Notification API)', async () => {
    if (navigator.permissions && navigator.permissions.query && window.PermissionStatus) {
        
        const originalNotification = window.Notification;
        let notificationModified = false;

        try {
            // 1. Simulate environment without Notification API
            try {
                // Attempt to redefine Notification to undefined.
                Object.defineProperty(window, 'Notification', { value: undefined, configurable: true, writable: true });
                notificationModified = (window.Notification === undefined);
            } catch (e) {
                console.warn("Failed to redefine window.Notification.", e);
            }

            if (!notificationModified) {
                 console.warn("Skipping Permissions Robustness test: Cannot modify window.Notification.");
                 return; // Skip test if we cannot set up the environment
            }
            
            // 2. Verify that querying permissions does not throw an error (e.g., ReferenceError/TypeError)
            const result = await navigator.permissions.query({ name: 'notifications' });
            
            // 3. Assert the fallback state
            assert.equal(result.state, 'prompt', 'Should default to prompt when Notification API is missing');

        } finally {
            // 4. Restore window.Notification
            if (notificationModified) {
                 Object.defineProperty(window, 'Notification', { value: originalNotification, configurable: true, writable: true });
            }
        }

    } else {
        console.warn("Skipping Permissions Robustness test: Permissions API not available.");
    }
});


ScalpelTestRunner.define('Evasion: WebGL Spoofing (Unmasked, Standard, and Masking)', () => {
    const persona = window.SCALPEL_PERSONA;
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

    // Standardized constants (Test for Bug 7)
    const UNMASKED_VENDOR_WEBGL = 0x9245;
    const UNMASKED_RENDERER_WEBGL = 0x9246;

    // 1. Verify unmasked parameters are spoofed (using constants, verifying Bug 7 fix)
    assert.equal(gl.getParameter(UNMASKED_VENDOR_WEBGL), persona.webGLVendor, 'WebGL Vendor mismatch (via constant)');
    assert.equal(gl.getParameter(UNMASKED_RENDERER_WEBGL), persona.webGLRenderer, 'WebGL Renderer mismatch (via constant)');

    // 2. Verify standard parameters are NOT spoofed (Test for Bug 6)
    if (gl.VENDOR) {
        assert.notEqual(gl.getParameter(gl.VENDOR), persona.webGLVendor, 'Standard gl.VENDOR should not match unmasked persona vendor');
    }
    if (gl.RENDERER) {
        assert.notEqual(gl.getParameter(gl.RENDERER), persona.webGLRenderer, 'Standard gl.RENDERER should not match unmasked persona renderer');
    }

    // 3. Check masking (Test for Bug 1)
    const targetFunc = gl.getParameter;
    assert.equal(targetFunc.toString(), 'function getParameter() { [native code] }', 'WebGL getParameter L1 masking failed');
    assert.equal(targetFunc.toString.toString(), NATIVE_TOSTRING, 'WebGL getParameter L2 masking failed');
    assert.equal(targetFunc.toString.toString.toString(), NATIVE_TOSTRING, 'WebGL getParameter L3 masking failed');
});


// Run the tests automatically when the script loads
ScalpelTestRunner.run();