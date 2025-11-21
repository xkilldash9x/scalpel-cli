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
    },
    // (Improvement: Add assertion for native function checks)
    isNative(func, message) {
        // We must use the authentic Function.prototype.toString for this check.
        const nativeString = Function.prototype.toString.call(func);
        assert.isTrue(nativeString.includes('[native code]'), `${message}: Function ${func.name || ''} does not appear native. Got: ${nativeString}`);
    }
};

// Constants for assertions
// We now rely on the authentic Function.prototype.toString for L2+ checks.

// --- Tests Definitions ---

ScalpelTestRunner.define('Evasion: Webdriver Flag Removal', () => {
    assert.isFalse(navigator.webdriver, 'navigator.webdriver should be false');
    
    // Test Descriptor Mimicry (Improvement 5).
    const descriptor = Object.getOwnPropertyDescriptor(Navigator.prototype, 'webdriver');
    assert.isTrue(descriptor !== undefined, 'Webdriver descriptor should exist on prototype');
    // We primarily verify that the override succeeded and the getter exists.
    assert.isTrue(descriptor.enumerable, 'Webdriver descriptor should be enumerable');
    assert.isTrue(typeof descriptor.get === 'function', 'Webdriver should have a getter');
});

// (Test for Fix 1: Function.prototype.toString.call detection)
ScalpelTestRunner.define('Evasion: Advanced Masking (Proxy vs Function.prototype.toString.call)', () => {
    // We test several masked functions to ensure the Proxy implementation is robust.
    const testCases = [
        { name: 'chrome.runtime.connect', func: window.chrome && window.chrome.runtime && window.chrome.runtime.connect },
        { name: 'navigator.permissions.query', func: navigator.permissions && navigator.permissions.query },
    ];

    // Setup WebGL context for WebGL testing (if available)
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (gl) {
        testCases.push({ name: 'getParameter', func: gl.getParameter });
    }
    
    // Add Plugins methods if available (Fix 6)
    if (navigator.plugins && navigator.plugins.refresh) {
         testCases.push({ name: 'refresh', func: navigator.plugins.refresh });
    }


    for (const { name, func } of testCases) {
        if (!func) {
            console.warn(`Skipping advanced masking test for ${name}: Function not available or not masked.`);
            continue;
        }

        // The name might be derived differently depending on how maskAsNative was called (hint vs func.name)
        const funcName = func.name || name;
        const expectedString = `function ${funcName}() { [native code] }`;

        // 1. Standard check (L1 masking)
        assert.equal(func.toString(), expectedString, `${name}.toString() failed (L1)`);

        // 2. The critical test for Fix 1: Using Function.prototype.toString.call()
        // If fixed, the Proxy intercepts the access and returns the spoofed string.
        const resultViaCall = Function.prototype.toString.call(func);
        assert.equal(resultViaCall, expectedString, `Function.prototype.toString.call(${name}) detection succeeded (Fix 1 failed)`);
    }
});


// (Test for Fix 1/Improvement 2: Masking/Authenticity)
ScalpelTestRunner.define('Evasion: window.chrome simulation and masking', () => {
    assert.isTrue(window.chrome !== undefined, 'window.chrome should be defined');
    assert.isTrue(window.chrome.runtime !== undefined, 'window.chrome.runtime should be defined');
    
    const targetFunc = window.chrome.runtime.connect;

    // Test Structure
    assert.isTrue(window.chrome.runtime.onConnect !== undefined, 'chrome.runtime.onConnect missing');

    // Test Masking (L1)
    assert.equal(targetFunc.toString(), 'function connect() { [native code] }', 'L1 masking failed');
    
    // Test Double Masking (L2 Authenticity)
    // The L2 toString should be the actual native Function.prototype.toString.
    assert.equal(targetFunc.toString.toString, Function.prototype.toString, 'L2 masking function mismatch (Authenticity failed)');
    // And calling it should yield the native string representation of toString itself.
    assert.isNative(targetFunc.toString.toString, 'L2 masking result');
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

        // (Test for Fix 4): Capture the prototype descriptor BEFORE the query.
        const initialProtoDescriptor = Object.getOwnPropertyDescriptor(PermissionStatus.prototype, 'state');
        
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
        // Check L2 masking (Authenticity)
        assert.equal(targetFunc.toString.toString, Function.prototype.toString, 'Permissions L2 masking function mismatch');
        assert.isNative(targetFunc.toString.toString, 'Permissions L2 masking result');


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

        // 5. Verify prototype integrity (Test for Fix 4)
        const protoDescriptor = Object.getOwnPropertyDescriptor(PermissionStatus.prototype, 'state');
        assert.isTrue(protoDescriptor && typeof protoDescriptor.get === 'function', 'Prototype descriptor missing or invalid');

        // Crucial check for Fix 4: Ensure the descriptor has not changed during the operation.
        assert.equal(protoDescriptor.get, initialProtoDescriptor.get, 'PermissionStatus.prototype.state getter was modified during query (Fix 4 failed)');
        assert.equal(protoDescriptor.configurable, initialProtoDescriptor.configurable, 'Prototype descriptor configurable flag changed');

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
    // Check L2 masking (Authenticity)
    assert.equal(targetFunc.toString.toString, Function.prototype.toString, 'WebGL L2 masking function mismatch');
    assert.isNative(targetFunc.toString.toString, 'WebGL L2 masking result');
});


// Test for Fix 6: Missing navigator.plugins/mimeTypes
ScalpelTestRunner.define('Evasion: navigator.plugins and mimeTypes (Structure, Content, Masking)', () => {
    // 1. Check existence and basic structure
    if (window.PluginArray) {
        assert.isTrue(navigator.plugins instanceof PluginArray, 'navigator.plugins should be PluginArray');
    }
    if (window.MimeTypeArray) {
        assert.isTrue(navigator.mimeTypes instanceof MimeTypeArray, 'navigator.mimeTypes should be MimeTypeArray');
    }
    assert.isTrue(navigator.plugins.length > 0, 'navigator.plugins should not be empty');
    assert.isTrue(navigator.mimeTypes.length > 0, 'navigator.mimeTypes should not be empty');

    // 2. Check content (verify PDF plugins are present)
    const pdfViewerPlugin = navigator.plugins['Chrome PDF Viewer'];
    assert.isTrue(pdfViewerPlugin !== undefined && pdfViewerPlugin !== null, 'Chrome PDF Viewer plugin should exist (named access)');
    assert.equal(pdfViewerPlugin.name, 'Chrome PDF Viewer', 'Plugin name mismatch (Viewer)');

    const pdfInternalPlugin = navigator.plugins['Chrome PDF Plugin'];
    assert.isTrue(pdfInternalPlugin !== undefined && pdfInternalPlugin !== null, 'Chrome PDF Plugin should exist (named access)');


    const pdfMime = navigator.mimeTypes['application/pdf'];
    assert.isTrue(pdfMime !== undefined && pdfMime !== null, 'application/pdf MimeType should exist (named access)');

    // 3. Check linking
    // application/pdf should link to "Chrome PDF Plugin" (based on the mock data structure)
    assert.equal(pdfMime.enabledPlugin, pdfInternalPlugin, 'MimeType enabledPlugin link is incorrect');

    // Check Plugin internal MimeTypes access
    assert.equal(pdfInternalPlugin.length, 2, 'Chrome PDF Plugin should report 2 associated MimeTypes (pdf, text/pdf)');
    assert.equal(pdfInternalPlugin[0].type, 'application/pdf', 'Plugin indexed MimeType access failed');


    // 4. Check methods (item, namedItem, refresh)
    assert.equal(navigator.plugins.item(0).name, navigator.plugins[0].name, 'plugins.item() mismatch');
    assert.equal(navigator.plugins.item(999), null, 'plugins.item(OOB) should return null');

    assert.equal(navigator.plugins.namedItem('Native Client').name, 'Native Client', 'plugins.namedItem() mismatch');
    assert.isTrue(typeof navigator.plugins.refresh === 'function', 'plugins.refresh() missing');


    // 5. Check Masking and toStringTag
    const checkMasking = (func, name) => {
         assert.equal(func.toString(), `function ${name}() { [native code] }`, `${name} L1 masking failed`);
         // Check L2 masking (Authenticity)
         assert.equal(func.toString.toString, Function.prototype.toString, `${name} L2 masking function mismatch`);
         assert.isNative(func.toString.toString, `${name} L2 masking result`);
    };

    // Check masking on the Proxied functions
    checkMasking(navigator.plugins.refresh, 'refresh');
    checkMasking(navigator.plugins.item, 'item');
    checkMasking(navigator.plugins.namedItem, 'namedItem');
    checkMasking(navigator.mimeTypes.item, 'item');

    assert.equal(Object.prototype.toString.call(navigator.plugins), '[object PluginArray]', 'PluginArray toStringTag mismatch');
    assert.equal(Object.prototype.toString.call(pdfViewerPlugin), '[object Plugin]', 'Plugin toStringTag mismatch');

    // 6. Check enumerability (Advanced structural check)
    const pluginKeys = Object.keys(navigator.plugins);
    assert.isTrue(pluginKeys.includes('0'), 'Indexed properties should be enumerable on PluginArray');
    assert.isFalse(pluginKeys.includes('Chrome PDF Viewer'), 'Named properties should NOT be enumerable on PluginArray');

    const mimeKeys = Object.keys(navigator.mimeTypes);
    assert.isTrue(mimeKeys.includes('0'), 'Indexed properties should be enumerable on MimeTypeArray');
    assert.isFalse(mimeKeys.includes('application/pdf'), 'Named properties should NOT be enumerable on MimeTypeArray');

    const pdfInternalPluginKeys = Object.keys(pdfInternalPlugin);
    // Check that indexed MimeTypes (e.g. '0', '1') are NOT enumerable on the Plugin object itself
    assert.isFalse(pdfInternalPluginKeys.includes('0'), 'Indexed MimeTypes should NOT be enumerable on Plugin');

});

// Run the tests automatically when the script loads
ScalpelTestRunner.run();