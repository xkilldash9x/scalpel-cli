// File: internal/browser/stealth/evasions.js
// This script runs in the browser context before any page scripts (via CDP Page.addScriptToEvaluateOnNewDocument).

(function() {
    'use strict';

    // Retrieve configuration injected via window.SCALPEL_PERSONA
    // NOTE: Properties are camelCase matching the Go struct JSON tags (e.g., userAgent).
    const persona = window.SCALPEL_PERSONA || {};

    // --- Utility Functions ---

    // Helper for safe property definition (getters).
    const overrideGetter = (obj, prop, value) => {
        try {
            Object.defineProperty(obj, prop, {
                get: () => value,
                configurable: true,
                enumerable: true
            });
        } catch (error) {
            // console.warn(`Scalpel Stealth: Failed to override property ${prop}`, error);
        }
    };

    // Utility function to make functions appear native (Advanced: Double Masking).
    const maskAsNative = (func, nameHint = '') => {
        try {
            const name = nameHint || func.name || '';
            const nativeString = `function ${name}() { [native code] }`;

            // Define the spoofed toString function
            const spoofedToString = () => nativeString;

            // Advanced Evasion: Mask the toString function itself (Double Masking)
            // This defeats detectors that check func.toString.toString().
            Object.defineProperty(spoofedToString, 'toString', {
                 value: () => 'function toString() { [native code] }',
                 configurable: true,
            });

            // Override instance toString
            Object.defineProperty(func, 'toString', {
                value: spoofedToString,
                configurable: true,
            });

        } catch (e) {}
    };


    // --- Evasion: Remove webdriver flag (CRITICAL) ---
    // Defining 'webdriver' on the Navigator prototype is the most robust method.
    if (navigator.webdriver !== false) {
        overrideGetter(Navigator.prototype, 'webdriver', false);
    }
    
    // Fallback check on the instance itself.
    try {
        if (navigator.webdriver === true) {
             overrideGetter(navigator, 'webdriver', false);
        }
    } catch (error) {
        // Ignore if instance override fails.
    }

    // Apply persona configurations.
    // --- Evasion: Navigator Properties ---
    if (persona.userAgent) {
        overrideGetter(Navigator.prototype, 'userAgent', persona.userAgent);
        // Also override appVersion which is derived from UserAgent.
        overrideGetter(Navigator.prototype, 'appVersion', persona.userAgent.replace(/^Mozilla\//, ''));
    }
    if (persona.platform) {
        overrideGetter(Navigator.prototype, 'platform', persona.platform);
    }
    if (Array.isArray(persona.languages) && persona.languages.length > 0) {
        // Languages should be a frozen array to mimic native behavior.
        const languages = Object.freeze([...persona.languages]);
        overrideGetter(Navigator.prototype, 'languages', languages);
        // Also override the singular 'language' property.
        overrideGetter(Navigator.prototype, 'language', languages[0]);
    }

    // --- Evasion: Screen Properties (Advanced) ---
    if (persona.width && persona.height && window.screen) {
        overrideGetter(Screen.prototype, 'width', persona.width);
        overrideGetter(Screen.prototype, 'height', persona.height);
        
        // Use provided values or fallback to main dimensions/defaults
        const availWidth = persona.availWidth || persona.width;
        const availHeight = persona.availHeight || persona.height;

        // Robustness: Clarify ColorDepth vs DPR.
        // Persona.colorDepth is the screen color depth (e.g. 24, 32).
        // Persona.pixelDepth is used as DevicePixelRatio (DPR) in the Go CDP implementation.
        // screen.pixelDepth in JS should match screen.colorDepth.
        const colorDepth = persona.colorDepth || 24;
        const pixelDepth = colorDepth;

        overrideGetter(Screen.prototype, 'availWidth', availWidth);
        overrideGetter(Screen.prototype, 'availHeight', availHeight);
        overrideGetter(Screen.prototype, 'colorDepth', colorDepth);
        overrideGetter(Screen.prototype, 'pixelDepth', pixelDepth);
        
        // Also spoof outerWidth/Height on the window object.
        try {
            if (window.outerWidth !== persona.width) {
                Object.defineProperty(window, 'outerWidth', { get: () => persona.width, configurable: true });
            }
            if (window.outerHeight !== persona.height) {
                Object.defineProperty(window, 'outerHeight', { get: () => persona.height, configurable: true });
            }
        } catch (e) {}
    }
    
    // --- Evasion: Basic Chrome simulation (Robustness Fix) ---
    // Headless Chrome might lack window.chrome entirely, or provide a partial object without 'runtime'.
    
    // 1. Define the core 'runtime' object and its masked functions.
    const runtimeObj = {
        connect: function connect() { return { disconnect: () => {} }; },
        sendMessage: function sendMessage() {},
        getManifest: function getManifest() { return ({}); },
        id: undefined,
    };
    maskAsNative(runtimeObj.connect);
    maskAsNative(runtimeObj.sendMessage);
    maskAsNative(runtimeObj.getManifest);

    // 2. Ensure window.chrome exists.
    if (window.chrome === undefined) {
        const appObj = { isInstalled: false, getDetails: function getDetails() { return null; } };
        maskAsNative(appObj.getDetails);

        const chromeObj = {
            runtime: runtimeObj,
            app: appObj,
            webstore: { installed: false },
        };

        Object.defineProperty(window, 'chrome', {
            value: chromeObj,
            writable: true, // Allows potential polyfills by the page itself
            configurable: true
        });
    }

    // 3. Ensure window.chrome.runtime exists (Defense in depth against partial implementations).
    if (window.chrome && window.chrome.runtime === undefined) {
         try {
            Object.defineProperty(window.chrome, 'runtime', {
                value: runtimeObj,
                writable: true,
                configurable: true,
                enumerable: true
            });
         } catch (e) {
             // Handle potential errors if window.chrome was frozen or non-configurable.
         }
    }


    // --- Evasion: Permissions API (Advanced) ---
    try {
        if (navigator.permissions && navigator.permissions.query && window.PermissionStatus) {
            const originalQuery = navigator.permissions.query;
            
            // Override the query function
            const spoofedQuery = function query(parameters) {
                // Input validation mimicking native behavior (Robustness)
                if (!parameters) {
                    throw new TypeError("Failed to execute 'query' on 'Permissions': 1 argument required, but only 0 present.");
                }
                if (typeof parameters !== 'object' || parameters === null) {
                     throw new TypeError("Failed to execute 'query' on 'Permissions': The provided value is not of type 'PermissionDescriptor'.");
                }
                if (!parameters.name) {
                    throw new TypeError("Failed to execute 'query' on 'Permissions': Failed to read the 'name' property from 'PermissionDescriptor': Required member is undefined.");
                }


                if (parameters.name === 'notifications') {
                    // Return consistent 'prompt' state instead of 'granted'/'denied' which headless often defaults to.
                    const permissionState = (window.Notification && Notification.permission === 'default') ? 'prompt' : Notification.permission;
                    
                    // Return a realistic PermissionStatus object instance.
                    return Promise.resolve(Object.create(PermissionStatus.prototype, {
                        state: { value: permissionState, enumerable: true },
                        name: { value: 'notifications', enumerable: true },
                        onchange: { value: null, writable: true, enumerable: true }
                    }));
                }
                // Use the context of the navigator.permissions object
                return originalQuery.call(this, parameters);
            };

            // Masking: Make the function appear native (includes Double Masking).
            maskAsNative(spoofedQuery);

            Object.defineProperty(navigator.permissions, 'query', {
                value: spoofedQuery,
                configurable: true,
                writable: false // Make it non-writable for better stealth
            });
        }
    } catch (error) {
        // console.warn("Scalpel Stealth: Failed to spoof Permissions API", error);
    }

    // --- Evasion: WebGL (Basic) ---
    // Basic spoofing of WebGL vendor/renderer if persona data is available.
    if (persona.webGLVendor && persona.webGLRenderer) {
        try {
            const overrideWebGLContext = (proto) => {
                const originalGetParameter = proto.getParameter;
                
                const spoofedGetParameter = function getParameter(parameter) {
                    const gl = this;
                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    
                    if (debugInfo) {
                        if (parameter === debugInfo.UNMASKED_VENDOR_WEBGL) return persona.webGLVendor;
                        if (parameter === debugInfo.UNMASKED_RENDERER_WEBGL) return persona.webGLRenderer;
                    }
                    // Fallback for standard parameters
                    if (parameter === gl.VENDOR) return persona.webGLVendor;
                    if (parameter === gl.RENDERER) return persona.webGLRenderer;

                    return originalGetParameter.call(this, parameter);
                };
                
                // Masking getParameter (includes Double Masking)
                maskAsNative(spoofedGetParameter);

                Object.defineProperty(proto, 'getParameter', {
                    value: spoofedGetParameter,
                    configurable: true
                });
            };

            if (window.WebGLRenderingContext) overrideWebGLContext(WebGLRenderingContext.prototype);
            if (window.WebGL2RenderingContext) overrideWebGLContext(WebGL2RenderingContext.prototype);
            
        } catch (error) {}
    }

})();