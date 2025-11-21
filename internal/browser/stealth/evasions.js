// File: internal/browser/stealth/evasions.js
// This script runs in the browser context before any page scripts (via CDP Page.addScriptToEvaluateOnNewDocument).

(function() {
    'use strict';

    // Retrieve configuration injected via window.SCALPEL_PERSONA
    // NOTE: Properties are camelCase matching the Go struct JSON tags (e.g., userAgent).
    const persona = window.SCALPEL_PERSONA || {};

    // --- Utility Functions ---
    
    // Helper to get the authentic Function.prototype.toString (for masking)
    // (Improvement 2: Use the actual native function instead of a mock string generator).
    const authenticNativeToString = Function.prototype.toString;

    // Helper for safe property definition (getters).
    // (Improvement 5: Automatic Descriptor Mimicry)
    const overrideGetter = (obj, prop, value) => {
        try {
            // Try to find the original descriptor on the object or its prototype chain.
            let originalDescriptor = Object.getOwnPropertyDescriptor(obj, prop);
            if (!originalDescriptor && obj) {
                let proto = Object.getPrototypeOf(obj);
                while (proto && !originalDescriptor) {
                    originalDescriptor = Object.getOwnPropertyDescriptor(proto, prop);
                    proto = Object.getPrototypeOf(proto);
                }
            }

            // Determine flags. We mimic the original if found.
            // If the property doesn't exist, we default to true for flexibility (matching previous behavior).
            const configurable = originalDescriptor ? originalDescriptor.configurable : true;
            const enumerable = originalDescriptor ? originalDescriptor.enumerable : true;

            // Define the new property.
            const newDescriptor = {
                get: () => value,
                configurable: configurable,
                enumerable: enumerable,
            };

            Object.defineProperty(obj, prop, newDescriptor);
        } catch (error) {
            // console.warn(`Scalpel Stealth: Failed to override property ${prop}`, error);
        }
    };


    // Utility function to make functions appear native (Proxy + Authenticity).
    // (Fix 1: Detection via Function.prototype.toString.call)
    // This function now returns a Proxy wrapping the original function.
    const maskAsNative = (func, nameHint = '') => {
        // Robustness: If func is not actually a function, return it as is.
        if (typeof func !== 'function') {
            return func;
        }

        try {
            const name = nameHint || func.name || '';
            const nativeString = `function ${name}() { [native code] }`;

            // Define the spoofed toString function (Masking Level 1)
            const spoofedToString = function toString() { return nativeString; };

            // Advanced Evasion: Mask the toString function itself (Masking Level 2+)
            // We use the authentic nativeToString (Function.prototype.toString).
            Object.defineProperty(spoofedToString, 'toString', {
                 value: authenticNativeToString,
                 configurable: true,
                 enumerable: false, // Native toString is not enumerable
                 writable: false,
            });

            // (Fix 1): Use a Proxy to intercept Function.prototype.toString.call()
            const proxy = new Proxy(func, {
                get(target, prop, receiver) {
                    if (prop === 'toString') {
                        return spoofedToString;
                    }
                    // Ensure 'name' property is correct on the proxy if hinted
                    if (prop === 'name' && nameHint) {
                        return nameHint;
                    }
                    // Forward other properties, ensuring correct 'this' context.
                    return Reflect.get(target, prop, receiver);
                },
                // Ensure 'apply' (function calls) are forwarded correctly.
                apply(target, thisArg, argumentsList) {
                    return Reflect.apply(target, thisArg, argumentsList);
                }
            });

            // Defense-in-depth: also try to set the name property on the original function if possible.
            if (nameHint) {
                try {
                    Object.defineProperty(func, 'name', {
                        value: nameHint,
                        configurable: true,
                    });
                } catch (e) {}
            }


            return proxy;

        } catch (e) {
            // Fallback to the original function if Proxy creation fails.
            return func;
        }
    };


    // --- Evasion: Remove webdriver flag (CRITICAL) ---
    // Defining 'webdriver' on the Navigator prototype is the most robust method.
    if (navigator.webdriver !== false) {
        // overrideGetter now handles descriptor mimicry automatically.
        overrideGetter(Navigator.prototype, 'webdriver', false);
    }
    
    // Fallback check on the instance itself.
    try {
        if (navigator.webdriver === true) {
             // overrideGetter handles this case too.
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
        
        // Spoof window dimensions (outerWidth/Height and innerWidth/innerHeight).
        // (Fix for Bug 3: Inconsistent Dimensions)
        try {
            if (window.outerWidth !== persona.width) {
                Object.defineProperty(window, 'outerWidth', { get: () => persona.width, configurable: true });
            }
            if (window.outerHeight !== persona.height) {
                Object.defineProperty(window, 'outerHeight', { get: () => persona.height, configurable: true });
            }
            // Also spoof innerWidth/innerHeight for consistency.
            if (window.innerWidth !== persona.width) {
                Object.defineProperty(window, 'innerWidth', { get: () => persona.width, configurable: true });
            }
            if (window.innerHeight !== persona.height) {
                Object.defineProperty(window, 'innerHeight', { get: () => persona.height, configurable: true });
            }
        } catch (e) {}
    }
    
    // --- Evasion: Basic Chrome simulation (Robustness Fix) ---
    // Headless Chrome might lack window.chrome entirely, or provide a partial object without 'runtime'.
    
    // (Fix 1: Use Proxies)
    
    // 1. Define the core 'runtime' object and its masked functions.
    // We define the functions first, then mask them, then build the object structure.
    // (FIX: Explicitly provide nameHint for robustness against name stripping)
    const rtConnect = maskAsNative(function connect() { return { disconnect: () => {} }; }, 'connect');
    const rtSendMessage = maskAsNative(function sendMessage() {}, 'sendMessage');
    const rtGetManifest = maskAsNative(function getManifest() { return ({}); }, 'getManifest');
    // Mock common event listeners (using a shared masked addListener instance)
    const rtAddListener = maskAsNative(function addListener() {}, 'addListener');

    const runtimeObj = {
        connect: rtConnect,
        sendMessage: rtSendMessage,
        getManifest: rtGetManifest,
        id: undefined,
        onConnect: { addListener: rtAddListener },
        onMessage: { addListener: rtAddListener },
    };

    // 2. Ensure window.chrome exists.
    if (window.chrome === undefined) {
        // Minimal 'app' object (often checked, though deprecated)
        const appObj = {
            isInstalled: false,
            // (FIX: Explicitly provide nameHint)
            getDetails: maskAsNative(function getDetails() { return null; }, 'getDetails')
        };
        
        const chromeObj = {
            runtime: runtimeObj,
            app: appObj,
            // webstore is also sometimes checked
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
                    // Return consistent 'prompt' state.
                    // (Fix for Bug 2: Handle missing window.Notification).
                    const permissionState = window.Notification
                        ? ((Notification.permission === 'default') ? 'prompt' : Notification.permission)
                        : 'prompt';
                    
                    // (Fix 4: Avoid Prototype Manipulation)
                    // Strategy: Call the original query and wrap the result in a Proxy.
                    // This avoids modifying PermissionStatus.prototype, which is detectable and risky.

                    try {
                        // Call the original query.
                        return originalQuery.call(this, parameters).then(result => {
                            
                            // Wrap the native result in a Proxy.
                            // This ensures that accessing 'state' returns the spoofed permissionState, 
                            // without modifying the prototype or defining a detectable 'own property'.
                            return new Proxy(result, {
                                get: function(target, prop, receiver) {
                                    if (prop === 'state') {
                                        return permissionState;
                                    }
                                    // Forward other properties (like 'onchange')
                                    return Reflect.get(target, prop, receiver);
                                }
                            });
                        });
                        // Errors from originalQuery propagate naturally.
                    } catch (error) {
                        // Handle synchronous errors during the call (e.g. invalid parameter name).
                        throw error;
                    }
                }
                // Use the context of the navigator.permissions object
                return originalQuery.call(this, parameters);
            };

            // Masking: Make the function appear native.
            // (Fix 1): Use the Proxy returned by maskAsNative.
            const maskedQuery = maskAsNative(spoofedQuery, 'query');

            Object.defineProperty(navigator.permissions, 'query', {
                value: maskedQuery, // Use the masked proxy
                configurable: true,
                writable: false // Make it non-writable for better stealth
            });
        }
    } catch (error) {
        // console.warn("Scalpel Stealth: Failed to spoof Permissions API", error);
    }

    // --- Evasion: WebGL (Advanced) ---
    // Spoofing of WebGL vendor/renderer if persona data is available.
    if (persona.webGLVendor && persona.webGLRenderer) {
        try {
            // Constants for WEBGL_debug_renderer_info (Fix for Bug 7: Robustness)
            const UNMASKED_VENDOR_WEBGL = 0x9245;
            const UNMASKED_RENDERER_WEBGL = 0x9246;

            const overrideWebGLContext = (proto) => {
                const originalGetParameter = proto.getParameter;
                
                const spoofedGetParameter = function getParameter(parameter) {
                    
                    // Check against hardcoded constants (Fix for Bug 7).
                    if (parameter === UNMASKED_VENDOR_WEBGL) return persona.webGLVendor;
                    if (parameter === UNMASKED_RENDERER_WEBGL) return persona.webGLRenderer;

                    // (Fix for Bug 6: Aggressive Spoofing)
                    // We do NOT override standard gl.VENDOR/gl.RENDERER. They should return
                    // the browser's generic values (e.g. "Google Inc."), not high-entropy hardware data.

                    return originalGetParameter.call(this, parameter);
                };
                
                // Masking getParameter
                // (Fix 1): Use the Proxy returned by maskAsNative.
                const maskedGetParameter = maskAsNative(spoofedGetParameter, 'getParameter');
                
                Object.defineProperty(proto, 'getParameter', {
                    value: maskedGetParameter, // Use the masked proxy
                    configurable: true
                });
            };

            if (window.WebGLRenderingContext) overrideWebGLContext(WebGLRenderingContext.prototype);
            if (window.WebGL2RenderingContext) overrideWebGLContext(WebGL2RenderingContext.prototype);
            
        } catch (error) {}
    }

    // --- Evasion: navigator.plugins and navigator.mimeTypes (Advanced) ---
    // (Fix 6: Implement Plugins/MimeTypes Evasion)
    // (FIX: Refactor using Proxies and Intermediate Prototypes to handle strict mode and exotic behavior)

    const mockPluginsAndMimeTypes = () => {
        try {
            // 1. Define Mock Data (Standard set found in modern Chrome)
            const mocks = [
                {
                    plugin: {
                        name: "Chrome PDF Plugin",
                        filename: "internal-pdf-viewer",
                        description: "Portable Document Format"
                    },
                    mimeTypes: [
                        { type: "application/pdf", suffixes: "pdf", description: "Portable Document Format" },
                        { type: "text/pdf", suffixes: "pdf", description: "Portable Document Format" }
                    ]
                },
                {
                     plugin: {
                        name: "Chrome PDF Viewer",
                        filename: "mhjfbmdgcfjbbpaeojofohoefgiehjai",
                        description: ""
                    },
                    mimeTypes: []
                },
                {
                     plugin: {
                        name: "Native Client",
                        filename: "internal-nacl-plugin",
                        description: ""
                    },
                    mimeTypes: [
                         { type: "application/x-nacl", suffixes: "", description: "Native Client Executable" },
                         { type: "application/x-pnacl", suffixes: "", description: "Portable Native Client Executable" },
                    ]
                }
            ];

            // 2. Helper functions for creating mock objects.

            // Helper to create a base object with correct prototype and toStringTag.
            const createMockBase = (protoName) => {
                let proto = window[protoName] ? window[protoName].prototype : Object.prototype;
                const obj = Object.create(proto);
                // Ensure toStringTag is set correctly
                try {
                    // Check if it's already correctly inherited, if not define it.
                    if (Object.prototype.toString.call(obj) !== `[object ${protoName}]`) {
                        Object.defineProperty(obj, Symbol.toStringTag, {
                            value: protoName,
                            configurable: false
                        });
                    }
                } catch (e) {}
                return obj;
            };

            // (FIX): Helper to create Plugin/MimeType items (instances).
            // We must override the read-only getters inherited from the prototype (strict mode fix).
            const createMockItem = (protoName, data) => {
                const obj = createMockBase(protoName);
                
                // Use overrideGetter to define the property on the instance, shadowing the prototype getter.
                Object.keys(data).forEach(key => {
                    overrideGetter(obj, key, data[key]);
                });
                return obj;
            };


            // 3. Prepare internal structures. Use Maps for efficient named lookups.
            const internalPlugins = new Map(); // Keyed by name
            const internalMimeTypes = new Map(); // Keyed by type

            // 4. Populate the internal structures
            mocks.forEach(mock => {
                const plugin = createMockItem('Plugin', mock.plugin);
                
                const associatedMimeTypes = [];

                mock.mimeTypes.forEach(mtMock => {
                    // Handle deduplication
                    let mimeType;
                    if (internalMimeTypes.has(mtMock.type)) {
                        mimeType = internalMimeTypes.get(mtMock.type);
                    } else {
                        mimeType = createMockItem('MimeType', mtMock);
                        internalMimeTypes.set(mimeType.type, mimeType);
                    }
                    
                    // Link MimeType to Plugin (enabledPlugin property)
                    // If multiple plugins support a type, the first one encountered typically wins.
                    if (Object.getOwnPropertyDescriptor(mimeType, 'enabledPlugin') === undefined) {
                         overrideGetter(mimeType, 'enabledPlugin', plugin);
                    }

                    associatedMimeTypes.push(mimeType);
                });

                // Link Plugin to MimeTypes (indexed access on the Plugin object itself)
                associatedMimeTypes.forEach((mt, index) => {
                    Object.defineProperty(plugin, index, {
                        value: mt,
                        enumerable: false, // CRITICAL: Native behavior: indexed properties on Plugin are NOT enumerable
                        configurable: true,
                    });
                });
                // Define length property on the plugin
                Object.defineProperty(plugin, 'length', { value: associatedMimeTypes.length, configurable: true, writable: true });

                // Add to internal map
                if (!internalPlugins.has(plugin.name)) {
                    internalPlugins.set(plugin.name, plugin);
                }
            });

            // 5. Create the Proxy-based Array objects (PluginArray, MimeTypeArray)
            // (FIX: Use Intermediate Prototype Strategy to handle exotic named access without violating Proxy invariants)

            const createMockArrayProxy = (protoName, internalMap) => {
                const nativeProto = window[protoName] ? window[protoName].prototype : Object.prototype;
                const items = Array.from(internalMap.values());

                // A. Create Intermediate Prototype for Named Access
                const intermediateProto = Object.create(nativeProto);
                
                // Define named properties as getters on the intermediate prototype.
                internalMap.forEach((value, key) => {
                    Object.defineProperty(intermediateProto, key, {
                        get: () => value,
                        enumerable: false, // CRITICAL: Named properties are NOT enumerable
                        configurable: true
                    });
                });

                // B. Create the Base Object (Proxy Target), inheriting from intermediateProto.
                const base = Object.create(intermediateProto);
                
                 // Ensure toStringTag is correctly set on the base object if needed.
                try {
                     if (Object.prototype.toString.call(base) !== `[object ${protoName}]`) {
                        Object.defineProperty(base, Symbol.toStringTag, {
                            value: protoName,
                            configurable: false
                        });
                    }
                } catch (e) {}

                // C. Define Methods (item, namedItem, refresh) and Length on the base object.
                
                const mockItem = function item(index) {
                    // Native behavior coerces index to number.
                    return items[Number(index)] || null;
                };
                const maskedItem = maskAsNative(mockItem, 'item');
                Object.defineProperty(base, 'item', { value: maskedItem, configurable: true, enumerable: true });

                const mockNamedItem = function namedItem(name) {
                    // Native behavior coerces name to string.
                    return internalMap.get(String(name)) || null;
                };
                const maskedNamedItem = maskAsNative(mockNamedItem, 'namedItem');
                Object.defineProperty(base, 'namedItem', { value: maskedNamedItem, configurable: true, enumerable: true });

                if (protoName === 'PluginArray') {
                    const mockRefresh = function refresh() {};
                    const maskedRefresh = maskAsNative(mockRefresh, 'refresh');
                    Object.defineProperty(base, 'refresh', { value: maskedRefresh, configurable: true, enumerable: true });
                }

                Object.defineProperty(base, 'length', { value: items.length, configurable: true, writable: true });


                // D. Create the Proxy
                const proxy = new Proxy(base, {
                    get(target, prop, receiver) {
                        // Handle symbols (like Symbol.iterator)
                        if (typeof prop === 'symbol') {
                            return Reflect.get(target, prop, receiver);
                        }

                        const propString = String(prop);

                        // 1. Handle Indexed Access (Must be handled by the proxy trap)
                        const index = Number(propString);
                        // Check for valid array index (non-negative integer, canonical string representation).
                        if (Number.isInteger(index) && index >= 0 && String(index) === propString) {
                             return items[index];
                        }
                        
                        // 2. Handle Named Access, Methods, Length (Delegated to prototype chain/base object)
                        // Reflect.get handles lookup on base (methods, length) and intermediate prototype (named access).
                        return Reflect.get(target, prop, receiver);
                    },
                    
                    getOwnPropertyDescriptor(target, prop) {
                        // Handle symbols
                        if (typeof prop === 'symbol') {
                            return Reflect.getOwnPropertyDescriptor(target, prop);
                        }
                        
                        const propString = String(prop);

                        // 1. Handle Indexed Access (Define as own properties on the proxy)
                        const index = Number(propString);
                        if (Number.isInteger(index) && index >= 0 && String(index) === propString && index < items.length) {
                            return {
                                value: items[index],
                                enumerable: true, // CRITICAL: Indexed properties ARE enumerable
                                configurable: true,
                                writable: true
                            };
                        }

                        // 2. Handle Named Access (Must return undefined, as they are inherited)
                        if (internalMap.has(propString)) {
                            return undefined;
                        }

                        // 3. Handle Methods/Length (Defined on the base object)
                        return Reflect.getOwnPropertyDescriptor(target, prop);
                    },
                    
                    ownKeys(target) {
                        // Should return indexed keys + own keys of the base object (methods, length).
                        const keys = [];
                        // Indexed keys
                        for (let i = 0; i < items.length; i++) {
                            keys.push(String(i));
                        }
                        // Base object keys
                        const baseKeys = Reflect.ownKeys(target);
                         // Ensure unique keys
                        baseKeys.forEach(key => {
                            // Check if the key (string or symbol) is already present.
                            if (!keys.includes(key) && !(typeof key === 'string' && keys.includes(key))) {
                                 keys.push(key);
                            }
                        });
                        
                        // Named properties are correctly excluded (they are on the prototype).
                        return keys;
                    }
                });

                return proxy;
            };

            const pluginArray = createMockArrayProxy('PluginArray', internalPlugins);
            const mimeTypeArray = createMockArrayProxy('MimeTypeArray', internalMimeTypes);


            // 7. Apply the overrides
            // overrideGetter handles descriptor mimicry automatically.
            overrideGetter(Navigator.prototype, 'plugins', pluginArray);
            overrideGetter(Navigator.prototype, 'mimeTypes', mimeTypeArray);

        } catch (error) {
            // console.warn("Scalpel Stealth: Failed to spoof Plugins/MimeTypes", error);
        }
    };

    // Check if overrides are needed (Headless often reports 0, or might lack the prototypes entirely)
    if (!window.PluginArray || navigator.plugins.length === 0 || !window.MimeTypeArray || navigator.mimeTypes.length === 0) {
         mockPluginsAndMimeTypes();
    }

})();