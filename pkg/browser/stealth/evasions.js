// pkg/browser/stealth/evasions.js
// Production-grade evasion script for Project Scalpel.
// Enhanced for advanced adversarial simulation.

// SCALPEL_PERSONA is injected globally by the Go host before this script executes.

(() => {
    'use strict';

    if (typeof SCALPEL_PERSONA === 'undefined') {
        console.error("Scalpel: SCALPEL_PERSONA configuration not injected. Evasions disabled.");
        return;
    }

    // ====================================================================================
    // UTILITY FUNCTIONS - The toolkit for surgical modifications.
    // ====================================================================================

    const utils = {
        // Replaces a property with a fixed value (getter only).
        replaceProperty: (obj, prop, value) => {
            try {
                const descriptor = Object.getOwnPropertyDescriptor(obj, prop);
                const enumerable = descriptor ? descriptor.enumerable : true;

                Object.defineProperty(obj, prop, {
                    get: () => value,
                    set: (v) => { /* No-op */ },
                    configurable: true,
                    enumerable: enumerable,
                });
            } catch (e) {
                console.error(`Scalpel: Failed to replace property ${prop}`, e);
            }
        },

        originals: new WeakMap(),
        originalImpls: new Map(),

        /**
         * Patches a function using a Proxy. Hardened against sophisticated detection.
         */
        patchFunction: (obj, prop, handler, implementationKey = null) => {
            const originalFn = obj[prop];
            if (typeof originalFn !== 'function') return;

            const originalToString = Function.prototype.toString.call(originalFn);
            utils.originals.set(originalFn, originalToString);

            if (implementationKey && !utils.originalImpls.has(implementationKey)) {
                utils.originalImpls.set(implementationKey, originalFn);
            }

            const replacementFn = function(...args) {
                return handler.call(this, originalFn, ...args);
            };

            // HARDENING: Mimic function properties (name, length) and prototype chain.
            try {
                Object.defineProperty(replacementFn, 'name', { value: originalFn.name, configurable: true });
                Object.defineProperty(replacementFn, 'length', { value: originalFn.length, configurable: true });
                Object.setPrototypeOf(replacementFn, Object.getPrototypeOf(originalFn));
            } catch (e) {}

            const proxy = new Proxy(replacementFn, {
                get(target, key, receiver) {
                    if (key === 'toString') {
                        return () => originalToString;
                    }
                    // HARDENING: Forward property access if not on replacement.
                    if (!(key in target) && key in originalFn) {
                        return Reflect.get(originalFn, key);
                    }
                    return Reflect.get(target, key, receiver);
                },
                apply(target, thisArg, args) {
                    return Reflect.apply(target, thisArg, args);
                },
                 // HARDENING: Handle constructor calls.
                construct(target, args, newTarget) {
                    if (typeof originalFn.prototype !== 'undefined') {
                        return Reflect.construct(originalFn, args, newTarget);
                    }
                    return Reflect.construct(target, args, newTarget);
                }
            });

            // Mask the proxy's own toString method.
            const toStringProxy = new Proxy(proxy.toString, {
                apply(target, thisArg, args) {
                    if (thisArg === proxy || thisArg === replacementFn) {
                        return originalToString;
                    }
                    return Reflect.apply(target, thisArg, args);
                }
            });
            
            try {
                Object.defineProperty(proxy, 'toString', { value: toStringProxy, writable: true, configurable: true });
            } catch (e) {}

            // Replace the property, preserving attributes.
             try {
                const descriptor = Object.getOwnPropertyDescriptor(obj, prop);
                const attributes = {
                    value: proxy,
                    writable: descriptor ? descriptor.writable : true,
                    configurable: descriptor ? descriptor.configurable : true,
                    enumerable: descriptor ? descriptor.enumerable : true
                };
                Object.defineProperty(obj, prop, attributes);
            } catch (e) {
                 obj[prop] = proxy;
            }
            utils.originals.set(proxy, originalToString);
        },

        patchPrototypeFunction: (proto, prop, handler) => {
            const protoRef = (proto && proto.prototype) ? proto.prototype : proto;

            if (protoRef && typeof protoRef[prop] === 'function') {
                let key = null;
                try {
                    const name = proto.name || (protoRef.constructor && protoRef.constructor.name);
                    if (name) {
                        key = `${name}.${prop}`;
                    }
                } catch (e) {}
                
                utils.patchFunction(protoRef, prop, handler, key);
           }
        },

        getOriginalImpl: (key) => {
            return utils.originalImpls.get(key);
        },

        // Seeded pseudo-random number generator (Mulberry32) for deterministic noise.
        createSeededRNG: (seed) => {
            let s = seed | 0;
            return () => {
                s = (s + 0x6D2B79F5) | 0;
                let t = Math.imul(s ^ s >>> 15, 1 | s);
                t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
                return ((t ^ t >>> 14) >>> 0) / 4294967296;
            };
        },
    };

    const seed = SCALPEL_PERSONA.noiseSeed || Date.now();
    const seededRNG = utils.createSeededRNG(seed);

    // ====================================================================================
    // EVASION 0: GLOBAL ENVIRONMENT SANITIZATION
    // ====================================================================================

    // 0.1 Global Object Cleanup: Eradicate WebDriver/Automation artifacts.
    try {
        const webdriverVars = [
            '$cdc_asdjflasutopfhvcZLmcfl_', '__webdriver_script_fn', '__driver_evaluate',
            '__selenium_evaluate', '__fxdriver_evaluate', '__webdriver_unwrapped',
            '__pw_script', '__puppeteer_evaluation_script__', // Playwright/Puppeteer
        ];
        for (const key of webdriverVars) {
            if (window[key]) {
                try { delete window[key]; } catch (e) {}
            }
        }

        for (const key in document) {
            if (key.match(/\$cdc_/) || key.match(/__webdriver/)) {
                try { delete document[key]; } catch(e) {}
            }
        }
    } catch (e) {}


    // 0.2 FUNCTION.PROTOTYPE.TOSTRING GLOBAL OVERRIDE
    const originalGlobalToString = Function.prototype.toString;
    utils.originals.set(originalGlobalToString, Function.prototype.toString.call(originalGlobalToString));

    Function.prototype.toString = function() {
        const storedOriginal = utils.originals.get(this);
        if (storedOriginal) {
            return storedOriginal;
        }
        return originalGlobalToString.apply(this, arguments);
    };

    // 0.3 ADVANCED: Error Stack Trace Sanitization
    // Prevent leaks of the automation environment or injection script paths in error traces.
    try {
        const sanitizeTrace = (trace) => {
            if (typeof trace !== 'string') return trace;
            // Generic replacements for common automation environments and evaluation script markers.
            trace = trace.replace(/pptr:\/\/[^\s)]+/g, '(internal/process/task_queues.js:1:1)');
            trace = trace.replace(/cdp:\/\/[^\s)]+/g, '(internal/process/task_queues.js:1:1)');
            trace = trace.replace(/__puppeteer_evaluation_script__/g, '<anonymous>');
            trace = trace.replace(/__playwright_evaluation_script__/g, '<anonymous>');
            // Remove evidence of our own utility functions/proxies.
            trace = trace.replace(/at replacementFn \(<anonymous>:\d+:\d+\)/g, 'at <anonymous>');
            trace = trace.replace(/at Proxy\.apply \(<anonymous>\)/g, '');
            return trace;
        };

        const originalPrepareStackTrace = Error.prepareStackTrace;
        Error.prepareStackTrace = (error, structuredStackTrace) => {
            let trace;
            if (originalPrepareStackTrace) {
                trace = originalPrepareStackTrace(error, structuredStackTrace);
            } else {
                trace = error.toString() + '\n' + structuredStackTrace.map(frame => '    at ' + frame.toString()).join('\n');
            }
            return sanitizeTrace(trace);
        };

        // Also patch the 'stack' getter on Error.prototype.
        const stackDesc = Object.getOwnPropertyDescriptor(Error.prototype, 'stack');
        if (stackDesc && stackDesc.get) {
            const originalStackGetter = stackDesc.get;
            Object.defineProperty(Error.prototype, 'stack', {
                get: function() {
                    let stack = originalStackGetter.call(this);
                    return sanitizeTrace(stack);
                },
                configurable: true
            });
        }
    } catch (e) {
        console.error('Scalpel: Failed to sanitize Error stack traces', e);
    }

    // ====================================================================================
    // EVASION 1: NAVIGATOR API SPOOFING
    // ====================================================================================

    // 1.1 Remove 'navigator.webdriver'.
    if (navigator.webdriver) {
        try {
            delete Navigator.prototype.webdriver;
        } catch (e) {
            utils.replaceProperty(navigator, 'webdriver', false);
        }
    }

    // 1.2 Core property spoofing.
    utils.replaceProperty(navigator, 'languages', SCALPEL_PERSONA.languages || ["en-US", "en"]);
    utils.replaceProperty(navigator, 'platform', SCALPEL_PERSONA.platform || 'Win32');
    utils.replaceProperty(navigator, 'hardwareConcurrency', SCALPEL_PERSONA.hardwareConcurrency || 8);

    if ('deviceMemory' in navigator) {
        utils.replaceProperty(navigator, 'deviceMemory', SCALPEL_PERSONA.deviceMemory || 8);
    }

    // 1.3 Network Information API Spoofing.
    if ('connection' in navigator && navigator.connection) {
        utils.replaceProperty(navigator.connection, 'downlink', SCALPEL_PERSONA.networkDownlink || 10);
        utils.replaceProperty(navigator.connection, 'effectiveType', SCALPEL_PERSONA.networkType || '4g');
        utils.replaceProperty(navigator.connection, 'rtt', SCALPEL_PERSONA.networkRtt || 50);
    }

    // 1.4 ADVANCED: User-Agent Client Hints (navigator.userAgentData).
    if ('userAgentData' in navigator && SCALPEL_PERSONA.clientHintsData) {
        const ch = SCALPEL_PERSONA.clientHintsData;
        const mockedUserAgentData = {
            brands: ch.brands || [],
            mobile: ch.mobile || false,
            platform: ch.platform || "",
            getHighEntropyValues: (hints) => {
                return new Promise((resolve) => {
                    const highEntropyValues = {
                        brands: ch.brands || [],
                        mobile: ch.mobile || false,
                        platform: ch.platform || "",
                        architecture: ch.architecture || "",
                        bitness: ch.bitness || "",
                        model: ch.model || "",
                        platformVersion: ch.platformVersion || "",
                        fullVersionList: ch.fullVersionList || ch.brands || [],
                    };
                    const result = {};
                    if (Array.isArray(hints)) {
                        hints.forEach(hint => {
                            if (highEntropyValues.hasOwnProperty(hint)) {
                                result[hint] = highEntropyValues[hint];
                            }
                        });
                    }
                    resolve(result);
                });
            }
        };
        utils.replaceProperty(navigator, 'userAgentData', mockedUserAgentData);
    }

    // ====================================================================================
    // EVASION 2: HIGH-FIDELITY PLUGIN ARRAY MOCKING
    // (Implementation is robust, retained as is)
    // ====================================================================================

    const createPlugin = (name, description, filename, mimeTypes = []) => {
        const plugin = { name, description, filename };
        Object.setPrototypeOf(plugin, Plugin.prototype);

        const mimeTypeArray = mimeTypes.map(mt => {
            const mimeType = { type: mt.type, suffixes: mt.suffixes, description: mt.description, enabledPlugin: plugin };
            Object.setPrototypeOf(mimeType, MimeType.prototype);
            return mimeType;
        });

         const mimeHandler = {
             get: (target, prop) => {
                if (prop === 'length') return target.length;
                if (prop === 'item') return (idx) => target[idx] || null;
                if (prop === 'namedItem') return (name) => target.find(m => m.type === name) || null;
                if (typeof prop === 'string' && /^\d+$/.test(prop)) return target[parseInt(prop, 10)];
                if (typeof prop === 'string') {
                     const mt = target.find(m => m.type === prop);
                     if (mt) return mt;
                }
                if (prop === Symbol.iterator) return function*() { yield* target; };
                return Reflect.get(target, prop);
            },
        };
        const mockedMimeTypeArray = new Proxy(mimeTypeArray, mimeHandler);
        Object.setPrototypeOf(mockedMimeTypeArray, MimeTypeArray.prototype);

        Object.assign(plugin, mockedMimeTypeArray);
        plugin.length = mimeTypeArray.length;

        return Object.freeze(plugin);
    };

    // Mock standard Chrome plugins.
    const mockedPlugins = [
        createPlugin('Chrome PDF Plugin', 'Portable Document Format', 'internal-pdf-viewer', [
            { type: 'application/x-google-chrome-pdf', suffixes: 'pdf', description: 'Portable Document Format' }
        ]),
        createPlugin('Chrome PDF Viewer', '', 'mhjfbmdgcfjbbpaeojofohoefgiehjai', [
             { type: 'application/pdf', suffixes: 'pdf', description: '' }
        ]),
        createPlugin('Native Client', '', 'internal-nacl-plugin', [
            { type: 'application/x-nacl', suffixes: '', description: 'Native ClientExecutable' },
            { type: 'application/x-pnacl', suffixes: '', description: 'Portable Native Client Executable' }
        ]),
    ];

    const pluginsHandler = {
        get: (target, prop) => {
            if (prop === 'length') return target.length;
            if (prop === 'item') return (idx) => target[idx] || null;
            if (prop === 'namedItem') return (name) => target.find(p => p.name === name) || null;
            if (typeof prop === 'string' && /^\d+$/.test(prop)) return target[parseInt(prop, 10)];
            if (typeof prop === 'string') {
                const plugin = target.find(p => p.name === prop);
                if (plugin) return plugin;
            }

            if (prop === Symbol.iterator) return function*() { yield* target; };
            return Reflect.get(target, prop);
        },
        ownKeys: (target) => {
            const keys = [...Array(target.length).keys()].map(k => k.toString());
            keys.push(...target.map(p => p.name));
            return keys;
        },
        getOwnPropertyDescriptor(target, prop) {
            if (typeof prop === 'string' && /^\d+$/.test(prop) && target[parseInt(prop, 10)]) {
                return { configurable: true, enumerable: true, value: target[parseInt(prop, 10)] };
            }
             if (typeof prop === 'string') {
                const plugin = target.find(p => p.name === prop);
                // Named properties are enumerable: false in native PluginArray.
                if (plugin) return { configurable: true, enumerable: false, value: plugin };
            }
            return Reflect.getOwnPropertyDescriptor(target, prop);
        }
    };

    const mockedPluginArray = new Proxy(mockedPlugins, pluginsHandler);
    Object.setPrototypeOf(mockedPluginArray, PluginArray.prototype);
    utils.replaceProperty(navigator, 'plugins', mockedPluginArray);

    // Consistency: Mock navigator.mimeTypes.
    const allMimeTypes = mockedPlugins.flatMap(p => Array.from(p));
     const mimeTypesHandlerGlobal = {
          get: (target, prop) => {
             if (prop === 'length') return target.length;
             if (prop === 'item') return (idx) => target[idx] || null;
             if (prop === 'namedItem') return (name) => target.find(m => m.type === name) || null;
             if (typeof prop === 'string' && /^\d+$/.test(prop)) return target[parseInt(prop, 10)];
             if (typeof prop === 'string') {
                const mt = target.find(m => m.type === prop);
                if (mt) return mt;
             }
             if (prop === Symbol.iterator) return function*() { yield* target; };
             return Reflect.get(target, prop);
         },
    };
    const mockedMimeTypeArrayGlobal = new Proxy(allMimeTypes, mimeTypesHandlerGlobal);
    Object.setPrototypeOf(mockedMimeTypeArrayGlobal, MimeTypeArray.prototype);
    utils.replaceProperty(navigator, 'mimeTypes', mockedMimeTypeArrayGlobal);


    // ====================================================================================
    // EVASION 3: PERMISSIONS API SPOOFING
    // ====================================================================================
    try {
        if (navigator.permissions && navigator.permissions.query) {
            utils.patchFunction(navigator.permissions, 'query', (originalFn, parameters) => {
                if (!parameters) return originalFn.call(navigator.permissions, parameters);

                // Spoof common permissions that often default to 'denied' in automation.
                const spoofToPrompt = ['notifications', 'push', 'midi'];
                
                if (spoofToPrompt.includes(parameters.name)) {
                    return Promise.resolve(Object.create(PermissionStatus.prototype, {
                        state: { value: 'prompt', enumerable: true },
                        status: { value: 'prompt', enumerable: true },
                        onchange: { value: null, enumerable: true }
                    }));
                }
                // Geolocation, Camera, Mic are often handled by browser-level permissions/CDP overrides.
                return originalFn.call(navigator.permissions, parameters);
            });
        }
    } catch (e) { /* Ignore errors */ }


    // ====================================================================================
    // EVASION 4: WEBRTC IP LEAK PREVENTION (SDP Munging and mDNS filtering)
    // ====================================================================================
    try {
        const originalRTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
        if (originalRTCPeerConnection) {
            const PatchedRTCPeerConnection = function(...args) {
                const pc = new originalRTCPeerConnection(...args);

                const ipv4PrivateRegex = /(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)[0-9\.]+/g;
                const ipv6LocalRegex = /([fF][cCdD][0-9a-fA-F]{2}:|fe80:)[0-9a-fA-F:]+/g;
                // ADVANCED: mDNS candidates leak unique identifiers.
                const mDNSRegex = /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\.local/g;


                const maskSDP = (sdp) => {
                    // Mask connection info (c=)
                    sdp = sdp.replace(/c=IN IP4 (192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.).*?/g, 'c=IN IP4 0.0.0.0');
                    sdp = sdp.replace(/c=IN IP6 ([fF][cCdD][0-9a-fA-F]{2}:|fe80:).*?/g, 'c=IN IP6 ::1');

                    // Mask candidates (a=candidate:)
                    sdp = sdp.split('\r\n').map(line => {
                        if (line.startsWith('a=candidate:')) {
                            const parts = line.split(' ');
                            if (parts.length > 5) {
                                const ip = parts[4];
                                ipv4PrivateRegex.lastIndex = 0;
                                ipv6LocalRegex.lastIndex = 0;
                                mDNSRegex.lastIndex = 0;

                                if (mDNSRegex.test(ip)) {
                                    return null; // Remove mDNS candidates
                                } else if (ipv4PrivateRegex.test(ip)) {
                                    parts[4] = '0.0.0.0';
                                } else if (ipv6LocalRegex.test(ip)) {
                                    parts[4] = '::1';
                                }
                            }
                            return parts.join(' ');
                        }
                        return line;
                    }).filter(Boolean).join('\r\n');
                    
                    return sdp;
                };

                utils.patchFunction(pc, 'setLocalDescription', (originalFn, description) => {
                    if (description && description.sdp) {
                        description.sdp = maskSDP(description.sdp);
                    }
                    return originalFn.call(pc, description);
                });

                 utils.patchFunction(pc, 'createOffer', (originalFn, options) => {
                    return originalFn.call(pc, options).then(offer => {
                         if (offer && offer.sdp) {
                             offer.sdp = maskSDP(offer.sdp);
                        }
                        return offer;
                    });
                });

                return pc;
            };

            PatchedRTCPeerConnection.prototype = originalRTCPeerConnection.prototype;
            window.RTCPeerConnection = PatchedRTCPeerConnection;
            if (window.webkitRTCPeerConnection) {
                window.webkitRTCPeerConnection = PatchedRTCPeerConnection;
            }
        }
    } catch (e) {
        console.error('Scalpel: Failed to patch RTCPeerConnection', e);
    }


    // ====================================================================================
    // EVASION 5: WEBGL FINGERPRINT SPOOFING
    // ====================================================================================
    try {
        const webglContexts = [window.WebGLRenderingContext, window.WebGL2RenderingContext].filter(Boolean);
        
        // --- 5.1 Spoofing Vendor/Renderer Parameters ---
        webglContexts.forEach(ctx => {
             utils.patchPrototypeFunction(ctx, 'getExtension', function(originalFn, name) {
                const ext = originalFn.call(this, name);
                if (name === 'WEBGL_debug_renderer_info' && !ext) {
                     return {
                         UNMASKED_VENDOR_WEBGL: 37445,
                         UNMASKED_RENDERER_WEBGL: 37446,
                     };
                }
                return ext;
            });

            utils.patchPrototypeFunction(ctx, 'getParameter', function(originalFn, parameter) {
                const vendor = SCALPEL_PERSONA.webGLVendor || 'Intel Inc.';
                const renderer = SCALPEL_PERSONA.webGLRenderer || 'Intel Iris OpenGL Engine';

                if (parameter === 37445) return vendor;
                if (parameter === 37446) return renderer;
                
                // Consistency check for standard parameters
                if (ctx && parameter === ctx.VENDOR) return vendor;
                if (ctx && parameter === ctx.RENDERER) return renderer;
                
                return originalFn.call(this, parameter);
            });
        });

        // --- 5.2 ADVANCED: WebGL Rendering Noise (readPixels) ---
        const addWebGLNoise = (data) => {
            const noiseAmount = 1;
            for (let i = 0; i < 10; i++) {
                const index = Math.floor(seededRNG() * (data.length / 4)) * 4;
                const component = Math.floor(seededRNG() * 3); // R, G, or B
                const noise = (seededRNG() > 0.5 ? noiseAmount : -noiseAmount);
                
                // Apply noise based on data type
                if (data instanceof Uint8Array || data instanceof Uint8ClampedArray) {
                    data[index + component] = Math.max(0, Math.min(255, data[index + component] + noise));
                } else if (data instanceof Float32Array) {
                    data[index + component] += (seededRNG() - 0.5) * 1e-4;
                }
            }
        };

        webglContexts.forEach(ctx => {
            // Patch readPixels to modify the rendering buffer output.
            utils.patchPrototypeFunction(ctx, 'readPixels', function(originalFn, ...args) {
                originalFn.apply(this, args);
                // Pixel data is typically the 7th argument (index 6).
                const pixels = args[6];
                if (pixels && (pixels.buffer || Array.isArray(pixels))) {
                     addWebGLNoise(pixels);
                }
            });
        });

    } catch (e) {
        console.error('Scalpel: Failed to spoof WebGL', e);
    }


    // ====================================================================================
    // EVASION 6: CANVAS FINGERPRINT SPOOFING (Non-Destructive Noise Injection)
    // ====================================================================================
    try {
        const noiseAmount = 2;
        const addCanvasNoise = (data) => {
            for (let i = 0; i < 20; i++) {
                const index = Math.floor(seededRNG() * (data.length / 4)) * 4;
                const component = Math.floor(seededRNG() * 3); // R, G, or B
                const noise = (seededRNG() > 0.5 ? noiseAmount : -noiseAmount);
                data[index + component] = Math.max(0, Math.min(255, data[index + component] + noise));
            }
        };

        // Patch getImageData.
        if (window.CanvasRenderingContext2D) {
            utils.patchPrototypeFunction(window.CanvasRenderingContext2D, 'getImageData', function(originalFn, ...args) {
                const imageData = originalFn.apply(this, args);
                addCanvasNoise(imageData.data);
                return imageData;
            });
        }

        // Patch toDataURL and toBlob.
        if (window.HTMLCanvasElement) {
             const patchCanvasExport = (propName) => {
                utils.patchPrototypeFunction(window.HTMLCanvasElement, propName, function(originalFn, ...args) {
                    const tempCanvas = document.createElement('canvas');
                    tempCanvas.width = this.width;
                    tempCanvas.height = this.height;
                    const tempCtx = tempCanvas.getContext('2d');

                    if (!tempCtx) return originalFn.apply(this, args);

                    try {
                        tempCtx.drawImage(this, 0, 0);
                    } catch (e) {
                        // Handle tainted canvas (CORS)
                        return originalFn.apply(this, args);
                    }

                    // Noise is applied via the patched getImageData.
                    const imageData = tempCtx.getImageData(0, 0, tempCanvas.width, tempCanvas.height);
                    tempCtx.putImageData(imageData, 0, 0);

                    // Prevent infinite recursion.
                    const originalExportFn = utils.getOriginalImpl(`HTMLCanvasElement.${propName}`) || originalFn;
                    return originalExportFn.apply(tempCanvas, args);
                });
            };

            patchCanvasExport('toDataURL');
            if (HTMLCanvasElement.prototype.toBlob) {
                patchCanvasExport('toBlob');
            }
        }
    } catch (e) {
        console.error('Scalpel: Failed to spoof Canvas', e);
    }


    // ====================================================================================
    // EVASION 7: AUDIO FINGERPRINT SPOOFING (Comprehensive)
    // ====================================================================================
    try {
        // --- 7.1 AudioBuffer Noise (Time-domain fingerprinting) ---
        if (window.AudioBuffer && AudioBuffer.prototype.getChannelData) {
            utils.patchPrototypeFunction(window.AudioBuffer, 'getChannelData', function(originalFn, ...args) {
                const data = originalFn.apply(this, args);
                const noiseLevel = 1e-6;
                for (let i = 0; i < data.length; i += Math.floor(seededRNG() * 1000) + 1) {
                    data[i] += (seededRNG() - 0.5) * noiseLevel;
                }
                return data;
            });
        }

        // --- 7.2 ADVANCED: AnalyserNode Noise (Frequency-domain fingerprinting) ---
        if (window.AnalyserNode) {
            const applyAnalyserNoise = (data, noiseLevel) => {
                for (let i = 0; i < data.length; i += Math.floor(seededRNG() * 50) + 1) {
                    if (data instanceof Float32Array) {
                        data[i] += (seededRNG() - 0.5) * noiseLevel;
                    } else if (data instanceof Uint8Array) {
                        const noise = (seededRNG() > 0.5 ? noiseLevel : -noiseLevel);
                        data[i] = Math.max(0, Math.min(255, data[i] + noise));
                    }
                }
            };

            utils.patchPrototypeFunction(window.AnalyserNode, 'getFloatFrequencyData', function(originalFn, data) {
                originalFn.call(this, data);
                applyAnalyserNoise(data, 1e-5);
            });

            utils.patchPrototypeFunction(window.AnalyserNode, 'getByteFrequencyData', function(originalFn, data) {
                originalFn.call(this, data);
                applyAnalyserNoise(data, 1);
            });
        }

        // --- 7.3 ADVANCED: DynamicsCompressor Noise ---
        if (window.DynamicsCompressorNode && DynamicsCompressorNode.prototype.reduction) {
            const descriptor = Object.getOwnPropertyDescriptor(DynamicsCompressorNode.prototype, 'reduction');
            if (descriptor && descriptor.get) {
                const originalGetter = descriptor.get;
                Object.defineProperty(DynamicsCompressorNode.prototype, 'reduction', {
                    get: function() {
                        const value = originalGetter.call(this);
                        // Add subtle noise to the reduction value.
                        return value + (seededRNG() - 0.5) * 1e-6;
                    },
                    configurable: true,
                    enumerable: true,
                });
            }
        }

    } catch (e) {
        console.error('Scalpel: Failed to spoof AudioContext', e);
    }

    // ====================================================================================
    // EVASION 8: WINDOW.CHROME MOCKING (Advanced Realism)
    // ====================================================================================
    if (SCALPEL_PERSONA.userAgent && SCALPEL_PERSONA.userAgent.includes('Chrome')) {
         if (!window.chrome) {
            window.chrome = {};
        }
        
        // 8.1 Mock runtime object.
        if (!window.chrome.runtime) {
            window.chrome.runtime = {
                id: undefined,
                connect: () => {},
                sendMessage: () => {},
                getManifest: () => ({ manifest_version: 3 }),
                getURL: (path) => `chrome-extension://[fake-id]/${path}`,
                PlatformOs: { MAC: 'mac', WIN: 'win', LINUX: 'linux' },
                PlatformArch: { X86_64: 'x86-64', ARM: 'arm' },
            };
        }

        // 8.2 Mock 'app' object (legacy).
        if (!window.chrome.app) {
            window.chrome.app = {
                isInstalled: false,
                getDetails: () => null,
            };
        }

        // 8.3 ADVANCED: Mock CSI (Chrome Status Information) and LoadTimes.
        // Spoofing timing data masks the unnatural speed of automation.
        if (!window.chrome.csi) {
            window.chrome.csi = function() {
                return {
                    onloadT: Date.now() - Math.floor(seededRNG() * 500 + 500),
                    startE: Date.now() - Math.floor(seededRNG() * 1000 + 1000),
                    pageT: Date.now(),
                    tran: 15
                };
            };
        }

        if (!window.chrome.loadTimes) {
            window.chrome.loadTimes = function() {
                const navigationStart = (Date.now() - Math.floor(seededRNG() * 1000 + 1000)) / 1000;
                const firstPaintTime = navigationStart + (Math.floor(seededRNG() * 500 + 300) / 1000);
                return {
                    requestTime: navigationStart,
                    startLoadTime: navigationStart,
                    commitLoadTime: navigationStart + 0.2,
                    finishDocumentLoadTime: navigationStart + 0.8,
                    finishLoadTime: navigationStart + 1.0,
                    firstPaintTime: firstPaintTime,
                    wasFetchedViaSpdy: true,
                    connectionInfo: "h3",
                };
            };
        }

         // Mask the mocked functions themselves to appear native.
        const chromeApis = [
            'app.getDetails', 'runtime.connect', 'runtime.sendMessage', 'runtime.getManifest', 'runtime.getURL',
            'csi', 'loadTimes'
        ];

        chromeApis.forEach(apiPath => {
            const parts = apiPath.split('.');
            let obj = window.chrome;
            for (let i = 0; i < parts.length - 1; i++) {
                obj = obj[parts[i]];
                if (!obj) return;
            }
            const prop = parts[parts.length - 1];
            if (typeof obj[prop] === 'function') {
                utils.patchFunction(obj, prop, (originalFn, ...args) => originalFn(...args));
            }
        });
    }

    // ====================================================================================
    // EVASION 9: SCREEN PROPERTIES SPOOFING
    // ====================================================================================
    try {
        const screenProps = SCALPEL_PERSONA.screen || {};
        const patches = {
            width: screenProps.width || 1920,
            height: screenProps.height || 1080,
            availWidth: screenProps.availWidth || 1920,
            availHeight: screenProps.availHeight || 1040,
            colorDepth: screenProps.colorDepth || 24,
            pixelDepth: screenProps.pixelDepth || 24,
        };

        for (const [key, value] of Object.entries(patches)) {
            utils.replaceProperty(window.screen, key, value);
        }
        utils.replaceProperty(window, 'outerWidth', patches.width);
        utils.replaceProperty(window, 'outerHeight', patches.height);
    } catch (e) {
        console.error('Scalpel: Failed to spoof Screen properties', e);
    }

    // ====================================================================================
    // EVASION 10: CLIENT RECTS / FONT FINGERPRINTING (Ringer)
    // ====================================================================================
    try {
        const noise = () => (seededRNG() - 0.5) * 0.1; // Noise < 0.1px

        const modifyRect = (rect) => {
            const noisyRect = new DOMRect(
                rect.x + noise(),
                rect.y + noise(),
                rect.width + noise(),
                rect.height + noise()
            );
            Object.defineProperties(noisyRect, {
                top: { get: () => noisyRect.y, enumerable: true },
                left: { get: () => noisyRect.x, enumerable: true },
                right: { get: () => noisyRect.x + noisyRect.width, enumerable: true },
                bottom: { get: () => noisyRect.y + noisyRect.height, enumerable: true },
            });
            return noisyRect;
        };

        const createModifiedRectList = (rectList) => {
            const modifiedList = Array.from(rectList).map(modifyRect);
            // ADVANCED: Mimic DOMRectList behavior using a Proxy.
            const proxy = new Proxy(modifiedList, {
                get(target, prop) {
                    if (prop === 'length') return target.length;
                    if (prop === 'item') return (i) => target[i];
                    if (typeof prop === 'string' && /^\d+$/.test(prop)) return target[parseInt(prop, 10)];
                    return Reflect.get(target, prop);
                }
            });
            if (window.DOMRectList) {
                Object.setPrototypeOf(proxy, DOMRectList.prototype);
            }
            return proxy;
        };

        if (window.Element) {
            utils.patchPrototypeFunction(window.Element, 'getBoundingClientRect', function(originalFn, ...args) {
                const rect = originalFn.apply(this, args);
                return modifyRect(rect);
            });

            utils.patchPrototypeFunction(window.Element, 'getClientRects', function(originalFn, ...args) {
                const rectList = originalFn.apply(this, args);
                return createModifiedRectList(rectList);
            });
        }

        // ADVANCED: Patch Range, used for precise text measurement.
        if (window.Range) {
            utils.patchPrototypeFunction(window.Range, 'getBoundingClientRect', function(originalFn, ...args) {
                return modifyRect(originalFn.apply(this, args));
            });
             utils.patchPrototypeFunction(window.Range, 'getClientRects', function(originalFn, ...args) {
                return createModifiedRectList(originalFn.apply(this, args));
            });
        }
    } catch (e) {
         console.error('Scalpel: Failed to spoof ClientRects', e);
    }

    // ====================================================================================
    // EVASION 11: INTL API (TIMEZONE/LOCALE) SPOOFING
    // ====================================================================================
    // Ensure consistency between CDP overrides and the JS environment.
    try {
        const timezone = SCALPEL_PERSONA.timezoneId;
        const locale = SCALPEL_PERSONA.locale || (SCALPEL_PERSONA.languages && SCALPEL_PERSONA.languages[0]);

        if ((timezone || locale) && window.Intl && Intl.DateTimeFormat) {
            // Patch Intl.DateTimeFormat.prototype.resolvedOptions
            utils.patchPrototypeFunction(Intl.DateTimeFormat, 'resolvedOptions', function(originalFn) {
                 const resolvedOptions = originalFn.call(this);
                 if (timezone) {
                    resolvedOptions.timeZone = timezone;
                 }
                 if (locale) {
                     // Basic enforcement of the target locale.
                     if (resolvedOptions.locale !== locale && resolvedOptions.locale.split('-')[0] !== locale.split('-')[0]) {
                        resolvedOptions.locale = locale;
                     }
                 }
                 return resolvedOptions;
            });
        }
    } catch (e) {
        console.error('Scalpel: Failed to spoof Timezone/Locale in JS', e);
    }

    // ====================================================================================
    // EVASION 12: BATTERY API SPOOFING
    // ====================================================================================
    try {
        if ('getBattery' in navigator) {
            const spoofedBattery = {
                charging: true,
                level: 0.9 + seededRNG() * 0.1, // High level (90-100%)
                chargingTime: 0,
                dischargingTime: Infinity,
                addEventListener: () => {},
            };
            
            if (window.BatteryManager) {
                Object.setPrototypeOf(spoofedBattery, BatteryManager.prototype);
            }

            utils.patchFunction(navigator, 'getBattery', (originalFn) => {
                return Promise.resolve(spoofedBattery);
            });
        }
    } catch (e) {
        console.error('Scalpel: Failed to spoof Battery API', e);
    }

})();
