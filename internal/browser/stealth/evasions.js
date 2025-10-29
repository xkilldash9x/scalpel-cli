// File: internal/browser/stealth/evasions.js
// This script runs in the browser context before any page scripts (via CDP Page.addScriptToEvaluateOnNewDocument).

(function(persona) {
    'use strict';

    // Retrieve configuration injected via window.SCALPEL_PERSONA
    if (!persona && window.SCALPEL_PERSONA) {
        // Basic retrieval; parsing logic might be needed depending on injection method.
        persona = window.SCALPEL_PERSONA;
    }

    // Helper function for safe property definition, primarily used for prototype overrides.
    const safeDefinePrototype = (proto, prop, value) => {
        try {
            Object.defineProperty(proto, prop, {
                get: () => value,
                configurable: true, // Allows further modification if necessary
                enumerable: true
            });
        } catch (error) {
            // console.warn(`Scalpel Stealth: Failed to override prototype property ${prop}`, error);
        }
    };

    // --- Evasion: Remove webdriver flag (CRITICAL FIX) ---
    // The most robust way to bypass this detection is to define 'webdriver' on the Navigator prototype
    // before the browser initializes the instance property. This ensures that when scripts check 
    // navigator.webdriver, they get our spoofed value.
    if (navigator.webdriver !== false) {
        safeDefinePrototype(Navigator.prototype, 'webdriver', false);
    }
    
    // Fallback check on the instance itself, just in case the prototype override failed or was checked too late.
    try {
        if (navigator.webdriver === true) {
             Object.defineProperty(navigator, 'webdriver', {
                get: () => false,
                configurable: true,
                enumerable: true
            });
        }
    } catch (error) {
        // Ignore if instance override fails, relying on the prototype definition.
    }


    // Apply persona configurations if available.
    if (persona) {
        // --- Evasion: Navigator Properties ---
        // Aligning the JS view with CDP overrides by spoofing the properties on the prototype.
        if (persona.userAgent) {
            safeDefinePrototype(Navigator.prototype, 'userAgent', persona.userAgent);
        }
        if (persona.platform) {
            safeDefinePrototype(Navigator.prototype, 'platform', persona.platform);
        }
        if (Array.isArray(persona.languages) && persona.languages.length > 0) {
            // Languages should be a frozen array.
            safeDefinePrototype(Navigator.prototype, 'languages', Object.freeze([...persona.languages]));
        }
    }
    
    // --- Evasion: Basic Chrome simulation ---
    // Headless Chrome often lacks the window.chrome object.
    if (window.chrome === undefined) {
        // Define a minimal chrome object structure.
        Object.defineProperty(window, 'chrome', {
            value: {
                runtime: {},
                // Other common properties can be added here if needed.
            },
            writable: false,
            configurable: true
        });
    }

    // Future evasions (WebGL noise, Canvas noise, Permissions API spoofing) can be added here.

})(window.SCALPEL_PERSONA);