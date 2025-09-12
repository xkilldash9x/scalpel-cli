// internal/browser/stealth/evasions.js
// This script runs in the browser context before any page scripts.

(function(persona) {
    // Retrieve configuration injected via window.SCALPEL_PERSONA
    if (!persona && window.SCALPEL_PERSONA) {
        persona = window.SCALPEL_PERSONA;
    }

    if (!persona) {
        // console.warn("Scalpel Stealth: Persona configuration not found.");
        return;
    }

    // Helper function for safe property definition
    const safeDefine = (obj, prop, value) => {
        try {
            Object.defineProperty(obj, prop, {
                get: () => value,
                configurable: true
            });
        } catch (error) {
            // console.warn(`Scalpel Stealth: Failed to override ${prop}`, error);
        }
    };

    // --- Evasion: Navigator Properties ---
    // Aligning the JS view with CDP overrides helps bypass checks that read directly.
    safeDefine(navigator, 'userAgent', persona.userAgent);
    safeDefine(navigator, 'platform', persona.platform);
    if (Array.isArray(persona.languages)) {
        safeDefine(navigator, 'languages', Object.freeze([...persona.languages]));
    }
    
    // --- Evasion: Remove webdriver flag ---
    // Modern headless detection often checks this property.
    if (navigator.webdriver === true) {
         safeDefine(navigator, 'webdriver', false);
    }

    // --- Evasion: Basic Chrome simulation (common headless detection vector) ---
    if (window.chrome === undefined) {
        window.chrome = {
            runtime: {},
            // Add other common properties as needed
        };
    }

    // Future evasions (WebGL noise, Canvas noise, Permissions API spoofing) can be added here.

})(window.SCALPEL_PERSONA);