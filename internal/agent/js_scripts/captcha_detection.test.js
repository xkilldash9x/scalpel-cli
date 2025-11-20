/**
 * @jest-environment jsdom
 */

// Add these Node.js built-in modules
const fs = require('fs');
const path = require('path');

// Import the function to be tested
const { detectCaptcha } = require('./captcha_detection.js');

// --- Script Content for 'eval' Test ---
// This is the full content of 'captcha_detection.js'
// KEPT for reference, but the 'eval' test is being refactored.
const scriptContent = `
// js_scripts/captcha_detection.js

/**
 * Analyzes the DOM to find common CAPTCHA indicators.
 * @returns {string|null} The CSS selector of the first visible CAPTCHA indicator found, or null.
 */
function detectCaptcha() {
    const captchaSelectors = [
        'iframe[src*="recaptcha/api"]', // Google reCAPTCHA v2/v3
        'iframe[src*="hcaptcha.com"]',  // hCaptcha
        '.g-recaptcha',                 // reCAPTCHA class
        '.h-captcha',                   // hCaptcha class
        '#cf-challenge-wrapper',        // Cloudflare Turnstile/Challenge
        'iframe[src*="challenges.cloudflare.com"]',
        '[data-sitekey]'                // Common attribute
    ];

    for (const selector of captchaSelectors) {
        try {
            const element = document.querySelector(selector);
            if (element) {
                // Basic visibility check heuristic
                const rect = element.getBoundingClientRect();
                const isVisible = (
                    (element.offsetWidth > 0 || element.offsetHeight > 0) ||
                    (rect.width > 0 && rect.height > 0)
                );
                
                if (isVisible) {
                    return selector;
                }
            }
        } catch (e) {
            // Silently ignore errors (e.g., invalid selector syntax)
        }
    }
    return null;
}

// Export for testing environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { detectCaptcha };
} else {
    // In a browser context (Go executor), the last evaluated expression is the return value.
    detectCaptcha();
}
`;
// --- End Script Content ---

// Helper function to set the document body HTML before running the analysis
function setDocumentBody(html) {
    document.body.innerHTML = html;
}

// Helper to mock visibility properties for an element
function mockVisibility(selector, isVisible) {
    try {
        const element = document.querySelector(selector);
        if (element) {
            Object.defineProperty(element, 'offsetWidth', { configurable: true, value: isVisible ? 100 : 0 });
            Object.defineProperty(element, 'offsetHeight', { configurable: true, value: isVisible ? 100 : 0 });
            // Mock getBoundingClientRect as a fallback
            element.getBoundingClientRect = () => ({
                width: isVisible ? 100 : 0,
                height: isVisible ? 100 : 0,
                top: isVisible ? 10 : 0,
                left: isVisible ? 10 : 0,
                bottom: isVisible ? 110 : 0,
                right: isVisible ? 110 : 0,
            });
        }
    } catch (e) {
        // Handle cases where the selector might be invalid during setup
    }
}


describe('detectCaptcha', () => {

    let originalModule;

    beforeEach(() => {
        originalModule = global.module; // Save original module
    });

    // Clean up the DOM after each test
    afterEach(() => {
        document.body.innerHTML = '';
        global.module = originalModule; // Restore module
        jest.restoreAllMocks(); // Restore any spies
        jest.resetModules(); // Reset module cache
    });

    test('should return null when no CAPTCHA elements are present', () => {
        setDocumentBody(`
            <div>
                <h1>Just a regular page</h1>
                <form id="login-form">
                    <input type="text" name="username">
                    <button>Login</button>
                </form>
            </div>
        `);
        expect(detectCaptcha()).toBeNull();
    });

    test('should detect a visible Google reCAPTCHA iframe', () => {
        const selector = 'iframe[src*="recaptcha/api"]';
        setDocumentBody(`
            <div>
                <iframe src="https://www.google.com/recaptcha/api/a-b-c"></iframe>
            </div>
        `);
        // Mock it as visible
        mockVisibility(selector, true);
        expect(detectCaptcha()).toBe(selector);
    });

    test('should detect a visible .g-recaptcha element', () => {
        const selector = '.g-recaptcha';
        setDocumentBody(`
            <div>
                <div class="g-recaptcha" data-sitekey="some-key"></div>
            </div>
        `);
        mockVisibility(selector, true);
        expect(detectCaptcha()).toBe(selector);
    });

    test('should detect a visible hCaptcha iframe', () => {
        const selector = 'iframe[src*="hcaptcha.com"]';
        setDocumentBody(`
            <div>
                <iframe src="https://js.hcaptcha.com/a-b-c"></iframe>
            </div>
        `);
        mockVisibility(selector, true);
        expect(detectCaptcha()).toBe(selector);
    });

    test('should detect a visible .h-captcha element', () => {
        const selector = '.h-captcha';
        setDocumentBody(`
            <div>
                <div class="h-captcha" data-sitekey="some-key"></div>
            </div>
        `);
        mockVisibility(selector, true);
        expect(detectCaptcha()).toBe(selector);
    });

    test('should detect a visible Cloudflare challenge wrapper', () => {
        const selector = '#cf-challenge-wrapper';
        setDocumentBody(`
            <div>
                <div id="cf-challenge-wrapper">
                    </div>
            </div>
        `);
        mockVisibility(selector, true);
        expect(detectCaptcha()).toBe(selector);
    });

    test('should detect a visible generic [data-sitekey] element', () => {
        const selector = '[data-sitekey]';
        setDocumentBody(`
            <div>
                <div class="some-custom-captcha" data-sitekey="some-key"></div>
            </div>
        `);
        mockVisibility(selector, true);
        expect(detectCaptcha()).toBe(selector);
    });

    test('should ignore a hidden CAPTCHA element', () => {
        const selector = '.g-recaptcha';
        setDocumentBody(`
            <div>
                <div class="g-recaptcha" data-sitekey="some-key"></div>
            </div>
        `);
        // Mock it as hidden (offset properties are 0)
        mockVisibility(selector, false);
        expect(detectCaptcha()).toBeNull();
    });

    test('should ignore a hidden hCaptcha iframe', () => {
        const selector = 'iframe[src*="hcaptcha.com"]';
        setDocumentBody(`
            <div>
                <iframe src="https://js.hcaptcha.com/a-b-c" style="display:none;"></iframe>
            </div>
        `);
        mockVisibility(selector, false);
        expect(detectCaptcha()).toBeNull();
    });

    test('should correctly find the first visible CAPTCHA when multiple are present', () => {
        const visibleSelector = '.g-recaptcha';
        const hiddenSelector = '.h-captcha';
        setDocumentBody(`
            <div>
                <div class="g-recaptcha" data-sitekey="google-key"></div>
                <div class="h-captcha" data-sitekey="hcaptcha-key"></div>
            </div>
        `);
        
        // Mock .g-recaptcha as visible
        mockVisibility(visibleSelector, true);
        // Mock .h-captcha as hidden
        mockVisibility(hiddenSelector, false);

        // The script iterates in order, and .g-recaptcha comes *after* hcaptcha iframe in the list.
        // Let's re-order the test HTML to match the script's selector list order for a more precise test.

        // Script list order:
        // 1. iframe[src*="recaptcha/api"]
        // 2. iframe[src*="hcaptcha.com"]
        // 3. .g-recaptcha
        // 4. .h-captcha
        // 5. #cf-challenge-wrapper
        // 6. iframe[src*="challenges.cloudflare.com"]
        // 7. [data-sitekey]

        setDocumentBody(`
             <div>
                <iframe src="https://js.hcaptcha.com/a-b-c"></iframe>
                <div class="g-recaptcha" data-sitekey="google-key"></div>
                <div class="h-captcha" data-sitekey="hcaptcha-key"></div>
            </div>
        `);

        mockVisibility('iframe[src*="hcaptcha.com"]', false);
        mockVisibility('.g-recaptcha', true);
        mockVisibility('.h-captcha', false);

        // It should skip the hidden hCaptcha iframe and find the visible .g-recaptcha
        expect(detectCaptcha()).toBe('.g-recaptcha');
    });

    test('should correctly find a visible CAPTCHA when preceded by a hidden one of the same type', () => {
        const selector = '.g-recaptcha';
        setDocumentBody(`
            <div>
                <div class="g-recaptcha" id="hidden" style="display:none;"></div>
                <div class="g-recaptcha" id="visible"></div>
            </div>
        `);

        // Mock the first one as hidden
        const hiddenEl = document.getElementById('hidden');
        mockVisibility('#hidden', false);
        // Mock the second one as visible
        const visibleEl = document.getElementById('visible');
        // We need to mock visibility on the element itself since our mock helper works on selector or finding element
        // but let's use a custom approach here since IDs are unique
        Object.defineProperty(hiddenEl, 'offsetWidth', { value: 0 });
        Object.defineProperty(hiddenEl, 'offsetHeight', { value: 0 });
        hiddenEl.getBoundingClientRect = () => ({ width: 0, height: 0 });

        Object.defineProperty(visibleEl, 'offsetWidth', { value: 100 });
        Object.defineProperty(visibleEl, 'offsetHeight', { value: 100 });
        visibleEl.getBoundingClientRect = () => ({ width: 100, height: 100 });

        // The script should iterate past the first hidden one and return the selector because the second one is visible
        expect(detectCaptcha()).toBe(selector);
    });

    // --- REFACTORED TEST ---
    // Test for line 45 (non-module environment)
    test('should execute detectCaptcha directly in non-module (browser) environment', () => {
        // 1. Spy on the document method *before* the script runs
        const querySelectorAllSpy = jest.spyOn(document, 'querySelectorAll').mockImplementation(() => []);
        
        // 2. Save original module
        const originalModule = global.module;
        
        try {
            // 3. Read the script file content
            const scriptPath = path.resolve(__dirname, 'captcha_detection.js');
            const scriptContent = fs.readFileSync(scriptPath, 'utf8');

            // 4. THE FIX: Shadow the test file's local 'module' variable
            const module = undefined;

            // 5. 'eval' the script content. This will run in the current
            // scope where 'module' is undefined, triggering the 'else' block.
            eval(scriptContent);
            
            // 6. Check that the spy was called by the 'else' block's execution
            expect(querySelectorAllSpy).toHaveBeenCalledWith('iframe[src*="recaptcha/api"]');
            
        } finally {
            // 7. Restore
            global.module = originalModule; // Restore global
            querySelectorAllSpy.mockRestore();
            jest.resetModules(); // Clean up
        }
    });
}); 