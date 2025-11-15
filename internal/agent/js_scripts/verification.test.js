/**
 * @jest-environment jsdom
 */

// Add these Node.js built-in modules
const fs = require('fs');
const path = require('path');

const { checkSuccessIndicators } = require('./verification_success.js');
const { checkErrorIndicators } = require('./verification_error.js');

// --- Script Content for 'eval' Tests ---
const successScriptContent = `
/**
 * Analyzes the DOM to find indicators that a sign-up action was successful.
 * @returns {string|null} A string describing the success indicator found, or null.
 */
function checkSuccessIndicators() {
    const successKeywords = ["welcome", "account created", "verification email sent", "check your email", "registration complete", "success"];
    // 1. Check for elements commonly associated with a logged-in state (strongest signal)
    const interactiveElements = document.querySelectorAll('a, button');
    for (const el of interactiveElements) {
        const href = el.getAttribute('href') || "";
        const elText = (el.innerText || el.textContent || "").toLowerCase();
        if (href.includes("logout") || href.includes("signout") || elText.includes("log out") || elText.includes("sign out") || href.includes("dashboard") || href.includes("profile")) {
            return "LoggedInElement: " + el.tagName;
        }
    }

    // 2. Check for specific success alerts/modals
    let alerts = [];
    try {
        alerts = document.querySelectorAll('[role="alert"], .alert-success, .modal-body');
    } catch (e) {
        console.warn("Error querying for success alerts:", e);
    }
    for (const alert of alerts) {
        const alertText = (alert.innerText || alert.textContent || "").toLowerCase();
        for (const keyword of successKeywords) {
            if (alertText.includes(keyword)) {
                return "Alert: " + keyword;
            }
        }
    }
    
    // 3. Fallback to checking the entire body text
    const text = (document.body && document.body.textContent) ? document.body.textContent.toLowerCase() : "";
    for (const keyword of successKeywords) {
        if (text.includes(keyword)) {
            return "Keyword: " + keyword;
        }
    }

    return null;
}

// Export for testing environments (Node.js/Jest)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { checkSuccessIndicators };
} else {
    // In a browser context (Go executor), the last evaluated expression is the return value.
    checkSuccessIndicators();
}
`;

const errorScriptContent = `
/**
 * Analyzes the DOM to find indicators that a sign-up action failed.
 * @returns {string|null} A string describing the error indicator found, or null.
 */
function checkErrorIndicators() {
    // Keywords suggesting validation errors or generic failures
    const errorKeywords = ["error", "failed", "invalid", "username taken", "email already in use", "email exists", "password too weak", "password mismatch", "required field missing", "CAPTCHA", "verification failed", "try again"];

    // Focus analysis on elements likely to contain errors (alerts, error classes, form fields themselves)
    let analysisContexts = [];
    try {
        analysisContexts = Array.from(document.querySelectorAll('.error, .alert, .alert-danger, [role="alert"], input:invalid, form'));
    } catch (e) {
        console.warn("Error querying for error contexts:", e);
    }

    if (analysisContexts.length === 0) {
        if (document.body) {
            analysisContexts.push(document.body); // Fallback to body
        } else {
            return null; // Cannot analyze if body is also missing
        }
    }

    for (const context of analysisContexts) {
        const contextText = (context.innerText || context.textContent || "").toLowerCase();
        for (const keyword of errorKeywords) {
            if (contextText.includes(keyword)) {
                return "Keyword: " + keyword;
            }
        }
        // Check for HTML5 validation messages on inputs
        // Check if the element is an INPUT and supports the validationMessage property.
        if (context.tagName === 'INPUT' && context.validationMessage) {
            // FIX: Removed stray "G" character
            return "ValidationMessage: " + context.validationMessage;
        }
    }
    return null;
}

// Export for testing environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { checkErrorIndicators };
} else {
    checkErrorIndicators();
}
`;
// --- End Script Content ---


// Helper function to set the document body HTML
function setDocumentBody(html) {
    document.body.innerHTML = html;
}

describe('Verification Scripts', () => {

    let originalModule;
    let consoleWarnMock;

    beforeEach(() => {
        // Save originals to restore after each test
        originalModule = global.module;
        consoleWarnMock = jest.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(() => {
        // Restore all mocks and globals
        jest.restoreAllMocks();
        global.module = originalModule;
        document.body.innerHTML = ''; // Clear body
        jest.resetModules(); // Reset module cache
    });

    describe('checkSuccessIndicators', () => {
        test('should find success keywords in body text', () => {
            setDocumentBody('<h1>Success! Your account created successfully.</h1>');
            // It finds the first keyword in the list present in the text
            expect(checkSuccessIndicators()).toBe('Keyword: account created');
        });

        test('should find logged-in elements (logout link)', () => {
            setDocumentBody('<nav><a href="/settings">Settings</a><a href="/logout">Log Out</a></nav>');
            expect(checkSuccessIndicators()).toBe('LoggedInElement: A');
        });

        test('should find success keywords in alerts', () => {
            setDocumentBody(`
                <div class="alert alert-success" role="alert">
                    Welcome to the platform!
                </div>
            `);
            expect(checkSuccessIndicators()).toBe('Alert: welcome');
        });

        test('should return null if no indicators are found', () => {
            setDocumentBody('<h1>Sign Up Form</h1><form>...</form>');
            expect(checkSuccessIndicators()).toBeNull();
        });

        // Test for line 22 (catch block)
        test('should handle errors during querySelectorAll for success alerts', () => {
            // Mock querySelectorAll to throw an error ONLY for the success alerts query
            const querySelectorMock = jest.spyOn(document, 'querySelectorAll').mockImplementation((selector) => {
                if (selector.includes('[role="alert"]')) {
                    throw new Error('Test Selector Error');
                }
                // We must return an empty array-like structure for other calls
                return []; 
            });

            // Set body text so it can fall back
            setDocumentBody('<div>welcome</div>');
            
            // It should not crash, it should skip the alert check and move to fallback
            expect(checkSuccessIndicators()).toBe('Keyword: welcome');
            // It should have logged the warning
            expect(consoleWarnMock).toHaveBeenCalledWith("Error querying for success alerts:", expect.any(Error));
        });

        // --- REFACTORED TEST ---
        // Test for line 49 (non-module environment)
        test('should execute checkSuccessIndicators directly in non-module (browser) environment', () => {
            // 1. Spy on the document method *before* the script runs
            const querySelectorAllSpy = jest.spyOn(document, 'querySelectorAll').mockImplementation(() => []);
            
            // 2. Save original module 
            const originalModule = global.module;
            
            try {
                // 3. Read the script file content
                const scriptPath = path.resolve(__dirname, 'verification_success.js');
                const scriptContent = fs.readFileSync(scriptPath, 'utf8');

                // 4. THE FIX: Shadow the test file's local 'module' variable
                const module = undefined;
                
                // 5. 'eval' the script. 'typeof module' will now be 'undefined'.
                eval(scriptContent);
                
                // 6. Check that the spy was called by the 'else' block's execution
                expect(querySelectorAllSpy).toHaveBeenCalledWith('a, button');
                
            } finally {
                // 7. Restore
                global.module = originalModule; // Restore global
                querySelectorAllSpy.mockRestore();
                jest.resetModules(); // Clean up
            }
        });
    });

    describe('checkErrorIndicators', () => {
        test('should find error keywords in error elements', () => {
            setDocumentBody(`
                <form>
                    <div class="error">Error: Invalid input provided.</div>
                </form>
            `);
            // Finds the first matching keyword
            expect(checkErrorIndicators()).toBe('Keyword: error');
        });

        test('should find specific validation keywords (email exists)', () => {
            setDocumentBody(`
                <div class="alert-danger">This email already in use.</div>
            `);
            expect(checkErrorIndicators()).toBe('Keyword: email already in use');
        });

         test('should detect HTML5 validation messages (JSDOM simulation)', () => {
            setDocumentBody('<form><input type="email" id="email" required></form>');
            const input = document.getElementById('email');

            // Simulate the validationMessage property (JSDOM doesn't fully implement constraint validation API automatically)
            Object.defineProperty(input, 'validationMessage', {
                get: function() {
                    return this.value ? '' : 'Please fill out this field.';
                }
            });

            // When checkErrorIndicators runs, it should find this input and read its validationMessage
            expect(checkErrorIndicators()).toContain('ValidationMessage: Please fill out this field.');
        });

        test('should return null if no errors are found', () => {
            setDocumentBody('<h1>Success Page</h1><p>Everything looks good.</p>');
            expect(checkErrorIndicators()).toBeNull();
        });

        // Test for line 14 (catch block)
        test('should handle errors during querySelectorAll for error contexts', () => {
            const querySelectorMock = jest.spyOn(document, 'querySelectorAll').mockImplementation(() => {
                throw new Error('Test Selector Error');
            });
            
            // It should not crash and should fallback to document.body
            // Since body is empty, it returns null
            setDocumentBody('');
            expect(checkErrorIndicators()).toBeNull();
            // It should have logged the warning
            expect(consoleWarnMock).toHaveBeenCalledWith("Error querying for error contexts:", expect.any(Error));
        });

        // --- REFACTORED TEST ---
        // Test for line 21/23 (null body)
        test('should return null if document.body is not present and no contexts found', () => {
            // 1. Spy on querySelectorAll to return no contexts
            const querySelectorAllSpy = jest.spyOn(document, 'querySelectorAll').mockImplementation(() => []);
            
            // 2. Spy on document.body's 'get' accessor to return null
            const bodySpy = jest.spyOn(document, 'body', 'get').mockImplementation(() => null);
            
            // 3. Run the function
            expect(checkErrorIndicators()).toBeNull(); // Should hit line 23
            
            // 4. Verify it checked for contexts first
            expect(querySelectorAllSpy).toHaveBeenCalledWith('.error, .alert, .alert-danger, [role="alert"], input:invalid, form');

            // 5. Restore spies
            querySelectorAllSpy.mockRestore();
            bodySpy.mockRestore();
        });

        // --- REFACTORED TEST ---
        // Test for line 45 (non-module environment)
        test('should execute checkErrorIndicators directly in non-module (browser) environment', () => {
            // 1. Spy on the document method *before* the script runs
            const querySelectorAllSpy = jest.spyOn(document, 'querySelectorAll').mockImplementation(() => []);
            
            // 2. Save original module
            const originalModule = global.module;
            
            try {
                // 3. Read the script file content
                const scriptPath = path.resolve(__dirname, 'verification_error.js');
                const scriptContent = fs.readFileSync(scriptPath, 'utf8');

                // 4. THE FIX: Shadow the test file's local 'module' variable
                const module = undefined;
                
                // 5. 'eval' the script, triggering the 'else' block
                eval(scriptContent);
                
                // 6. Check that the spy was called by the 'else' block's execution
                expect(querySelectorAllSpy).toHaveBeenCalledWith('.error, .alert, .alert-danger, [role="alert"], input:invalid, form');
                
            } finally {
                // 7. Restore
                global.module = originalModule; // Restore global
                querySelectorAllSpy.mockRestore();
                jest.resetModules(); // Clean up
            }
        });
    });
});