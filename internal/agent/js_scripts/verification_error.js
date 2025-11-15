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
            // FIX: Removed stray "G" character which caused a SyntaxError
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