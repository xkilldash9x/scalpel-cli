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