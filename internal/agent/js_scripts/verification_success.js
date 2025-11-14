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
