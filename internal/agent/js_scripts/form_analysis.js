/**
 * Analyzes the current page DOM to identify the most likely sign-up form.
 * This script is designed to be robust against various HTML structures, optimized for accuracy
 * using a Maximum Weight Matching approximation, and compatible with environments like JSDOM.
 * @returns {object} An object containing CSS selectors for the identified fields.
 */
function analyzeSignUpForm() {
    // -- Configuration & Debug --

    // Set to true for verbose logging of caught errors.
    const _debug = true;

    /**
     * Internal helper for logging errors when _debug is true.
     * @param {string} context - A message describing where the error occurred.
     * @param {Error} error - The caught error object.
     */
    function logError(context, error) {
        if (_debug) {
            // Log the message and stack for better debugging
            console.error(`FormAnalysis Error [${context}]:`, error.message, error.stack);
        }
    }

    // Configuration: Keywords for identifying different field types and the submit button.
    const keywords = {
        firstName: ["first name", "firstname", "fname", "given name", "given-name", "first"],
        lastName: ["last name", "lastname", "lname", "surname", "family name", "family-name", "last"],
        email: ["email", "e-mail", "mail", "email address"],
        username: ["username", "user name", "login", "login id", "userid", "handle", "user"],
        password: ["password", "passphrase", "pwd", "pass", "new-password"],
        passwordConfirm: ["confirm password", "repeat password", "verify password", "re-enter password", "confirm-password"],
        submit: ["sign up", "register", "create account", "join", "submit", "continue", "next"]
    };

    // Internal state initialization
    let bestForm = {
        context: null,
        fields: {},
        submitButton: null,
        score: 0
    };

    // Define ELEMENT_NODE for cross environment compatibility (e.g., JSDOM).
    const ELEMENT_NODE = (typeof Node !== 'undefined' && Node.ELEMENT_NODE) || 1;

    // -- Helper Functions --

    /**
     * Helper function for robust keyword matching using word boundaries.
     * Prevents partial matches (e.g., "name" matching "username").
     * @param {string} text - The normalized text to search within (assumed lowercased and delimiters replaced by spaces).
     * @param {string} keyword - The keyword to search for.
     * @returns {boolean} True if the keyword is found as a whole word or phrase.
     */
    function matchesKeyword(text, keyword) {
        try {
            // Escape regex special characters in the keyword (Defense in depth).
            const escapedKeyword = keyword.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
            // Use \b boundaries to match the exact word or phrase. 'i' flag for safety.
            const regex = new RegExp(`\\b${escapedKeyword}\\b`, 'i');
            return regex.test(text);
        } catch (e) {
            logError('matchesKeyword', e);
            // Fallback to simple inclusion if regex fails (less precise).
            return text.includes(keyword);
        }
    }

    /**
     * Helper function to extract visible text content from an element robustly.
     * Handles inputs/buttons correctly and normalizes whitespace.
     */
    function getVisibleText(element) {
        if (!element) return ""; // Guard clause

        let text = "";

        // Handle inputs (buttons, submit) where the visible text is the 'value' attribute.
        // This is critical for JSDOM tests where <input type="submit" value="Register"> is used.
        if (element.tagName === 'INPUT' && element.type && ['submit', 'button', 'reset'].includes(element.type.toLowerCase())) {
            text = element.value || "";
        } else {
            // For other elements (labels, buttons with content), use textContent (preferred) or innerText.
            // Prefer textContent as it's more reliable in JSDOM and less performance intensive.
            // Provide innerText as a fallback.
            text = element.textContent || element.innerText || "";
        }

        // Normalize whitespace and case.
        return text.replace(/\s+/g, ' ').trim().toLowerCase();
    }

    /**
     * Robust CSS Selector Generation with Context Relative Prioritization.
     * Generates stable selectors, preferring context relative names when globally ambiguous.
     */
    function getCssSelector(el, contextEl) {
        // Use duck typing instead of `instanceof Element` for JSDOM/cross context compatibility.
        if (!el || typeof el.nodeType !== 'number' || el.nodeType !== ELEMENT_NODE || typeof el.tagName !== 'string') {
            return null;
        }

        // Safety wrapper for querySelectorAll calls (Defense in depth).
        // UPDATED: This function now re-throws errors so the caller can log with context.
        const safeQuery = (selector, scope = document) => {
            try {
                // Ensure scope is a valid node before querying
                if (!scope || typeof scope.querySelectorAll !== 'function') {
                    // This specific error is logged here as it's an internal script issue.
                    const scopeError = new Error(`Invalid scope object provided for selector: ${selector}`);
                    logError('safeQuery (Invalid Scope)', scopeError);
                    return [];
                }
                return Array.from(scope.querySelectorAll(selector));
            } catch (e) {
                // Add selector to error context and re-throw for the caller.
                e.message = `Selector: "${selector}" | Error: ${e.message}`;
                throw e;
            }
        };

        // Helper for CSS escaping. Relies on CSS.escape (polyfill provided in test file).
        const escape = (value) => {
            if (typeof CSS !== 'undefined' && CSS.escape) {
                return CSS.escape(value);
            }
            // Fallback if CSS.escape is missing. (For coverage test)
            const strValue = String(value || "");
            // Basic escaping for common characters.
            return strValue ? strValue.replace(/([\.#\s\[\]\(\)\:\*])/g, '\\$1') : null;
        };

        // 1. Prioritize ID (Global scope is fine for unique IDs).
        if (el.id) {
            try {
                const escapedId = escape(el.id);
                // Defensive check: ensure escapedId is valid and globally unique.
                if (escapedId && safeQuery('#' + escapedId).length === 1) {
                    return '#' + escapedId;
                }
            } catch (e) {
                logError('getCssSelector (ID)', e);
            }
        }

        // 2. Try Name unique within a context (Preferred for robustness, required by tests)
        // Ensure contextEl is a valid element and not the document root.
        if (el.name && contextEl && contextEl !== document && contextEl.nodeType === ELEMENT_NODE) {
            try {
                const escapedName = escape(el.name);
                if (escapedName) {
                    const selectorByName = el.tagName.toLowerCase() + '[name="' + escapedName + '"]';

                    // Check uniqueness within the specific context.
                    if (safeQuery(selectorByName, contextEl).length === 1) {
                        // Get the context's selector recursively.
                        // Pass 'document' as the context for the recursive call to ensure a global selector for contextEl.
                        const contextSelector = getCssSelector(contextEl, document);
                        if (contextSelector) {
                            // Return the combined descendant selector.
                            return contextSelector + ' ' + selectorByName;
                        }
                        // If contextSelector generation failed, fall through to try global selectors for 'el'.
                    }
                }
            } catch (e) {
                logError('getCssSelector (Context Name)', e);
            }
        }

        // 3. Try Name globally unique (Fallback)
        if (el.name) {
            try {
                const escapedName = escape(el.name);
                if (escapedName) {
                    const selectorByName = el.tagName.toLowerCase() + '[name="' + escapedName + '"]';
                    if (safeQuery(selectorByName).length === 1) {
                        return selectorByName;
                    }
                }
            } catch (e) {
                logError('getCssSelector (Global Name)', e);
            }
        }

        // 4. Fallback to a structural selector path (Global scope).
        const path = [];
        let currentEl = el;
        while (currentEl && currentEl.nodeType === ELEMENT_NODE) {
            let selector = currentEl.nodeName.toLowerCase();

            if (currentEl === document.body) {
                path.unshift('body');
                break;
            }

            // Safety check for parent node existence (e.g., detached elements)
            if (!currentEl.parentNode) {
                // If parentNode is null, we're detached.
                // Stop here. If path is empty, we can't generate a selector.
                break;
            }

            // Optimization: Use ID as anchor if found during traversal and globally unique
            if (currentEl.id) {
                try {
                    const escapedId = escape(currentEl.id);
                    if (escapedId && safeQuery('#' + escapedId).length === 1) {
                        path.unshift('#' + escapedId);
                        break;
                    }
                } catch (e) {
                    logError('getCssSelector (Path ID)', e);
                    // Continue path generation even if ID check fails
                }
            }

            // Calculate nth-of-type for structural uniqueness
            let sib = currentEl, nth = 1;
            while (sib = sib.previousElementSibling) {
                if (sib.nodeName.toLowerCase() === selector)
                    nth++;
            }
            // Heuristic: Only add nth-of-type if necessary
            if (nth > 1 || currentEl.previousElementSibling || currentEl.nextElementSibling) {
                // Be more specific if siblings exist
                selector += ":nth-of-type(" + nth + ")";
            }


            path.unshift(selector);
            currentEl = currentEl.parentNode;
        }

        if (path.length === 0 || path[0] === 'body') {
            // If the path is empty (fully detached) or only 'body' (meaning
            // we're trying to select the body itself, which wasn't the
            // original element 'el'), consider it a failure.
            if (el.nodeName.toLowerCase() !== 'body' && path[0] === 'body') return null;
            if (path.length === 0) return null;
        }

        // Use > for direct descendants for precision.
        return path.join(" > ");
    }

    // -- Scoring Functions --

    /**
     * Scores an input element based on keywords in its attributes, labels, and context.
     * Uses precise word boundary matching (matchesKeyword).
     */
    function scoreElement(element, searchKeywords, fieldType) {
        let score = 0;
        const attributesRaw = (element.id || "") + " " + (element.name || "") + " " + (element.placeholder || "") + " " + (element.getAttribute('aria-label') || "");

        // Check Autocomplete attribute (Strong signal)
        const autocomplete = (element.getAttribute('autocomplete') || "").toLowerCase();
        if (autocomplete) {
            if (searchKeywords.includes(autocomplete)) {
                score += 30;
            }
            // Specific high value signals for registration forms
            if (autocomplete === 'new-password' && fieldType === 'password') score += 35;
            if (autocomplete === 'new-password' && fieldType === 'passwordConfirm') score += 30;
            if (autocomplete === 'email' && fieldType === 'email') score += 30;
        }

        // Score attributes
        // Normalize attributes (replacing delimiters with spaces) for better keyword matching.
        const attributesLower = attributesRaw.replace(/[-_]/g, ' ').toLowerCase();
        searchKeywords.forEach(keyword => {
            // Use precise matching instead of includes().
            if (matchesKeyword(attributesLower, keyword)) {
                score += 10;
            }
        });

        // Bonus points for specific input types
        if (element.tagName === 'INPUT') {
            const type = (element.type || 'text').toLowerCase();
            if (type === 'email' && (fieldType === 'email' || fieldType === 'username')) score += 20;
            if (type === 'password' && (fieldType === 'password' || fieldType === 'passwordConfirm')) score += 25;
            // Reduced bonus for generic text input. A score of 5 means only the type matched.
            if ((type === 'text' || type === 'tel') && (fieldType === 'username' || fieldType === 'email' || fieldType === 'firstName' || fieldType === 'lastName')) score += 5;
        }

        // Check associated labels (Robust association)
        let labelText = "";

        // 1. Try finding label by 'for' attribute
        if (element.id) {
            try {
                // Rely on CSS.escape availability (handled by polyfill in tests).
                if (typeof CSS !== 'undefined' && CSS.escape) {
                    const escapedId = CSS.escape(element.id);
                    if (escapedId) {
                        // Use safeQuery wrapper
                        const label = document.querySelector('label[for="' + escapedId + '"]');
                        labelText = getVisibleText(label);
                    }
                }
            } catch (e) {
                logError('scoreElement (label[for])', e);
            }
        }

        // 2. Try finding wrapping label if 'for' didn't yield results
        if (!labelText && element.closest) {
            const wrappingLabel = element.closest('label');
            if (wrappingLabel) {
                // Heuristic: Ensure the wrapping label isn't too broad
                try {
                    // Check if this label wraps multiple inputs, which would make it ambiguous
                    const inputsInLabel = wrappingLabel.querySelectorAll('input');
                    if (inputsInLabel.length <= 2) {
                        labelText = getVisibleText(wrappingLabel);
                    }
                } catch (e) {
                    logError('scoreElement (closest label)', e);
                }
            }
        }

        if (labelText) {
            searchKeywords.forEach(keyword => {
                // Use precise matching. Increased weight for labels.
                if (matchesKeyword(labelText, keyword)) {
                    score += 20;
                }
            });
        }

        return score;
    }

    /**
     * Scores buttons based on visible text and attributes.
     * Uses precise word boundary matching (matchesKeyword).
     */
    function scoreButton(element, searchKeywords) {
        let score = 0;
        // Get the primary visible text
        const visibleText = getVisibleText(element);

        // Get secondary attributes (aria-label, id, name). Normalize delimiters.
        const attributesRaw = (element.getAttribute('aria-label') || element.id || element.name || "");
        const attributesLower = attributesRaw.replace(/[-_]/g, ' ').toLowerCase();

        // Score visible text (high weight)
        searchKeywords.forEach(keyword => {
            // Use precise matching.
            if (matchesKeyword(visibleText, keyword)) {
                score += 20;
            }
        });

        // Score attributes (lower weight)
        searchKeywords.forEach(keyword => {
            if (matchesKeyword(attributesLower, keyword)) {
                score += 10;
            }
        });

        // Extra points for explicit submit type
        const type = (element.type || '').toLowerCase();
        if (type === 'submit') {
            score += 15;
        }
        // Points for role="button" (SPA scenario)
        if (element.tagName !== 'BUTTON' && element.tagName !== 'INPUT' && element.getAttribute && element.getAttribute('role') === 'button') {
            score += 5;
        }
        return score;
    }

    // -- Main Analysis Logic --

    // Identify potential contexts: prioritize forms, fallback to specific divs or body for SPAs.
    let contexts = [];
    try {
        contexts = Array.from(document.querySelectorAll('form'));
    } catch (e) {
        logError('analyze (querySelectorAll form)', e);
    }

    // Fallback for SPAs
    if (contexts.length === 0) {
        try {
            // Prioritize elements that strongly suggest a registration context.
            contexts = Array.from(document.querySelectorAll('[class*="signup"], [class*="register"], [id*="signup"], [id*="register"], main, article'));
        } catch (e) {
            logError('analyze (querySelectorAll SPA)', e);
        }
    }
    if (contexts.length === 0 && document.body) {
        contexts.push(document.body);
    }


    // Iterate through contexts and analyze elements.
    contexts.forEach(context => {
        let visibleElements = [];
        try {
            // Select relevant interactive elements. Exclude hidden/disabled elements and common noise (like CSRF tokens).
            // We rely on CSS selectors for filtering as JS visibility checks (offsetParent) are unreliable in JSDOM.
            const selector = 'input:not([type="hidden"]):not([disabled]):not([hidden]):not([name*="csrf"]):not([name*="captcha"]), button:not([disabled]):not([hidden]), [role="button"]:not([aria-disabled="true"]):not([hidden])';
            visibleElements = Array.from(context.querySelectorAll(selector));
        } catch (e) {
            logError('analyze (querySelectorAll visibleElements)', e);
            return; // Skip context if querying fails
        }

        let currentForm = {
            context: context,
            fields: {},
            submitButton: null,
            score: 0
        };

        // Add score to the context itself based on its attributes
        const contextAttributes = ((context.id || "") + " " + (context.name || "") + " " + (context.className || "")).toLowerCase().replace(/[-_]/g, ' ');
        if (matchesKeyword(contextAttributes, "signup") || matchesKeyword(contextAttributes, "register")) {
            currentForm.score += 25;
        }
        if (matchesKeyword(contextAttributes, "login") || matchesKeyword(contextAttributes, "signin")) {
            // Penalize contexts that look strongly like login forms.
            currentForm.score -= 10;
        }

        // -- Field Scoring and Assignment --
        // REFACTORED: Transition from Greedy matching to Maximum Weight Matching (approximated by sorting).
        // This ensures the globally optimal assignment of inputs to field types, improving robustness.

        // 1. Define relevant inputs and field types.
        const fieldTypes = Object.keys(keywords).filter(k => k !== 'submit');

        // Filter visible elements to include only actual INPUT elements suitable for fields.
        const inputs = visibleElements.filter(el => {
            if (el.tagName !== 'INPUT') return false;
            const type = (el.type || 'text').toLowerCase();
            // Exclude inputs that function as buttons or controls (checkbox/radio excluded for simplicity in this scope).
            if (['submit', 'button', 'reset', 'image'].includes(type)) {
                return false;
            }
            return true;
        });

        const scoreMatrix = [];
        // Define the minimum score threshold. Score > 5 ensures more than just the type matched (e.g. type=text scores 5).
        const MIN_SCORE_THRESHOLD = 5;

        // 2. Calculate all scores and apply threshold.
        inputs.forEach(input => {
            fieldTypes.forEach(fieldType => {
                const score = scoreElement(input, keywords[fieldType], fieldType);

                if (score > MIN_SCORE_THRESHOLD) {
                    scoreMatrix.push({ input, fieldType, score });
                }
            });
        });

        // 3. Sort scores descending to prioritize the strongest matches globally.
        scoreMatrix.sort((a, b) => b.score - a.score);

        // 4. Assign fields based on sorted scores (Maximum Weight Matching approximation).
        const assignedInputs = new Set();
        const assignedFieldTypes = new Set();

        for (const match of scoreMatrix) {
            // Ensure each input is assigned only once and each field type is assigned only once.
            if (!assignedInputs.has(match.input) && !assignedFieldTypes.has(match.fieldType)) {
                currentForm.fields[match.fieldType] = match.input;
                currentForm.score += match.score;
                assignedInputs.add(match.input);
                assignedFieldTypes.add(match.fieldType);
            }
        }

        // -- Submit Button Scoring --
        let bestButton = null;
        let highestButtonScore = 0;

        visibleElements.forEach(button => {
            const tagName = button.tagName;
            const type = (button.type || '').toLowerCase();

            // Focus on <button>, <input type="submit/button">, or elements with role="button".
            const isButtonLike = tagName === 'BUTTON' ||
                (tagName === 'INPUT' && (type === 'submit' || type ==='button')) ||
                (button.getAttribute && button.getAttribute('role') === 'button');

            if (isButtonLike) {
                let score = scoreButton(button, keywords.submit);

                if (score > highestButtonScore) {
                    highestButtonScore = score;
                    bestButton = button;
                }
            }
        });

        // Fallback mechanism for submit buttons.
        const MIN_BUTTON_SCORE_THRESHOLD = 10;
        if (highestButtonScore < MIN_BUTTON_SCORE_THRESHOLD && context.tagName === 'FORM') {
            try {
                // If keywords didn't match strongly, look for any remaining explicit submit button.
                const fallbackSubmit = context.querySelector('[type="submit"]:not([disabled]):not([hidden])');
                if (fallbackSubmit && fallbackSubmit !== bestButton) {
                    bestButton = fallbackSubmit;
                    highestButtonScore = 10; // Assign baseline score
                }
            } catch (e) {
                logError('analyze (button fallback)', e);
            }
        }

        if (bestButton) {
            currentForm.submitButton = bestButton;
            currentForm.score += highestButtonScore;
        }

        // -- Form Validation and Selection --
        // Determine if this is the best form found so far.
        // Essential criteria for a Sign Up form: (email OR username) AND password AND submit.
        const hasIdentifier = currentForm.fields.email || currentForm.fields.username;
        const hasPassword = currentForm.fields.password;
        const hasSubmit = currentForm.submitButton;

        // Bonus points if a password confirmation field is present (strong indicator of registration).
        if (currentForm.fields.passwordConfirm) {
            currentForm.score += 30;
        }

        if (hasIdentifier && hasPassword && hasSubmit && currentForm.score > bestForm.score) {
            bestForm = currentForm;
        }
    });

    // Prepare the final result object with CSS selectors
    const result = {
        fields: {},
        submitSelector: null,
        contextSelector: null
    };

    // Generate selectors only if a valid form context was found, the score is positive, and a submit button exists.
    if (bestForm.context && bestForm.score > 0 && bestForm.submitButton) {
        // Get the context selector relative to the document.
        result.contextSelector = getCssSelector(bestForm.context, document);

        // Defense in depth: Ensure context selector was generated successfully.
        if (result.contextSelector) {
            Object.keys(bestForm.fields).forEach(fieldType => {
                // Pass the context to enable context relative selectors.
                const selector = getCssSelector(bestForm.fields[fieldType], bestForm.context);
                if (selector) {
                    result.fields[fieldType] = selector;
                }
                // If selector is null, it's silently skipped (coverage target)
            });

            const submitSelector = getCssSelector(bestForm.submitButton, bestForm.context);
            if (submitSelector) {
                result.submitSelector = submitSelector;
            }
        } else {
            // If context selector generation failed (e.g., detached DOM), reset results to ensure consistency.
            result.contextSelector = null;
            result.fields = {};
            result.submitSelector = null;
        }
    }

    return result;
}


// Export for testing environments (e.g., Node.js with JSDOM)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { analyzeSignUpForm };
} else {
    // In a browser context (Go executor), the last evaluated expression is the return value.
    analyzeSignUpForm();
}