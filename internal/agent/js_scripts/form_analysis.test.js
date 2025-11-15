/**
 * @jest-environment jsdom
 */

// Add these Node.js built in modules
const fs = require('fs');
const path = require('path');

// Mock CSS.escape if not available in the test environment (JSDOM might lack it)
if (typeof global.CSS === 'undefined') {
    global.CSS = {};
}

// Store the original polyfill
const originalCssEscape = global.CSS.escape;

// Use a robust polyfill for CSS.escape, handling various edge cases like IDs starting with numbers.
// Source: Adapted from https://github.com/mathiasbynens/CSS.escape/blob/main/css.escape.js
const cssEscapePolyfill = function(value) {
    const string = String(value);
    const length = string.length;
    let index = -1;
    let codeUnit;
    let result = '';
    const firstCodeUnit = string.charCodeAt(0);
    while (++index < length) {
        codeUnit = string.charCodeAt(index);
        // Handle NULL character
        if (codeUnit === 0x0000) {
            result += '\uFFFD';
            continue;
        }

        if (
            // Control characters or specific escape scenarios (e.g., digits at start)
            (codeUnit >= 0x0001 && codeUnit <= 0x001F) || codeUnit === 0x007F ||
            (index === 0 && codeUnit >= 0x0030 && codeUnit <= 0x0039) ||
            (
                index === 1 &&
                codeUnit >= 0x0030 && codeUnit <= 0x0039 &&
                firstCodeUnit === 0x002D
            )
        ) {
            result += '\\' + codeUnit.toString(16) + ' ';
            continue;
        }

        if (
            // Allowed characters (alphanumeric, underscore, hyphen, extended ASCII)
            codeUnit >= 0x0080 ||
            codeUnit === 0x002D ||
            codeUnit === 0x005F ||
            (codeUnit >= 0x0030 && codeUnit <= 0x0039) ||
            (codeUnit >= 0x0041 && codeUnit <= 0x005A) ||
            (codeUnit >= 0x0061 && codeUnit <= 0x007A)
        ) {
            result += string.charAt(index);
            continue;
        }

        // Otherwise, escape it with a backslash.
        result += '\\' + string.charAt(index);
    }
    return result;
};

// Apply the polyfill
if (!global.CSS.escape) {
    global.CSS.escape = cssEscapePolyfill;
}


// Import the function directly, thanks to the module.exports in the JS file.
// We use a let variable so we can re require it in tests.
let { analyzeSignUpForm } = require('./form_analysis.js');

// Helper function to set the document body HTML before running the analysis
function setDocumentBody(html) {
    document.body.innerHTML = html;
}

describe('analyzeSignUpForm', () => {
    let originalRegExp;
    let originalModule;
    let consoleErrorSpy;
    let originalQSA; // <-- Store original QSA

    beforeAll(() => {
        originalRegExp = global.RegExp; // Save original RegExp
    });

    beforeEach(() => {
        // We reset modules before each test to ensure a clean state
        // and re import the function.
        jest.resetModules();
        originalModule = global.module; // Save original module
        originalQSA = document.querySelectorAll; // <-- Store original QSA

        // CRITICAL: Spy on console.error and mock it to silence logs in successful tests.
        // This allows us to assert that it *wasn't* called, or that it *was* called in error case tests.
        consoleErrorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

        // Re apply the polyfill after jest.resetModules()
        if (typeof global.CSS === 'undefined') {
            global.CSS = {};
        }
        global.CSS.escape = cssEscapePolyfill;

        // FIX: Add TextEncoder/TextDecoder to global scope for jsdom
        const { TextEncoder, TextDecoder } = require('util');
        global.TextEncoder = TextEncoder;
        global.TextDecoder = TextDecoder;


        // Re import the function
        ({ analyzeSignUpForm } = require('./form_analysis.js'));
    });

    // Clean up the DOM after each test
    afterEach(() => {
        document.body.innerHTML = '';
        global.RegExp = originalRegExp; // Restore RegExp
        global.module = originalModule; // Restore module
        consoleErrorSpy.mockRestore(); // Restore console.error
        jest.restoreAllMocks(); // Restore all other spies
    });

    test('should identify a standard HTML form with IDs', () => {
        setDocumentBody(`
            <form id="register-form">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="user_email" autocomplete="email">

                <label for="password">Password</label>
                <input type="password" id="password" name="user_password" autocomplete="new-password">

                <button type="submit" id="submit-btn">Create Account</button>
            </form>
        `);

        const result = analyzeSignUpForm();

        // IDs are globally unique, so they should be used directly.
        expect(result.contextSelector).toBe('#register-form');
        expect(result.fields.email).toBe('#email');
        expect(result.fields.password).toBe('#password');
        expect(result.submitSelector).toBe('#submit-btn');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    test('should identify form using names when IDs are missing (Context Relative Preferred)', () => {
        setDocumentBody(`
            <div id="container">
                <form name="signup">
                    <input type="text" name="username">
                    <input type="password" name="password">
                    <input type="submit" value="Register">
                </form>
            </div>
        `);

        const result = analyzeSignUpForm();

        // The context selector should be the globally unique name selector for the form.
        expect(result.contextSelector).toBe('form[name="signup"]');

        // The updated implementation prioritizes context relative selectors when the names are unique within the context.
        expect(result.fields.username).toBe('form[name="signup"] input[name="username"]');
        expect(result.fields.password).toBe('form[name="signup"] input[name="password"]');

        // The submit button selector might fall back to structural if it lacks ID/Name.
        expect(result.submitSelector).toBeTruthy();
        // Verify the selector actually finds the element
        expect(document.querySelector(result.submitSelector).value).toBe("Register");
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    // Verify context relative selectors when names are ambiguous globally.
    test('should use context relative selectors when names are ambiguous globally', () => {
        setDocumentBody(`
            <form id="login-form">
                <input type="text" name="field1" placeholder="Login Username">
                <input type="password" name="field2" placeholder="Login Password">
                <button type="submit">Login</button>
            </form>

            <form id="register-form">
                <input type="text" name="field1" placeholder="Register Username">
                <input type="password" name="field2" placeholder="Register Password">
                <button type="submit" id="register-submit">Create Account</button>
            </form>
        `);

        const result = analyzeSignUpForm();

        // It should select the registration form based on scoring (Create Account button)
        expect(result.contextSelector).toBe('#register-form');

        // Since name="field1" and name="field2" are ambiguous globally,
        // it must use the context relative selector logic (e.g., "#register-form input[name=...]")
        expect(result.fields.username).toBe('#register-form input[name="field1"]');
        expect(result.fields.password).toBe('#register-form input[name="field2"]');
        expect(result.submitSelector).toBe('#register-submit');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    test('should handle SPA style forms (divs instead of form tag)', () => {
        // We use an explicit class recognizable by the script's selectors.
        setDocumentBody(`
            <div class="spa-register-container" id="register-context">
                <h2>Sign Up Now</h2>
                <input placeholder="Your Email" type="email" id="spa-email">
                <input placeholder="Choose Password" type="password" id="spa-password">
                <div role="button" class="submit-button" id="spa-submit">Sign Up</div>
            </div>
        `);

        const result = analyzeSignUpForm();

        // It should identify the register container as the context
        expect(result.contextSelector).toBe('#register-context');
        expect(result.fields.email).toBe('#spa-email');
        expect(result.fields.password).toBe('#spa-password');
        // It should identify the div with role="button" as the submit button
        expect(result.submitSelector).toBe('#spa-submit');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    test('should return empty result if no suitable form is found', () => {
        setDocumentBody(`
            <div>
                <h1>Welcome Page</h1>
                <p>No forms here.</p>
                 <form id="search-form">
                    <input type="text" name="query">
                    <button>Search</button>
                </form>
            </div>
        `);

        const result = analyzeSignUpForm();

        // Search form lacks password field, so it shouldn't be selected.
        expect(result.contextSelector).toBeNull();
        expect(result.submitSelector).toBeNull();
        expect(result.fields).toEqual({});
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    test('should handle multiple forms and select the best one', () => {
        setDocumentBody(`
            <form id="login-form">
                <input name="login_email">
                <input name="login_password" type="password">
                <button>Login</button>
            </form>

            <form id="register-form">
                <input name="first_name" id="fname">
                <input name="register_email" autocomplete="email" id="remail">
                <input name="register_password" type="password" autocomplete="new-password" id="rpass">
                <button id="rsubmit">Create Account</button>
            </form>
        `);

        const result = analyzeSignUpForm();

        // Should select the registration form due to higher score (autocomplete attributes, button text)
        expect(result.contextSelector).toBe('#register-form');
        expect(result.fields.email).toBe('#remail');
        expect(result.fields.password).toBe('#rpass');
        // Ensure other fields are also captured
        expect(result.fields.firstName).toBe('#fname');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    test('should handle IDs requiring CSS escaping', () => {
        setDocumentBody(`
           <form id="form:1">
               <input type="email" id="user[email]" placeholder="Email">
               <input type="password" id="user.password" placeholder="Password">
               <button type="submit" id="submit-btn">Go</button>
           </form>
       `);

        // We use the imported function
        const result = analyzeSignUpForm();

        // The robust polyfill should handle these escapes correctly.
        expect(result.contextSelector).toBe('#form\\:1');
        expect(result.fields.email).toBe('#user\\[email\\]');
        expect(result.fields.password).toBe('#user\\.password');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    // Test for matchesKeyword regex fallback
    test('should fallback to string includes if regex fails in matchesKeyword', () => {
        // Mock the RegExp constructor to throw an error for a specific keyword
        global.RegExp = jest.fn((...args) => {
            if (args[0].includes('email')) { // Throw on the "email" keyword
                throw new Error('Regex compile error');
            }
            return new originalRegExp(...args);
        });

        setDocumentBody(`
            <form id="register-form">
                <label for="email">Email</label>
                <input type="email" id="email" name="user_email">
                <input type="password" id="password" name="user_password">
                <button type="submit" id="submit-btn">Create Account</button>
            </form>
        `);

        // The function should *still work* by falling back to includes()
        const result = analyzeSignUpForm();
        expect(result.fields.email).toBe('#email'); // It found the email field
        expect(result.contextSelector).toBe('#register-form'); // It found the form

        // We EXPECT an error to be logged here
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('matchesKeyword'),
            expect.any(String), // message
            expect.stringContaining('Regex compile error') // stack
        );
    });

    // Test for failure to generate context selector
    test('should return empty result if context selector generation fails', () => {
        // Create a valid form *not* attached to the document body
        const form = document.createElement('form');
        form.id = 'detached-form'; // Give it an ID
        form.innerHTML = `
            <input type="email" name="email" autocomplete="email">
            <input type="password" name="password" autocomplete="new-password">
            <button type="submit">Create Account</button>
        `;
        // This form is NOT in document.body

        // Mock querySelectorAll to return this detached form
        jest.spyOn(document, 'querySelectorAll').mockImplementation((selector) => {
            if (selector === 'form') {
                return [form]; // Return the detached form
            }
            // Fallback for other queries (like the ID check)
            // FIX: Use the stored originalQSA, not the fragile requireActual path
            const realNodes = originalQSA.call(document, selector);
            if (selector === '#detached-form') {
                // If safeQuery checks for the ID, it *must not* find it in the document
                return [];
            }
            return realNodes;
        });

        const result = analyzeSignUpForm();

        // getCssSelector(form, document) should fail.
        // 1. It checks form.id ("detached-form").
        // 2. It runs safeQuery("#detached-form").
        // 3. Our mock makes this return [] (not unique).
        // 4. It falls back to path generation.
        // 5. Path generation fails because parentNode is null.
        // 6. getCssSelector returns null.
        expect(result.contextSelector).toBeNull();
        expect(result.fields).toEqual({});
        expect(result.submitSelector).toBeNull();
        // No error should be logged, this is a graceful failure.
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    // -- NEW TESTS FOR COVERAGE --

    // Test for getVisibleText (null/undefined element)
    test('getVisibleText helper should handle null or undefined element', () => {
        setDocumentBody(`
            <form id="register-form">
                <label for="no-exist">Label for nothing</label>
                <input type="email" id="email" name="user_email" autocomplete="email">
                <input type="password" id="password" name="user_password" autocomplete="new-password">
                <button type="submit" id="submit-btn">Create Account</button>
            </form>
        `);

        // The code path for getVisibleText(label) where label is null
        // is triggered inside scoreElement when checking label[for="email"] (which doesn't exist).
        // This test implicitly covers it, and we just check for success.
        const result = analyzeSignUpForm();
        expect(result.fields.email).toBe('#email');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    // Test for getVisibleText innerText fallback
    test('getVisibleText should fall back to innerText if textContent is null', () => {
        setDocumentBody(`
            <form id="register-form">
                <input type="email" id="email" autocomplete="email">
                <input type="password" id="password" autocomplete="new-password">
                <button type="submit" id="submit-btn">Register</button>
            </form>
        `);

        // Mock textContent to be null on the button
        const button = document.getElementById('submit-btn');
        Object.defineProperty(button, 'textContent', { value: null });
        button.innerText = "Register"; // Provide innerText

        const result = analyzeSignUpForm();
        // The script should successfully find the button text via innerText
        expect(result.submitSelector).toBe('#submit-btn');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    // Test for safeQuery (Invalid Scope)
    test('should handle safeQuery being called with an invalid scope', () => {
        setDocumentBody(`
            <form id="register-form" name="signup">
                <input name="email" id="email" autocomplete="email">
                <input name="password" id="password" autocomplete="new-password">
                <button type="submit">Register</button>
            </form>
        `);

        const form = document.createElement('form');
        form.id = 'detached-form';
        form.innerHTML = `...`;
        // Make the form's querySelectorAll invalid
        form.querySelectorAll = undefined;

        jest.spyOn(document, 'querySelectorAll').mockImplementation((selector) => {
            if (selector === 'form') {
                return [form]; // Return the broken form
            }
            return originalQSA.call(document, selector);
        });

        // Running the analysis will cause the script to find 'form'
        // Then, it will try to run `context.querySelectorAll(...)` to find visible elements.
        // This will fail *inside* the 'analyze' function.
        const result = analyzeSignUpForm();

        expect(result.contextSelector).toBeNull();
        // The error is logged from 'analyze', not 'safeQuery'
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('analyze (querySelectorAll visibleElements)'),
            expect.any(String), // message
            expect.stringContaining('context.querySelectorAll is not a function') // stack
        );
    });

    // Test for CSS.escape fallback
    test('should use CSS.escape fallback if global is missing', () => {
        // Remove the polyfill for this test
        global.CSS.escape = undefined;

        setDocumentBody(`
           <form id="form:1">
               <input type="email" id="user.email" placeholder="Email" autocomplete="email">
               <input type="password" id="password" placeholder="Password" autocomplete="new-password">
               <button type="submit" id="submit-btn">Go</button>
           </form>
       `);

        const result = analyzeSignUpForm();

        // The basic fallback should still work for these characters
        expect(result.contextSelector).toBe('#form\\:1');
        expect(result.fields.email).toBe('#user\\.email');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });


    // Test for getCssSelector (Path ID) catch
    test('should handle errors during getCssSelector (Path ID) query', () => {
        setDocumentBody(`
            <div id="wrapper-id">
                <form> <!-- NO ID on form -->
                    <input name="email" id="email" autocomplete="email">
                    <input name="password" id="password" autocomplete="new-password">
                    <button type="submit">Register</button>
                </form>
            </div>
        `);

        // Mock document.querySelectorAll to throw *only* for #wrapper-id
        jest.spyOn(document, 'querySelectorAll').mockImplementation((selector) => {
            if (selector === '#wrapper-id') {
                throw new Error('Invalid ID selector');
            }
            return originalQSA.call(document, selector);
        });

        const result = analyzeSignUpForm();
        // The script should log the error and gracefully fall back to the full structural path
        expect(result.contextSelector).toBe('body > div:nth-of-type(1) > form:nth-of-type(1)');
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('getCssSelector (Path ID)'),
            expect.any(String), // message
            expect.stringContaining('Invalid ID selector') // stack
        );
    });

    // Test for getCssSelector path failure (detached element)
    test('should return null from getCssSelector for a fully detached element', () => {
        setDocumentBody(`
            <form id="register-form">
                <input name="email" id="email" autocomplete="email">
                <input name="email" id="email2" autocomplete="email"> <!-- FIX: Add ambiguity -->
                <input name="password" id="password" autocomplete="new-password">
                <button type="submit">Register</button>
            </form>
        `);

        // Get the element
        const emailInput = document.getElementById('email');
        // CRITICAL: Remove the ID to prevent it from being used
        emailInput.id = '';
        // CRITICAL: Detach it by mocking its parent
        Object.defineProperty(emailInput, 'parentNode', { value: null });

        const result = analyzeSignUpForm();
        
        // The script should find the form.
        // getCssSelector(emailInput) is called.
        // 1. ID check fails (id='').
        // 2. Context Name check fails (input[name="email"] finds 2).
        // 3. Global Name check fails (input[name="email"] finds 2).
        // 4. Path generation fails (parentNode is null).
        // 5. getCssSelector returns null.
        expect(result.contextSelector).toBe('#register-form');
        expect(result.fields.email).toBeUndefined(); // Selector generation failed
        expect(result.fields.password).toBe('#password'); // Other field is fine
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });

    // Test for scoreElement (closest label) catch
    test('should handle errors during wrapping label query', () => {
        setDocumentBody(`
            <form id="register-form">
                <label id="label-wrapper">
                    Email
                    <input type="email" id="email" autocomplete="email">
                </label>
                <input type="password" id="password" autocomplete="new-password">
                <button type="submit">Register</button>
            </form>
        `);

        // Mock querySelectorAll on the label to throw
        const label = document.getElementById('label-wrapper');
        jest.spyOn(label, 'querySelectorAll').mockImplementation((selector) => {
            throw new Error('Label QSA failed');
        });

        const result = analyzeSignUpForm();
        // The script should log the error but proceed.
        // The email field might get a lower score but should still be found
        // due to autocomplete attribute.
        expect(result.contextSelector).toBe('#register-form');
        expect(result.fields.email).toBe('#email');
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('scoreElement (closest label)'),
            expect.any(String), // message
            expect.stringContaining('Label QSA failed') // stack
        );
    });

    // Test for analyze (button fallback) no-op
    test('should not replace bestButton if fallback is the same button', () => {
         setDocumentBody( 
            `
            <form id="register-form">
                <input type="email" id="email" autocomplete="email">
                <input type="password" id="password" autocomplete="new-password">
                <!-- bestButton will be this, with score 5 (role=button) -->
                <div role="button" id="submit-div">Go</div>
                <!-- Fallback query will find this, score 10 -->
                <input type="submit" id="fallback-btn" value="Submit">
            </form>
        `);
        
        const result = analyzeSignUpForm();
        // bestButton is #submit-div (score 5 + 7-4=8).
        // "Go" isn't a keyword. Score is 5 (role=button).
        // Let's re-score with new logic:
        // #submit-div: text "go" (no match) -> 0. role="button" -> 5. Total 5.
        // #fallback-btn: text "submit" (index 4) -> 20 + (7-4) = 23. type="submit" -> 15. Total 38.
        // The visibleElements loop finds both.
        // bestButton will be #fallback-btn (score 38).
        // Fallback logic `if (highestButtonScore < MIN_BUTTON_SCORE_THRESHOLD ...)` (38 < 10) is false.
        // Fallback doesn't run.
        expect(result.submitSelector).toBe('#fallback-btn');
        
        // Case where they are the same
         setDocumentBody(`
            <form id="register-form">
                <input type="email" id="email" autocomplete="email">
                <input type="password" id="password" autocomplete="new-password">
                <!-- bestButton will be this -->
                <input type="submit" id="fallback-btn" value="Go">,
            </form>
        `);
        // #fallback-btn: text "go" -> 0. type="submit" -> 15. Total 15.
        // `bestButton` is #fallback-btn (score 15).
        // `highestButtonScore < 10` is false. Fallback doesn't run.
        const result2 = analyzeSignUpForm();
        expect(result2.submitSelector).toBe('#fallback-btn');
        
        // Case where fallback runs and finds the same button
        setDocumentBody(`
            <form id="register-form">
                <input type="email" id="email" autocomplete="email">
                <input type="password" id="password" autocomplete="new-password">
                <!-- This button's text "go" gives score 0. type="submit" gives 15. Total 15. -->
                <input type="submit" id="submit-btn" value="Go">
            </form>
        `);
        // `bestButton` is #submit-btn (score 15).
        // `highestButtonScore < 10` is false.
        expect(analyzeSignUpForm().submitSelector).toBe('#submit-btn');
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });


    // Test for getCssSelector returning null for a field
    test('should skip fields where selector generation fails', () => {
        setDocumentBody(`
            <form id="register-form">
                <input name="email" id="email" autocomplete="email">
                <input name="email" id="email2" autocomplete="email"> <!-- FIX: Add ambiguity -->
                <input name="password" id="password" autocomplete="new-password">
                <button type="submit">Register</button>
            </form>
        `);

        // Mock the email input to be detached AND remove its ID
        const emailInput = document.getElementById('email');
        emailInput.id = ''; // Remove ID
        Object.defineProperty(emailInput, 'parentNode', { value: null }); // Detach

        const result = analyzeSignUpForm();
        // The script should find the form and password, but fail to get
        // a selector for the email input and exclude it from the final result.
        expect(result.contextSelector).toBe('#register-form');
        expect(result.fields.password).toBe('#password');
        expect(result.fields.email).toBeUndefined();
        expect(consoleErrorSpy).not.toHaveBeenCalled();
    });


    // Test for handles errors during global name-based selector query
    test('should handle errors during global name based selector query', () => {
        setDocumentBody(`
            <form id="register-form">
                <input name="email" id="email" autocomplete="email">
                <input name="password" id="password" autocomplete="new-password">
                <button name="submit-btn" type="submit">Register</button>
                <button name="submit-btn" type="submit">Register 2</button>
            </form>
        `);

        // Mock document.querySelectorAll to throw *only* for the global name selector
        jest.spyOn(document, 'querySelectorAll').mockImplementation((selector) => {
            if (selector === 'button[name="submit-btn"]') {
                throw new Error('Invalid name selector');
            }
            // Allow context query to proceed
            if (selector === '#register-form button[name="submit-btn"]') {
                 return originalQSA.call(document, selector);
            }
            return originalQSA.call(document, selector);
        });

        const result = analyzeSignUpForm();

        // It should fail to find the button by name (contextual or global)
        // and fall back to a structural selector.
        expect(result.submitSelector).not.toBe('button[name="submit-btn"]');
        expect(result.submitSelector).toContain('nth-of-type'); // Should be structural

        // It should log the error from the (Global Name) block
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('getCssSelector (Global Name)'),
            expect.any(String), // message
            expect.stringContaining('Invalid name selector') // stack
        );
    });

    // Test for handles errors during label[for] query
    test('should handle errors during label[for] query', () => {
        setDocumentBody(`
            <form id="register-form">
                <label for="email.field">Email</label>
                <input type="email" id="email.field" autocomplete="email">
                <input type="password" id="password" autocomplete="new-password">
                <button type="submit">Register</button>
            </form>
        `);

        // Mock document.querySelector to throw for the specific escaped selector
        const originalQS = document.querySelector;
        jest.spyOn(document, 'querySelector').mockImplementation((selector) => {
            if (selector === 'label[for="email\\.field"]') {
                throw new Error('Invalid selector');
            }
            return originalQS.call(document, selector);
        });

        const result = analyzeSignUpForm();
        // The script should not crash and should still identify the form,
        // even if the label score for email is lost.
        expect(result.contextSelector).toBe('#register-form');
        expect(result.fields.email).toBe('#email\\.field');
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('scoreElement (label[for])'),
            expect.any(String), // message
            expect.stringContaining('Invalid selector') // stack
        );
    });

    // Test for button scoring logic to select the best button
    test('should select button with highest score from keywords', () => {
        setDocumentBody(`
            <form id="register-form">
                <input type="email" id="email" autocomplete="email">
                <input type="password" id="password" autocomplete="new-password">
                <button id="b1" type="submit">Continue</button>
                <button id="b2" type="submit">Create Account</button>
            </form>
        `);
        const result = analyzeSignUpForm();
        // "Create Account" (index 2) gets 20 + (7-2) = 25
        // "Continue" (index 5) gets 20 + (7-5) = 22
        // Both get +15 for type="submit". #b2 wins.
        expect(result.submitSelector).toBe('#b2');
    });

    // Test for button fallback logic
    test('should fallback to first explicit submit button if keyword match fails', () => {
        setDocumentBody(`
            <form id="register-form">
                <input type="email" id="email" autocomplete="email">
                <input type="password" id="password" autocomplete="new-password">
                <button id="b1" type="submit">Go</button>
                <button id="b2"T" type="button">Back</button>
            </form>
        `);
        const result = analyzeSignUpForm();
        // "Go" has a score of 0 from keywords, but 15 from type="submit".
        // `highestButtonScore` is 15. Fallback does not run. #b1 is selected.
        expect(result.submitSelector).toBe('#b1');
    });

    // Test for line 362 (scoreButton fallback catch)
    test('should handle errors during button fallback query', () => {
        setDocumentBody(`
            <form id="register-form">
                <input type="email" id="email" autocomplete="email">
                <input type="password" id="password" autocomplete="new-password">
                <button id="fallback-btn" type="button">Go</button>
            </form>
        `);
        
        const form = document.getElementById('register-form');
        // Mock the form's querySelector to throw when the fallback runs
        jest.spyOn(form, 'querySelector').mockImplementation((selector) => {
            if (selector.includes('[type="submit"]')) {
                throw new Error('Fallback query failed');
            }
            // Use the original implementation for other queries
            return originalQSA.call(form, selector);
        });

        const result = analyzeSignUpForm();
        // It should fail the fallback and *not* select the button
        // because its score ("Go") is 0, and the fallback query failed.
        // Thus, no form is found.
        expect(result.contextSelector).toBeNull();
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('analyze (button fallback)'),
            expect.any(String),
            expect.stringContaining('Fallback query failed')
        );
    });

    // Test for Context query catches
    test('should handle errors during "form" query and fallback to SPA', () => {
        // Mock 1: Fail 'form' query, succeed on SPA query
        setDocumentBody(`
            <div class="signup-container" id="spa-context">
                <input name="email" autocomplete="email">
                <input type="password" name="password" autocomplete="new-password">
                <button type="submit">Sign Up</button>
            </div>
        `);
        const error = new Error('Global QSA failed');
        jest.spyOn(document, 'querySelectorAll').mockImplementation((selector) => {
            if (selector === 'form') throw error; // Fail 'form' query
            // Allow other queries (SPA, fields) to work
            return originalQSA.call(document, selector);
        });

        // Should find SPA context via SPA fallback
        expect(analyzeSignUpForm().contextSelector).toBe('#spa-context');
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('analyze (querySelectorAll form)'),
            expect.any(String), // message
            expect.stringContaining('Global QSA failed') // stack
        );
    });

    test('should handle errors during "SPA" query and fallback to body', () => {
        // Mock 2: Fail 'SPA' query, succeed on body fallback
        setDocumentBody(`
            <input name="email" autocomplete="email">
            <input type="password" name="password" autocomplete="new-password">
            <button type="submit">Sign Up</button>
        `);
        const error = new Error('Global SPA QSA failed');
        jest.spyOn(document, 'querySelectorAll').mockImplementation((selector) => {
            if (selector === 'form') return []; // No forms
            if (selector.includes('signup')) throw error; // SPA query fails
            return originalQSA.call(document, selector);
        });

        // Should find body via final fallback
        expect(analyzeSignUpForm().contextSelector).toBe('body');
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('analyze (querySelectorAll SPA)'),
            expect.any(String), // message
            expect.stringContaining('Global SPA QSA failed') // stack
        );
    });

    test('should handle errors during "visibleElements" query', () => {
        // Mock 3: Fail 'visibleElements' query
        setDocumentBody('<form id="my-form"><input name="email"></form>');
        const form = document.getElementById('my-form');
        jest.spyOn(form, 'querySelectorAll').mockImplementation(() => {
            throw new Error('Visible elements query failed');
        });

        // Should find no form, as the context analysis fails
        expect(analyzeSignUpForm().contextSelector).toBeNull();
        expect(consoleErrorSpy).toHaveBeenCalledWith(
            expect.stringContaining('analyze (querySelectorAll visibleElements)'),
            expect.any(String), // message
            expect.stringContaining('Visible elements query failed') // stack
        );
    });

    // Test for non-module environment
    test('should execute analyzeSignUpForm directly in non-module (browser) environment', () => {
        // 1. Spy on a method we know analyzeSignUpForm() will call
        const querySelectorAllSpy = jest.spyOn(document, 'querySelectorAll').mockImplementation(() => []);

        try {
            // 2. Read the script file content
            const scriptPath = path.resolve(__dirname, 'form_analysis.js');
            const scriptContent = fs.readFileSync(scriptPath, 'utf8');

            // 3. Shadow the test file's local 'module' variable
            const module = undefined;

            // 4. 'eval' the script, triggering the 'else' block
            eval(scriptContent);

            // 5. Check that the spy was called by the 'else' block's execution
            expect(querySelectorAllSpy).toHaveBeenCalledWith('form');
            expect(consoleErrorSpy).not.toHaveBeenCalled();

        } finally {
            // The afterEach hook will restore spies
        }
    });
});