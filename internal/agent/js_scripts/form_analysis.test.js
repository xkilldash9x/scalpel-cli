/**
 * @jest-environment jsdom
 */

// Mock CSS.escape if not available in the test environment (JSDOM might lack it)
if (typeof global.CSS === 'undefined') {
    global.CSS = {};
}
if (!global.CSS.escape) {
    // Use a robust polyfill for CSS.escape, handling various edge cases like IDs starting with numbers.
    // Source: Adapted from https://github.com/mathiasbynens/CSS.escape/blob/main/css.escape.js
    global.CSS.escape = function(value) {
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
}

// Import the function directly, thanks to the module.exports in the JS file.
const { analyzeSignUpForm } = require('./form_analysis.js');

// Helper function to set the document body HTML before running the analysis
function setDocumentBody(html) {
    document.body.innerHTML = html;
}

describe('analyzeSignUpForm', () => {

    // Clean up the DOM after each test
    afterEach(() => {
        document.body.innerHTML = '';
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
    });

    test('should identify form using names when IDs are missing (Context-Relative Preferred)', () => {
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
        
        // The updated implementation prioritizes context-relative selectors when the names are unique within the context.
        expect(result.fields.username).toBe('form[name="signup"] input[name="username"]');
        expect(result.fields.password).toBe('form[name="signup"] input[name="password"]');
        
        // The submit button selector might fall back to structural if it lacks ID/Name.
        expect(result.submitSelector).toBeTruthy();
        // Verify the selector actually finds the element
        expect(document.querySelector(result.submitSelector).value).toBe("Register");
    });

     // Verify context-relative selectors when names are ambiguous globally.
     test('should use context-relative selectors when names are ambiguous globally', () => {
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
        // it must use the context-relative selector logic (e.g., "#register-form input[name=...]")
        expect(result.fields.username).toBe('#register-form input[name="field1"]');
        expect(result.fields.password).toBe('#register-form input[name="field2"]');
        expect(result.submitSelector).toBe('#register-submit');
    });

    test('should handle SPA-style forms (divs instead of form tag)', () => {
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
    });

    test('should handle IDs requiring CSS escaping', () => {
        setDocumentBody(`
           <form id="form:1">
               <input type="email" id="user[email]" placeholder="Email">
               <input type="password" id="user.password" placeholder="Password">
               <button type="submit" id="submit-btn">Go</button>
           </form>
       `);

       const result = analyzeSignUpForm();

       // The robust polyfill should handle these escapes correctly.
       expect(result.contextSelector).toBe('#form\\:1');
       expect(result.fields.email).toBe('#user\\[email\\]');
       expect(result.fields.password).toBe('#user\\.password');
   });
});
