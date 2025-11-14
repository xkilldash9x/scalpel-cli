
/**
 * @jest-environment jsdom
 */

const { checkSuccessIndicators } = require('./verification_success.js');
const { checkErrorIndicators } = require('./verification_error.js');

// Helper function to set the document body HTML
function setDocumentBody(html) {
    document.body.innerHTML = html;
}

describe('Verification Scripts', () => {

    afterEach(() => {
        document.body.innerHTML = '';
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
    });
});
