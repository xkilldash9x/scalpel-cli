// internal/browser/interactor_test.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Increased timeout for stability, especially in CI environments.
const interactorTestTimeout = 90 * time.Second

func TestInteractor(t *testing.T) {
	// Ensure the global manager is ready.
	if suiteManagerErr != nil {
		t.Fatalf("Skipping Interactor tests due to initialization failure: %v", suiteManagerErr)
	}

	t.Run("FormInteraction", func(t *testing.T) {
		// Test comprehensive form filling including text, password, select inputs, and submission.
		fixture := newTestFixture(t)
		session := fixture.Session

		submissionChan := make(chan url.Values, 1)

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/submit" {
				r.ParseForm()
				// Make a copy of the form data.
				copiedForm := r.Form.Clone()
				select {
				case submissionChan <- copiedForm:
				default:
					t.Log("Warning: Form submission received but channel was full.")
				}
				fmt.Fprintln(w, `<html><body>Form processed</body></html>`)
				return
			}
			// Serve the form HTML.
			fmt.Fprintln(w, `
                <html><body>
                    <form action="/submit" method="POST">
                        <input type="text" name="username" id="userField" placeholder="Enter Username">
                        <input type="password" name="password">
                        <select name="color">
                            <option value="">Select...</option>
                            <option value="red">Red</option>
                            <option value="blue">Blue</option>
							<option value="disabled_opt" disabled>Disabled</option>
                        </select>
						<textarea name="comments"></textarea>
                        <button type="submit" id="submitBtn">Submit</button>
                    </form>
                </body></html>
            `)
		}))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), interactorTestTimeout)
		t.Cleanup(cancel)

		err := session.Navigate(ctx, server.URL)
		require.NoError(t, err)

		config := schemas.InteractionConfig{
			MaxDepth:                3,
			MaxInteractionsPerDepth: 10, // High enough to cover all form elements + submit.
			InteractionDelayMs:      50,
			PostInteractionWaitMs:   300,
		}

		// Run the interactor.
		err = session.Interact(ctx, config)
		require.NoError(t, err, "Interaction phase failed")

		// Wait for the form submission.
		var formData url.Values
		select {
		case formData = <-submissionChan:
			// Success
		case <-ctx.Done():
			t.Fatal("Test timed out waiting for form submission")
		}

		// Verify the interactor filled the form using the expected generated payloads.
		// The generator uses context clues (name, placeholder) to determine the payload.
		assert.Equal(t, "Test User", formData.Get("username"))
		assert.Equal(t, "ScalpelTest123!", formData.Get("password"))
		assert.Equal(t, "scalpel test input", formData.Get("comments")) // Default payload for textarea

		selectedColor := formData.Get("color")
		assert.True(t, selectedColor == "red" || selectedColor == "blue", "A valid color should have been selected")
		assert.NotEqual(t, "disabled_opt", selectedColor, "Should not select a disabled option")
	})

	t.Run("DynamicContentHandling_SPA", func(t *testing.T) {
		// Tests the interactor's ability to handle dynamically appearing content (common in SPAs).
		fixture := newTestFixture(t)
		session := fixture.Session

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `
                <html><body>
                    <div id="status">Initial</div>
                    <button id="revealBtn">Reveal Content</button>
                    <div id="dynamicContainer"></div>
                    <script>
                        document.getElementById('revealBtn').addEventListener('click', () => {
                            document.getElementById('status').innerText = 'Loading...';
                            // Simulate async loading (e.g., API call).
                            setTimeout(() => {
                                const dynamicContent = document.createElement('div');
                                dynamicContent.innerHTML = '<button id="dynamicBtn">Interact Dynamically</button>';
                                document.getElementById('dynamicContainer').appendChild(dynamicContent);
                                
                                document.getElementById('dynamicBtn').addEventListener('click', () => {
                                    document.getElementById('status').innerText = 'Dynamic Success';
                                });
                                
                                document.getElementById('status').innerText = 'Revealed';
                            }, 250);
                        });
                    </script>
                </body></html>
            `)
		}))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), interactorTestTimeout)
		t.Cleanup(cancel)

		err := session.Navigate(ctx, server.URL)
		require.NoError(t, err)

		config := schemas.InteractionConfig{
			MaxDepth:                3,
			MaxInteractionsPerDepth: 2,
			InteractionDelayMs:      50,
			// Ensure wait time allows the dynamic content to load and stabilize.
			PostInteractionWaitMs: 500,
		}

		// Run the interactor. The recursive nature should handle the depth.
		err = session.Interact(ctx, config)
		require.NoError(t, err)

		// Verify the final state.
		// Use Eventually because the final interaction might take a moment to update the DOM.
		assert.Eventually(t, func() bool {
			var finalStatus string
			// Use ExecuteScript which handles context management internally.
			// Use a fresh context for the check to avoid failure if the main ctx is cancelled right after Interact finishes.
			checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer checkCancel()

			// Check if the page is still open before executing the script.
			if session.page == nil || session.page.IsClosed() {
				return false
			}

			err := session.ExecuteScript(checkCtx, `document.getElementById('status').innerText`, &finalStatus)
			return err == nil && finalStatus == "Dynamic Success"
		}, 15*time.Second, 200*time.Millisecond, "Interactor failed to interact with dynamic content")
	})
}