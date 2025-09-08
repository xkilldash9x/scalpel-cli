// internal/browser/interactor_test.go
package browser_test

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestInteractor_FormInteraction verifies input filling, selection, and clicking.
func TestInteractor_FormInteraction(t *testing.T) {
	t.Parallel()
	fixture := setupBrowserManager(t)

	var submissionData atomic.Value

	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/submit" {
			r.ParseForm()
			submissionData.Store(r.Form)
			fmt.Fprintln(w, `<html><body>Form processed</body></html>`)
			return
		}

		// Initial page (GET /)
		fmt.Fprintln(w, `
			<html>
				<body>
					<form action="/submit" method="POST">
						<input type="text" name="username" id="userField">
						<input type="password" name="password">
						<select name="color">
							<option value="">Select...</option>
							<option value="red">Red</option>
							<option value="blue">Blue</option>
						</select>
						<button type="submit" id="submitBtn">Submit</button>
						<input type="reset" value="Clear"> <input type="text" readonly value="Readonly"> </form>
					<button disabled>Inactive</button> </body>
			</html>
		`)
	}))

	session := fixture.initializeSession(t)

	err := session.Navigate(server.URL)
	require.NoError(t, err)

	config := schemas.InteractionConfig{
		MaxDepth:                2,
		MaxInteractionsPerDepth: 5,
		InteractionDelayMs:      50,
		PostInteractionWaitMs:   200,
	}

	// Execute interaction phase.
	err = session.Interact(config)
	require.NoError(t, err, "Interaction phase failed")

	// Verification
	// Wait briefly for the final navigation after submit
	time.Sleep(500 * time.Millisecond)

	formDataRaw := submissionData.Load()
	require.NotNil(t, formDataRaw, "Form submission did not occur")
	formData := formDataRaw.(map[string][]string)

	// Verify inputs based on Interactor heuristics (defined in interactor.go).
	assert.Equal(t, "Test User", formData["username"][0], "Username payload mismatch")
	assert.Equal(t, "ScalpelTest123!", formData["password"][0], "Password payload mismatch")

	// Verify select interaction (randomly selects Red or Blue).
	selectedColor := formData["color"][0]
	assert.True(t, selectedColor == "red" || selectedColor == "blue", "Select interaction failed or selected invalid option")
}

// TestInteractor_DynamicContentHandling verifies the interactor can handle content that appears after an initial interaction (DFS).
func TestInteractor_DynamicContentHandling(t *testing.T) {
	t.Parallel()
	fixture := setupBrowserManager(t)

	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
			<html>
				<body>
					<div id="status">Initial</div>
					<button id="revealBtn" onclick="reveal()">Reveal Content</button>
					<div id="dynamicContent" style="display:none;">
						<button id="dynamicBtn" onclick="updateStatus()">Interact Dynamically</button>
					</div>
					<script>
						function reveal() {
							// Simulate delay
							setTimeout(() => {
								document.getElementById('dynamicContent').style.display = 'block';
								document.getElementById('status').innerText = 'Revealed';
							}, 150);
						}
						function updateStatus() {
							document.getElementById('status').innerText = 'Dynamic Interaction Success';
						}
					</script>
				</body>
			</html>
		`)
	}))

	session := fixture.initializeSession(t)
	err := session.Navigate(server.URL)
	require.NoError(t, err)

	config := schemas.InteractionConfig{
		MaxDepth:                3, // Requires depth > 1 to find the dynamic button after the reveal button click.
		MaxInteractionsPerDepth: 2,
		InteractionDelayMs:      50,
		PostInteractionWaitMs:   500, // Must be longer than the setTimeout delay (150ms).
	}

	err = session.Interact(config)
	require.NoError(t, err)

	// Verify the final state by evaluating JS.
	var finalStatus string
	ctx := session.GetContext()
	// Use chromedp.Text to retrieve the final status text.
	err = chromedp.Run(ctx, chromedp.Text("#status", &finalStatus, chromedp.ByQuery))
	require.NoError(t, err)

	// If the interactor correctly waited and recursed, it should have found and clicked the dynamic button.
	assert.Equal(t, "Dynamic Interaction Success", finalStatus, "Interactor failed to interact with dynamic content")
}