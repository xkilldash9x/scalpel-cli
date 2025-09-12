// internal/browser/interactor_test.go
package browser_test

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestInteractor_FormInteraction now uses the global fixture.
func TestInteractor_FormInteraction(t *testing.T) {
	t.Parallel()
	fixture := globalFixture

	// Using a channel is the most robust way to handle waiting for the
	// concurrent server-side action (form submission) to complete.
	submissionChan := make(chan url.Values, 1)

	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/submit" {
			r.ParseForm()

			// To prevent a data race, we must make a deep copy of the form
			// data before sending it over the channel. The original r.Form
			// is owned by the net/http server and can be recycled.
			copiedForm := make(url.Values)
			for k, v := range r.Form {
				newVal := make([]string, len(v))
				copy(newVal, v)
				copiedForm[k] = newVal
			}
			// Signal the main test goroutine that the data is ready.
			submissionChan <- copiedForm

			fmt.Fprintln(w, `<html><body>Form processed</body></html>`)
			return
		}

		// The initial page served on a GET request.
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

	err = session.Interact(config)
	require.NoError(t, err, "Interaction phase failed")

	// This is the deterministic wait. The test will block here until the
	// server handler sends data into the channel. A timeout prevents the
	// test from hanging indefinitely if something goes wrong.
	var formData url.Values
	select {
	case formData = <-submissionChan:
		// Success! Data received.
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out waiting for form submission")
	}

	// Assertions can now be made safely.
	assert.Equal(t, "Test User", formData.Get("username"), "Username payload mismatch")
	assert.Equal(t, "ScalpelTest123!", formData.Get("password"), "Password payload mismatch")

	selectedColor := formData.Get("color")
	assert.True(t, selectedColor == "red" || selectedColor == "blue", "Select interaction failed or selected invalid option")
}

// TestInteractor_DynamicContentHandling uses the global fixture.
// This test is now fully deterministic, waiting for a specific DOM state change
// rather than relying on a fixed time delay.
func TestInteractor_DynamicContentHandling(t *testing.T) {
	t.Parallel()
	fixture := globalFixture

	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This test page now includes JavaScript that signals when its async
		// operation is complete by setting a data attribute on the body.
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
							setTimeout(() => {
								document.getElementById('dynamicContent').style.display = 'block';
								document.getElementById('status').innerText = 'Revealed';
								// This is our signal that the page state has changed.
								document.body.setAttribute('data-status', 'ready');
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

	// We no longer need to worry about PostInteractionWaitMs being long enough.
	// The interactor will find the first button, click it, and then recurse.
	// The subsequent DOM query will find the newly visible button.
	config := schemas.InteractionConfig{
		MaxDepth:                3,
		MaxInteractionsPerDepth: 2,
		InteractionDelayMs:      50,
		// This can be short, as our test logic is no longer dependent on it.
		PostInteractionWaitMs: 100,
	}

	// Before interaction, wait for the page to be in its initial ready state.
	err = chromedp.Run(session.GetContext(), chromedp.WaitReady("body"))
	require.NoError(t, err)

	err = session.Interact(config)
	require.NoError(t, err)

	// After interaction, we deterministically wait for the JavaScript to signal
	// that it's finished by setting the 'data-status' attribute.
	err = chromedp.Run(session.GetContext(), chromedp.WaitReady(`body[data-status="ready"]`))
	require.NoError(t, err, "Timed out waiting for dynamic content to be revealed")

	// Now we can safely verify the final state.
	var finalStatus string
	err = chromedp.Run(session.GetContext(), chromedp.Text("#status", &finalStatus, chromedp.ByQuery))
	require.NoError(t, err)

	assert.Equal(t, "Dynamic Interaction Success", finalStatus, "Interactor failed to interact with dynamic content")
}

