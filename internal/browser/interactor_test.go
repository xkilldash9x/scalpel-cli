// internal/browser/interactor_test.go
package browser

import (
	"context"
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

const interactorTestTimeout = 25 * time.Second

func TestInteractor(t *testing.T) {
	t.Run("FormInteraction", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)
		session := fixture.Session

		submissionChan := make(chan url.Values, 1)

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/submit" {
				r.ParseForm()
				// Make a copy to avoid race conditions as the original request form might be reused.
				copiedForm := make(url.Values)
				for k, v := range r.Form {
					newVal := make([]string, len(v))
					copy(newVal, v)
					copiedForm[k] = newVal
				}
				select {
				case submissionChan <- copiedForm:
				default:
					t.Log("Form submission received but channel was full or closed.")
				}
				fmt.Fprintln(w, `<html><body>Form processed</body></html>`)
				return
			}
			fmt.Fprintln(w, `
                    <html><body>
                        <form action="/submit" method="POST">
                            <input type="text" name="username" id="userField">
                            <input type="password" name="password">
                            <select name="color">
                                <option value="">Select...</option>
                                <option value="red">Red</option>
                                <option value="blue">Blue</option>
                            </select>
                            <button type="submit" id="submitBtn">Submit</button>
                        </form>
                    </body></html>
                `)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), interactorTestTimeout)
		// FIX: Use t.Cleanup instead of defer cancel() in parallel tests.
		t.Cleanup(cancel)

		err := session.Navigate(ctx, server.URL)
		require.NoError(t, err)

		config := schemas.InteractionConfig{
			MaxDepth:                2,
			MaxInteractionsPerDepth: 5,
			InteractionDelayMs:      50,
			PostInteractionWaitMs:   200,
		}

		err = session.Interact(ctx, config)
		require.NoError(t, err, "Interaction phase failed")

		var formData url.Values
		select {
		case formData = <-submissionChan:
			// Success
		case <-ctx.Done():
			t.Fatal("Test timed out waiting for form submission")
		}

		// Verify that the interactor filled the form with expected data.
		assert.Equal(t, "Test User", formData.Get("username"))
		assert.Equal(t, "ScalpelTest123!", formData.Get("password"))
		selectedColor := formData.Get("color")
		assert.True(t, selectedColor == "red" || selectedColor == "blue", "A color should have been selected")
	})

	t.Run("DynamicContentHandling", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)
		session := fixture.Session

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `
                    <html><body>
                        <div id="status">Initial</div>
                        <button id="revealBtn" onclick="reveal()">Reveal</button>
                        <div id="dynamicContent" style="display:none;">
                            <button id="dynamicBtn" onclick="updateStatus()">Interact</button>
                        </div>
                        <script>
                            function reveal() {
                                setTimeout(() => {
                                    document.getElementById('dynamicContent').style.display = 'block';
                                    document.getElementById('status').innerText = 'Revealed';
                                }, 150);
                            }
                            function updateStatus() {
                                document.getElementById('status').innerText = 'Dynamic Success';
                            }
                        </script>
                    </body></html>
                `)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), interactorTestTimeout)
		// FIX: Use t.Cleanup instead of defer cancel() in parallel tests.
		t.Cleanup(cancel)

		err := session.Navigate(ctx, server.URL)
		require.NoError(t, err)

		config := schemas.InteractionConfig{
			MaxDepth:                3,
			MaxInteractionsPerDepth: 2,
			InteractionDelayMs:      50,
			PostInteractionWaitMs:   250,
		}

		err = session.Interact(ctx, config)
		require.NoError(t, err)

		// Use Eventually to handle the async nature of the interaction.
		assert.Eventually(t, func() bool {
			var finalStatus string
			// Derive a short lived context for the check.
			checkCtx, checkCancel := context.WithTimeout(session.GetContext(), 2*time.Second)
			defer checkCancel()
			err := chromedp.Run(checkCtx, chromedp.Text("#status", &finalStatus, chromedp.ByQuery))
			return err == nil && finalStatus == "Dynamic Success"
		}, 10*time.Second, 100*time.Millisecond, "Interactor failed to interact with dynamic content")
	})
}
