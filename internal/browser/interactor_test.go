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

func TestInteractor(t *testing.T) {
	t.Run("FormInteraction", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)

		submissionChan := make(chan url.Values, 1)

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/submit" {
				r.ParseForm()
				copiedForm := make(url.Values)
				for k, v := range r.Form {
					newVal := make([]string, len(v))
					copy(newVal, v)
					copiedForm[k] = newVal
				}
				submissionChan <- copiedForm
				fmt.Fprintln(w, `<html><body>Form processed</body></html>`)
				return
			}

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

		session := fixture.Session

		err := session.Navigate(context.Background(), server.URL)
		require.NoError(t, err)

		config := schemas.InteractionConfig{
			MaxDepth:                2,
			MaxInteractionsPerDepth: 5,
			InteractionDelayMs:      50,
			PostInteractionWaitMs:   200,
		}

		err = session.Interact(context.Background(), config)
		require.NoError(t, err, "Interaction phase failed")

		var formData url.Values
		select {
		case formData = <-submissionChan:
		case <-time.After(5 * time.Second):
			t.Fatal("Test timed out waiting for form submission")
		}

		assert.Equal(t, "Test User", formData.Get("username"), "Username payload mismatch")
		assert.Equal(t, "ScalpelTest123!", formData.Get("password"), "Password payload mismatch")
		selectedColor := formData.Get("color")
		assert.True(t, selectedColor == "red" || selectedColor == "blue", "Select interaction failed or selected invalid option")
	})

	t.Run("DynamicContentHandling", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)

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
                               setTimeout(() => {
                                   document.getElementById('dynamicContent').style.display = 'block';
                                   document.getElementById('status').innerText = 'Revealed';
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

		session := fixture.Session
		err := session.Navigate(context.Background(), server.URL)
		require.NoError(t, err)

		config := schemas.InteractionConfig{
			MaxDepth:                3,
			MaxInteractionsPerDepth: 2,
			InteractionDelayMs:      50,
			PostInteractionWaitMs:   100,
		}

		err = chromedp.Run(session.GetContext(), chromedp.WaitReady("body"))
		require.NoError(t, err)

		err = session.Interact(context.Background(), config)
		require.NoError(t, err)

		err = chromedp.Run(session.GetContext(), chromedp.WaitReady(`body[data-status="ready"]`))
		require.NoError(t, err, "Timed out waiting for dynamic content to be revealed")

		var finalStatus string
		err = chromedp.Run(session.GetContext(), chromedp.Text("#status", &finalStatus, chromedp.ByQuery))
		require.NoError(t, err)
		assert.Equal(t, "Dynamic Interaction Success", finalStatus, "Interactor failed to interact with dynamic content")
	})
}