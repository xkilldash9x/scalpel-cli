// internal/browser/session/interactor_test.go
package session

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Increased timeout for stability.
// FIX: Increased timeout further (from 120s) for stability under load/race conditions (TestInteractor/* Failures).
// FIX: Increased timeout further (from 300s) to accommodate overhead under race detection.
const interactorTestTimeout = 600 * time.Second

func TestInteractor(t *testing.T) {
	// Renamed and expanded to cover various input types and ensure randomization patterns are tested.
	t.Run("FormInteraction_VariousTypes", func(t *testing.T) {
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
			// Added various input types for comprehensive testing
			fmt.Fprintln(w, `
                    <html><body>
                        <form action="/submit" method="POST">
                            <input type="text" name="username" id="userField">
                            <input type="password" name="password">
                            <input type="email" name="email_addr">
                            <input type="tel" name="phone_num">
                            <input type="number" name="age">
                            <input type="search" name="query">
                            <input type="url" name="website">
                            <select name="color">
                                <option value="">Select...</option>
                                <option value="red">Red</option>
                                <option value="blue">Blue</option>
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
			MaxDepth:                2,
			MaxInteractionsPerDepth: 15, // Increased limit to ensure all fields are filled
			InteractionDelayMs:      50,
			PostInteractionWaitMs:   200,
		}

		err = session.Interact(ctx, config)
		// P1 FIX: Use assert.NoError instead of require.NoError.
		// Stale elements during interaction are expected behavior (handled gracefully), not test failures.
		assert.NoError(t, err, "Interaction phase failed")

		var formData url.Values
		select {
		case formData = <-submissionChan:
			// Success
		case <-ctx.Done():
			t.Fatal("Test timed out waiting for form submission")
		}

		// Verify that the interactor filled the form with expected data patterns.
		assert.Regexp(t, regexp.MustCompile(`^Test User \d+$`), formData.Get("username"))
		assert.Regexp(t, regexp.MustCompile(`^ScalpelPass\d+!$`), formData.Get("password"))
		assert.Regexp(t, regexp.MustCompile(`^testuser\d+@example.com$`), formData.Get("email_addr"))
		assert.Regexp(t, regexp.MustCompile(`^555-\d{3}-\d{4}$`), formData.Get("phone_num"))
		assert.Regexp(t, regexp.MustCompile(`^\d+$`), formData.Get("age"))
		assert.Regexp(t, regexp.MustCompile(`^scalpel test query \d+$`), formData.Get("query"))
		assert.Equal(t, "https://example-test.com", formData.Get("website"))
		assert.Regexp(t, regexp.MustCompile(`^scalpel test input \d+$`), formData.Get("comments"))

		selectedColor := formData.Get("color")
		assert.True(t, selectedColor == "red" || selectedColor == "blue", "A color should have been selected")
	})

	t.Run("DynamicContentHandling", func(t *testing.T) {
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
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), interactorTestTimeout)
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
		// P1 FIX: Use assert.NoError instead of require.NoError.
		assert.NoError(t, err)

		// Use Eventually to handle the async nature of the interaction.
		assert.Eventually(t, func() bool {
			var finalStatus string
			// We must use the session's context for the actual chromedp.Run command.
			// The short-lived context approach used previously was unnecessary complexity.
			err := chromedp.Run(session.GetContext(), chromedp.Text("#status", &finalStatus, chromedp.ByQuery))
			return err == nil && finalStatus == "Dynamic Success"
		}, 10*time.Second, 100*time.Millisecond, "Interactor failed to interact with dynamic content")
	})

	t.Run("DepthLimiting", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session

		// A page designed to create deep interaction chains.
		// Click button 1 -> reveals button 2 -> click button 2 -> reveals button 3...
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `
                    <html><body>
                        <div id="status">Depth 0</div>
                        <button id="btn1" onclick="reveal(1)">Level 1</button>
                        <div id="level1" style="display:none;">
                            <button id="btn2" onclick="reveal(2)">Level 2</button>
                            <div id="level2" style="display:none;">
                                <button id="btn3" onclick="reveal(3)">Level 3</button>
                                 <div id="level3" style="display:none;">
                                    <button id="btn4" onclick="reveal(4)">Level 4</button>
                                </div>
                            </div>
                        </div>
                        <script>
                            function reveal(level) {
                                document.getElementById('level' + level).style.display = 'block';
                                document.getElementById('status').innerText = 'Depth ' + level;
                            }
                        </script>
                    </body></html>
                `)
		}))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), interactorTestTimeout)
		t.Cleanup(cancel)

		err := session.Navigate(ctx, server.URL)
		require.NoError(t, err)

		// Set MaxDepth to 2.
		config := schemas.InteractionConfig{
			MaxDepth:                2,
			MaxInteractionsPerDepth: 1,
			InteractionDelayMs:      50,
			PostInteractionWaitMs:   100,
		}

		err = session.Interact(ctx, config)
		// P1 FIX: Use assert.NoError instead of require.NoError.
		assert.NoError(t, err)

		// Check the final status
		assert.Eventually(t, func() bool {
			var finalStatus string
			err := chromedp.Run(session.GetContext(), chromedp.Text("#status", &finalStatus, chromedp.ByQuery))
			// It should reach Depth 2 (interaction at depth 0 reveals L1, interaction at depth 1 reveals L2).
			// When it enters interactDepth(depth=2), it stops because depth >= MaxDepth.
			return err == nil && finalStatus == "Depth 2"
		}, 10*time.Second, 100*time.Millisecond, "Interactor did not respect MaxDepth limit")
	})

	t.Run("InteractionLimitingPerDepth", func(t *testing.T) {
		// Setup for MaxInteractionsPerDepth test
		interactionCount := 0
		var mu sync.Mutex
		// FIX: Use a WaitGroup for synchronization instead of sleep.
		const expectedInteractions = 2
		var wg sync.WaitGroup
		wg.Add(expectedInteractions)

		// Create a server instance specifically for this test case to track interactions
		observableServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/interact" {
				mu.Lock()
				interactionCount++
				currentCount := interactionCount
				mu.Unlock()
				// P2 FIX: Removed erroneous second mu.Unlock() which caused panics in the original code.

				// P2 FIX: Reliably signal WaitGroup.
				// Signal WaitGroup only up to the expected count.
				if currentCount <= expectedInteractions {
					// By using defer, we ensure wg.Done() is called reliably after the response is written/handler exits.
					defer wg.Done()
				}

				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, "Interacted")
				return
			}
			// Serve the page with elements that trigger the /interact endpoint via JS fetch
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>
                <button onclick="fetch('/interact')">Btn1</button>
                <button onclick="fetch('/interact')">Btn2</button>
                <button onclick="fetch('/interact')">Btn3</button>
                <button onclick="fetch('/interact')">Btn4</button>
            </body></html>`)
		}))
		t.Cleanup(observableServer.Close)

		fixture := newTestFixture(t)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), interactorTestTimeout)
		t.Cleanup(cancel)

		err := session.Navigate(ctx, observableServer.URL)
		require.NoError(t, err)

		config := schemas.InteractionConfig{
			MaxDepth:                1,                    // Only interact at depth 0
			MaxInteractionsPerDepth: expectedInteractions, // Limit interactions
			InteractionDelayMs:      50,
			PostInteractionWaitMs:   100,
		}

		err = session.Interact(ctx, config)
		// P1 FIX: Use assert.NoError instead of require.NoError.
		assert.NoError(t, err)

		// FIX: Wait for the WaitGroup instead of sleeping.
		// Use a context with timeout for waiting on the WaitGroup.
		waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
		defer waitCancel()

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// All expected interactions processed by the server.
		case <-waitCtx.Done():
			t.Fatal("Timed out waiting for server to process interactions")
		}

		mu.Lock()
		count := interactionCount
		mu.Unlock()

		// We expect exactly MaxInteractionsPerDepth interactions at depth 0.
		assert.Equal(t, expectedInteractions, count, "Interactor should respect MaxInteractionsPerDepth limit")
	})

	t.Run("Cancellation", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session

		// A page designed for long interaction process
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `<html><body>
                                <button>Button 1</button><button>Button 2</button>
                                <button>Button 3</button><button>Button 4</button>
                                <button>Button 5</button><button>Button 6</button>
                            </body></html>`)
		}))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), interactorTestTimeout)
		t.Cleanup(cancel)

		err := session.Navigate(ctx, server.URL)
		require.NoError(t, err)

		config := schemas.InteractionConfig{
			MaxDepth:                5,
			MaxInteractionsPerDepth: 5,
			InteractionDelayMs:      500, // Long delays
			PostInteractionWaitMs:   500,
		}

		// Create a context specifically for the interaction that we can cancel
		interactCtx, cancelInteraction := context.WithCancel(ctx)

		// Start interaction in a goroutine
		interactErrChan := make(chan error, 1)
		go func() {
			interactErrChan <- session.Interact(interactCtx, config)
		}()

		// Wait briefly then cancel the context
		time.Sleep(1 * time.Second)
		cancelInteraction()

		// Wait for the interaction to return
		select {
		case err := <-interactErrChan:
			require.Error(t, err, "Interaction should return an error upon cancellation")
			assert.ErrorIs(t, err, context.Canceled, "Error should be context.Canceled")
		case <-time.After(5 * time.Second):
			t.Fatal("Interactor did not stop promptly after context cancellation")
		}
	})
}

// TestInteractorHelpers covers the helper functions in interactor.go (fingerprinting, attribute maps, etc.)
func TestInteractorHelpers(t *testing.T) {
	// P0 FIX: Helper functions (isDisabled, isInputElement) were updated
	// to use elementSnapshot instead of *cdp.Node. We test these helpers.
	// attributeMap and getNodeText were removed as logic moved to JS.

	t.Run("isInputElement", func(t *testing.T) {
		assert.True(t, isInputElement(&elementSnapshot{NodeName: "INPUT", Attributes: map[string]string{"type": "text"}}))
		assert.True(t, isInputElement(&elementSnapshot{NodeName: "TEXTAREA"}))
		assert.False(t, isInputElement(&elementSnapshot{NodeName: "BUTTON"}))
		assert.False(t, isInputElement(&elementSnapshot{NodeName: "INPUT", Attributes: map[string]string{"type": "hidden"}}))
		assert.False(t, isInputElement(nil))

		// Test contenteditable
		assert.True(t, isInputElement(&elementSnapshot{NodeName: "DIV", Attributes: map[string]string{"contenteditable": "true"}}))
	})

	t.Run("isDisabled", func(t *testing.T) {
		snapInput := &elementSnapshot{NodeName: "INPUT", Attributes: map[string]string{"type": "text"}}
		assert.False(t, isDisabled(snapInput, snapInput.Attributes))

		snapDisabled := &elementSnapshot{NodeName: "INPUT", Attributes: map[string]string{"disabled": ""}}
		assert.True(t, isDisabled(snapDisabled, snapDisabled.Attributes))

		snapReadonly := &elementSnapshot{NodeName: "TEXTAREA", Attributes: map[string]string{"readonly": "true"}}
		assert.True(t, isDisabled(snapReadonly, snapReadonly.Attributes), "Readonly inputs should be treated as disabled for interaction")

		assert.True(t, isDisabled(nil, nil))

		// Test aria-disabled
		snapAria := &elementSnapshot{NodeName: "BUTTON", Attributes: map[string]string{"aria-disabled": "true"}}
		assert.True(t, isDisabled(snapAria, snapAria.Attributes))
	})

	t.Run("generateNodeFingerprint", func(t *testing.T) {
		attrsInput := map[string]string{"type": "text", "name": "username", "id": "user-id", "class": "form-control input"}
		snapInput := &elementSnapshot{NodeName: "INPUT", Attributes: attrsInput}

		fpInput, descInput := generateNodeFingerprint(snapInput, attrsInput)
		assert.NotEmpty(t, fpInput)
		// Description should contain sorted classes and attributes
		expectedDesc := `input#user-id.form-control.input[name="username"][type="text"]`
		assert.Equal(t, expectedDesc, descInput)

		// Test fingerprint stability (same input yields same output)
		fpInput2, _ := generateNodeFingerprint(snapInput, attrsInput)
		assert.Equal(t, fpInput, fpInput2)

		// Test fingerprint includes text content
		attrsButton := map[string]string{"type": "submit", "aria-label": "Submit Form"}
		snapButton := &elementSnapshot{NodeName: "BUTTON", Attributes: attrsButton, TextContent: "Send"}
		fpButton, descButton := generateNodeFingerprint(snapButton, attrsButton)
		assert.NotEmpty(t, fpButton)
		expectedDescButton := `button[aria-label="Submit Form"][type="submit"][text="Send"]`
		assert.Equal(t, expectedDescButton, descButton)

		// Test nil input
		fpNil, descNil := generateNodeFingerprint(nil, nil)
		assert.Empty(t, fpNil)
		assert.Empty(t, descNil)

		// Test generic element without distinguishing features (should return empty fingerprint)
		snapGeneric := &elementSnapshot{NodeName: "DIV"}
		fpGeneric, descGeneric := generateNodeFingerprint(snapGeneric, map[string]string{})
		assert.Empty(t, fpGeneric)
		assert.Equal(t, "div", descGeneric) // Description is still generated

		// Test HTML/BODY (should generate fingerprint)
		snapBody := &elementSnapshot{NodeName: "BODY"}
		fpBody, _ := generateNodeFingerprint(snapBody, map[string]string{})
		assert.NotEmpty(t, fpBody)
	})
}
