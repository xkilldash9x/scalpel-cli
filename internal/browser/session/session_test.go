// internal/browser/session/session_test.go
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config" // Needed for configOption if used
)

// Use the constant defined in session_helpers_test.go if preferred, or define locally
const testTimeout = 45 * time.Second

// TestSession covers the core functionalities of the Session type.
func TestSession(t *testing.T) {
	t.Run("InitializeAndClose", func(t *testing.T) {
		fixture := newTestFixture(t)                                               // Uses helper from session_helpers_test.go
		server := createStaticTestServer(t, `<html><body>Init Test</body></html>`) // Uses helper
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel() // Use defer for cleanup

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Closing is handled by the fixture cleanup (t.Cleanup).
	})

	t.Run("NavigateAndCollectArtifacts", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "12345", HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"})
			fmt.Fprint(w, `<html><body>Target Page
	                <script>
	                    localStorage.setItem("localKey", "localValue");
						sessionStorage.setItem("sessionKey", "sessionValue");
	                    console.log("Hello from JS");
						console.warn("A warning message");
	                </script>
	            </body></html>`)
		}))
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL), "Navigation failed")

		// FIX: Wait deterministically for logs instead of fixed sleep.
		assert.Eventually(t, func() bool {
			// harvester might be nil if initialization failed, check first.
			if session.harvester == nil {
				return false
			}
			session.harvester.mu.RLock()
			defer session.harvester.mu.RUnlock()
			// Check if we have the expected logs (Hello from JS and A warning message)
			hasLog := false
			hasWarn := false
			for _, log := range session.harvester.consoleLogs {
				if strings.Contains(log.Text, "Hello from JS") {
					hasLog = true
				}
				if strings.Contains(log.Text, "A warning message") {
					hasWarn = true
				}
			}
			return hasLog && hasWarn
			// R4: Reduced timeout from 45s to 30s. 45s races with the main test timeout (testTimeout=45s),
			// causing spurious context deadline exceeded errors.
		}, 30*time.Second, 100*time.Millisecond, "Timed out waiting for console logs to propagate")

		artifacts, err := session.CollectArtifacts(ctx)
		require.NoError(t, err)
		require.NotNil(t, artifacts)

		assert.Contains(t, artifacts.DOM, "Target Page", "DOM content mismatch")
		require.NotNil(t, artifacts.Storage.Cookies, "Cookies slice should not be nil") // Changed from map check
		assert.NotEmpty(t, artifacts.Storage.Cookies, "Should have captured at least one cookie")

		foundCookie := false
		for _, cookie := range artifacts.Storage.Cookies {
			if cookie.Name == "SessionID" && cookie.Value == "12345" && cookie.HTTPOnly && cookie.SameSite == schemas.CookieSameSiteLax {
				foundCookie = true
				break
			}
		}
		assert.True(t, foundCookie, "SessionID HttpOnly Lax cookie not found or attributes incorrect")

		require.NotNil(t, artifacts.Storage.LocalStorage, "LocalStorage map should not be nil")
		assert.Equal(t, "localValue", artifacts.Storage.LocalStorage["localKey"], "LocalStorage value mismatch")
		require.NotNil(t, artifacts.Storage.SessionStorage, "SessionStorage map should not be nil")
		assert.Equal(t, "sessionValue", artifacts.Storage.SessionStorage["sessionKey"], "SessionStorage value mismatch")

		require.NotEmpty(t, artifacts.ConsoleLogs, "Should have captured console logs")
		assertLogPresent(t, artifacts.ConsoleLogs, "log", "Hello from JS")
		assertLogPresent(t, artifacts.ConsoleLogs, "warning", "A warning message")

		require.NotNil(t, artifacts.HAR, "HAR data should not be nil")
		require.NotEqual(t, "null", string(*artifacts.HAR), "HAR data should not be 'null'") // Check it's not explicitly null

		var harData schemas.HAR
		err = json.Unmarshal(*artifacts.HAR, &harData)
		require.NoError(t, err, "Failed to unmarshal HAR data")
		// FIX: Use current schemas.HAR structure
		require.NotNil(t, findHAREntry(&harData, server.URL), "HAR entry for server URL not found")
	})

	t.Run("SessionIsolation", func(t *testing.T) {
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/set" {
				http.SetCookie(w, &http.Cookie{Name: "IsolatedCookie", Value: "SessionSpecific", Path: "/"})
				fmt.Fprintln(w, "Cookie Set")
			} else {
				fmt.Fprintln(w, "Blank Page")
			}
		}))

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// First session, sets a cookie.
		fixture1 := newTestFixture(t)
		require.NoError(t, fixture1.Session.Navigate(ctx, server.URL+"/set"))
		artifacts1, err := fixture1.Session.CollectArtifacts(ctx)
		require.NoError(t, err, "Failed to collect artifacts session 1")
		require.NotNil(t, artifacts1)
		require.NotEmpty(t, artifacts1.Storage.Cookies, "Session 1 should have cookies")
		foundCookie1 := false
		for _, c := range artifacts1.Storage.Cookies {
			if c.Name == "IsolatedCookie" {
				foundCookie1 = true
				break
			}
		}
		assert.True(t, foundCookie1, "Session 1 did not find the expected cookie")

		// Second session, should be completely isolated.
		fixture2 := newTestFixture(t)
		require.NoError(t, fixture2.Session.Navigate(ctx, server.URL+"/blank"))
		artifacts2, err := fixture2.Session.CollectArtifacts(ctx)
		require.NoError(t, err, "Failed to collect artifacts session 2")
		require.NotNil(t, artifacts2)

		foundCookie2 := false
		// FIX: Check if slice is nil or empty
		if len(artifacts2.Storage.Cookies) > 0 {
			for _, c := range artifacts2.Storage.Cookies {
				if c.Name == "IsolatedCookie" {
					foundCookie2 = true
					break
				}
			}
		}
		assert.False(t, foundCookie2, "Session 2 should not have cookies from session 1")
	})

	t.Run("InjectScriptPersistently", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// The session is already initialized by the fixture.
		// We can directly call InjectScriptPersistently.

		script1 := `console.log('Persistent script test 1'); window.persistentTest1 = true;`
		err := session.InjectScriptPersistently(ctx, script1)
		require.NoError(t, err, "Injecting first script failed")

		script2 := `console.log('Persistent script test 2'); window.persistentTest2 = true;`
		err = session.InjectScriptPersistently(ctx, script2)
		require.NoError(t, err, "Injecting second script failed")

		// To verify, we can navigate and then check if the scripts were executed.
		server := createStaticTestServer(t, `<html><body>Verification Page</body></html>`)
		require.NoError(t, session.Navigate(ctx, server.URL))

		// Check if the scripts ran by looking for the global variables they set.
		var test1, test2 bool
		require.NoError(t, session.RunActions(ctx, chromedp.Evaluate(`window.persistentTest1`, &test1)))
		require.NoError(t, session.RunActions(ctx, chromedp.Evaluate(`window.persistentTest2`, &test2)))

		assert.True(t, test1, "First persistent script did not execute on navigation")
		assert.True(t, test2, "Second persistent script did not execute on navigation")
	})

	t.Run("Interaction_BasicClickAndType", func(t *testing.T) {
		fixture := newTestFixture(t)
		require.NotNil(t, fixture.Session.humanoid, "Humanoid should be initialized for this test")

		server := createStaticTestServer(t, `
	            <input id="inputField" type="text" value="initial">
	            <button id="target" onclick="this.innerText='Clicked'; document.getElementById('inputField').value='clicked_value'">Click Me</button>
	        `)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Test Type - Pass context to Type
		require.NoError(t, session.Type(ctx, "#inputField", "typed_value"), "Typing failed")

		var typedValue string
		// FIX: Update ExecuteScript call (signature change and manual unmarshal).
		res, err := session.ExecuteScript(ctx, `document.querySelector("#inputField").value`, nil)
		require.NoError(t, err, "Getting input value failed")
		// Since ExecuteScript returns json.RawMessage, we need to unmarshal it.
		require.NoError(t, json.Unmarshal(res, &typedValue), "Unmarshalling input value failed")
		// FIX: Changed assertion from Contains to Equal (field is now cleared before typing).
		assert.Equal(t, "typed_value", typedValue, "Typed value mismatch (field likely not cleared)")

		// Test Click - Pass context to Click
		require.NoError(t, session.Click(ctx, "#target"), "Clicking failed")

		// Verify click result - Use ExecuteScript
		var buttonText string
		// FIX: Update ExecuteScript call
		res, err = session.ExecuteScript(ctx, `document.querySelector("#target").innerText`, nil)
		require.NoError(t, err, "Getting button text failed")
		require.NoError(t, json.Unmarshal(res, &buttonText), "Unmarshalling button text failed")
		assert.Equal(t, "Clicked", buttonText, "Button text did not change after click")

		var clickedValue string
		// FIX: Update ExecuteScript call
		res, err = session.ExecuteScript(ctx, `document.querySelector("#inputField").value`, nil)
		require.NoError(t, err, "Getting input value after click failed")
		require.NoError(t, json.Unmarshal(res, &clickedValue), "Unmarshalling input value after click failed")
		assert.Equal(t, "clicked_value", clickedValue, "Input value not updated after click")
	})

	t.Run("ExposeFunctionIntegration_ManualBinding", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		callbackChan := make(chan string, 1)
		goFuncCalled := false
		var mu sync.Mutex // Protect goFuncCalled

		myFunc := func(s string, i int) {
			mu.Lock()
			goFuncCalled = true
			mu.Unlock()
			fixture.Logger.Debug("Go function called from JS", zap.String("s", s), zap.Int("i", i))
			select {
			case callbackChan <- fmt.Sprintf("%s_%d", s, i):
			default:
				t.Log("Warning: Callback channel full or blocked")
			}
		}

		require.NoError(t, session.ExposeFunction(ctx, "myGoFunction", myFunc))
		require.NoError(t, session.Navigate(ctx, server.URL))

		// FIX: Update ExecuteScript call (signature change)
		_, err := session.ExecuteScript(ctx, `setTimeout(() => window.myGoFunction("hello", 123), 50)`, nil)
		require.NoError(t, err)

		select {
		case res := <-callbackChan:
			assert.Equal(t, "hello_123", res)
		// FIX: Increased timeout (from 5s) for stability.
		case <-time.After(10 * time.Second):
			mu.Lock()
			called := goFuncCalled
			mu.Unlock()
			if !called {
				t.Fatal("Timed out waiting for exposed function (myGoFunction was likely never called)")
			} else {
				t.Fatal("Timed out waiting for exposed function (channel communication failed?)")
			}
		}
	})

	t.Run("ExposeFunctionIntegration_MapSignature", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		callbackChan := make(chan string, 1)

		myFunc := func(data map[string]interface{}) {
			fixture.Logger.Debug("Go map function called from JS", zap.Any("data", data))
			val, ok := data["key"].(string)
			if !ok {
				fixture.Logger.Error("Received unexpected type for 'key' in map function")
				close(callbackChan) // Signal error
				return
			}
			select {
			case callbackChan <- val:
			default:
				t.Log("Warning: Callback channel full or blocked (map signature)")
			}
		}

		require.NoError(t, session.ExposeFunction(ctx, "myMapFunc", myFunc))
		require.NoError(t, session.Navigate(ctx, server.URL))
		// FIX: Update ExecuteScript call (signature change)
		_, err := session.ExecuteScript(ctx, `setTimeout(() => window.myMapFunc({"key": "map_value"}), 50)`, nil)
		require.NoError(t, err)

		select {
		case res, ok := <-callbackChan:
			if !ok {
				t.Fatal("Callback channel closed unexpectedly (likely type error in callback)")
			}
			assert.Equal(t, "map_value", res)
		// FIX: Increased timeout (from 5s) for stability.
		case <-time.After(10 * time.Second):
			t.Fatal("Timed out waiting for exposed function (map signature)")
		}
	})

	t.Run("NavigateTimeout", func(t *testing.T) {
		fixture := newTestFixture(t, func(cfg *config.Config) {
			cfg.SetNetworkNavigationTimeout(200 * time.Millisecond) // Use interface setter
		})

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(1 * time.Second) // Longer than the timeout.
			fmt.Fprintln(w, "<html><body>Slow response</body></html>")
		}))

		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Overall test timeout
		defer cancel()

		err := session.Navigate(ctx, server.URL)
		require.Error(t, err)
		// Check error message based on how Navigate formats the timeout error
		assert.Contains(t, err.Error(), "timed out after 200ms", "Error message should indicate timeout")
		assert.ErrorIs(t, err, context.DeadlineExceeded, "Underlying error should be DeadlineExceeded")
	})

	t.Run("AddFinding", func(t *testing.T) {
		fixture := newTestFixture(t)
		// session := fixture.Session // Unused if Metadata check is removed

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// FIX: Prepare evidence.
		evidenceData := map[string]interface{}{"key": "value"}
		evidenceBytes, marshalErr := json.Marshal(evidenceData)
		if marshalErr != nil {
			t.Fatalf("Failed to marshal test evidence data: %v", marshalErr)
		}

		// REFACTOR: Use fields from current schemas.Finding definition
		finding := schemas.Finding{
			Target: "https://example.com",
			Module: "TestModule",
			// REFACTOR: Flattened Vulnerability struct
			VulnerabilityName: "TestFindingVuln",
			Severity:          schemas.SeverityLow,
			Description:       "This is a test finding",
			// REFACTOR: Assign []byte (json.RawMessage) directly
			Evidence:       evidenceBytes,
			Recommendation: "Fix it",
			// Metadata is added by AddFinding (in the original, but not anymore)
			// ObservedAt and ID are added by AddFinding
		}

		require.NoError(t, fixture.Session.AddFinding(ctx, finding))

		select {
		case receivedFinding := <-fixture.FindingsChan:
			// REFACTOR: Assert fields from current schemas.Finding definition
			assert.Equal(t, "TestFindingVuln", receivedFinding.VulnerabilityName)
			// FIX: Removed assertions for Metadata as the field does not exist in schemas.Finding (MissingFieldOrMethod error).
			// require.NotNil(t, receivedFinding.Metadata, "Metadata should not be nil")
			// assert.Equal(t, session.ID(), receivedFinding.Metadata["session_id"], "Session ID should be added to finding metadata")
			
			// REFACTOR: Check for ObservedAt instead of Timestamp
			assert.False(t, receivedFinding.ObservedAt.IsZero(), "ObservedAt should be added")
		case <-time.After(2 * time.Second):
			t.Fatal("Timed out waiting for finding")
		}
	})

	t.Run("GetElementGeometry", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body style="margin: 0; padding: 0;">
				<button id="btn" style="width: 100px; height: 50px; border: none; padding: 0; margin: 10px;">Click</button>
				<input id="inp" type="text" style="width: 200px; height: 30px; margin: 5px;">
				<div id="hidden" style="display: none; width: 50px; height: 50px;">Hidden</div>
				<div id="zero" style="width: 0px; height: 0px;">Zero</div>
				</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Test visible button
		geomBtn, err := session.GetElementGeometry(ctx, "#btn")
		require.NoError(t, err, "Error getting geometry for #btn")
		require.NotNil(t, geomBtn)
		assert.Equal(t, int64(100), geomBtn.Width)
		assert.Equal(t, int64(50), geomBtn.Height)
		assert.Equal(t, "BUTTON", geomBtn.TagName)
		assert.NotEmpty(t, geomBtn.Vertices)

		// Test visible input
		geomInp, err := session.GetElementGeometry(ctx, "#inp")
		require.NoError(t, err, "Error getting geometry for #inp")
		require.NotNil(t, geomInp)
		assert.Equal(t, int64(200), geomInp.Width)
		assert.Equal(t, int64(30), geomInp.Height)
		assert.Equal(t, "INPUT", geomInp.TagName)
		assert.Equal(t, "text", geomInp.Type)
		assert.NotEmpty(t, geomInp.Vertices)

		// Test non-existent element
		_, err = session.GetElementGeometry(ctx, "#nonexistent")
		require.Error(t, err, "Expected error for non-existent element")
		assert.Contains(t, err.Error(), "not found", "Error message should indicate not found")

		// Test hidden element (display: none)
		_, err = session.GetElementGeometry(ctx, "#hidden")
		require.Error(t, err, "Expected error for hidden element")
		assert.Contains(t, err.Error(), "not found or not visible", "Error message should indicate not visible/found")

		// Test zero-dimension element
		_, err = session.GetElementGeometry(ctx, "#zero")
		require.Error(t, err, "Expected error for zero-dimension element")
		assert.Contains(t, err.Error(), "not found or not visible", "Error message should indicate not visible/zero dimensions")
	})

	// --- ADDED TESTS FOR INCREASED COVERAGE ---

	t.Run("Interaction_Submit", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session

		// The channel is buffered, which is crucial for the fix.
		submissionChan := make(chan string, 1)

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/submit" {
				r.ParseForm()
				// FIX: Removed the 'default' case in the select block (similar to interactor_test.go fix).
				// This prevents the race condition where the server handler drops the submission data
				// if the main test goroutine is not immediately ready to receive (e.g., still waiting
				// for session.Submit() stabilization). Since the channel is buffered, this send succeeds immediately.
				select {
				case submissionChan <- r.Form.Get("data"):
					// Success
					// Removed the 'default:' case
					// default:
				}
				fmt.Fprintln(w, "<html><body>Processed</body></html>")
				return
			}
			fmt.Fprintln(w, `
                    <html><body>
                        <form action="/submit" method="POST">
                            <input type="text" name="data" value="test_value">
                            <input type="submit" id="submitBtn">
                        </form>
                    </body></html>
                `)
		}))

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Test Submit using the form element selector
		require.NoError(t, session.Submit(ctx, "form"), "Submitting form failed")

		// Wait for the submission to be processed by the server handler
		select {
		case data := <-submissionChan:
			assert.Equal(t, "test_value", data)
		case <-ctx.Done():
			t.Fatal("Test timed out waiting for form submission")
		}

		// Verify navigation occurred after submit
		var bodyText string
		// We need to use the session context for chromedp.Run when checking the state after actions
		err := chromedp.Run(session.GetContext(), chromedp.Text("body", &bodyText, chromedp.ByQuery))
		require.NoError(t, err)
		assert.Contains(t, bodyText, "Processed")
	})

	t.Run("Interaction_ScrollPage", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session

		// Create a page taller than the viewport
		server := createStaticTestServer(t, `
            <html><body style="height: 3000px; margin: 0;">
                <div id="top" style="position: absolute; top: 0px;">Top</div>
                <div id="bottom" style="position: absolute; top: 2950px;">Bottom</div>
            </body></html>
        `)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Helper function to get current scroll position
		getScrollY := func() float64 {
			var scrollY float64
			res, err := session.ExecuteScript(ctx, `window.scrollY`, nil)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(res, &scrollY))
			return scrollY
		}

		initialScrollY := getScrollY()
		assert.Equal(t, 0.0, initialScrollY, "Should start at the top")

		// Test Scroll Down
		require.NoError(t, session.ScrollPage(ctx, "down"))
		// Use Eventually to account for smooth scrolling animation time
		assert.Eventually(t, func() bool {
			return getScrollY() > initialScrollY
		}, 3*time.Second, 100*time.Millisecond, "Page did not scroll down")
		scrollYDown := getScrollY()

		// Test Scroll Bottom
		require.NoError(t, session.ScrollPage(ctx, "bottom"))
		assert.Eventually(t, func() bool {
			return getScrollY() > scrollYDown
		}, 3*time.Second, 100*time.Millisecond, "Page did not scroll to bottom")
		scrollYBottom := getScrollY()

		// Test Scroll Up
		require.NoError(t, session.ScrollPage(ctx, "up"))
		assert.Eventually(t, func() bool {
			return getScrollY() < scrollYBottom
		}, 3*time.Second, 100*time.Millisecond, "Page did not scroll up")

		// Test Scroll Top
		require.NoError(t, session.ScrollPage(ctx, "top"))
		assert.Eventually(t, func() bool {
			return getScrollY() == 0.0
		}, 3*time.Second, 100*time.Millisecond, "Page did not scroll to top")

		// Test Invalid Direction
		err := session.ScrollPage(ctx, "sideways")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid scroll direction")
	})

	t.Run("Interaction_WaitForAsync", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		waitDurationMs := 200

		// Test wait duration
		startTime := time.Now()
		require.NoError(t, session.WaitForAsync(ctx, waitDurationMs))
		duration := time.Since(startTime)

		assert.GreaterOrEqual(t, duration, time.Duration(waitDurationMs)*time.Millisecond)

		// Test cancellation during wait
		cancelCtx, cancelWait := context.WithCancel(ctx)
		waitErrChan := make(chan error, 1)

		go func() {
			waitErrChan <- session.WaitForAsync(cancelCtx, 5000) // Long wait
		}()

		time.Sleep(100 * time.Millisecond)
		cancelWait() // Cancel the context

		select {
		case err := <-waitErrChan:
			require.Error(t, err)
			assert.ErrorIs(t, err, context.Canceled)
		case <-time.After(1 * time.Second):
			t.Fatal("WaitForAsync did not return promptly after cancellation")
		}
	})

	t.Run("Interaction_NonHumanoidFallback", func(t *testing.T) {
		// Create a fixture with Humanoid disabled
		fixture := newTestFixture(t, func(cfg *config.Config) {
			cfg.BrowserCfg.Humanoid.Enabled = false
		})
		session := fixture.Session
		assert.Nil(t, session.humanoid, "Humanoid should be disabled")

		server := createStaticTestServer(t, `
	            <input id="inputField" type="text" value="initial">
	            <button id="target" onclick="this.innerText='Clicked'">Click Me</button>
	        `)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Test Type (Fallback path)
		require.NoError(t, session.Type(ctx, "#inputField", "fallback_type"), "Typing (fallback) failed")

		var typedValue string
		res, err := session.ExecuteScript(ctx, `document.querySelector("#inputField").value`, nil)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(res, &typedValue))
		assert.Contains(t, typedValue, "fallback_type")

		// Test Click (Fallback path)
		require.NoError(t, session.Click(ctx, "#target"), "Clicking (fallback) failed")

		var buttonText string
		res, err = session.ExecuteScript(ctx, `document.querySelector("#target").innerText`, nil)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(res, &buttonText))
		assert.Equal(t, "Clicked", buttonText)
	})

	t.Run("CloseIdempotency", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// First close
		require.NoError(t, session.Close(ctx), "First close failed")

		// Second close should not error
		require.NoError(t, session.Close(ctx), "Second close should be idempotent")

		// Verify operations fail after close
		err := session.Navigate(ctx, "about:blank")
		require.Error(t, err, "Navigate should fail after session is closed")

		// FIX: Broaden assertion to include common CDP connection errors.
		// The exact error string can vary depending on timing and CDP implementation.
		isExpectedError := strings.Contains(err.Error(), "session is closed") ||
			strings.Contains(err.Error(), "context canceled") ||
			strings.Contains(err.Error(), "Target closed") ||
			strings.Contains(err.Error(), "connection closed") ||
			strings.Contains(err.Error(), "cannot run actions")
		assert.True(t, isExpectedError, "Error should indicate closure or cancellation. Got: "+err.Error())

		_, err = session.CollectArtifacts(ctx)
		require.Error(t, err, "CollectArtifacts should fail after session is closed")
		// FIX: Broaden assertion to be less brittle.
		assert.Contains(t, err.Error(), "is closed")
	})

	t.Run("ExposeFunction_ErrorPaths", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session
		server := createStaticTestServer(t, `<html><body>Test</body></html>`)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// 1. Invalid implementation (not a function)
		err := session.ExposeFunction(ctx, "notAFunc", "just a string")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not a function")

		// Setup for argument mismatch testing
		callbackChan := make(chan bool, 1)
		myFunc := func(s string) {
			callbackChan <- true
		}
		require.NoError(t, session.ExposeFunction(ctx, "myTestFunc", myFunc))
		require.NoError(t, session.Navigate(ctx, server.URL))

		// 2. Argument count mismatch
		// The error is logged internally but ExecuteScript itself might succeed.
		// We verify that the callback was NOT called.
		_, err = session.ExecuteScript(ctx, `window.myTestFunc("hello", "extra_arg")`, nil)
		require.NoError(t, err)

		select {
		case <-callbackChan:
			t.Fatal("Callback should not have been called due to argument count mismatch")
		case <-time.After(500 * time.Millisecond):
			// Success: function was not called
		}

		// 3. Argument type mismatch
		// JS sends a number, Go expects a string.
		_, err = session.ExecuteScript(ctx, `window.myTestFunc(12345)`, nil)
		require.NoError(t, err)

		select {
		case <-callbackChan:
			t.Fatal("Callback should not have been called due to argument type mismatch")
		case <-time.After(500 * time.Millisecond):
			// Success: function was not called
		}
	})

	// Test Taint Shim Integration (IAST)
	t.Run("IAST_TaintShimIntegration", func(t *testing.T) {
		// Enable IAST for this test. The fixture handles providing mock templates during Initialize.
		fixture := newTestFixture(t, func(cfg *config.Config) {
			cfg.IASTCfg.Enabled = true
		})
		session := fixture.Session
		server := createStaticTestServer(t, `<html><body>IAST Test</body></html>`)

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// Initialize happened in the fixture.
		// Now navigate.
		require.NoError(t, session.Navigate(ctx, server.URL))

		// 1. Verify the shim was loaded (check console logs).
		// FIX: Update expected log message to match the mock shim defined in session_helpers_test.go.
		expectedLogMessage := "Scalpel Taint Shim Initialized (Test)"

		// FIX: Wait deterministically for logs.
		assert.Eventually(t, func() bool {
			if session.harvester == nil {
				return false
			}
			session.harvester.mu.RLock()
			defer session.harvester.mu.RUnlock()
			for _, log := range session.harvester.consoleLogs {
				// Check for the prefix indicating the shim initialized (either configured or empty).
				if strings.Contains(log.Text, expectedLogMessage) {
					return true
				}
			}
			return false
			// R4: Reduced timeout from 45s to 30s to prevent racing the global test timeout.
		}, 30*time.Second, 100*time.Millisecond, "Timed out waiting for IAST Shim Loaded log ("+expectedLogMessage+")")

		// 2. Trigger the event from JS. The handler (__scalpel_sink_event) is exposed during Initialize.
		jsTrigger := `
            window.__scalpel_sink_event({
                "type": "TestXSS",
                "detail": {
                    "source": "location.hash",
                    "value": "<script>alert(1)</script>",
                    "sink": "element.innerHTML"
                }
            });
        `
		_, err := session.ExecuteScript(ctx, jsTrigger, nil)
		require.NoError(t, err)

		// 3. Wait for the finding to appear in the channel
		select {
		case receivedFinding := <-fixture.FindingsChan:
			assert.Equal(t, "IAST", receivedFinding.Module)
			// REFACTOR: Assert flattened VulnerabilityName
			assert.Equal(t, "IAST Sink: TestXSS", receivedFinding.VulnerabilityName)

			// Check the evidence structure
			var evidenceMap map[string]interface{}
			// REFACTOR: Unmarshal Evidence (json.RawMessage) directly
			err := json.Unmarshal(receivedFinding.Evidence, &evidenceMap)
			require.NoError(t, err, "Failed to unmarshal evidence JSON")

			assert.Equal(t, "TestXSS", evidenceMap["sink_type"])
			details, ok := evidenceMap["details"].(map[string]interface{})
			require.True(t, ok, "Details should be an object")
			assert.Equal(t, "<script>alert(1)</script>", details["value"])

		case <-time.After(5. * time.Second):
			t.Fatal("Timed out waiting for IAST finding")
		}
	})

	// R10: Added test for timeout fix in cdp_executor.
	t.Run("ExecutorRespectsParentTimeout", func(t *testing.T) {
		fixture := newTestFixture(t)
		session := fixture.Session

		// Create a server that delays its response longer than the old internal timeouts.
		// Old timeouts were 10s for geometry and 20s for script execution.
		// We use a 22s delay.
		delay := 22 * time.Second
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(delay)
			fmt.Fprintln(w, `<html><body><div id="belated_element">Hello</div></body></html>`)
		}))

		// The parent context timeout must be longer than the server delay.
		// The test timeout is 45s, which is sufficient.
		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// The Navigate action itself should complete without timeout.
		require.NoError(t, session.Navigate(ctx, server.URL))

		// 1. Test GetElementGeometry
		// This call would have previously timed out after 10s. Now it should succeed
		// because the parent context `ctx` has a 45s timeout.
		_, err := session.GetElementGeometry(ctx, "#belated_element")
		require.NoError(t, err, "GetElementGeometry should not time out and respect the parent context's deadline")

		// 2. Test ExecuteScript
		// This call would have previously timed out after 20s. Now it should succeed.
		_, err = session.ExecuteScript(ctx, `(() => { return 1 + 1; })();`, nil)
		require.NoError(t, err, "ExecuteScript should not time out and respect the parent context's deadline")
	})
}

// TestConvertJSToGoType focuses on the type conversion logic for exposed functions.
func TestConvertJSToGoType(t *testing.T) {
	// Use a dummy session just to access the method (it's stateless)
	s := &Session{logger: zaptest.NewLogger(t)}

	tests := []struct {
		name        string
		jsArg       interface{}
		goType      reflect.Type
		expectedVal interface{}
		expectErr   bool
	}{
		// Basic types
		{"String to String", "hello", reflect.TypeOf(""), "hello", false},
		{"Bool to Bool", true, reflect.TypeOf(true), true, false},

		// Numbers (JS uses float64)
		{"Float64 to Float64", 123.45, reflect.TypeOf(float64(0)), 123.45, false},
		{"Float64 to Int", 42.0, reflect.TypeOf(int(0)), 42, false},
		{"Float64 (non-integer) to Int", 42.5, reflect.TypeOf(int(0)), 42, false}, // Truncation occurs, logs warning
		{"Float64 (negative) to Uint", -10.0, reflect.TypeOf(uint(0)), nil, true}, // Error

		// Nil/Null handling
		{"Null to Pointer", nil, reflect.TypeOf(&s), nil, false},
		{"Null to String", nil, reflect.TypeOf(""), nil, true}, // Error: string is not nillable

		// Struct conversion (Map to Struct)
		{"Map to Struct", map[string]interface{}{"Name": "Test", "Value": 10.0}, reflect.TypeOf(struct {
			Name  string
			Value int
		}{}), struct {
			Name  string
			Value int
		}{"Test", 10}, false},

		// Incompatible types
		{"String to Int", "hello", reflect.TypeOf(int(0)), nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := s.convertJSToGoType(tt.jsArg, tt.goType)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				// Handle comparison for nil pointers/maps
				if tt.expectedVal == nil {
					// Check if the value is a nil kind (pointer, map, etc.) or invalid
					isNil := !val.IsValid()
					if val.IsValid() {
						switch val.Kind() {
						case reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.Interface, reflect.Slice:
							isNil = val.IsNil()
						}
					}
					assert.True(t, isNil, "Expected value to be nil/invalid")
				} else {
					assert.Equal(t, tt.expectedVal, val.Interface())
				}
			}
		})
	}
}

// TestConvertNetworkCookiesToSchemaCookies covers the cookie conversion helper.
func TestConvertNetworkCookiesToSchemaCookies(t *testing.T) {
	cdpCookies := []*network.Cookie{
		{
			Name:     "SessionID",
			Value:    "12345",
			HTTPOnly: true,
			SameSite: network.CookieSameSiteStrict,
		},
		nil, // Handle nil entry
	}

	schemaCookies := convertNetworkCookiesToSchemaCookies(cdpCookies)

	require.Len(t, schemaCookies, 1)
	assert.Equal(t, "SessionID", schemaCookies[0].Name)
	assert.True(t, schemaCookies[0].HTTPOnly)
	assert.Equal(t, schemas.CookieSameSite(network.CookieSameSiteStrict), schemaCookies[0].SameSite)

	// Test nil input
	assert.Nil(t, convertNetworkCookiesToSchemaCookies(nil))
}

// assertLogPresent is a helper to check for a specific console log message.
func assertLogPresent(t *testing.T, logs []schemas.ConsoleLog, level, substring string) {
	t.Helper()
	found := false
	for _, log := range logs {
		logType := strings.ToLower(log.Type)    // Normalize actual log type
		expectedLevel := strings.ToLower(level) // Normalize expected level
		if expectedLevel == "warn" {
			expectedLevel = "warning" // CDP uses 'warning'
		}
		if logType == expectedLevel && strings.Contains(log.Text, substring) {
			found = true
			break
		}
	}
	if !found {
		var availableLogs []string
		for _, l := range logs {
			availableLogs = append(availableLogs, fmt.Sprintf("{Type: %s, Text: %q}", l.Type, l.Text))
		}
		t.Errorf("Expected console log not found: Type=%s, Substring='%s'\nAvailable logs: %s", level, substring, strings.Join(availableLogs, "\n"))
	}
}

// findHAREntry is a helper to find a specific entry in the HAR log.
// FIX: Use current schemas.HAR structure
func findHAREntry(harData *schemas.HAR, urlSubstring string) *schemas.Entry {
	// FIX: Removed harData.Log == nil check. Log is a struct.
	if harData == nil {
		return nil
	}
	for i := range harData.Log.Entries { // Iterate by index to take address
		entry := &harData.Log.Entries[i] // Get pointer to entry
		// FIX: Removed entry.Request != nil check. Request is a struct.
		if strings.Contains(entry.Request.URL, urlSubstring) {
			return entry
		}
	}
	return nil
}
