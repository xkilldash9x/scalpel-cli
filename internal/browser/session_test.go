// internal/browser/session_test.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

const testTimeout = 45 * time.Second

// Renamed TestAnalysisContext to TestSession
func TestSession(t *testing.T) {
	t.Run("InitializeAndClose", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Init Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(cancel)

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Closing is handled by the fixture cleanup, but calling it explicitly here is fine too.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		require.NoError(t, session.Close(closeCtx))

		// Verifies that the session context is properly canceled upon closing.
		select {
		case <-session.GetContext().Done():
			// Expected outcome.
		case <-time.After(5 * time.Second):
			t.Error("Session context did not close as expected")
		}
		assert.ErrorIs(t, session.GetContext().Err(), context.Canceled)
	})

	t.Run("NavigateAndCollectArtifacts", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "12345", HttpOnly: true})
			fmt.Fprint(w, `<html><body>Target Page
                <script>
                    localStorage.setItem("localKey", "localValue");
                    console.log("Hello from JS");
                </script>
            </body></html>`)
		}))
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(cancel)

		require.NoError(t, session.Navigate(ctx, server.URL), "Navigation failed")

		// CollectArtifacts now requires a context.
		artifacts, err := session.CollectArtifacts(ctx)
		require.NoError(t, err)
		require.NotNil(t, artifacts)

		// Assertions to validate the collected artifacts.
		assert.Contains(t, artifacts.DOM, "Target Page")
		assert.True(t, len(artifacts.Storage.Cookies) > 0, "Should have captured cookies")

		// Check if the cookie attributes are captured correctly.
		foundCookie := false
		for _, cookie := range artifacts.Storage.Cookies {
			if cookie.Name == "SessionID" && cookie.HTTPOnly {
				foundCookie = true
				break
			}
		}
		assert.True(t, foundCookie, "SessionID HttpOnly cookie not found or attributes incorrect")
        assert.Equal(t, "localValue", artifacts.Storage.LocalStorage["localKey"])

		assertLogPresent(t, artifacts.ConsoleLogs, "log", "Hello from JS")
		require.NotNil(t, findHAREntry(artifacts.HAR, server.URL), "HAR entry not found")
	})

	t.Run("SessionIsolation", func(t *testing.T) {
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/set" {
				http.SetCookie(w, &http.Cookie{Name: "IsolatedCookie", Value: "SessionSpecific"})
				fmt.Fprintln(w, "Cookie Set")
			} else {
				fmt.Fprintln(w, "Blank Page")
			}
		}))

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(cancel)

		// First session, sets a cookie.
		fixture1 := newTestFixture(t)
		require.NoError(t, fixture1.Session.Navigate(ctx, server.URL+"/set"))
		artifacts1, _ := fixture1.Session.CollectArtifacts(ctx)
		assert.NotEmpty(t, artifacts1.Storage.Cookies, "Session 1 should have cookies")

		// Second session, should be completely isolated.
		fixture2 := newTestFixture(t)
		require.NoError(t, fixture2.Session.Navigate(ctx, server.URL+"/blank"))
		artifacts2, _ := fixture2.Session.CollectArtifacts(ctx)
		assert.Empty(t, artifacts2.Storage.Cookies, "Session 2 should not have cookies from session 1")
	})

	t.Run("Interaction_BasicClickAndType", func(t *testing.T) {
		fixture := newTestFixture(t)
		// Check internal state (humanoid should be initialized if enabled in config).
		require.NotNil(t, fixture.Session.humanoid, "Humanoid should be initialized")

		server := createStaticTestServer(t, `
            <input id="inputField" type="text" value="initial">
            <button id="target" onclick="this.innerText='Clicked'; document.getElementById('inputField').value='clicked_value'">Click Me</button>
        `)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(cancel)

		require.NoError(t, session.Navigate(ctx, server.URL))

        // Test Type
        require.NoError(t, session.Type("#inputField", "typed_value"))
        var typedValue string
        require.NoError(t, chromedp.Run(session.GetContext(), chromedp.Value("#inputField", &typedValue)))
        // Humanoid typing appends, it does not replace by default.
		assert.Contains(t, typedValue, "typed_value")

		// Test Click
		require.NoError(t, session.Click("#target"))

        // Verify click result
		artifacts, _ := session.CollectArtifacts(ctx)
		assert.Contains(t, artifacts.DOM, ">Clicked<")

        var clickedValue string
        require.NoError(t, chromedp.Run(session.GetContext(), chromedp.Value("#inputField", &clickedValue)))
        assert.Equal(t, "clicked_value", clickedValue)
	})

	// Note: The full 'Interact' (crawler) test is in interactor_test.go

	t.Run("ExposeFunctionIntegration_ManualBinding", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(cancel)

		callbackChan := make(chan string, 1)

		// The function signature must match the arguments passed from JS.
		// JS calls: window.myGoFunction("hello", 123) -> Go func: func(s string, i int)
		myFunc := func(s string, i int) {
			callbackChan <- fmt.Sprintf("%s_%d", s, i)
		}

		// ExposeFunction requires a context. We use the main test context here.
		require.NoError(t, session.ExposeFunction(ctx, "myGoFunction", myFunc))
		require.NoError(t, session.Navigate(ctx, server.URL))
		// FIX: Added nil as the third argument to satisfy the updated method signature.
		require.NoError(t, session.ExecuteScript(ctx, `window.myGoFunction("hello", 123)`, nil))

		// Check that the exposed Go function was called.
		select {
		case res := <-callbackChan:
			assert.Equal(t, "hello_123", res)
		case <-time.After(10 * time.Second):
			t.Fatal("Timed out waiting for exposed function")
		}
	})

    t.Run("ExposeFunctionIntegration_MapSignature", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		t.Cleanup(cancel)

		callbackChan := make(chan string, 1)

		// Test using a map signature, common for the IAST shim.
		myFunc := func(data map[string]interface{}) {
            val, _ := data["key"].(string)
			callbackChan <- val
		}

		require.NoError(t, session.ExposeFunction(ctx, "myMapFunc", myFunc))
		require.NoError(t, session.Navigate(ctx, server.URL))
		require.NoError(t, session.ExecuteScript(ctx, `window.myMapFunc({"key": "map_value"})`, nil))

		select {
		case res := <-callbackChan:
			assert.Equal(t, "map_value", res)
		case <-time.After(10 * time.Second):
			t.Fatal("Timed out waiting for exposed function (map signature)")
		}
	})

	t.Run("NavigateTimeout", func(t *testing.T) {
		// Configure a short timeout for this specific test.
		fixture := newTestFixture(t, func(cfg *config.Config) {
			cfg.Network.NavigationTimeout = 200 * time.Millisecond
		})

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(1 * time.Second) // Longer than the timeout.
			fmt.Fprintln(w, "<html><body>Slow response</body></html>")
		}))

		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		t.Cleanup(cancel)

		// Navigation should fail with a timeout error.
		err := session.Navigate(ctx, server.URL)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Contains(t, err.Error(), "timed out after 200ms")
	})
}

// assertLogPresent is a helper to check for a specific console log message.
func assertLogPresent(t *testing.T, logs []schemas.ConsoleLog, level, substring string) {
	t.Helper()
	for _, log := range logs {
		if log.Type == level && strings.Contains(log.Text, substring) {
			return
		}
	}
	t.Errorf("Expected console log not found: Type=%s, Substring='%s'", level, substring)
}

// findHAREntry is a helper to find a specific entry in the HAR log.
func findHAREntry(har *schemas.HAR, urlSubstring string) *schemas.Entry {
	if har == nil {
		return nil
	}
	for i, entry := range har.Log.Entries {
		if strings.Contains(entry.Request.URL, urlSubstring) {
			return &har.Log.Entries[i]
		}
	}
	return nil
}