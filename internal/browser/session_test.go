// internal/browser/session_test.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

const sessionTestTimeout = 60 * time.Second

func TestSession(t *testing.T) {
	// Ensure the global manager is ready.
	if suiteManagerErr != nil {
		t.Fatalf("Skipping Session tests due to initialization failure: %v", suiteManagerErr)
	}

	t.Run("InitializeAndClose", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Init Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), sessionTestTimeout)
		t.Cleanup(cancel)

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Explicitly close the session.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		require.NoError(t, session.Close(closeCtx))

		// Verifies context cancellation.
		assert.ErrorIs(t, session.GetContext().Err(), context.Canceled)

		// Verify Playwright resources are closed.
		assert.True(t, session.page.IsClosed(), "Page should be closed")
	})

	t.Run("NavigateAndCollectArtifacts", func(t *testing.T) {
		fixture := newTestFixture(t)
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set multiple cookies to test Harvester's handling of Set-Cookie headers.
			http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "12345", HttpOnly: true, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "Analytics", Value: "Enabled", Path: "/"})

			fmt.Fprint(w, `<html><body><h1>Target Page</h1>
                <script>
                    localStorage.setItem("localKey", "localValue");
					sessionStorage.setItem("sessionKey", "sessionValue");
                    console.log("Hello from JS");
					fetch('/data.json'); // Trigger network request
                </script>
            </body></html>`)
		}))

		// Add handler for the fetch request.
		mux := http.NewServeMux()
		mux.HandleFunc("/data.json", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status": "ok"}`)
		})
		// Use the original handler for the main page.
		mux.HandleFunc("/", server.Config.Handler.ServeHTTP)
		server.Config.Handler = mux

		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), sessionTestTimeout)
		t.Cleanup(cancel)

		require.NoError(t, session.Navigate(ctx, server.URL), "Navigation failed")

		artifacts, err := session.CollectArtifacts(ctx)
		require.NoError(t, err)
		require.NotNil(t, artifacts)

		// Assertions
		assert.Contains(t, artifacts.DOM, "<h1>Target Page</h1>")

		// Storage Assertions
		assert.Equal(t, "localValue", artifacts.Storage.LocalStorage["localKey"])
		assert.Equal(t, "sessionValue", artifacts.Storage.SessionStorage["sessionKey"])

		// Cookie Assertions (collected via BrowserContext.Cookies())
		require.True(t, len(artifacts.Storage.Cookies) >= 2, "Should have captured cookies")
		foundCookie := false
		for _, cookie := range artifacts.Storage.Cookies {
			if cookie.Name == "SessionID" {
				assert.True(t, cookie.HTTPOnly, "SessionID should be HttpOnly")
				assert.Equal(t, "12345", cookie.Value)
				foundCookie = true
				break
			}
		}
		assert.True(t, foundCookie, "SessionID cookie not found")

		// Console Log Assertions
		assertLogPresent(t, artifacts.ConsoleLogs, "log", "Hello from JS")

		// HAR Assertions
		mainEntry := findHAREntry(artifacts.HAR, server.URL)
		require.NotNil(t, mainEntry, "Main HAR entry not found")

		// Check that the Harvester correctly parsed cookies from the response headers.
		foundHarCookie := false
		for _, cookie := range mainEntry.Response.Cookies {
			if cookie.Name == "Analytics" {
				foundHarCookie = true
				break
			}
		}
		assert.True(t, foundHarCookie, "Analytics cookie missing from HAR response")

		jsonEntry := findHAREntry(artifacts.HAR, "/data.json")
		require.NotNil(t, jsonEntry, "JSON fetch HAR entry not found")
	})

	t.Run("SessionIsolation", func(t *testing.T) {
		// Test that cookies do not bleed between sessions (BrowserContexts).
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/set" {
				http.SetCookie(w, &http.Cookie{Name: "IsolatedCookie", Value: "SessionSpecific", Path: "/"})
				fmt.Fprintln(w, "Cookie Set")
			} else {
				fmt.Fprintln(w, "Blank Page")
			}
		}))

		ctx, cancel := context.WithTimeout(context.Background(), sessionTestTimeout)
		t.Cleanup(cancel)

		// Session 1: Sets the cookie.
		fixture1 := newTestFixture(t)
		require.NoError(t, fixture1.Session.Navigate(ctx, server.URL+"/set"))
		artifacts1, _ := fixture1.Session.CollectArtifacts(ctx)
		assert.NotEmpty(t, artifacts1.Storage.Cookies, "Session 1 should have cookies")

		// Session 2: Should start clean.
		fixture2 := newTestFixture(t)
		require.NoError(t, fixture2.Session.Navigate(ctx, server.URL+"/blank"))
		artifacts2, _ := fixture2.Session.CollectArtifacts(ctx)

		// Verify isolation.
		assert.Empty(t, artifacts2.Storage.Cookies, "Session 2 should not have cookies from session 1")
	})

	t.Run("Interaction_ClickAndType_Humanoid", func(t *testing.T) {
		// Humanoid is enabled by default in the test config.
		fixture := newTestFixture(t)

		server := createStaticTestServer(t, `
            <input id="inputField" type="text" value="initial">
            <button id="target" onclick="this.innerText='Clicked'; document.getElementById('inputField').value='clicked_value'">Click Me</button>
        `)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), sessionTestTimeout)
		t.Cleanup(cancel)

		require.NoError(t, session.Navigate(ctx, server.URL))

		// Test Type (Session.Type handles clearing the field first when humanoid is enabled)
		require.NoError(t, session.Type("#inputField", "typed_value"))

		var typedValue string
		require.NoError(t, session.ExecuteScript(ctx, `document.getElementById('inputField').value`, &typedValue))
		assert.Equal(t, "typed_value", typedValue, "Humanoid typing should replace the value")

		// Test Click
		require.NoError(t, session.Click("#target"))

		// Verify click result
		var clickedValue string
		// Use Eventually to allow time for the JS onclick handler to execute.
		assert.Eventually(t, func() bool {
			err := session.ExecuteScript(ctx, `document.getElementById('inputField').value`, &clickedValue)
			return err == nil && clickedValue == "clicked_value"
		}, 5*time.Second, 100*time.Millisecond)
	})

	t.Run("ExposeFunctionIntegration_MapSignature", func(t *testing.T) {
		// This tests the robust function exposure mechanism, crucial for IAST.
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), sessionTestTimeout)
		t.Cleanup(cancel)

		callbackChan := make(chan map[string]interface{}, 1)

		// Function signature matching the IAST shim handler.
		myFunc := func(data map[string]interface{}) {
			callbackChan <- data
		}

		require.NoError(t, session.ExposeFunction(ctx, "myMapFunc", myFunc))
		require.NoError(t, session.Navigate(ctx, server.URL))

		// Call the exposed function from JS with a complex object.
		require.NoError(t, session.ExecuteScript(ctx, `window.myMapFunc({"key": "map_value", "nested": {"id": 123}})`, nil))

		// Check that the Go function was called and data marshaled correctly via the JSON intermediary.
		select {
		case res := <-callbackChan:
			assert.Equal(t, "map_value", res["key"])
			nested, ok := res["nested"].(map[string]interface{})
			require.True(t, ok, "Nested object should be a map")
			// Numbers are typically unmarshaled as float64 from JSON intermediary.
			assert.Equal(t, float64(123), nested["id"])
		case <-time.After(10 * time.Second):
			t.Fatal("Timed out waiting for exposed function (map signature)")
		}
	})

	t.Run("NavigateTimeout", func(t *testing.T) {
		// Configure a very short timeout for this specific test.
		timeoutDuration := 500 * time.Millisecond
		fixture := newTestFixture(t, func(cfg *config.Config) {
			cfg.Network.NavigationTimeout = timeoutDuration
		})

		// Server that intentionally delays the response.
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second) // Longer than the timeout.
			fmt.Fprintln(w, "<html><body>Slow response</body></html>")
		}))

		session := fixture.Session

		// Use a longer context for the test execution itself.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)

		// Navigation should fail with a timeout error.
		err := session.Navigate(ctx, server.URL)
		require.Error(t, err)
		// Playwright provides specific timeout errors.
		assert.True(t, strings.Contains(err.Error(), "navigation timed out") || strings.Contains(err.Error(), "Timeout"), "Error should be a timeout error")
	})
}

// Helper functions (remain the same as they are generic)

func assertLogPresent(t *testing.T, logs []schemas.ConsoleLog, level, substring string) {
	t.Helper()
	for _, log := range logs {
		// Playwright console types are often lowercase (e.g., "log", "error", "warning").
		if strings.EqualFold(log.Type, level) && strings.Contains(log.Text, substring) {
			return
		}
	}
	t.Errorf("Expected console log not found: Type=%s, Substring='%s'. Found %d logs.", level, substring, len(logs))
}

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