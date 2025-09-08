// internal/browser/analysis_context_test.go
package browser_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestAnalysisContext_NavigateAndCollectArtifacts is a comprehensive integration test.
func TestAnalysisContext_NavigateAndCollectArtifacts(t *testing.T) {
	t.Parallel()
	fixture := setupBrowserManager(t)

	// Setup Test Server with various features to capture.
	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			// Set an HttpOnly cookie.
			http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "12345", HttpOnly: true, Secure: false, Path: "/"})
			fmt.Fprintln(w, `
				<html>
					<body>
						<h1>Target Page</h1>
						<script>
							// Set storage items.
							localStorage.setItem('userPref', 'darkmode');
							sessionStorage.setItem('tempData', 'active');
							// Log a console message.
							console.info('Initializing application...');
							// Trigger asynchronous network request.
							fetch('/api/data')
                                .then(res => res.text())
                                .then(data => console.log('API data fetched:', data.length));
                            // Trigger an error.
                            setTimeout(() => {
                                console.error("An expected error occurred.");
                            }, 50);
						</script>
					</body>
				</html>
			`)
		} else if r.URL.Path == "/api/data" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"key": "value", "id": 99}`)
		}
	}))

	session := fixture.initializeSession(t)

	// 1. Navigate
	// PostLoadWait in the test config should help handle the async stabilization.
	err := session.Navigate(server.URL)
	require.NoError(t, err, "Navigation failed")

	// 2. Collect Artifacts
	artifacts, err := session.CollectArtifacts()
	require.NoError(t, err, "Failed to collect artifacts")
	require.NotNil(t, artifacts)

	// 3. Verify Artifacts
	t.Run("DOM", func(t *testing.T) {
		assert.Contains(t, artifacts.DOM, "<h1>Target Page</h1>")
	})

	t.Run("Storage", func(t *testing.T) {
		storage := artifacts.Storage
		// Check Cookies (including HttpOnly, which confirms CDP collection worked)
		foundCookie := false
		// We must assert the type if the schema uses interface{}, or assume the concrete type if the schema uses it.
		// Assuming the schema uses []*network.Cookie based on the implementation provided.
		for _, cookie := range storage.Cookies {
			if cookie.Name == "SessionID" && cookie.Value == "12345" {
				assert.True(t, cookie.HTTPOnly, "HttpOnly flag should be preserved")
				foundCookie = true
				break
			}
		}
		assert.True(t, foundCookie, "SessionID cookie not captured")
		// Check Local/Session Storage
		assert.Equal(t, "darkmode", storage.LocalStorage["userPref"], "LocalStorage mismatch")
		assert.Equal(t, "active", storage.SessionStorage["tempData"], "SessionStorage mismatch")
	})

	t.Run("ConsoleLogs", func(t *testing.T) {
		logs := artifacts.ConsoleLogs
		assert.GreaterOrEqual(t, len(logs), 3, "Should capture at least 3 console logs")

		assertLogPresent(t, logs, "info", "Initializing application...")
		assertLogPresent(t, logs, "log", "API data fetched:")
		assertLogPresent(t, logs, "error", "An expected error occurred.")
	})

	t.Run("HAR", func(t *testing.T) {
		require.NotNil(t, artifacts.HAR)
		entries := artifacts.HAR.Log.Entries
		assert.Equal(t, 2, len(entries), "Expected 2 HAR entries (page + fetch)")

		// Check for main page and API request
		apiBodyFound := false
		mainPageFound := false
		for _, entry := range entries {
			if strings.HasSuffix(entry.Request.URL, "/api/data") {
				require.NotNil(t, entry.Response.Content)
				// Check response body content (CaptureResponseBodies is true)
				if strings.Contains(entry.Response.Content.Text, `{"key": "value", "id": 99}`) {
					apiBodyFound = true
				}
			}
			if entry.Request.URL == server.URL+"/" {
				mainPageFound = true
				assert.Equal(t, int64(200), entry.Response.Status)
			}
		}
		assert.True(t, mainPageFound, "Main page request missing from HAR")
		assert.True(t, apiBodyFound, "Response body for API request was not captured correctly")
	})
}

// TestSessionIsolation verifies that sessions do not share state (e.g., cookies).
func TestSessionIsolation(t *testing.T) {
	// Cannot run in parallel as it tests isolation within the same manager instance.
	fixture := setupBrowserManager(t)

	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "IsolatedCookie", Value: "SessionSpecific", Path: "/"})
			fmt.Fprintln(w, "Cookie Set")
		} else {
			fmt.Fprintln(w, "Blank Page")
		}
	}))

	// 1. Set cookie in Session 1
	session1 := fixture.initializeSession(t)
	err := session1.Navigate(server.URL + "/set")
	require.NoError(t, err)
	artifacts1, err := session1.CollectArtifacts()
	require.NoError(t, err)
	assert.NotEmpty(t, artifacts1.Storage.Cookies, "Session 1 should have cookies")

	// 2. Create Session 2
	session2 := fixture.initializeSession(t)

	// 3. Navigate in Session 2
	err = session2.Navigate(server.URL + "/blank")
	require.NoError(t, err)
	artifacts2, err := session2.CollectArtifacts()
	require.NoError(t, err)

	// 4. Verify Isolation
	assert.Empty(t, artifacts2.Storage.Cookies, "Session 2 should not inherit cookies from Session 1")
}

// Helper function for console log assertions
func assertLogPresent(t *testing.T, logs []schemas.ConsoleLog, level, substring string) {
	t.Helper()
	found := false
	for _, log := range logs {
		if log.Level == level && strings.Contains(log.Text, substring) {
			found = true
			break
		}
	}
	assert.True(t, found, fmt.Sprintf("Expected console log not found: Level=%s, Substring='%s'", level, substring))
}