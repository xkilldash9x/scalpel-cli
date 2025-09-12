// in: internal/browser/analysis_context_test.go

package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestAnalysisContext_InitializeAndClose now pulls the fixture from the global
// variable initialized in TestMain, simplifying its signature.
func TestAnalysisContext_InitializeAndClose(t *testing.T) {
	t.Parallel()
	fixture := globalFixture

	server := createStaticTestServer(t, `<!DOCTYPE html><html><body><h1>Init Test</h1></body></html>`)

	session := fixture.initializeSession(t)
	assert.NotEmpty(t, session.ID(), "AnalysisContext should have a valid ID")

	err := session.Navigate(server.URL)
	require.NoError(t, err)

	session.Close(context.Background())

	<-session.GetContext().Done()
	assert.Error(t, session.GetContext().Err(), "Context should be cancelled after close")
}

// TestAnalysisContext_NavigateAndCollectArtifacts also uses the global fixture.
// This test has been refactored for more robust and specific artifact verification.
func TestAnalysisContext_NavigateAndCollectArtifacts(t *testing.T) {
	t.Parallel()
	fixture := globalFixture

	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "12345", HttpOnly: true, Path: "/"})
			fmt.Fprintln(w, `
				<html>
					<body>
						<h1>Target Page</h1>
						<script>
							localStorage.setItem('userPref', 'darkmode');
							sessionStorage.setItem('tempData', 'active');
							console.info('Initializing application...');
							fetch('/api/data')
                                    .then(res => res.text())
                                    .then(data => console.log('API data fetched:', data.length));
                                setTimeout(() => { console.error("An expected error occurred."); }, 50);
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

	err := session.Navigate(server.URL)
	require.NoError(t, err, "Navigation failed")

	artifacts, err := session.CollectArtifacts()
	require.NoError(t, err, "Failed to collect artifacts")
	require.NotNil(t, artifacts)

	// -- Verify DOM --
	assert.Contains(t, artifacts.DOM, "<h1>Target Page</h1>", "DOM should contain the test page content")

	// -- Verify Storage State --
	storage := artifacts.Storage
	require.NotNil(t, storage, "Storage state should not be nil")
	assert.Equal(t, "darkmode", storage.LocalStorage["userPref"], "LocalStorage mismatch")
	assert.Equal(t, "active", storage.SessionStorage["tempData"], "SessionStorage mismatch")

	// Refactored cookie verification for more precise assertions.
	var sessionCookie *network.Cookie
	for _, cookie := range storage.Cookies {
		if cookie.Name == "SessionID" {
			sessionCookie = cookie
			break
		}
	}
	require.NotNil(t, sessionCookie, "HttpOnly SessionID cookie not captured")
	assert.Equal(t, "12345", sessionCookie.Value, "Cookie value mismatch")
	assert.True(t, sessionCookie.HTTPOnly, "HttpOnly flag should be preserved")

	// -- Verify Console Logs --
	assertLogPresent(t, artifacts.ConsoleLogs, "info", "Initializing application...")
	assertLogPresent(t, artifacts.ConsoleLogs, "log", "API data fetched:")
	assertLogPresent(t, artifacts.ConsoleLogs, "error", "An expected error occurred.")

	// -- Verify HAR log with a helper for cleaner assertions --
	require.NotNil(t, artifacts.HAR, "HAR log should not be nil")
	require.NotEmpty(t, artifacts.HAR.Log.Entries, "HAR log should not be empty")

	mainPageEntry := findHAREntry(artifacts.HAR, server.URL+"/")
	require.NotNil(t, mainPageEntry, "Main page request missing from HAR")
	assert.Equal(t, 200, mainPageEntry.Response.Status)

	apiEntry := findHAREntry(artifacts.HAR, "/api/data")
	require.NotNil(t, apiEntry, "API request missing from HAR")
	require.NotNil(t, apiEntry.Response.Content, "API response content should not be nil")
	assert.Contains(t, apiEntry.Response.Content.Text, `{"key": "value", "id": 99}`, "Response body for API request was not captured correctly")
}

// TestSessionIsolation uses the global fixture.
func TestSessionIsolation(t *testing.T) {
	t.Parallel()
	fixture := globalFixture

	server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/set" {
			http.SetCookie(w, &http.Cookie{Name: "IsolatedCookie", Value: "SessionSpecific", Path: "/"})
			fmt.Fprintln(w, "Cookie Set")
		} else {
			fmt.Fprintln(w, "Blank Page")
		}
	}))

	session1 := fixture.initializeSession(t)
	err := session1.Navigate(server.URL + "/set")
	require.NoError(t, err)
	artifacts1, err := session1.CollectArtifacts()
	require.NoError(t, err)
	assert.NotEmpty(t, artifacts1.Storage.Cookies, "Session 1 should have received a cookie")

	session2 := fixture.initializeSession(t)

	err = session2.Navigate(server.URL + "/blank")
	require.NoError(t, err)
	artifacts2, err := session2.CollectArtifacts()
	require.NoError(t, err)

	assert.Empty(t, artifacts2.Storage.Cookies, "Session 2 should not inherit cookies from Session 1")
}

// TestAnalysisContext_Interaction uses the global fixture.
func TestAnalysisContext_Interaction(t *testing.T) {
	t.Parallel()
	fixture := globalFixture
	server := createStaticTestServer(t, `
		<!DOCTYPE html>
		<html>
		<body>
			<button id="btn">Click Me</button>
			<input type="text" id="inputfield" />
		</body>
		</html>
	`)

	session := fixture.initializeSession(t)

	err := session.Navigate(server.URL)
	require.NoError(t, err)

	interactionConfig := schemas.InteractionConfig{
		MaxDepth:               2,
		MaxInteractionsPerDepth: 5,
		InteractionDelayMs:      10,
		PostInteractionWaitMs:  100,
	}

	err = session.Interact(interactionConfig)
	assert.NoError(t, err, "Interaction should not produce an error on a simple page")
}

// -- Test Helper Functions --

// assertLogPresent is a helper function to check for the existence of a specific console message.
func assertLogPresent(t *testing.T, logs []schemas.ConsoleLog, level, substring string) {
	t.Helper()
	found := false
	for _, log := range logs {
		if log.Type == level && strings.Contains(log.Text, substring) {
			found = true
			break
		}
	}
	assert.True(t, found, fmt.Sprintf("Expected console log not found: Type=%s, Substring='%s'", level, substring))
}

// findHAREntry is a helper to find the first HAR entry whose URL contains a given substring.
func findHAREntry(har *schemas.HAR, urlSubstring string) *schemas.Entry {
	for i, entry := range har.Log.Entries {
		if strings.Contains(entry.Request.URL, urlSubstring) {
			// Return a pointer to the actual entry in the slice.
			return &har.Log.Entries[i]
		}
	}
	return nil
}

