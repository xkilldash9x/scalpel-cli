// File: internal/browser/analysis_context_test.go

// FIX: Changed package to 'browser' (internal test) to allow access to unexported test helpers
// (newTestFixture, createStaticTestServer, createTestServer) and unexported fields (sessionID).
package browser

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
	// Removed internal/browser import as we are now inside the package.
)

// TestAnalysisContext serves as a grouping for all related sub-tests.
func TestAnalysisContext(t *testing.T) {
	t.Run("InitializeAndClose", func(t *testing.T) {
		t.Parallel()
		// Assuming newTestFixture is defined in the browser package tests (e.g., browser_helper_test.go).
		fixture := newTestFixture(t)

		require.NotNil(t, fixture.Session)
		// Accessing unexported field 'sessionID' is allowed in internal tests.
		require.NotEmpty(t, fixture.Session.sessionID, "Session ID should not be empty")

		// Assuming createStaticTestServer is defined in the browser package tests.
		server := createStaticTestServer(t, `<!DOCTYPE html><html><body><h1>Init Test</h1></body></html>`)
		defer server.Close()

		session := fixture.Session

		// FIX: Pass a context to Navigate as required by the interface.
		err := session.Navigate(context.Background(), server.URL)
		require.NoError(t, err)

		session.Close(context.Background())

		<-session.GetContext().Done()
		assert.Error(t, session.GetContext().Err(), "Context should be cancelled after close")
	})

	t.Run("NavigateAndCollectArtifacts", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)

		// Assuming createTestServer is defined in the browser package tests.
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "12345", HttpOnly: true, Path: "/"})
				fmt.Fprintln(w, `<html><body><h1>Target Page</h1></body></html>`)
			}
		}))
		defer server.Close()

		session := fixture.Session

		// FIX: Pass a context to Navigate.
		err := session.Navigate(context.Background(), server.URL)
		require.NoError(t, err, "Navigation failed")

		artifacts, err := session.CollectArtifacts()
		require.NoError(t, err, "Failed to collect artifacts")
		require.NotNil(t, artifacts)

		assert.Contains(t, artifacts.DOM, "<h1>Target Page</h1>")

		storage := artifacts.Storage
		require.NotNil(t, storage)

		var sessionCookie *network.Cookie
		for _, cookie := range storage.Cookies {
			if cookie.Name == "SessionID" {
				sessionCookie = cookie
				break
			}
		}
		require.NotNil(t, sessionCookie, "HttpOnly SessionID cookie not captured")
		assert.Equal(t, "12345", sessionCookie.Value)
		assert.True(t, sessionCookie.HTTPOnly)
	})

	t.Run("SessionIsolation", func(t *testing.T) {
		t.Parallel()
		fixture1 := newTestFixture(t)
		session1 := fixture1.Session

		fixture2 := newTestFixture(t)
		session2 := fixture2.Session

		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/set" {
				http.SetCookie(w, &http.Cookie{Name: "IsolatedCookie", Value: "SessionSpecific", Path: "/"})
				fmt.Fprintln(w, "Cookie Set")
			} else {
				fmt.Fprintln(w, "Blank Page")
			}
		}))
		defer server.Close()

		// FIX: Pass a context to Navigate.
		err := session1.Navigate(context.Background(), server.URL+"/set")
		require.NoError(t, err)
		artifacts1, err := session1.CollectArtifacts()
		require.NoError(t, err)
		assert.NotEmpty(t, artifacts1.Storage.Cookies)

		// FIX: Pass a context to Navigate.
		err = session2.Navigate(context.Background(), server.URL+"/blank")
		require.NoError(t, err)
		artifacts2, err := session2.CollectArtifacts()
		require.NoError(t, err)

		assert.Empty(t, artifacts2.Storage.Cookies, "Session 2 should not inherit cookies from Session 1")
	})

	t.Run("Interaction", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<!DOCTYPE html><html><body><button id="btn">Click Me</button></body></html>`)
		defer server.Close()
		session := fixture.Session

		// FIX: Pass a context to Navigate.
		err := session.Navigate(context.Background(), server.URL)
		require.NoError(t, err)

		interactionConfig := schemas.InteractionConfig{
			MaxDepth:                2,
			MaxInteractionsPerDepth: 5,
			InteractionDelayMs:      10,
			PostInteractionWaitMs:   100,
		}

		// FIX: Pass a context to Interact.
		err = session.Interact(context.Background(), interactionConfig)
		assert.NoError(t, err, "Interaction should not produce an error on a simple page")
	})
}

// -- Test Helper Functions --

// FIX: Updated to use schemas.ConsoleLog instead of the undefined browser.ConsoleLog.
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

func findHAREntry(har *schemas.HAR, urlSubstring string) *schemas.Entry {
	// Updated to use HARLog structure.
	for i, entry := range har.Log.Entries {
		if strings.Contains(entry.Request.URL, urlSubstring) {
			return &har.Log.Entries[i]
		}
	}
	return nil
}
