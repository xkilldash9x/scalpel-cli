// internal/browser/analysis_context_test.go
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
)

const testTimeout = 25 * time.Second

func TestAnalysisContext(t *testing.T) {
	t.Run("InitializeAndClose", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Init Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL))
		require.NoError(t, session.Close(ctx))

		// Verifies that the session context is properly canceled upon closing.
		select {
		case <-session.GetContext().Done():
			// This is the expected outcome.
		case <-time.After(2 * time.Second):
			t.Error("Session context did not close as expected")
		}
		assert.ErrorIs(t, session.GetContext().Err(), context.Canceled)
	})

	t.Run("NavigateAndCollectArtifacts", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "SessionID", Value: "12345"})
			fmt.Fprint(w, `<html><body>Target Page<script>console.log("Hello from JS");</script></body></html>`)
		}))
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL), "Navigation failed")
		artifacts, err := session.CollectArtifacts()
		require.NoError(t, err)
		require.NotNil(t, artifacts)

		// Assertions to validate the collected artifacts are correct.
		assert.Contains(t, artifacts.DOM, "Target Page")
		assert.True(t, len(artifacts.Storage.Cookies) > 0, "Should have captured cookies")
		assertLogPresent(t, artifacts.ConsoleLogs, "log", "Hello from JS")
		require.NotNil(t, findHAREntry(artifacts.HAR, server.URL), "HAR entry not found")
	})

	t.Run("SessionIsolation", func(t *testing.T) {
		t.Parallel()
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/set" {
				http.SetCookie(w, &http.Cookie{Name: "IsolatedCookie", Value: "SessionSpecific"})
			}
		}))

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		// First session, sets a cookie.
		fixture1 := newTestFixture(t)
		require.NoError(t, fixture1.Session.Navigate(ctx, server.URL+"/set"))
		artifacts1, _ := fixture1.Session.CollectArtifacts()
		assert.NotEmpty(t, artifacts1.Storage.Cookies, "Session 1 should have cookies")

		// Second session, should be completely isolated.
		fixture2 := newTestFixture(t)
		require.NoError(t, fixture2.Session.Navigate(ctx, server.URL+"/blank"))
		artifacts2, _ := fixture2.Session.CollectArtifacts()
		assert.Empty(t, artifacts2.Storage.Cookies, "Session 2 should not have cookies from session 1")
	})

	t.Run("Interaction", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)
		require.NotNil(t, fixture.Session.humanoid, "Humanoid should be initialized")
		server := createStaticTestServer(t, `<button onclick="this.innerText='Clicked'">Click Me</button>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		require.NoError(t, session.Navigate(ctx, server.URL))
		config := schemas.InteractionConfig{MaxDepth: 1, MaxInteractionsPerDepth: 1}
		require.NoError(t, session.Interact(ctx, config))

		artifacts, _ := session.CollectArtifacts()
		assert.Contains(t, artifacts.DOM, ">Clicked<")
	})

	t.Run("ExposeFunctionIntegration", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)
		server := createStaticTestServer(t, `<html><body>Test</body></html>`)
		session := fixture.Session

		ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
		defer cancel()

		callbackChan := make(chan string, 1)
		myFunc := func(s string) { callbackChan <- s }

		require.NoError(t, session.ExposeFunction(ctx, "myGoFunction", myFunc))
		require.NoError(t, session.Navigate(ctx, server.URL))
		require.NoError(t, session.ExecuteScript(ctx, `window.myGoFunction("hello")`))

		// Check that the exposed Go function was called by the browser's JS.
		select {
		case res := <-callbackChan:
			assert.Equal(t, "hello", res)
		case <-time.After(5 * time.Second):
			t.Fatal("Timed out waiting for exposed function")
		}
	})

	t.Run("NavigateTimeout", func(t *testing.T) {
		t.Parallel()
		fixture := newTestFixture(t)
		cfg := *fixture.Config
		cfg.Network.NavigationTimeout = 100 * time.Millisecond
		server := createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(500 * time.Millisecond) // This sleep is longer than the timeout.
		}))

		fixtureCtx, fixtureCancel := context.WithCancel(context.Background())
		defer fixtureCancel()
		manager, err := NewManager(fixtureCtx, getTestLogger(), &cfg)
		require.NoError(t, err)

		session, err := manager.NewAnalysisContext(fixtureCtx, &cfg, schemas.DefaultPersona, "", "")
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Navigation should fail with a timeout error.
		err = session.Navigate(ctx, server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "context deadline exceeded")
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
