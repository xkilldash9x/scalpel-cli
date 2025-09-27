package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// setupTestManager creates a new Manager instance configured for testing.
func setupTestManager(t *testing.T) (*browser.Manager, *config.Config) {
	// Manually create a config for testing, as NewDefaultConfig is no longer available.
	cfg := &config.Config{
		Browser: config.BrowserConfig{
			// Initialize with a default humanoid config, which can then be modified.
			Humanoid: humanoid.DefaultConfig(),
		},
		Network: config.NetworkConfig{},
		IAST:    config.IASTConfig{},
	}
	// Configure minimal settings for testing.
	cfg.Browser.Humanoid.Enabled = false
	cfg.Network.PostLoadWait = 10 * time.Millisecond

	logger := zap.NewNop()
	// NewManager is assumed to be the Pure Go implementation as per file context.
	m, err := browser.NewManager(context.Background(), cfg, logger)
	require.NoError(t, err)
	return m, cfg
}

// TestManager_SessionLifecycleAndShutdown verifies session creation, manual closure,
// and graceful manager shutdown.
func TestManager_SessionLifecycleAndShutdown(t *testing.T) {
	m, cfg := setupTestManager(t)

	const sessionCount = 5
	sessions := make([]schemas.SessionContext, sessionCount)
	findingsChan := make(chan schemas.Finding, 1)

	// Create multiple sessions.
	for i := 0; i < sessionCount; i++ {
		// Use a minimal context for creation.
		s, err := m.NewAnalysisContext(context.Background(), cfg, schemas.DefaultPersona, "", "", findingsChan)
		require.NoError(t, err)
		sessions[i] = s
	}

	// Verify the number of active sessions before closure.
	// NOTE: Direct access to internal map is not possible, but we rely on the logic
	// that creation succeeds and is tracked by the manager's WaitGroup.

	// Close one session manually. This should trigger the WG.Done() and map deletion.
	err := sessions[0].Close(context.Background())
	require.NoError(t, err)

	// Shutdown the manager (should close the remaining 4 sessions and wait for all 5).
	// Use a short, bounded context for the shutdown operation.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = m.Shutdown(ctx)
	require.NoError(t, err, "Manager should shut down cleanly after closing remaining sessions")

	// Verify all sessions contexts are cancelled (indicating closure).
	for i, s := range sessions {
		// Check that the session's internal context is canceled.
		assert.ErrorIs(t, s.GetContext().Err(), context.Canceled, "Session %d context should be cancelled after manager shutdown", i)
	}
}

// TestManager_ConcurrentSessionCreation verifies thread safety when creating/closing sessions.
func TestManager_ConcurrentSessionCreation(t *testing.T) {
	m, cfg := setupTestManager(t)
	// Defer shutdown, but the test's main verification is ensuring no race/deadlock under concurrency.
	defer m.Shutdown(context.Background())

	const concurrency = 10
	var wg sync.WaitGroup

	sessionIDs := make(chan string, concurrency)

	// Create and immediately close sessions concurrently.
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Use a shorter context for the creation/work phase.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			s, err := m.NewAnalysisContext(ctx, cfg, schemas.DefaultPersona, "", "", nil)
			if assert.NoError(t, err) {
				sessionIDs <- s.ID()
				// Simulate minimal work
				time.Sleep(5 * time.Millisecond)
				s.Close(context.Background())
			}
		}()
	}
	wg.Wait()
	close(sessionIDs)

	// Verify all sessions were created and have unique IDs.
	collectedIDs := make(map[string]bool)
	for id := range sessionIDs {
		_, duplicate := collectedIDs[id]
		assert.False(t, duplicate, "Found duplicate session ID: %s", id)
		collectedIDs[id] = true
	}
	assert.Len(t, collectedIDs, concurrency, "Should have created the expected number of unique sessions")
}

// TestManager_NavigateAndExtract verifies the convenience method's correctness,
// focusing on URL resolution and temporary session cleanup.
func TestManager_NavigateAndExtract(t *testing.T) {
	// 1. Setup Mock Server with various link types.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assume the initial request is always to the root, and the response is HTML.
		fmt.Fprintln(w, `
		<html><body>
			<a href="/absolute/path">Absolute Link</a>
			<a href="relative/path">Relative Link</a>
			<a href="/?query=1">Query Link</a>
			<a href="http://external.com/link">External Link</a>
			<a href="#fragment">Fragment Link</a>
			<a href="">Empty Link</a>
		</body></html>`)
	}))
	defer server.Close()

	// 2. Setup Manager
	m, _ := setupTestManager(t)
	defer m.Shutdown(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	// 3. Execute NavigateAndExtract
	links, err := m.NavigateAndExtract(ctx, server.URL)
	require.NoError(t, err)

	// 4. Verify Results (including URL resolution against the final navigated URL)

	// The session implementation resolves the initial URL (e.g., http://127.0.0.1:1234)
	// and stores it as the base for link resolution.
	// Go's net/url ResolveReference will often append a trailing slash if the base URL doesn't have a path,
	// which affects relative links like "relative/path" vs "/absolute/path".

	// The base URL for relative link resolution is the URL of the navigated page.
	baseURL, _ := url.Parse(server.URL)

	expectedLinks := []string{
		// /absolute/path resolves to the root of the server
		baseURL.ResolveReference(&url.URL{Path: "/absolute/path"}).String(),

		// relative/path resolves against the full URL (e.g., http://host/relative/path)
		baseURL.ResolveReference(&url.URL{Path: "relative/path"}).String(),

		// /?query=1 resolves to the root path with a new query
		baseURL.ResolveReference(&url.URL{Path: "/", RawQuery: "query=1"}).String(),

		// External links remain absolute
		"http://external.com/link",

		// Fragment links resolve against the current path and append the fragment
		baseURL.ResolveReference(&url.URL{Fragment: "fragment"}).String(),

		// Empty href resolves to the current URL
		baseURL.String(),
	}

	assert.ElementsMatch(t, expectedLinks, links, "Extracted links do not match expected, particularly after URL resolution")
}

func TestManager_NavigateAndExtract_ErrorHandling(t *testing.T) {
	m, _ := setupTestManager(t)
	defer m.Shutdown(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	// Test case: Navigation fails (e.g., to a closed port/non-existent server).
	t.Run("NavigationFails", func(t *testing.T) {
		// Use a URL that won't connect.
		nonExistentURL := "http://localhost:11111/fail"

		_, err := m.NavigateAndExtract(ctx, nonExistentURL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to navigate")
	})

	// Test case: HTML Parsing Fails (Simulated by an invalid response type, though hard to truly mock)
	// NOTE: The underlying htmlquery.Parse is quite robust, so we rely on its error handling
	// or simulate an impossible scenario where the DOM snapshot is unreadable.
	t.Run("DOMParsingFails", func(t *testing.T) {
		// A direct mock is complex, but rely on the logic that errors during navigation or DOM read are bubbled up.
		// A successfully completed navigation that returns a non-HTML response should yield an empty list, not an error.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Return valid JSON, which the DOM parser will fail on (not actually parsing failure, but error check)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status": "ok"}`)
		}))
		defer server.Close()

		// Navigation succeeds, but the processResponse in session.go skips DOM parsing for non-HTML.
		// The DOM will be nil, and GetDOMSnapshot returns empty HTML, which should yield an empty link list.
		links, err := m.NavigateAndExtract(ctx, server.URL)
		require.NoError(t, err)
		assert.Empty(t, links)
	})
}

