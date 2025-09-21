// internal/browser/manager_test.go
package browser

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This constant is specific to the manager tests to avoid conflicts.
// Increased slightly for stability.
const managerTestTimeout = 30 * time.Second

func TestManager(t *testing.T) {
	t.Run("InitializeAndCloseSession", func(t *testing.T) {
		fixture := newTestFixture(t)

		// A session should be created successfully by the fixture.
		require.NotNil(t, fixture.Session)
		require.NotEmpty(t, fixture.Session.ID(), "Session ID should not be empty")

		// The fixture's cleanup function will handle closing the session.
	})

	t.Run("InitializeMultipleSessions", func(t *testing.T) {
		fixture1 := newTestFixture(t)
		require.NotNil(t, fixture1.Session)

		fixture2 := newTestFixture(t)
		require.NotNil(t, fixture2.Session)

		// Each browser context should be isolated, resulting in unique session IDs.
		require.NotEqual(t, fixture1.Session.ID(), fixture2.Session.ID(), "Each session should have a unique ID")
	})

	t.Run("NavigateAndExtract", func(t *testing.T) {
		fixture := newTestFixture(t)
		// This is a more comprehensive integration test that validates the manager's
		// ability to handle a complete, self contained task.
		server := createStaticTestServer(t, `
                    <html>
                        <body>
                            <a href="/page1">Link 1</a>
                            <a href="http://sub.example.com/page2">Link 2</a>
                            <a href="#fragment">Fragment Link</a>
                            <a href="/page1">Duplicate Link</a>
                            <a>Link without href</a>
                        </body>
                    </html>
                `)
		t.Cleanup(server.Close)

		// Use a timed context to make the test robust.
		ctx, cancel := context.WithTimeout(context.Background(), managerTestTimeout)
		t.Cleanup(cancel)

		// Execute the manager's utility function, now using the sandboxed manager from the fixture.
		extractedHrefs, err := fixture.Manager.NavigateAndExtract(ctx, server.URL)
		require.NoError(t, err)

		// The extracted hrefs might be relative. We need to resolve them against
		// the base URL of our test server to perform a reliable comparison.
		base, err := url.Parse(server.URL)
		require.NoError(t, err)

		absHrefs := make([]string, 0, len(extractedHrefs))
		for _, href := range extractedHrefs {
			ref, err := url.Parse(href)
			if err == nil {
				absHrefs = append(absHrefs, base.ResolveReference(ref).String())
			}
		}

		// The expected links, resolved to their absolute URLs.
		expectedHrefs := []string{
			base.ResolveReference(&url.URL{Path: "/page1"}).String(),
			"http://sub.example.com/page2",
			base.ResolveReference(&url.URL{Fragment: "fragment"}).String(),
			base.ResolveReference(&url.URL{Path: "/page1"}).String(), // The duplicate
		}

		// Use ElementsMatch because the order of extracted links is not guaranteed.
		assert.ElementsMatch(t, expectedHrefs, absHrefs, "Extracted links do not match expected links")
	})
}
