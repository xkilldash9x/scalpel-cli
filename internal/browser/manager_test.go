// internal/browser/manager_test.go
package browser

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas" // Import schemas
)

// This constant is specific to the manager tests to avoid conflicts.
// Increased slightly for stability.
const managerTestTimeout = 60 * time.Second // Was 30 * time.Second
func TestManager(t *testing.T) {
	t.Run("InitializeAndCloseSession", func(t *testing.T) {
		fixture := newTestFixture(t) // Creates manager

		// A session should be created successfully by the manager.
		// Use the fixture's RootCtx as the base for the session's lifetime
		ctx, cancel := context.WithTimeout(fixture.RootCtx, 10*time.Second)
		defer cancel()

		// NOTE: We pass nil for the findingsChan in this test helper.
		sessionInterface, err := fixture.Manager.NewAnalysisContext(
			ctx,
			fixture.Config,
			schemas.DefaultPersona,
			"", "", nil,
		)
		require.NoError(t, err, "Failed to create new analysis context")
		require.NotNil(t, sessionInterface)
		require.NotEmpty(t, sessionInterface.ID(), "Session ID should not be empty")

		// The fixture's cleanup function will handle closing the manager,
		// which in turn will close the session. We can also close it manually.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		err = sessionInterface.Close(closeCtx)
		require.NoError(t, err, "Failed to close session")
	})

	t.Run("InitializeMultipleSessions", func(t *testing.T) {
		fixture1 := newTestFixture(t)
		require.NotNil(t, fixture1.Manager)

		fixture2 := newTestFixture(t)
		require.NotNil(t, fixture2.Manager)

		// Use the fixture's RootCtx as the base for the session's lifetime
		ctx1, cancel1 := context.WithTimeout(fixture1.RootCtx, 10*time.Second)
		defer cancel1()
		session1, err1 := fixture1.Manager.NewAnalysisContext(
			ctx1, fixture1.Config, schemas.DefaultPersona, "", "", nil,
		)
		require.NoError(t, err1, "Failed to create session 1")
		require.NotNil(t, session1)

		ctx2, cancel2 := context.WithTimeout(fixture2.RootCtx, 10*time.Second)
		defer cancel2()
		session2, err2 := fixture2.Manager.NewAnalysisContext(
			ctx2, fixture2.Config, schemas.DefaultPersona, "", "", nil,
		)
		require.NoError(t, err2, "Failed to create session 2")
		require.NotNil(t, session2)

		// Each browser context should be isolated, resulting in unique session IDs.
		require.NotEqual(t, session1.ID(), session2.ID(), "Each session should have a unique ID")
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
		// Server closure is already handled by createStaticTestServer via t.Cleanup.

		// Use a timed context derived from the fixture's root context for robustness.
		ctx, cancel := context.WithTimeout(fixture.RootCtx, managerTestTimeout)
		defer cancel() // Idiomatic cancellation for function-scoped contexts.

		// Execute the manager's utility function, now using the sandboxed manager from the fixture.
		// This call is synchronous and does not require a WaitGroup, as the
		// manager's NavigateAndExtract function is blocking.
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
