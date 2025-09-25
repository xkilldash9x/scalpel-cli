// internal/browser/manager_test.go
package browser

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

const managerTestTimeout = 60 * time.Second

func TestManager(t *testing.T) {
	// Ensure the global manager is initialized before running tests.
	if suiteManagerErr != nil {
		t.Fatalf("Skipping Manager tests due to initialization failure: %v", suiteManagerErr)
	}

	t.Run("InitializeAndCloseSession", func(t *testing.T) {
		// This test validates the fixture setup itself.
		fixture := newTestFixture(t)

		require.NotNil(t, fixture.Session)
		require.NotEmpty(t, fixture.Session.ID(), "Session ID should not be empty")

		// Verify the session is usable.
		assert.NotNil(t, fixture.Session.page, "Session page should be initialized")
		assert.False(t, fixture.Session.page.IsClosed(), "Session page should be open")
	})

	t.Run("InitializeMultipleSessionsConcurrently", func(t *testing.T) {
		// Test the manager's ability to handle concurrent session creation and ensure isolation.
		manager := suiteManager
		logger := suiteLogger

		const sessionCount = 3
		sessions := make(chan *Session, sessionCount)
		errs := make(chan error, sessionCount)

		ctx, cancel := context.WithTimeout(context.Background(), managerTestTimeout)
		defer cancel()

		// Create sessions concurrently.
		for i := 0; i < sessionCount; i++ {
			go func() {
				findingsChan := make(chan schemas.Finding, 1)
				defer close(findingsChan)

				sessionInterface, err := manager.NewAnalysisContext(
					ctx,
					suiteConfig,
					schemas.DefaultPersona,
					"",
					"",
					findingsChan,
				)
				if err != nil {
					errs <- err
					return
				}
				session, ok := sessionInterface.(*Session)
				if !ok {
					errs <- fmt.Errorf("invalid session type")
					return
				}
				sessions <- session
			}()
		}

		// Collect results.
		createdSessions := []*Session{}
		for i := 0; i < sessionCount; i++ {
			select {
			case s := <-sessions:
				createdSessions = append(createdSessions, s)
			case err := <-errs:
				t.Fatalf("Failed to create session concurrently: %v", err)
			case <-ctx.Done():
				t.Fatalf("Timeout waiting for sessions to be created: %v", ctx.Err())
			}
		}

		require.Len(t, createdSessions, sessionCount)

		// Verify uniqueness (isolation).
		sessionIDs := map[string]bool{}
		for _, s := range createdSessions {
			sessionIDs[s.ID()] = true
		}
		assert.Len(t, sessionIDs, sessionCount, "Session IDs should be unique")

		// Clean up.
		for _, s := range createdSessions {
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := s.Close(closeCtx); err != nil {
				logger.Warn("Error closing session during cleanup.", zap.Error(err))
			}
			closeCancel()
		}
	})

	t.Run("NavigateAndExtract", func(t *testing.T) {
		// Test the utility function that manages its own temporary session.
		manager := suiteManager

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

		ctx, cancel := context.WithTimeout(context.Background(), managerTestTimeout)
		t.Cleanup(cancel)

		extractedHrefs, err := manager.NavigateAndExtract(ctx, server.URL)
		require.NoError(t, err)

		// The extraction script returns absolute URLs.
		base, err := url.Parse(server.URL)
		require.NoError(t, err)

		expectedHrefs := []string{
			base.ResolveReference(&url.URL{Path: "/page1"}).String(),
			"http://sub.example.com/page2",
			base.ResolveReference(&url.URL{Fragment: "fragment"}).String(),
			base.ResolveReference(&url.URL{Path: "/page1"}).String(), // The duplicate
		}

		// Use ElementsMatch as order is not guaranteed.
		assert.ElementsMatch(t, expectedHrefs, extractedHrefs, "Extracted links do not match expected links")
	})
}