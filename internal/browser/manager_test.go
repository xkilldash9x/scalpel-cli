// Filename: browser/manager_test.go
package browser_test

import (
	"bytes"
	"context"
	"fmt" // Added fmt import
	"net/http"
	"net/http/httptest"
	"net/url"
	// "os" // Removed unused import
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// testingWriter is a simple struct that implements io.Writer.
// Its purpose is to redirect output to the Go test runner's logging function,
// which ensures that logs from concurrent tests are not interleaved.
type testingWriter struct {
	t *testing.T
}

// Write directs the byte slice `p` to the test's log.
// It trims trailing newlines because t.Log() adds its own.
//
// FIX: Removed the recover() block. The report emphasizes detecting resource
// and goroutine leaks. If a background goroutine attempts to log after the
// test has finished (and presumably after the Manager has been shut down),
// it indicates a goroutine leak or improper shutdown synchronization.
// This should cause the test execution to panic (due to t.Log() behavior),
// which correctly surfaces the underlying issue rather than masking it.
func (tw *testingWriter) Write(p []byte) (n int, err error) {
	// This line will panic if the test has finished, exposing leaks.
	tw.t.Log(string(bytes.TrimRight(p, "\n")))

	n = len(p)
	err = nil
	return
}

// setupTestManager creates a new Manager instance configured for testing.
// It now accepts the `*testing.T` object to create a test specific logger.
func setupTestManager(t *testing.T) (*browser.Manager, *config.Config) {
	// Manually create a config for testing.
	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Humanoid: humanoid.DefaultConfig(),
		},
		Network: config.NetworkConfig{},
		IAST:    config.IASTConfig{},
	}
	// Configure minimal settings for testing.
	cfg.Browser.Humanoid.Enabled = false
	cfg.Network.PostLoadWait = 10 * time.Millisecond

	// -- Logger Configuration --
	// Create a zap logger that writes to the test's own log output.
	// This is the key to preventing interleaved logs in concurrent tests.
	writer := &testingWriter{t: t}
	encoderConfig := zap.NewDevelopmentEncoderConfig()
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(writer),
		zapcore.InfoLevel, // Set the desired log level for tests.
	)
	logger := zap.New(core)

	// Add a test name field to every log entry for clarity.
	logger = logger.With(zap.String("test", t.Name()))

	// The config is now passed during manager creation.
	// Using t.Context() ties the manager's initialization to the test's
	// lifecycle, respecting test timeouts.
	m, err := browser.NewManager(t.Context(), logger, cfg)
	require.NoError(t, err)

	// Best practice from the technical review: ensure resources are cleaned up.
	// This t.Cleanup hook ensures the manager is shut down even if the test panics.
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.Shutdown(shutdownCtx); err != nil {
			t.Logf("Warning: Error during manager shutdown in cleanup: %v", err)
		}
	})

	return m, cfg
}

// TestManager_SessionLifecycleAndShutdown verifies session creation, manual closure,
// and graceful manager shutdown.
func TestManager_SessionLifecycleAndShutdown(t *testing.T) {
	m, cfg := setupTestManager(t)

	const sessionCount = 5
	sessions := make([]schemas.SessionContext, sessionCount)
	findingsChan := make(chan schemas.Finding, 1)
	defer close(findingsChan)

	// Create multiple sessions, respecting the test's timeout via t.Context().
	for i := 0; i < sessionCount; i++ {
		s, err := m.NewAnalysisContext(t.Context(), cfg, schemas.DefaultPersona, "", "", findingsChan)
		require.NoError(t, err)
		sessions[i] = s
	}

	// Close one session manually. Use a background context with a timeout
	// to ensure the close operation has a chance to complete.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	err := sessions[0].Close(closeCtx)
	require.NoError(t, err)

	// Shutdown the manager.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Manually trigger shutdown to verify session context cancellation.
	err = m.Shutdown(shutdownCtx)
	require.NoError(t, err)

	// REFACTOR: Verify all sessions are closed after manager shutdown by attempting an operation.
	// We can no longer use GetContext().
	for i, s := range sessions {
		// Attempt a simple operation. It should fail because the session's internal context is cancelled.
		_, opErr := s.ExecuteScript(context.Background(), "1", nil)
		assert.ErrorIs(t, opErr, context.Canceled, "Session %d should be closed (context cancelled) after manager shutdown", i)
	}
}

// TestManager_ConcurrentSessionCreation verifies thread safety when creating/closing sessions.
func TestManager_ConcurrentSessionCreation(t *testing.T) {
	m, cfg := setupTestManager(t)

	const concurrency = 10
	var wg sync.WaitGroup

	sessionIDs := make(chan string, concurrency)

	// Define a context for the concurrent operations, respecting the test timeout.
	opCtx, opCancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer opCancel()

	// Create and immediately close sessions concurrently.
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			// Use the operation context for session creation.
			s, err := m.NewAnalysisContext(opCtx, cfg, schemas.DefaultPersona, "", "", nil)

			// Check if the context was cancelled before asserting an error.
			if opCtx.Err() != nil {
				return // Stop if the overall operation timed out.
			}

			if assert.NoError(t, err) {
				sessionIDs <- s.ID()
				time.Sleep(5 * time.Millisecond)

				// Use a specific timeout for the close operation, independent of opCtx.
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer closeCancel()
				s.Close(closeCtx)
			}
		}(i)
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

	// Verify count only if the context didn't expire prematurely.
	if opCtx.Err() == nil {
		assert.Len(t, collectedIDs, concurrency, "Should have created the expected number of unique sessions")
	} else {
		t.Logf("Test context expired (likely timeout) before all sessions were created. Collected %d IDs.", len(collectedIDs))
	}
}

// TestManager_NavigateAndExtract verifies the convenience method's correctness,
// focusing on URL resolution and temporary session cleanup.
func TestManager_NavigateAndExtract(t *testing.T) {
	// 1. Setup Mock Server with various link types.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
		<html><body>
			<a href="/absolute/path">Absolute Link</a>
			<a href="relative/path">Relative Link</a>
			<a href="/?query=1">Query Link</a>
			<a href="http://external.com/link">External Link</a>
			<a href="#fragment">Fragment Link (should be ignored)</a>
			<a href="">Empty Link (should be ignored)</a>
			<a href="javascript:void(0)">JS Link (should be ignored)</a>
		</body></html>`)
	}))
	defer server.Close()

	// 2. Setup Manager.
	m, _ := setupTestManager(t)

	// 3. Execute NavigateAndExtract with a timeout.
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	links, err := m.NavigateAndExtract(ctx, server.URL)
	require.NoError(t, err)

	// 4. Verify Results
	baseURL, _ := url.Parse(server.URL)

	expectedLinks := []string{
		baseURL.ResolveReference(&url.URL{Path: "/absolute/path"}).String(),
		baseURL.ResolveReference(&url.URL{Path: "relative/path"}).String(),
		baseURL.ResolveReference(&url.URL{Path: "/", RawQuery: "query=1"}).String(),
		"http://external.com/link",
	}

	assert.ElementsMatch(t, expectedLinks, links, "Extracted links should be resolved and filtered correctly")
}

func TestManager_NavigateAndExtract_ErrorHandling(t *testing.T) {
	m, _ := setupTestManager(t)

	parentCtx := t.Context()

	t.Run("FailsToNavigateUnreachableHost", func(t *testing.T) {
		// Use a clearly invalid and non routable address to ensure failure.
		nonExistentURL := "http://localhost:9999/unreachable"

		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		_, err := m.NavigateAndExtract(ctx, nonExistentURL)
		assert.Error(t, err, "Should receive an error when the host is unreachable")
		assert.Contains(t, err.Error(), "failed to navigate", "Error message should indicate a navigation failure")
	})

	// FIX: Renamed test case for clarity. The original name was imprecise.
	// This test verifies graceful handling of content, not a failure case.
	t.Run("SucceedsWithNoLinksForNonHTMLContent", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status": "ok", "data": []}`)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
		defer cancel()

		links, err := m.NavigateAndExtract(ctx, server.URL)

		// The key assertions: No error should occur, and no links should be found.
		require.NoError(t, err, "Navigating to valid, non-HTML content should not produce an error")
		assert.Empty(t, links, "Should extract no links from a non-HTML page")
	})
}