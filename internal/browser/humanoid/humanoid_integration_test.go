// File: internal/browser/humanoid/humanoid_integration_test.go
package humanoid_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/session"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// =============================================================================
// Test Infrastructure
// =============================================================================

// assertContextCancellation is a helper to verify that an error is due to context cancellation.
func assertContextCancellation(t *testing.T, err error) {
	require.Error(t, err, "Action should have been interrupted and returned an error")
	// Check for the specific context cancellation errors.
	isCanceled := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	assert.True(t, isCanceled, "Expected context.Canceled or context.DeadlineExceeded, but got: %v", err)
}

// setupSessionTestEnvironment initializes a real browser session and a test server.
// The session itself serves as the humanoid.Executor.
// internal/browser/humanoid/humanoid_integration_test.go

// setupSessionTestEnvironment initializes a real browser session and a test server.
// The session itself serves as the humanoid.Executor.
func setupSessionTestEnvironment(t *testing.T) (context.Context, *session.Session, *httptest.Server) {
	t.Helper()

	// -- Create a default configuration and modify it for the test --
	cfg := config.NewDefaultConfig()

	// Ensure humanoid is active and speed up tests by reducing delays.
	cfg.SetBrowserHumanoidEnabled(true)
	// Use the standardized setter name for the new Ex-Gaussian model.
	cfg.SetBrowserHumanoidKeyHoldMu(5.0)
	cfg.SetBrowserHumanoidClickHoldMinMs(5)
	cfg.SetBrowserHumanoidClickHoldMaxMs(15)
	cfg.SetNetworkPostLoadWait(50 * time.Millisecond)

	logger := zap.NewNop()
	findingsChan := make(chan schemas.Finding, 10)

	// -- Create the test HTTP server --
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
			            <html>
			                <head>
			                    <style>
			                        /* Basic styles to ensure elements have dimensions */
			                        #target { width: 100px; height: 100px; background: blue; margin-top: 50px; }
			                        #inputField { width: 200px; height: 20px; margin-top: 20px; display: inline-block; }
			                    </style>
			                </head>
			                <body>
			                    <h1>Humanoid Integration Test</h1>
			                    <div id='target'>Target Box</div>
			                    <input id="inputField" type="text" />
			                </body>
			            </html>
			        `)
	}))
	t.Cleanup(server.Close) // Close server on cleanup

	// -- Set up headless browser --
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(
		context.Background(),
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
		)...,
	)
	t.Cleanup(cancelAlloc)

	// -- Create the master session context --
	masterCtx, masterCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(t.Logf))
	// Note: masterCancel is called by sess.Close(), so we don't add it to t.Cleanup separately.

	// -- Create the session --
	// This session will act as our executor, bridging humanoid actions to our browser engine.
	sess, err := session.NewSession(
		masterCtx,    // Pass the master browser context
		masterCancel, // Pass its cancel function
		cfg,
		schemas.DefaultPersona,
		logger,
		nil, // onClose callback (not needed for this test)
		findingsChan,
	)
	require.NoError(t, err, "Failed to create a new session")

	// -- Setup cleanup function for the session --
	t.Cleanup(func() {
		if err := sess.Close(context.Background()); err != nil {
			t.Logf("Error closing session during cleanup: %v", err)
		}
		close(findingsChan)
	})

	// -- Navigate the session to the test server --
	// We use an operational context (can be masterCtx or a derived one)
	err = sess.Initialize(masterCtx, "", "") // Pass empty taint strings
	require.NoError(t, err, "Session failed to initialize")
	err = sess.Navigate(masterCtx, server.URL)
	require.NoError(t, err, "Session could not navigate to the test server")

	return masterCtx, sess, server
}

// TestContextCancellation_DuringMovement verifies that a MoveTo operation
// can be correctly interrupted by context cancellation.
func TestContextCancellation_DuringMovement(t *testing.T) {
	t.Parallel()
	ctx, sess, _ := setupSessionTestEnvironment(t) // sess is now the executor
	h := humanoid.NewTestHumanoid(sess, 12345)     // Pass the session directly

	// Create a new context that we can cancel independently for the action.
	actionCtx, actionCancel := context.WithCancel(ctx)
	errChan := make(chan error, 1)

	go func() {
		// The humanoid will use the session's GetElementGeometry, Sleep, etc.
		// FIX: Use CSS selector
		errChan <- h.MoveTo(actionCtx, "#target", nil)
	}()

	// Give the MoveTo operation a moment to start.
	time.Sleep(100 * time.Millisecond)
	actionCancel() // Cancel the operation.

	// Wait for the error from the cancelled operation.
	select {
	case err := <-errChan:
		assertContextCancellation(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out waiting for the MoveTo action to return after cancellation.")
	}
}

// TestContextCancellation_DuringTyping verifies that a long Type operation
// respects context cancellation.
func TestContextCancellation_DuringTyping(t *testing.T) {
	t.Parallel()
	ctx, sess, _ := setupSessionTestEnvironment(t) // sess is now the executor
	h := humanoid.NewTestHumanoid(sess, 12345)     // Pass the session directly

	actionCtx, actionCancel := context.WithCancel(ctx)
	errChan := make(chan error, 1)

	go func() {
		// A long string ensures the typing action is in progress when we cancel it.
		longSentence := "This is a very long sentence designed to take a significant amount of time to type, ensuring we can cancel it mid-operation."
		// FIX: Use CSS selector
		errChan <- h.Type(actionCtx, "#inputField", longSentence, nil)
	}()

	// Allow the typing to get started.
	time.Sleep(200 * time.Millisecond)
	actionCancel() // Cancel the operation.
	select {
	case err := <-errChan:
		assertContextCancellation(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out waiting for the Type action to return after cancellation.")
	}
}

// =============================================================================
// NEW: Concurrent Safety Validation Test
// =============================================================================

// TestConcurrentActions_OnSingleSession verifies that the executor (Session)
// can safely handle multiple concurrent actions without data races.
// This test is specifically designed to be run with the Go race detector enabled
// (`go test -race ./...`) to validate the concurrent-safe VM Pool architecture.
func TestConcurrentActions_OnSingleSession(t *testing.T) {
	ctx, sess, _ := setupSessionTestEnvironment(t)
	h := humanoid.NewTestHumanoid(sess, 12345)

	var wg sync.WaitGroup
	actionCount := 10 // Fire 10 actions concurrently to stress the pool.
	wg.Add(actionCount)

	for i := 0; i < actionCount; i++ {
		go func() {
			defer wg.Done()
			// Each goroutine performs an action using the SAME humanoid instance,
			// which in turn uses the SAME session. This directly tests the
			// concurrent safety of the underlying executor implementation.
			// FIX: Use CSS selector
			err := h.MoveTo(ctx, "#target", nil)
			// A nil error here confirms the action could complete.
			// The race detector confirms it did so safely.
			assert.NoError(t, err)
		}()
	}

	// Wait for all concurrent move actions to complete.
	wg.Wait()
}
