// Filename: internal/humanoid/humanoid_integration_test.go
package humanoid

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test Infrastructure: Helpers
// =============================================================================

// NOTE: The 'newTestHumanoid' function has been removed from this file.
// It is now assumed to exist in another file within the same package,
// such as 'trajectory_test.go', which will be compiled along with this test.

// assertContextCancellation checks if the error is a cancellation error and ensures it is NOT an "invalid context" error.
func assertContextCancellation(t *testing.T, err error) {
	assert.Error(t, err, "Action should have been interrupted and returned an error")

	if err == nil {
		return
	}

	// Crucial check: Ensure the error is context.Canceled or context.DeadlineExceeded.
	isCanceled := err == context.Canceled || err == context.DeadlineExceeded ||
		strings.Contains(err.Error(), context.Canceled.Error()) ||
		strings.Contains(err.Error(), context.DeadlineExceeded.Error())

	assert.True(t, isCanceled, "Expected context.Canceled or context.DeadlineExceeded, but got: %v", err)

	// Explicitly check against the error we want to avoid.
	if strings.Contains(err.Error(), "invalid context") || strings.Contains(err.Error(), "execution context was destroyed") {
		t.Errorf("CRITICAL: Received 'invalid context' related error. This indicates the module might have attempted to execute a command after context closure. Error: %v", err)
	}
}

// =============================================================================
// Integration Test Setup
// =============================================================================

// setupTestEnvironment initializes a real Chromedp context and an httptest server.
func setupTestEnvironment(t *testing.T) (context.Context, *httptest.Server) {
	// 1. Configure Chromedp (headless mode).
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancelCtx := chromedp.NewContext(allocCtx)

	// 2. Setup httptest server.
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Default HTML content.
		fmt.Fprintln(w, `
			<html><body>
				<h1>Test Page</h1>
				<div id='target' style='width:100px;height:100px;background:red;margin-top:50px;'>Target</div>
				<div id='dragSource' style='width:50px;height:50px;background:blue;'>Drag Me</div>
				<input id="inputField" type="text" />
			</body></html>
		`)
	}))

	// 3. Ensure cleanup.
	t.Cleanup(func() {
		server.Close()
		// Give a moment (50ms) for pending CDP commands to finalize before closing the context.
		// This helps prevent "context canceled" errors during shutdown from polluting the test results.
		time.Sleep(50 * time.Millisecond)
		cancelCtx()
		allocCancel()
	})

	// 4. Navigate to the test server URL.
	err := chromedp.Run(ctx, chromedp.Navigate(server.URL))
	require.NoError(t, err)

	return ctx, server
}

// =============================================================================
// Context Cancellation Tests
// =============================================================================

// TestContextCancellation_DuringMovement verifies that a cancellation mid-movement is handled gracefully.
func TestContextCancellation_DuringMovement(t *testing.T) {
	t.Parallel()
	ctx, _ := setupTestEnvironment(t)
	h := newTestHumanoid()

	actionCtx, actionCancel := context.WithCancel(ctx)

	// Start the movement action in a separate goroutine.
	errChan := make(chan error, 1)
	go func() {
		// Move towards the target. This involves trajectory simulation with many sleeps and mouse events.
		errChan <- h.MoveTo("#target", nil).Do(actionCtx)
	}()

	// Wait briefly to allow the movement simulation to start.
	time.Sleep(100 * time.Millisecond)

	// Cancel the context mid-action.
	actionCancel()

	// Wait for the action to return and check the error.
	select {
	case err := <-errChan:
		assertContextCancellation(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out waiting for movement action to return after cancellation.")
	}
}

// TestContextCancellation_DuringTyping verifies cancellation during a long typing sequence.
func TestContextCancellation_DuringTyping(t *testing.T) {
	t.Parallel()
	ctx, _ := setupTestEnvironment(t)
	h := newTestHumanoid()

	actionCtx, actionCancel := context.WithCancel(ctx)

	errChan := make(chan error, 1)
	go func() {
		// Type a long string.
		errChan <- h.Type("#inputField", "This is a very long sentence that should take some time to type completely.").Do(actionCtx)
	}()

	// Wait for typing to start (includes the initial click and pause).
	time.Sleep(300 * time.Millisecond)

	// Cancel mid-typing.
	actionCancel()

	// Check the result.
	select {
	case err := <-errChan:
		assertContextCancellation(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out waiting for typing action to return after cancellation.")
	}
}

// TestContextCancellation_DuringPause verifies that long pauses (Hesitate) respect cancellation.
func TestContextCancellation_DuringPause(t *testing.T) {
	t.Parallel()
	ctx, _ := setupTestEnvironment(t)
	h := newTestHumanoid()

	actionCtx, actionCancel := context.WithCancel(ctx)

	errChan := make(chan error, 1)
	go func() {
		// A very long pause (5 seconds mean). This uses Hesitate internally.
		errChan <- h.CognitivePause(5000, 100).Do(actionCtx)
	}()

	// Wait briefly for the pause/hesitation loop to start.
	time.Sleep(50 * time.Millisecond)

	// Cancel during the pause.
	actionCancel()

	// Check the result.
	select {
	case err := <-errChan:
		assertContextCancellation(t, err)
	case <-time.After(2 * time.Second):
		// Should return almost immediately after cancellation.
		t.Fatal("Test timed out waiting for CognitivePause to return after cancellation.")
	}
}

// TestContextCancellation_DuringScroll verifies cancellation during complex scrolling behavior.
func TestContextCancellation_DuringScroll(t *testing.T) {
	t.Parallel()
	ctx, server := setupTestEnvironment(t)
	h := newTestHumanoid()

	// Setup a page that requires significant scrolling using JS evaluation on the existing page.
	longContent := strings.Repeat("<div>Scrollable content line...</div>", 300)
	// We use JS to inject the content safely.
	jsInject := fmt.Sprintf(`
        document.body.innerHTML = '%s<div id="bottomTarget" style="background: green;">Bottom</div>';
    `, longContent)

	err := chromedp.Run(ctx,
		chromedp.Navigate(server.URL), // Ensure we are on the correct origin
		chromedp.Evaluate(jsInject, nil),
	)
	require.NoError(t, err)

	actionCtx, actionCancel := context.WithCancel(ctx)

	errChan := make(chan error, 1)
	go func() {
		// The intelligentScroll (which involves iterative JS execution and pauses) is called internally by MoveTo.
		errChan <- h.MoveTo("#bottomTarget", nil).Do(actionCtx)
	}()

	// Wait for the scrolling logic to engage.
	time.Sleep(150 * time.Millisecond)

	// Cancel during the scroll phase.
	actionCancel()

	// Check the result.
	select {
	case err := <-errChan:
		// The error might occur during JS execution or during a pause.
		assertContextCancellation(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out waiting for MoveTo (scroll) to return after cancellation.")
	}
}

// TestContextCancellation_DuringDragAndDrop verifies cancellation during a drag operation.
func TestContextCancellation_DuringDragAndDrop(t *testing.T) {
	t.Parallel()
	ctx, _ := setupTestEnvironment(t)
	h := newTestHumanoid()

	// Uses #dragSource and #target defined in setupTestEnvironment.

	actionCtx, actionCancel := context.WithCancel(ctx)

	errChan := make(chan error, 1)
	go func() {
		errChan <- h.DragAndDrop("#dragSource", "#target").Do(actionCtx)
	}()

	// Wait for the drag to initiate (MoveTo source, MouseDown, pauses, start MoveTo target).
	// This requires waiting longer as several actions happen before the main drag movement.
	time.Sleep(400 * time.Millisecond)

	// Cancel during the drag movement.
	actionCancel()

	// Check the result.
	select {
	case err := <-errChan:
		assertContextCancellation(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out waiting for DragAndDrop to return after cancellation.")
	}
}

// =============================================================================
// Robustness and Stress Tests
// =============================================================================

// TestErrorHandling_ElementNotFound ensures actions fail fast if the element is missing.
func TestErrorHandling_ElementNotFound(t *testing.T) {
	t.Parallel()
	ctx, _ := setupTestEnvironment(t)
	h := newTestHumanoid()

	// Use a short timeout context to verify it fails fast.
	shortCtx, shortCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer shortCancel()

	startTime := time.Now()
	// Attempt to move to a selector that does not exist.
	err := h.MoveTo("#nonExistentElement", nil).Do(shortCtx)
	duration := time.Since(startTime)

	assert.Error(t, err)
	// It should fail around the timeout duration, not significantly longer.
	assert.Less(t, duration, 1*time.Second, "Element not found should fail relatively quickly based on the context timeout.")

	// The specific error returned by chromedp.WaitVisible when timing out is context.DeadlineExceeded.
	assertContextCancellation(t, err)
}

// TestContextStress_RapidFire tests rapid sequences of actions with aggressive cancellation.
// This test is specifically designed to provoke the "invalid context" error if the module handles context closure poorly.
func TestContextStress_RapidFire(t *testing.T) {
	// Do not run in parallel due to high intensity.
	ctx, _ := setupTestEnvironment(t)
	h := newTestHumanoid()

	iterations := 30
	// We use a very short timeout to ensure actions are frequently interrupted.
	actionTimeout := 80 * time.Millisecond

	for i := 0; i < iterations; i++ {
		t.Run(fmt.Sprintf("Iteration_%d", i), func(t *testing.T) {
			// Create a specific context for this action sequence.
			actionCtx, cancelAction := context.WithTimeout(ctx, actionTimeout)
			defer cancelAction()

			// Execute a complex sequence of actions.
			err := chromedp.Run(actionCtx,
				// Movement will likely be interrupted.
				h.MoveTo("#inputField", nil),
				// Typing will likely not even start or be interrupted quickly.
				h.Type("#inputField", "This text is long and will be cut off."),
			)

			// Verification:
			if err == nil {
				// If it succeeded, the timeout was long enough (which is fine).
				return
			}

			// The error MUST be a cancellation/timeout error, OR another acceptable failure (like element not interactable).
			// It MUST NOT be "invalid context".

			isCanceled := err == context.DeadlineExceeded || err == context.Canceled ||
				strings.Contains(err.Error(), context.Canceled.Error()) ||
				strings.Contains(err.Error(), context.DeadlineExceeded.Error())

			if !isCanceled {
				// Check for the specific error we are trying to avoid.
				if strings.Contains(err.Error(), "invalid context") || strings.Contains(err.Error(), "execution context was destroyed") {
					t.Errorf("CRITICAL: Received 'invalid context' error. This indicates the module attempted to execute a command after context closure. Error: %v", err)
				} else {
					// Other errors are acceptable failures in a stress test.
					t.Logf("Action failed with an acceptable error other than timeout: %v", err)
				}
			}
		})
	}
}

