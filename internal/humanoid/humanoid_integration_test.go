// Filename: internal/humanoid/humanoid_integration_test.go
package humanoid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test Infrastructure: Playwright Executor Adapter (The New Translator)
// =============================================================================

// playwrightExecutor implements the agnostic Executor interface using a real Playwright page.
// This adapter translates the agnostic Humanoid commands into specific Playwright actions.
type playwrightExecutor struct {
	page playwright.Page
}

// DispatchMouseEvent translates agnostic MouseEventData to a Playwright command.
func (e *playwrightExecutor) DispatchMouseEvent(ctx context.Context, data MouseEventData) error {
	switch data.Type {
	case MouseMove:
		err := e.page.Mouse().Move(data.X, data.Y)
		return err
	case MousePress:
		btn := playwright.MouseButton(data.Button)
		return e.page.Mouse().Down(playwright.MouseDownOptions{
			Button:     &btn,
			ClickCount: playwright.Int(data.ClickCount),
		})
	case MouseRelease:
		btn := playwright.MouseButton(data.Button)
		return e.page.Mouse().Up(playwright.MouseUpOptions{
			Button:     &btn,
			ClickCount: playwright.Int(data.ClickCount),
		})
	case MouseWheel:
		return e.page.Mouse().Wheel(data.DeltaX, data.DeltaY)
	}
	return fmt.Errorf("playwrightExecutor: unsupported mouse event type: %s", data.Type)
}

// SendKeys translates an agnostic keys string to a playwright.Keyboard.Type action.
func (e *playwrightExecutor) SendKeys(ctx context.Context, keys string) error {
	// The contract is that the element is already focused, so we just type.
	return e.page.Keyboard().Type(keys)
}

// Sleep uses a standard Go context-aware sleep.
func (e *playwrightExecutor) Sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetElementGeometry translates the agnostic call to a series of Playwright actions.
func (e *playwrightExecutor) GetElementGeometry(ctx context.Context, selector string) (*ElementGeometry, error) {
	element, err := e.page.WaitForSelector(selector, playwright.PageWaitForSelectorOptions{
		State: playwright.WaitForSelectorStateVisible,
	})
	if err != nil {
		return nil, err
	}

	box, err := element.BoundingBox()
	if err != nil {
		return nil, err
	}
	if box == nil {
		return nil, fmt.Errorf("playwrightExecutor: failed to get bounding box for selector: %s", selector)
	}

	// Translate Playwright BoundingBox to agnostic ElementGeometry.
	return &ElementGeometry{
		Vertices: []float64{
			box.X, box.Y,
			box.X + box.Width, box.Y,
			box.X + box.Width, box.Y + box.Height,
			box.X, box.Y + box.Height,
		},
		Width:  int64(box.Width),
		Height: int64(box.Height),
	}, nil
}

// ExecuteScript translates the agnostic script execution call to a page.Evaluate command.
func (e *playwrightExecutor) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	// Playwright's Evaluate handles promises automatically and returns the final value.
	result, err := e.page.Evaluate(script, args)
	if err != nil {
		return nil, err
	}

	// The result from Evaluate is already deserialized, so we just need to marshal it
	// back to JSON to fit the interface contract.
	return json.Marshal(result)
}

// =============================================================================
// Test Infrastructure: Helpers and Setup (Refactored for Playwright)
// =============================================================================

// assertContextCancellation is unchanged as its logic is generic.
func assertContextCancellation(t *testing.T, err error) {
	require.Error(t, err, "Action should have been interrupted and returned an error")
	isCanceled := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	assert.True(t, isCanceled, "Expected context.Canceled or context.DeadlineExceeded, but got: %v", err)
}

func setupTestEnvironment(t *testing.T) (context.Context, playwright.Page, *httptest.Server) {
	// Initialize Playwright
	pw, err := playwright.Run()
	require.NoError(t, err, "could not start playwright")

	// Launch a browser
	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	require.NoError(t, err, "could not launch browser")

	// Create a new page
	page, err := browser.NewPage()
	require.NoError(t, err, "could not create page")

	// Create the test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `
			<html><body>
				<h1>Test Page</h1>
				<div id='target' style='width:100px;height:100px;background:red;margin-top:50px;'>Target</div>
				<div id='dragSource' style='width:50px;height:50px;background:blue;'>Drag Me</div>
				<input id="inputField" type="text" />
			</body></html>
		`)
	}))

	// Navigate to the test server
	_, err = page.Goto(server.URL)
	require.NoError(t, err, "could not navigate to test server")

	// Setup cleanup function
	t.Cleanup(func() {
		server.Close()
		if err := browser.Close(); err != nil {
			t.Logf("could not close browser: %v", err)
		}
		if err := pw.Stop(); err != nil {
			t.Logf("could not stop playwright: %v", err)
		}
	})

	return context.Background(), page, server
}

// =============================================================================
// Integration Tests (Largely Unchanged Logic)
// =============================================================================

func TestContextCancellation_DuringMovement(t *testing.T) {
	t.Parallel()
	ctx, page, _ := setupTestEnvironment(t)
	h := newTestHumanoid(&playwrightExecutor{page: page})

	actionCtx, actionCancel := context.WithCancel(ctx)
	errChan := make(chan error, 1)
	go func() {
		errChan <- h.MoveTo(actionCtx, "#target", nil)
	}()

	time.Sleep(100 * time.Millisecond)
	actionCancel()

	select {
	case err := <-errChan:
		assertContextCancellation(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out waiting for movement action to return after cancellation.")
	}
}

func TestContextCancellation_DuringTyping(t *testing.T) {
	t.Parallel()
	ctx, page, _ := setupTestEnvironment(t)
	h := newTestHumanoid(&playwrightExecutor{page: page})

	actionCtx, actionCancel := context.WithCancel(ctx)
	errChan := make(chan error, 1)
	go func() {
		// Use a long string to ensure typing is in progress when cancelled.
		errChan <- h.Type(actionCtx, "#inputField", "This is a very long sentence that should take some time to type completely.")
	}()

	time.Sleep(300 * time.Millisecond)
	actionCancel()

	select {
	case err := <-errChan:
		assertContextCancellation(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Test timed out waiting for typing action to return after cancellation.")
	}
}