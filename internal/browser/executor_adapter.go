package browser

import (
	"context"
	"encoding/json"
	"errors" // Import added
	"fmt"
	"time"

	"github.com/playwright-community/playwright-go"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// PlaywrightExecutorAdapter implements the humanoid.Executor interface using Playwright via the Session.
// This adapter decouples the humanoid logic from the specific Playwright implementation details,
// ensuring the core interaction engine remains browser agnostic.
type PlaywrightExecutorAdapter struct {
	session *Session
}

// NewPlaywrightExecutorAdapter creates a new adapter wrapping the browser session.
func NewPlaywrightExecutorAdapter(session *Session) *PlaywrightExecutorAdapter {
	return &PlaywrightExecutorAdapter{
		session: session,
	}
}

// Ensure implementation compliance at compile time. This acts as a safeguard
// to make sure PlaywrightExecutorAdapter always satisfies the humanoid.Executor interface.
var _ humanoid.Executor = (*PlaywrightExecutorAdapter)(nil)

// Sleep implements humanoid.Executor. It provides a context aware sleep mechanism.
func (a *PlaywrightExecutorAdapter) Sleep(ctx context.Context, d time.Duration) error {
	if a.session == nil {
		return fmt.Errorf("adapter session is nil")
	}
	// Use CombineContext to respect both the specific operation deadline and the overall session lifecycle.
	// This ensures the sleep can be interrupted if the overarching task context is cancelled.
	opCtx, opCancel := CombineContext(a.session.ctx, ctx)
	defer opCancel()

	select {
	case <-time.After(d):
		// Sleep completed successfully.
		return nil
	case <-opCtx.Done():
		// Context was cancelled or timed out.
		return opCtx.Err()
	}
}

// DispatchMouseEvent implements humanoid.Executor. It converts agnostic MouseEventData to Playwright calls.
func (a *PlaywrightExecutorAdapter) DispatchMouseEvent(ctx context.Context, data humanoid.MouseEventData) error {
	if a.session == nil || a.session.page == nil || a.session.page.IsClosed() {
		return fmt.Errorf("session page not available for mouse event")
	}

	// Check context before proceeding, as Playwright mouse functions do not directly accept a context.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	mouse := a.session.page.Mouse()

	switch data.Type {
	case humanoid.MouseMove:
		// Playwright's Mouse.Move is fire and forget, not context aware.
		return mouse.Move(data.X, data.Y)

	case humanoid.MousePress:
		// Convert the string to the enum type and provide a pointer, as required by Playwright.
		button := playwright.MouseButton(data.Button)
		options := playwright.MouseDownOptions{
			Button:      &button,
			ClickCount: playwright.Int(data.ClickCount),
		}
		// Playwright's Mouse.Down is fire and forget, not context aware.
		return mouse.Down(options)

	case humanoid.MouseRelease:
		// Convert the string to the enum type and provide a pointer, as required by Playwright.
		button := playwright.MouseButton(data.Button)
		options := playwright.MouseUpOptions{
			Button:      &button,
			ClickCount: playwright.Int(data.ClickCount),
		}
		// Playwright's Mouse.Up is fire and forget, not context aware.
		return mouse.Up(options)

	case humanoid.MouseWheel:
		// Playwright's Mouse.Wheel is fire and forget, not context aware.
		return mouse.Wheel(data.DeltaX, data.DeltaY)

	default:
		return fmt.Errorf("unsupported mouse event type: %s", data.Type)
	}
}

// SendKeys implements humanoid.Executor. It handles text insertion and control keys.
func (a *PlaywrightExecutorAdapter) SendKeys(ctx context.Context, keys string) error {
	if a.session == nil || a.session.page == nil || a.session.page.IsClosed() {
		return fmt.Errorf("session page not available for key event")
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	keyboard := a.session.page.Keyboard()

	// Explicitly handle control characters defined in the humanoid package, mapping them to
	// Playwright's keyboard Press command for precise control.
	if len(keys) == 1 {
		r := rune(keys[0])
		var keyName string
		switch r {
		case '\b': // Backspace
			keyName = "Backspace"
		case '\r': // Enter
			keyName = "Enter"
		case '\t': // Tab
			keyName = "Tab"
		case '\x1b': // Escape
			keyName = "Escape"
		}
		if keyName != "" {
			// Press sends a keydown, keypress/input, and keyup event sequence.
			return keyboard.Press(keyName)
		}
	}

	// For general text input, InsertText is more efficient and appropriate.
	return keyboard.InsertText(keys)
}

// GetElementGeometry implements humanoid.Executor. It uses Playwright Locators for robust retrieval
// of an element's bounding box and size.
func (a *PlaywrightExecutorAdapter) GetElementGeometry(ctx context.Context, selector string) (*humanoid.ElementGeometry, error) {
	if a.session == nil || a.session.page == nil || a.session.page.IsClosed() {
		return nil, fmt.Errorf("session page not available for geometry retrieval")
	}

	locator := a.session.page.Locator(selector)

	// Playwright's BoundingBox uses a Timeout option for control flow, which we respect.
	options := playwright.LocatorBoundingBoxOptions{
		Timeout: playwright.Float(15000), // 15s timeout
	}

	box, err := locator.BoundingBox(options)
	if err != nil {
		// If the Go context was cancelled during the Playwright wait, prioritize the Go context error.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		
		// The original code tried to use `playwright.TimeoutError`, which is likely not exported
		// in this version. We rely on the context check above and return the underlying error.
		// For Playwright timeout errors not tied to the Go context, this ensures the failure is propagated.
		// var timeoutError *playwright.TimeoutError
		// if errors.As(err, &timeoutError) {
		// 	return nil, fmt.Errorf("timeout waiting for element '%s' geometry: %w", selector, err)
		// }
		return nil, fmt.Errorf("failed to get bounding box for '%s': %w", selector, err)
	}

	if box == nil {
		// This happens if the element is found in the DOM but is not rendered (e.g., display:none).
		return nil, fmt.Errorf("element '%s' found but has no bounding box (not interactable)", selector)
	}

	// Convert Playwright BoundingBox coordinates to the agnostic ElementGeometry structure.
	x, y, w, h := box.X, box.Y, box.Width, box.Height

	// Defensive checking for negative dimensions.
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}

	geo := &humanoid.ElementGeometry{
		Vertices: []float64{
			x, y,         // Top left
			x + w, y,     // Top right
			x + w, y + h, // Bottom right
			x, y + h,     // Bottom left
		},
		Width:  int64(w),
		Height: int64(h),
	}
	return geo, nil
}

// ExecuteScript implements humanoid.Executor. It executes JS in the page context and returns the raw JSON result.
func (a *PlaywrightExecutorAdapter) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	if a.session == nil || a.session.page == nil || a.session.page.IsClosed() {
		return nil, fmt.Errorf("session page not available for script execution")
	}

	// Check context before execution.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Page.Evaluate runs the script. Since it doesn't take context, we must rely on the
	// initial context check and Playwright's internal timeouts.
	result, err := a.session.page.Evaluate(script, args...)
	if err != nil {
		// If the Go context was cancelled during the Playwright call, prioritize the Go context error.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed to execute script via playwright: %w", err)
	}

	// Marshal the result (interface{}) into json.RawMessage as required by the Executor interface.
	if result == nil {
		return json.RawMessage("null"), nil
	}

	jsonData, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal script result to JSON: %w", err)
	}

	return jsonData, nil
}

