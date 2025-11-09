// internal/browser/session/cdp_executor.go
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
)

// cdpExecutor is an adapter that implements the humanoid.Executor interface
// using chromedp actions. This bridges the browser-agnostic humanoid logic
// with the concrete CDP implementation.
type cdpExecutor struct {
	ctx            context.Context // This should be the session's master context
	logger         *zap.Logger
	runActionsFunc func(ctx context.Context, actions ...chromedp.Action) error // Points to Session.RunActions
}

// ensure cdpExecutor implements the interface
var _ humanoid.Executor = (*cdpExecutor)(nil)

// Sleep pauses execution for the specified duration, respecting the context.
func (e *cdpExecutor) Sleep(ctx context.Context, d time.Duration) error {
	// Use the provided runActionsFunc (Session.RunActions) to execute the sleep.
	// This centralizes context combination (combining ctx and e.ctx) within RunActions.
	return e.runActionsFunc(ctx, chromedp.Sleep(d))
}

// RunActions implements the humanoid.Executor interface.
func (e *cdpExecutor) RunActions(ctx context.Context, actions ...chromedp.Action) error {
	// Pass the actions directly to the underlying session's RunActions function.
	return e.runActionsFunc(ctx, actions...)
}

// DispatchMouseEvent dispatches a single mouse event via CDP.
// ctx here is the operational context.
func (e *cdpExecutor) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	// Construct the parameters using the builder pattern for clarity
	p := input.DispatchMouseEvent(input.MouseType(data.Type), data.X, data.Y).WithButton(input.MouseButton(data.Button)).
		WithButtons(data.Buttons).
		WithClickCount(int64(data.ClickCount)) // Ensure correct type cast

	// Add wheel delta only for mouseWheel events
	if data.Type == schemas.MouseWheel {
		p = p.WithDeltaX(data.DeltaX).WithDeltaY(data.DeltaY)
	}

	// --- START FIX (Removed internal timeout) ---
	// Do not create an internal timeout here. An action (like a click)
	// that triggers a navigation must be allowed to run for the full
	// duration of the 'ctx' passed in from the humanoid layer.
	// The 'ctx' passed in manages the timeout for the *entire* logical operation.

	// (Original code with internal timeout removed)
	// timeout := 10 * time.Second
	// opCtx, cancel := context.WithTimeout(ctx, timeout)
	// defer cancel()

	// Use the session's runActionsFunc (RunActions) with the original context.
	err := e.runActionsFunc(ctx, p)

	// Check if the error is due to the context passed in
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		e.logger.Debug("cdpExecutor DispatchMouseEvent timed out.", zap.Error(ctx.Err()))
		// Return a generic error that respects the original context.
		return fmt.Errorf("cdpExecutor DispatchMouseEvent timed out: %w", ctx.Err())
	}
	return err
}

// SendKeys dispatches keyboard events via CDP.
// ctx here is the operational context.
func (e *cdpExecutor) SendKeys(ctx context.Context, keys string) error {
	// --- START FIX (Removed internal timeout) ---
	// Do not create an internal timeout. A "SendKeys" action (like pressing Enter)
	// might trigger a navigation and must be allowed to complete.
	// The 'ctx' from the humanoid layer controls the overall operation timeout.

	// (Original code with internal timeout removed)
	// timeout := 10 * time.Second
	// opCtx, cancel := context.WithTimeout(ctx, timeout)
	// defer cancel()

	// Use the session's runActionsFunc (RunActions).
	err := e.runActionsFunc(ctx, chromedp.KeyEvent(keys))

	// Check if the error is due to the context passed in
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		e.logger.Debug("cdpExecutor SendKeys timed out.", zap.Error(ctx.Err()))
		return fmt.Errorf("cdpExecutor SendKeys timed out: %w", ctx.Err())
	}
	return err
}

// DispatchStructuredKey implements the humanoid.Executor interface.
// It handles pressing a key combination (modifiers + key).
func (e *cdpExecutor) DispatchStructuredKey(ctx context.Context, data schemas.KeyEventData) error {
	// 1. Determine CDP modifiers bitmask from our internal representation.
	var cdpModifiers input.Modifier
	if data.Modifiers&schemas.ModAlt != 0 {
		cdpModifiers |= input.ModifierAlt
	}
	if data.Modifiers&schemas.ModCtrl != 0 {
		cdpModifiers |= input.ModifierCtrl
	}
	if data.Modifiers&schemas.ModMeta != 0 {
		cdpModifiers |= input.ModifierMeta
	}
	if data.Modifiers&schemas.ModShift != 0 {
		cdpModifiers |= input.ModifierShift
	}

	// 2. Construct the KeyDown event using the modern, simplified API.
	// The key name from data.Key is passed directly.
	keyDown := input.DispatchKeyEvent(input.KeyDown).
		WithModifiers(cdpModifiers).
		WithKey(data.Key)

	// 3. Construct the KeyUp event.
	keyUp := input.DispatchKeyEvent(input.KeyUp).
		WithModifiers(cdpModifiers).
		WithKey(data.Key)

	// 4. Execute the sequence (KeyDown, then KeyUp).
	// R9 FIX: Removed internal timeout (5s). A structured key press (e.g., Enter, shortcuts)
	// might trigger navigation or long-running JS. The operation must respect the full
	// duration of the incoming operational context (ctx).

	// (Original code with internal timeout removed)
	// timeout := 5 * time.Second
	// opCtx, cancel := context.WithTimeout(ctx, timeout)
	// defer cancel()

	// Send KeyDown and KeyUp sequentially in one batch using the operational context (ctx).
	err := e.runActionsFunc(ctx, keyDown, keyUp)

	if err != nil {
		// Check if the error is due to the context passed in
		if ctx.Err() == context.DeadlineExceeded {
			e.logger.Debug("cdpExecutor DispatchStructuredKey timed out.", zap.Error(ctx.Err()))
			// Return a generic error that respects the original context.
			return fmt.Errorf("cdpExecutor: timeout dispatching shortcut sequence: %w", ctx.Err())
		}
		return fmt.Errorf("cdpExecutor: failed to dispatch shortcut sequence: %w", err)
	}

	return nil
}

// GetElementGeometry retrieves the bounding box, vertices, and tag name for a selector.
// ctx here is used to derive the timeout context for this specific operation.
func (e *cdpExecutor) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	// Use JS to get geometry and attributes in one go for efficiency and atomicity.
	// Enhanced script to handle visibility and use getBoxQuads for accuracy.
	// This explicit check for visibility aligns with Doc 2.2 (Mastering Synchronization).
	script := fmt.Sprintf(`
	        (function(sel) {
	            const node = document.querySelector(sel);
	            if (!node) return null; // Element not found
	
	            // Check visibility based on dimensions and computed style
	            const rect = node.getBoundingClientRect();
	            const style = window.getComputedStyle(node);
	            const isVisible = rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
	
	            if (!isVisible) {
	                 console.debug("Element found but not visible:", sel, { rect: { width: rect.width, height: rect.height }, style: { display: style.display, visibility: style.visibility, opacity: style.opacity } });
	                 return null; // Not interactable
	            }
	
	            // Use DOMQuad vertices if available (more accurate for transforms/rotations)
	            let quadVertices;
	            if (typeof node.getBoxQuads === 'function') {
	                // Ensure coordinates are relative to the viewport/document for CDP mouse events
	                const quads = node.getBoxQuads({ box: 'border', relativeTo: document.documentElement }); // Use border-box, relative to document
	                 if (quads && quads.length > 0) {
	                    const q = quads[0]; // Use the first quad
	                    quadVertices = [
	                        q.p1.x, q.p1.y,
	                        q.p2.x, q.p2.y,
	                        q.p3.x, q.p3.y,
	                        q.p4.x, q.p4.y
	                    ];
	                 }
	            }
	            // Fallback using bounding client rect if getBoxQuads isn't supported/fails
	            if (!quadVertices) {
	                 console.debug("Falling back to getBoundingClientRect for geometry:", sel);
	                 quadVertices = [
	                    rect.left, rect.top,
	                    rect.right, rect.top,
	                    rect.right, rect.bottom,
	                    rect.left, rect.bottom
	                 ];
	            }
	
	            return {
	                vertices: quadVertices,
	                width: Math.round(rect.width), // Use integers matching schema
	                height: Math.round(rect.height),
	                tagName: node.tagName || '', // Ensure tagName is not null
	                type: node.type || '' // Handle cases where 'type' attribute doesn't exist
	            };
	        })(%s); // Pass selector directly to IIFE
	    `, jsonEncode(selector)) // Ensure selector is properly escaped for JS

	var res json.RawMessage

	// R10 FIX: Removed internal timeout (10s). The overall operation timeout is controlled
	// by the incoming context (ctx). For example, a `Click` action might have a 30s timeout,
	// and this geometry lookup is just one part of it. It must respect the parent context's deadline.
	// opCtx, cancel := context.WithTimeout(ctx, timeout) // OLD

	// Use the session's runActionsFunc (RunActions).
	err := e.runActionsFunc(ctx, // Use the original context
		// Evaluate the script and expect a result back
		chromedp.Evaluate(script, &res, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			// Ensure promises resolve, return actual value, handle exceptions silently in JS
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	if err != nil {
		// Check if it was specifically a timeout error
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timeout getting geometry for '%s': %w", selector, ctx.Err())
		}
		// Check if the error is a context cancellation (from ctx or e.ctx)
		if ctx.Err() != nil || e.ctx.Err() != nil {
			// Return the actual error returned by runActionsFunc, as it prioritizes the cause.
			return nil, fmt.Errorf("context error getting geometry for '%s': %w", selector, err)
		}

		return nil, fmt.Errorf("failed JS evaluation for geometry '%s': %w", selector, err)
	}

	// Check for explicit null return from JS, indicating element not found or not visible
	if string(res) == "null" {
		e.logger.Debug("Element geometry JS evaluation returned null (not found or not visible).", zap.String("selector", selector))
		// Distinguish between not found and not visible if possible? For now, treat same.
		return nil, fmt.Errorf("element '%s' not found or not visible", selector)
	}

	var geom schemas.ElementGeometry
	if err := json.Unmarshal(res, &geom); err != nil {
		return nil, fmt.Errorf("failed to unmarshal geometry for '%s': %w (payload: %s)", selector, err, string(res))
	}

	// Sanity check dimensions after unmarshal
	if geom.Width <= 0 || geom.Height <= 0 {
		e.logger.Warn("Element geometry has non-positive dimensions after unmarshal.", zap.String("selector", selector), zap.Int64("width", geom.Width), zap.Int64("height", geom.Height))
		// Treat as not interactable if dimensions are invalid. Updated message for consistency.
		return nil, fmt.Errorf("element '%s' not found or not visible (invalid dimensions: width=%d, height=%d)", selector, geom.Width, geom.Height)
	}

	return &geom, nil
}

// ExecuteScript executes JavaScript within the browser context.
// ctx here is used to derive the timeout context for this specific operation.
func (e *cdpExecutor) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	// Note: chromedp.Evaluate doesn't directly support passing arguments like Playwright.
	// If args are needed, they must be embedded into the script string carefully,
	// or set via bindings/window properties beforehand. This implementation assumes args are not used directly.
	if len(args) > 0 {
		e.logger.Warn("cdpExecutor.ExecuteScript received arguments, but they are not directly passed to Evaluate.", zap.Int("num_args", len(args)))
		// Consider erroring out if args are essential:
		// return nil, fmt.Errorf("passing arguments to ExecuteScript via cdpExecutor is not directly supported")
	}

	var res json.RawMessage

	// R10 FIX: Removed internal timeout (20s). Script execution must respect the deadline
	// of the parent context (ctx) that it is a part of.
	// opCtx, cancel := context.WithTimeout(ctx, timeout) // OLD

	// Use the session's runActionsFunc (RunActions).
	err := e.runActionsFunc(ctx, // Use the original context
		chromedp.Evaluate(script, &res, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			// Ensure we get the actual result, await promises, handle exceptions silently in JS
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	if err != nil {
		// Check for specific timeout error
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("timeout during ExecuteScript: %w", err)
		}
		// Check if the error is a context cancellation (from ctx or e.ctx)
		if ctx.Err() != nil || e.ctx.Err() != nil {
			return nil, fmt.Errorf("context error during ExecuteScript: %w", err)
		}

		// Return the evaluation error
		return nil, fmt.Errorf("failed ExecuteScript evaluation: %w", err)
	}

	// Return the raw JSON message result (can be "null", "true", number, string, object, array)
	return res, nil
}

// jsonEncode is a helper to safely encode a value (especially strings) for JS injection.
// Moved here as it is used by interaction.go and cdp_executor.go
func jsonEncode(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Fallback for safety
		return `""`
	}
	return string(b)
}
