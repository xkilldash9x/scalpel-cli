// Filename: internal/humanoid/interface.go
package humanoid

import (
	"context"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

// Controller defines the high-level interface for human-like interactions.
type Controller interface {
	MoveTo(ctx context.Context, selector string, field *PotentialField) error
	Click(ctx context.Context) error
	ClickOn(ctx context.Context, selector string, field *PotentialField) error
	DoubleClick(ctx context.Context) error
	Drag(ctx context.Context, start, end Vector2D, field *PotentialField) error
	Scroll(ctx context.Context, deltaX, deltaY float64) error
	Type(ctx context.Context, text string) error
}

// Executor defines the interface for interacting with the browser via CDP.
// This interface facilitates dependency injection and mocking for tests.
type Executor interface {
	// DispatchMouseEvent sends a mouse event.
	DispatchMouseEvent(ctx context.Context, p *input.DispatchMouseEventParams) error

	// DispatchKeyEvent sends a keyboard event.
	DispatchKeyEvent(ctx context.Context, p *input.DispatchKeyEventParams) error

	// Sleep pauses execution, respecting context cancellation.
	Sleep(ctx context.Context, d time.Duration) error

	// ExecuteAction executes a generic chromedp.Action (useful for JS execution via runtime.Evaluate).
	ExecuteAction(ctx context.Context, a chromedp.Action) error

	// GetLayoutMetrics retrieves the current viewport metrics.
	// The signature matches the return values of the page.GetLayoutMetrics CDP command.
	GetLayoutMetrics(ctx context.Context) (*page.LayoutViewport, *page.VisualViewport, *dom.Rect, error)

	// GetBoxModel retrieves the box model for a node ID.
	GetBoxModel(ctx context.Context, nodeID cdp.NodeID) (*dom.BoxModel, error)

	// CallFunctionOn executes JavaScript on a specific object.
	CallFunctionOn(ctx context.Context, params *runtime.CallFunctionOnParams) (*runtime.RemoteObject, *runtime.ExceptionDetails, error)

	// QueryNodes finds nodes matching a CSS selector.
	QueryNodes(ctx context.Context, selector string) ([]*cdp.Node, error)
}