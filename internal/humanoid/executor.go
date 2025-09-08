// Filename: internal/humanoid/executor.go
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

// Executor defines the contract for external browser interactions,
// allowing for mocking during tests. This interface is the cornerstone
// of the module's testability strategy.
type Executor interface {
	// Sleep pauses execution for a given duration (context-aware).
	Sleep(ctx context.Context, d time.Duration) error

	// DispatchMouseEvent sends a raw low-level mouse event.
	DispatchMouseEvent(ctx context.Context, p *input.DispatchMouseEventParams) error

	// ExecuteAction executes a standard chromedp.Action (used for composed actions like SendKeys or MouseEvent).
	ExecuteAction(ctx context.Context, a chromedp.Action) error

	// GetLayoutMetrics retrieves the browser's layout metrics.
	GetLayoutMetrics(ctx context.Context) (cssVisualViewport *page.VisualViewport, err error)

	// GetBoxModel retrieves the BoxModel for a given NodeID.
	GetBoxModel(ctx context.Context, nodeID cdp.NodeID) (*dom.BoxModel, error)

	// CallFunctionOn executes a JavaScript function.
	CallFunctionOn(ctx context.Context, params *runtime.CallFunctionOnParams) (result *runtime.RemoteObject, exceptionDetails *runtime.ExceptionDetails, err error)

	// QueryNodes finds nodes by a selector, ensuring visibility first (matching production behavior).
	QueryNodes(ctx context.Context, selector string) ([]*cdp.Node, error)
}

// CDPExecutor is the production implementation of the Executor interface.
// It wraps the real chromedp library calls.
type CDPExecutor struct{}

// NewCDPExecutor creates a new production-ready executor.
func NewCDPExecutor() *CDPExecutor {
	return &CDPExecutor{}
}

func (e *CDPExecutor) Sleep(ctx context.Context, d time.Duration) error {
	return chromedp.Sleep(d).Do(ctx)
}

func (e *CDPExecutor) DispatchMouseEvent(ctx context.Context, p *input.DispatchMouseEventParams) error {
	return p.Do(ctx)
}

func (e *CDPExecutor) ExecuteAction(ctx context.Context, a chromedp.Action) error {
	return a.Do(ctx)
}

func (e *CDPExecutor) GetLayoutMetrics(ctx context.Context) (*page.VisualViewport, error) {
	// Use the modern 7-value return signature and only return what we need.
	_, _, _, _, cssVisualViewport, _, err := page.GetLayoutMetrics().Do(ctx)
	return cssVisualViewport, err
}

func (e *CDPExecutor) GetBoxModel(ctx context.Context, nodeID cdp.NodeID) (*dom.BoxModel, error) {
	return dom.GetBoxModel().WithNodeID(nodeID).Do(ctx)
}

func (e *CDPExecutor) CallFunctionOn(ctx context.Context, params *runtime.CallFunctionOnParams) (*runtime.RemoteObject, *runtime.ExceptionDetails, error) {
	// The Do method for CallFunctionOn returns these three values.
	return params.Do(ctx)
}

func (e *CDPExecutor) QueryNodes(ctx context.Context, selector string) ([]*cdp.Node, error) {
	var nodes []*cdp.Node
	// In production, we must ensure the element is visible before querying nodes,
	// mirroring the behavior expected by the original helpers.go implementation.
	err := chromedp.Tasks{
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		chromedp.Nodes(selector, &nodes, chromedp.ByQuery),
	}.Do(ctx)

	// We return nodes even if err is not nil, matching the behavior in the original helpers.go.
	return nodes, err
}