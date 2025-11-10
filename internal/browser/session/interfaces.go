// internal/browser/session/interfaces.go
package session

import (
	"context"

	"github.com/chromedp/chromedp"
)

// ActionExecutor defines a generic interface for executing browser actions,
// abstracting the underlying implementation (which is `chromedp` in this case).
// This allows components like the `Interactor` and `Harvester` to request browser
// operations without being directly coupled to the `Session` struct or `chromedp`.
type ActionExecutor interface {
	// RunActions executes a sequence of browser actions within a given operational
	// context. The implementation is responsible for combining this context with
	// the long-lived session context to ensure actions have the necessary CDP
	// connection information.
	RunActions(ctx context.Context, actions ...chromedp.Action) error

	// RunBackgroundActions executes a sequence of browser actions in a "detached"
	// context. This is crucial for tasks that must not be cancelled when the
	// parent operational context finishes, such as asynchronously fetching a
	// response body after a request has already completed.
	RunBackgroundActions(ctx context.Context, actions ...chromedp.Action) error
}
