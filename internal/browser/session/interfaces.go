// internal/browser/session/interfaces.go
package session

import (
	"context"

	"github.com/chromedp/chromedp"
)

// ActionExecutor defines an interface for executing chromedp actions within a session context.
// This allows components like Interactor to run CDP commands without direct dependency on the full Session struct.
type ActionExecutor interface {
	// RunActions executes a sequence of chromedp actions.
	// It should handle context combination (operational context vs session lifetime context)
	// and error prioritization.
	RunActions(ctx context.Context, actions ...chromedp.Action) error
	// RunBackgroundActions executes actions in a detached context, ensuring they are not
	// cancelled when the parent operational context finishes.
	RunBackgroundActions(ctx context.Context, actions ...chromedp.Action) error
}
