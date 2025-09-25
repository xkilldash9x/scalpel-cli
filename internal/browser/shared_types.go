// internal/browser/shared_types.go
package browser

import (
	"context"
	"time"
)

// CombineContext creates a new context that is a child of parentCtx.
// It is canceled when *either* parentCtx or secondaryCtx is canceled.
// This is crucial for ensuring that operations respect both the long-running session lifecycle
// and the specific request/task deadline.
func CombineContext(parentCtx, secondaryCtx context.Context) (context.Context, context.CancelFunc) {
	// Start with the parent context (e.g., session context).
	combinedCtx, cancel := context.WithCancel(parentCtx)

	// Link the secondary context's lifecycle (e.g., request context) to the new combined context.
	go func() {
		select {
		case <-secondaryCtx.Done():
			// If the secondary context is canceled, cancel the combined context.
			cancel()
		case <-combinedCtx.Done():
			// The combined context was already canceled (likely from the parent), so exit.
		}
	}()

	return combinedCtx, cancel
}

// valueOnlyContext is retained for potential cleanup tasks that should run detached from the main context cancellation.
type valueOnlyContext struct {
	context.Context
}

func (valueOnlyContext) Deadline() (deadline time.Time, ok bool) { return }
func (valueOnlyContext) Done() <-chan struct{}                   { return nil }
func (valueOnlyContext) Err() error                              { return nil }