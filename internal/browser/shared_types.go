// internal/browser/shared_types.go
package browser

import (
	"context"
	"time"
)

// valueOnlyContext wraps a parent context to create a "detached" context.
// It inherits all values (like CDP target information) from its parent,
// but it explicitly ignores the parent's deadline and cancellation signal.
type valueOnlyContext struct {
	context.Context
}

// Deadline always returns false, removing any deadline from the parent.
func (valueOnlyContext) Deadline() (deadline time.Time, ok bool) { return }

// Done always returns nil, making the context un-cancellable from its parent.
func (valueOnlyContext) Done() <-chan struct{} { return nil }

// Err always returns nil.
func (valueOnlyContext) Err() error { return nil }

// CombineContext creates a new context that is a child of parentCtx.
// It is canceled when *either* parentCtx or secondaryCtx is canceled.
func CombineContext(parentCtx, secondaryCtx context.Context) (context.Context, context.CancelFunc) {
	combinedCtx, cancel := context.WithCancel(parentCtx)

	// Link the secondary context's lifecycle to the new combined context.
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
