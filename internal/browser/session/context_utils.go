// internal/browser/session/context_utils.go
package session

import (
	"context"
	"time"
)

// CombineContext creates a new context derived from ctx1 (primary/master context)
// that is canceled when *either* ctx1 or ctx2 (secondary/operational context) is canceled.
// It inherits values from ctx1. This is crucial for chromedp operations where
// ctx1 carries the CDP connection info (the session context), and ctx2 carries the operational deadline.
// This pattern aligns with Chromedp Best Practices (Section 1.1) by preserving CDP values.
func CombineContext(ctx1, ctx2 context.Context) (context.Context, context.CancelFunc) {
	// Derive from ctx1 to inherit values and ctx1's cancellation/deadline.
	combinedCtx, cancel := context.WithCancel(ctx1)

	// Link ctx2's lifecycle to the combined context.
	// The goroutine stops when either context is done.
	go func() {
		select {
		case <-ctx2.Done():
			// If ctx2 is canceled, cancel the combined context.
			cancel()
		case <-combinedCtx.Done():
			// The combined context was already canceled (e.g., from ctx1 or direct call), so exit.
		}
	}()

	return combinedCtx, cancel
}

// valueOnlyContext wraps a parent context to create a "detached" context.
// It inherits all values (like CDP target information) from its parent,
// but it explicitly ignores the parent's deadline and cancellation signal.
// (Moved from internal/browser/shared_types.go)
type valueOnlyContext struct {
	context.Context
}

// Deadline always returns false, removing any deadline from the parent.
func (valueOnlyContext) Deadline() (deadline time.Time, ok bool) { return }

// Done always returns nil, making the context un-cancellable from its parent.
func (valueOnlyContext) Done() <-chan struct{} { return nil }

// Err always returns nil.
func (valueOnlyContext) Err() error { return nil }

// Detach returns a context that inherits values from ctx but is not canceled when ctx is.
// This is useful for background tasks or cleanup operations that must outlive the parent context,
// particularly in chromedp where the context carries connection information (Context Best Practices, Section 3.3).
func Detach(ctx context.Context) context.Context {
	return valueOnlyContext{ctx}
}
