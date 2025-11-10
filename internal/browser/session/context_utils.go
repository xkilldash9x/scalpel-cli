// internal/browser/session/context_utils.go
package session

import (
	"context"
	"time"
)

// CombineContext creates a new context that is a child of a primary context (`ctx1`)
// but is also cancelled when a secondary context (`ctx2`) is cancelled. This is a
// critical utility for working with `chromedp`, where `ctx1` is typically the
// long-lived session or allocator context carrying essential connection values,
// and `ctx2` is a shorter-lived operational context with a specific deadline
// (e.g., for a single navigation or action).
//
// By deriving the new context from `ctx1`, it inherits all necessary values. By
// monitoring `ctx2` in a separate goroutine, it ensures that the combined context
// respects the operational timeout of `ctx2`.
//
// Returns the combined context and its cancel function. The caller is responsible
// for calling the cancel function to release the monitoring goroutine.
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

// valueOnlyContext is a custom context type that wraps a parent context but
// explicitly ignores the parent's deadline and cancellation. It inherits all
// values from the parent, which is essential for preserving `chromedp`'s
// connection and target information.
type valueOnlyContext struct {
	context.Context
}

// Deadline is overridden to always return `false`, effectively removing any
// deadline inherited from the parent context.
func (valueOnlyContext) Deadline() (deadline time.Time, ok bool) { return }

// Done is overridden to always return `nil`, making the context immune to
// cancellation signals from its parent.
func (valueOnlyContext) Done() <-chan struct{} { return nil }

// Err is overridden to always return `nil`.
func (valueOnlyContext) Err() error { return nil }

// Detach creates and returns a new context that is "detached" from its parent's
// lifecycle. The new context inherits all the values of the parent `ctx` but will
// not be cancelled when `ctx` is cancelled, nor will it expire when `ctx`'s
// deadline is reached.
//
// This is particularly useful for launching background tasks or performing cleanup
// operations that need to continue running even after the originating operation's
// context has been cancelled.
func Detach(ctx context.Context) context.Context {
	return valueOnlyContext{ctx}
}
