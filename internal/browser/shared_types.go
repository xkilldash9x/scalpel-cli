// internal/browser/shared_types.go
package browser

import (
	"context"
	"time"
)

// SessionLifecycleObserver defines an interface for components that need to be
// notified when a session is terminated.
type SessionLifecycleObserver interface {
	unregisterSession(ac *AnalysisContext)
}

// valueOnlyContext wraps a parent context to create a "detached" context.
// It inherits all values (like CDP target information) from its parent,
// but it explicitly ignores the parent's deadline and cancellation signal.
//
// This is an essential tool for operations that must attempt to run to completion
// even if the originating context is canceled. Common use cases include:
//   - Finalizer/cleanup tasks (e.g., removing a temporary attribute from a DOM element).
//   - Asynchronous data fetching that should not be aborted by a user-facing timeout
//     (e.g., fetching a response body after a navigation context has timed out).
//
// A timeout should almost always be applied to a valueOnlyContext to prevent it
// from running indefinitely.
type valueOnlyContext struct {
	context.Context
}

// Deadline always returns false, effectively removing any deadline from the parent.
func (valueOnlyContext) Deadline() (deadline time.Time, ok bool) { return }

// Done always returns nil, making the context un-cancellable from its parent.
func (valueOnlyContext) Done() <-chan struct{} { return nil }

// Err always returns nil.
func (valueOnlyContext) Err() error { return nil }

// CombineContext creates a new context that is a child of sessionCtx.
// It is designed to be canceled when *either* its parent (sessionCtx) is canceled
// *or* the provided operational context (opCtx) is canceled.
//
// This is useful for creating contexts for specific operations (like a navigation)
// that should respect both the overall session lifecycle and the specific
// timeout or cancellation signal of the operation itself.
func CombineContext(sessionCtx, opCtx context.Context) (context.Context, context.CancelFunc) {
	combinedCtx, cancel := context.WithCancel(sessionCtx)

	// This goroutine links the operational context's lifecycle to the new combined context.
	go func() {
		select {
		case <-opCtx.Done():
			// If the operation's context is canceled, cancel our new context.
			cancel()
		case <-combinedCtx.Done():
			// The combined context was already canceled (likely from the session closing),
			// so we can just exit.
		}
	}()

	return combinedCtx, cancel
}
