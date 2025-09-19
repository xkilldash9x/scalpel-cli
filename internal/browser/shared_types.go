// internal/browser/shared_types.go
package browser

import (
	"context"
	"time"
)

// SessionLifecycleObserver defines an interface for components that need to be
// notified when a session is terminated. This decouples AnalysisContext from the Manager.
type SessionLifecycleObserver interface {
	unregisterSession(ac *AnalysisContext)
}

// valueOnlyContext is a context that inherits values but not cancellation.
// This is crucial for cleanup tasks that must run even if the parent context is cancelled.
type valueOnlyContext struct{ context.Context }

func (valueOnlyContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (valueOnlyContext) Done() <-chan struct{}       { return nil }
func (valueOnlyContext) Err() error                  { return nil }
