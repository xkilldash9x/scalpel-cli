// Filename: internal/humanoid/interface.go
package humanoid

import (
	"context"
	"encoding/json"
	"time"


)

// Controller defines the high-level interface for human-like interactions.

type Controller interface {
	MoveTo(ctx context.Context, selector string, field *PotentialField) error
	// IntelligentClick includes movement and clicking behavior.
	IntelligentClick(ctx context.Context, selector string, field *PotentialField) error
	// DragAndDrop performs a drag operation between two selectors.
	DragAndDrop(ctx context.Context, startSelector, endSelector string) error
	Type(ctx context.Context, selector string, text string) error
	CognitivePause(ctx context.Context, meanMs, stdDevMs float64) error
}

// Executor defines the interface for interacting with the browser automation layer (e.g., CDP, Playwright).
// This interface is designed to be agnostic of the underlying technology.
type Executor interface {
	// Sleep pauses execution, respecting context cancellation.
	Sleep(ctx context.Context, d time.Duration) error

	// DispatchMouseEvent sends a mouse event using agnostic data structures.
	DispatchMouseEvent(ctx context.Context, data MouseEventData) error

	// SendKeys sends the specified keys to the currently active element.
	// The humanoid logic ensures the target element is focused (via clicking) before calling this.
	SendKeys(ctx context.Context, keys string) error

	// GetElementGeometry finds the first element matching the selector and returns its geometry.
	// The implementation (the adapter) is responsible for waiting until the element is visible and interactable.
	GetElementGeometry(ctx context.Context, selector string) (*ElementGeometry, error)

	// ExecuteScript runs the provided JavaScript function/script with arguments and returns the result.
	// The implementation is responsible for executing the script and waiting for completion (including promises).
	// The result is returned as a raw JSON message representing the value returned by the script.
	ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error)
}
