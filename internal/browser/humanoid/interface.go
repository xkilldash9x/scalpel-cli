// internal/browser/humanoid/interface.go
package humanoid

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// InteractionOptions provides a flexible way to configure humanoid actions.
type InteractionOptions struct {
	// If true, the humanoid will automatically scroll until the element is in view before interacting.
	// This defaults to true if the options struct is nil.
	EnsureVisible bool
	// PotentialField can be used to influence the mouse trajectory.
	Field *PotentialField
	// More options like timeouts, custom scroll alignment, etc., can be added here.
}

// Controller defines the high-level interface for human-like interactions.
// This is the interface implemented by the Humanoid struct itself.
type Controller interface {
	MoveTo(ctx context.Context, selector string, opts *InteractionOptions) error
	IntelligentClick(ctx context.Context, selector string, opts *InteractionOptions) error
	DragAndDrop(ctx context.Context, startSelector, endSelector string, opts *InteractionOptions) error
	Type(ctx context.Context, selector string, text string, opts *InteractionOptions) error
	CognitivePause(ctx context.Context, meanMs, stdDevMs float64) error
}

// Executor defines the low-level interface required by the Humanoid controller.
type Executor interface {
	Sleep(ctx context.Context, d time.Duration) error
	DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error
	SendKeys(ctx context.Context, keys string) error
	GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error)
	ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error)
}

// ControlKey defines constants for common control characters used in SendKeys.
type ControlKey string

const (
	KeyBackspace ControlKey = "\b"   // Backspace
	KeyEnter     ControlKey = "\r"   // Carriage Return (often used for Enter)
	KeyTab       ControlKey = "\t"   // Tab
	KeyEscape    ControlKey = "\x1b" // Escape
)


