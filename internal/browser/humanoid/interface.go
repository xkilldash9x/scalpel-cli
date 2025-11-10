// internal/browser/humanoid/interface.go
package humanoid

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// ActionType is an enumeration that categorizes the type of interaction being
// performed by the humanoid. This is used internally to model "task switching"
// delays, where changing from one type of action (e.g., moving the mouse) to
// another (e.g., typing) incurs a realistic cognitive pause.
type ActionType string

const (
	// ActionTypeNone represents the initial state before any action is taken.
	ActionTypeNone ActionType = "NONE"
	// ActionTypeMove represents a mouse movement action.
	ActionTypeMove ActionType = "MOVE"
	// ActionTypeClick represents a mouse click action.
	ActionTypeClick ActionType = "CLICK"
	// ActionTypeDrag represents a mouse drag-and-drop action.
	ActionTypeDrag ActionType = "DRAG"
	// ActionTypeType represents a keyboard typing action.
	ActionTypeType ActionType = "TYPE"
	// ActionTypeScroll represents a mouse wheel or scrolling action.
	ActionTypeScroll ActionType = "SCROLL"
	// ActionTypePause represents a deliberate cognitive pause.
	ActionTypePause ActionType = "PAUSE"
	// ActionTypeNavigate represents a browser navigation action.
	ActionTypeNavigate ActionType = "NAVIGATE"
)

// InteractionOptions provides a flexible way to configure and customize the
// behavior of high-level humanoid actions like clicks and movements.
type InteractionOptions struct {
	// EnsureVisible, if set, overrides the default behavior of automatically
	// scrolling an element into view before interacting with it. If nil (the
	// default), scrolling is enabled. To disable, this must be a pointer to a
	// boolean `false`.
	EnsureVisible *bool
	// Field, if provided, specifies a PotentialField that will influence the
	// trajectory of the mouse movement, allowing for the simulation of attraction
	// or repulsion from certain points on the screen.
	Field *PotentialField
}

// Controller defines the high-level public interface for a Humanoid. It exposes
// the primary actions that a user can perform on a web page, abstracting away
// the complex simulation logic. This is the interface implemented by the
// Humanoid struct.
type Controller interface {
	MoveTo(ctx context.Context, selector string, opts *InteractionOptions) error
	IntelligentClick(ctx context.Context, selector string, opts *InteractionOptions) error
	DragAndDrop(ctx context.Context, startSelector, endSelector string, opts *InteractionOptions) error
	Type(ctx context.Context, selector string, text string, opts *InteractionOptions) error
	// Shortcut executes a keyboard shortcut (e.g., "ctrl+c", "meta+a").
	Shortcut(ctx context.Context, keysExpression string) error
	// CognitivePause signature updated to use scaling factors for the Ex-Gaussian model.
	CognitivePause(ctx context.Context, meanScale, stdDevScale float64) error
}

// Executor defines the low-level abstraction that the Humanoid controller uses
// to interact with the browser. This interface separates the simulation logic
// from the underlying browser control mechanism (e.g., ChromeDP), making the
// Humanoid component more modular and testable. It provides the essential
// primitives for dispatching events and querying the state of the web page.
type Executor interface {
	// Sleep pauses execution for a specified duration.
	Sleep(ctx context.Context, d time.Duration) error
	// DispatchMouseEvent sends a mouse event (e.g., move, press, release) to the browser.
	DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error
	// SendKeys sends a string of characters to be typed, simulating raw keyboard input.
	SendKeys(ctx context.Context, keys string) error
	// DispatchStructuredKey sends a structured key event, used for shortcuts and
	// actions that require specifying modifiers (Ctrl, Shift, etc.).
	DispatchStructuredKey(ctx context.Context, data schemas.KeyEventData) error
	// GetElementGeometry retrieves the geometric properties (size, position) of
	// an element specified by a selector.
	GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error)
	// ExecuteScript executes a JavaScript snippet in the browser and returns the result.
	ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error)
}

// ControlKey defines constants for common non-printable control characters that
// can be used in keyboard interactions.
type ControlKey string

const (
	// KeyBackspace represents the backspace key.
	KeyBackspace ControlKey = "\b"
	// KeyEnter represents the enter key (carriage return).
	KeyEnter ControlKey = "\r"
	// KeyTab represents the tab key.
	KeyTab ControlKey = "\t"
	// KeyEscape represents the escape key.
	KeyEscape ControlKey = "\x1b"
)
