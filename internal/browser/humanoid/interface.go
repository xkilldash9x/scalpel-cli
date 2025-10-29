// internal/browser/humanoid/interface.go
package humanoid

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// ActionType categorizes the type of interaction performed. Used for task switching logic.
type ActionType string

const (
	ActionTypeNone     ActionType = "NONE"
	ActionTypeMove     ActionType = "MOVE"
	ActionTypeClick    ActionType = "CLICK"
	ActionTypeDrag     ActionType = "DRAG"
	ActionTypeType     ActionType = "TYPE"
	ActionTypeScroll   ActionType = "SCROLL"
	ActionTypePause    ActionType = "PAUSE"
	ActionTypeNavigate ActionType = "NAVIGATE"
)

// InteractionOptions provides a flexible way to configure humanoid actions.
type InteractionOptions struct {
	// If set, controls whether the humanoid will automatically scroll until the element is in view.
	// If nil (default when options are nil or the field is unset), the behavior is enabled (true).
	// To disable, set to a pointer to false.
	EnsureVisible *bool
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
	// Shortcut executes a keyboard shortcut (e.g., "ctrl+c", "meta+a").
	Shortcut(ctx context.Context, keysExpression string) error
	// CognitivePause signature updated to use scaling factors for the Ex-Gaussian model.
	CognitivePause(ctx context.Context, meanScale, stdDevScale float64) error
}

// Executor defines the low-level interface required by the Humanoid controller.
type Executor interface {
	Sleep(ctx context.Context, d time.Duration) error
	DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error
	SendKeys(ctx context.Context, keys string) error
	// DispatchStructuredKey handles pressing a key combination (like a shortcut).
	// The executor is responsible for the KeyDown and KeyUp sequence.
	DispatchStructuredKey(ctx context.Context, data schemas.KeyEventData) error
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
