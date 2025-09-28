package humanoid

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- REFACTORING NOTE --
// This file establishes the core interfaces for the humanoid package.
// It now imports the canonical types directly from the api/schemas package.
// This change removes the local `types.go` file and centralizes all definitions.

// Controller defines the high-level interface for human-like interactions.
// This is the interface implemented by the Humanoid struct itself.
type Controller interface {
	MoveTo(ctx context.Context, selector string, field *PotentialField) error
	IntelligentClick(ctx context.Context, selector string, field *PotentialField) error
	DragAndDrop(ctx context.Context, startSelector, endSelector string) error
	Type(ctx context.Context, selector string, text string) error
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
