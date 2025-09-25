// internal/humanoid/types.go
package humanoid

// MouseEventType defines the type of mouse event.
// These strings align with standard DOM event types (and common automation protocols).
type MouseEventType string

const (
	MouseMove    MouseEventType = "mouseMoved"
	MousePress   MouseEventType = "mousePressed"
	MouseRelease MouseEventType = "mouseReleased"
	MouseWheel   MouseEventType = "mouseWheel"
)

// MouseButton defines the mouse button.
type MouseButton string

const (
	ButtonNone   MouseButton = "none"
	ButtonLeft   MouseButton = "left"
	ButtonRight  MouseButton = "right"
	ButtonMiddle MouseButton = "middle"
)

// MouseEventData holds the data required to dispatch a mouse event.
// This is an agnostic structure used by the Executor interface.
type MouseEventData struct {
	Type MouseEventType
	X    float64
	Y    float64
	// Button that was pressed or released (relevant for Press/Release events).
	Button MouseButton
	// Number of consecutive clicks.
	ClickCount int
	// Buttons is a bitfield representing the buttons currently pressed (1: Left, 2: Right, 4: Middle).
	// Required for realistic dragging simulation.
	Buttons int64
	// DeltaX and DeltaY are used for MouseWheel events.
	DeltaX float64
	DeltaY float64
}

// ElementGeometry represents the bounding box and dimensions of a DOM element.
// This replaces library-specific geometry types (like dom.BoxModel).
type ElementGeometry struct {
	// Content box vertices [x0, y0, x1, y1, x2, y2, x3, y3].
	Vertices []float64
	Width    int64
	Height   int64
}

// ControlKey defines constants for common control characters used in SendKeys.
// We use standard ASCII/Unicode control characters.
type ControlKey string

const (
	KeyBackspace ControlKey = "\b"   // Backspace
	KeyEnter     ControlKey = "\r"   // Carriage Return (often used for Enter)
	KeyTab       ControlKey = "\t"   // Tab
	KeyEscape    ControlKey = "\x1b" // Escape
)
