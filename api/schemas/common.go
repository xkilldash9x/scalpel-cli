package schemas

import (
	"time"
)

// -- Common Schemas --

// Credential represents a set of login credentials, typically a username and
// password combination, used for authentication.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// KeyEventData encapsulates the information for a single keyboard event,
// including the primary key that was pressed and any active modifier keys like
// Shift, Ctrl, or Alt.
type KeyEventData struct {
	// Key represents the main key being pressed (e.g., "a", "Enter", "Tab").
	// The value should be compatible with the strings expected by the Chrome
	// DevTools Protocol's `input.dispatchKeyEvent` command.
	Key string
	// Modifiers is a bitmask representing the combination of active modifier keys.
	Modifiers KeyModifier
}

// KeyModifier defines a bitmask for keyboard modifiers (Ctrl, Alt, Shift, Meta)
// to be used in keyboard events. The values are aligned with the Chrome
// DevTools Protocol's `input.DispatchKeyEvent` modifiers.
type KeyModifier int

// Constants for keyboard modifiers, designed to be combined using bitwise OR.
const (
	ModNone  KeyModifier = 0 // No modifiers are active.
	ModAlt   KeyModifier = 1 // The Alt key is active.
	ModCtrl  KeyModifier = 2 // The Ctrl key is active.
	ModMeta  KeyModifier = 4 // The Meta key (e.g., Command on Mac) is active.
	ModShift KeyModifier = 8 // The Shift key is active.
)

// -- Result Schemas --

// ResultEnvelope serves as the top-level container for the output of a single
// analysis task. It includes metadata like scan and task IDs, a timestamp, a
// list of all findings, and any updates to be made to the knowledge graph.
type ResultEnvelope struct {
	ScanID    string                `json:"scan_id"`
	TaskID    string                `json:"task_id"`
	Timestamp time.Time             `json:"timestamp"`
	Findings  []Finding             `json:"findings"`
	KGUpdates *KnowledgeGraphUpdate `json:"kg_updates,omitempty"`
}
