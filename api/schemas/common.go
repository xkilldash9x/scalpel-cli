package schemas

import (
	"time"
)

// -- Common Schemas --

// Credential holds a username and password pair.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// KeyEventData represents a structured key event, including the main key and active modifiers.
type KeyEventData struct {
	// Key is the primary key pressed (e.g., "a", "c", "Enter", "Tab").
	// This should match the string expected by the underlying executor (e.g., chromedp/kb).
	Key string
	// Modifiers is a bitmask of active modifiers.
	Modifiers KeyModifier
}

// KeyModifier represents keyboard modifiers (Ctrl, Alt, Shift, Meta).
// These values correspond directly to the CDP input.DispatchKeyEvent modifiers bitfield.
type KeyModifier int

const (
	ModNone  KeyModifier = 0
	ModAlt   KeyModifier = 1 // Corresponds to CDP modifier 1
	ModCtrl  KeyModifier = 2 // Corresponds to CDP modifier 2
	ModMeta  KeyModifier = 4 // Corresponds to CDP modifier 4
	ModShift KeyModifier = 8 // Corresponds to CDP modifier 8
)

// -- Result Schemas --

// ResultEnvelope is the top level wrapper for all results from a single task.
type ResultEnvelope struct {
	ScanID    string                `json:"scan_id"`
	TaskID    string                `json:"task_id"`
	Timestamp time.Time             `json:"timestamp"`
	Findings  []Finding             `json:"findings"`
	KGUpdates *KnowledgeGraphUpdate `json:"kg_updates,omitempty"`
}
