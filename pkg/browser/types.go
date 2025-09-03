// pkg/browser/types.go
package browser

import (
	"context"

	"github.com/chromedp/cdproto/har"
	"github.com/chromedp/cdproto/network"
)

// NOTE: The original content of this file contained misplaced JWT analysis logic.
// It has been replaced with the appropriate interfaces and types for the browser module.

// SessionContext defines the interface for interacting with a single, isolated browser session (tab).
type SessionContext interface {
	// ID returns the unique identifier for this session.
	ID() string

	// Initialize prepares the session (e.g., creating the tab, applying instrumentation).
	Initialize(ctx context.Context) error

	// --- Instrumentation ---

	// InjectScriptPersistently ensures a script is executed on every new document load.
	InjectScriptPersistently(script string) error

	// ExposeFunction makes a Go function callable from the browser's JavaScript context.
	ExposeFunction(name string, function interface{}) error

	// --- Navigation and Waiting ---

	// Navigate loads a URL and waits for the page to be ready.
	Navigate(url string) error

	// WaitForAsync waits for a specified duration, allowing asynchronous operations to complete.
	WaitForAsync(milliseconds int) error

	// --- Interaction (Humanoid) ---

	// Click performs a human-like click on an element matching the selector.
	Click(selector string) error

	// Type performs human-like typing into a field matching the selector.
	Type(selector, text string) error

	// Submit simulates submitting a form identified by the selector.
	Submit(selector string) error

	// ScrollPage scrolls the viewport 'up' or 'down'.
	ScrollPage(direction string) error

	// Interact uses an automated engine to explore and interact with the page.
	Interact(config InteractionConfig) error

	// --- Artifact Collection ---

	// CollectArtifacts gathers data like HAR logs, DOM snapshot, and storage state from the session.
	CollectArtifacts() (*Artifacts, error)

	// Close safely terminates the browser tab and releases associated resources.
	Close(ctx context.Context) error

	// --- Internal/Advanced ---

	// GetContext returns the underlying context.Context for the session, useful for advanced CDP operations.
	GetContext() context.Context
}

// Artifacts represents the data collected from a browser session.
type Artifacts struct {
	HAR         *har.HAR
	DOM         string
	ConsoleLogs []ConsoleLog
	Storage     StorageState
}

// ConsoleLog represents a single entry from the browser console.
type ConsoleLog struct {
	Type string
	Text string
}

// StorageState captures the state of cookies, localStorage, and sessionStorage.
type StorageState struct {
	Cookies        []*network.Cookie
	LocalStorage   map[string]string `json:"localStorage"`
	SessionStorage map[string]string `json:"sessionStorage"`
}

// InteractionConfig holds parameters for automated interaction/crawling.
type InteractionConfig struct {
	MaxDepth                int
	MaxInteractionsPerDepth int
	InteractionDelayMs      int
	PostInteractionWaitMs   int
}
