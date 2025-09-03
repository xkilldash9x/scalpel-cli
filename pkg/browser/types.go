// pkg/browser/types.go
package browser

import (
	"context"

	"github.com/chromedp/cdproto/har"
	"github.com/chromedp/cdproto/network"
)

// SessionContext defines the interface for interacting with a single, isolated browser session (tab).
type SessionContext interface {
	// ID returns the unique identifier for this session.
	ID() string

	// Initialize prepares the session (e.g., creating the tab, applying instrumentation).
	Initialize(ctx context.Context) error

	// --- Instrumentation ---
	InjectScriptPersistently(script string) error
	ExposeFunction(name string, function interface{}) error

	// --- Navigation and Waiting ---
	Navigate(url string) error
	WaitForAsync(milliseconds int) error

	// --- Interaction (Humanoid) ---
	Click(selector string) error
	Type(selector, text string) error
	Submit(selector string) error
	ScrollPage(direction string) error
	Interact(config InteractionConfig) error

	// --- Artifact Collection ---
	CollectArtifacts(ctx context.Context) (*Artifacts, error)

	// Close safely terminates the browser tab and releases associated resources.
	Close(ctx context.Context) error

	// --- Internal/Advanced ---
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