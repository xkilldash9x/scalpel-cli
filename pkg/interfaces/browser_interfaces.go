// This new file isolates browser-specific interfaces to fully decouple them.

package interfaces

import (
	"context"

	// Note: We are importing a sub-package of browser, not browser itself,
	// to get the Artifacts struct, which is a pure data container.
	// This is an acceptable, non-cyclical dependency.
	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
)

// SessionContext defines the contract for an active, instrumented browser session.
// This interface is implemented by AnalysisContext in the cdp package.
type SessionContext interface {
	ID() string
	GetContext() context.Context
	InjectScriptPersistently(script string) error
	ExposeFunction(name string, function interface{}) error
	Navigate(url string) error
	WaitForAsync(milliseconds int) error
	Click(selector string) error
	Type(selector, text string) error
	Submit(selector string) error
	ScrollPage(direction string) error
	Interact(config browser.InteractionConfig) error
	CollectArtifacts() (*browser.Artifacts, error)
	Close(ctx context.Context) error
}

// SessionManager defines the contract for the headless browser pool/manager.
// It's responsible for the lifecycle of browser sessions.
type SessionManager interface {
	// CORRECTED (ARC-01): This now returns the SessionContext interface
	// defined within this package, removing the dependency on pkg/browser.
	InitializeSession(ctx context.Context) (SessionContext, error)
	Shutdown(ctx context.Context) error
}