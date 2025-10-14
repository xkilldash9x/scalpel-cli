// browser/dom/config.go
package dom

import (
	"context"
	"io"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// NewDefaultInteractionConfig returns a default configuration for autonomous interaction.
// This is used when a user requests autonomous exploration without providing specific parameters.
func NewDefaultInteractionConfig() schemas.InteractionConfig {
	return schemas.InteractionConfig{
		Steps:                   []schemas.InteractionStep{},
		MaxDepth:                5,
		MaxInteractionsPerDepth: 15,
		InteractionDelayMs:      500,
	}
}

// Logger defines a simple interface for logging within the DOM package.
type Logger interface {
	Warn(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// NopLogger is a default logger that does nothing.
type NopLogger struct{}

func (n *NopLogger) Warn(msg string, args ...interface{})  {}
func (n *NopLogger) Info(msg string, args ...interface{})  {}
func (n *NopLogger) Debug(msg string, args ...interface{}) {}
func (n *NopLogger) Error(msg string, args ...interface{}) {}

// StabilizationFunc waits for the application state to stabilize (e.g., network idle, layout complete).
type StabilizationFunc func(ctx context.Context) error

// CorePagePrimitives defines the minimal interface the interactor needs to control the underlying page engine.
// The browser's Session implementation will provide these. Selectors are expected to be XPath.
type CorePagePrimitives interface {
	// ExecuteClick simulates a click action.
	ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error
	// ExecuteType simulates typing text into a selector.
	ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error
	// ExecuteSelect handles dropdown selection by value.
	ExecuteSelect(ctx context.Context, selector string, value string) error
	// GetCurrentURL returns the URL of the current page state.
	GetCurrentURL() string
	// GetDOMSnapshot fetches the current HTML body for parsing.
	GetDOMSnapshot(ctx context.Context) (io.Reader, error)
	// IsVisible checks if the element matching the selector is visible according to the Layout Engine.
	IsVisible(ctx context.Context, selector string) bool
}
