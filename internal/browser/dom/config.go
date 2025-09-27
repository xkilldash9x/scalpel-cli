// browser/dom/config.go
package dom

import (
	"context"
	"io"
    // humanoid import removed as it is unused in this file.
)

// InteractionConfig defines how the Interactor should behave during exploration.
type InteractionConfig struct {
	MaxDepth                int
	MaxInteractionsPerDepth int
	InteractionDelayMs      int // Delay immediately after an interaction (if no major state change)
	PostInteractionWaitMs   int // Wait time after stabilization before starting the next discovery phase
}

// HumanoidConfig defines parameters for simulating human behavior timings.
type HumanoidConfig struct {
	Enabled        bool
	KeyHoldMeanMs  float64 // Average time a key is held down during typing
	ClickHoldMinMs int     // Minimum time the mouse button is held down
	ClickHoldMaxMs int     // Maximum time the mouse button is held down
}

// Default Configs
func NewDefaultInteractionConfig() InteractionConfig {
	return InteractionConfig{
		MaxDepth:                5,
		MaxInteractionsPerDepth: 5,
		InteractionDelayMs:      500,
		PostInteractionWaitMs:   1000,
	}
}

func NewDefaultHumanoidConfig() HumanoidConfig {
	return HumanoidConfig{
		Enabled:        true,
		KeyHoldMeanMs:  65.0,
		ClickHoldMinMs: 50,
		ClickHoldMaxMs: 150,
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
