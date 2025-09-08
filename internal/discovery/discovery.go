// internal/discovery/discovery.go
package discovery

import (
	"context"
	// removed chromedp dependency. interfaces must be implementation agnostic.
)

// Technology represents a detected web technology.
// this relates more to fingerprinting than pure discovery, but it lives here for now.
type Technology struct {
	Name    string
	Version string
	// maybe add a confidence score later
}

// Discoverer defines the interface for technology discovery modules.
// we keep this interface generic and decoupled from the underlying browser implementation.
type Discoverer interface {
	Discover(ctx context.Context, targetURL string) ([]Technology, error)
}
