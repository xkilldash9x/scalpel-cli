// internal/discovery/discovery.go
package discovery

import (
	"context"

	// an interface to abstract away the concrete browser session implementation.
	interfaces "github.com/xkilldash9x/scalpel-cli/internal/agent"
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
// It now operates on a SessionContext to allow for DOM-based and other interactive discoveries.
type Discoverer interface {
	Discover(ctx context.Context, session interfaces.SessionContext) ([]Technology, error)
}