// File:         internal/agent/interfaces.go
// Description:  Defines the core internal interfaces for the agent's components.
//
package agent

import (
	"context"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Mind defines the interface for the agent's cognitive core (The OODA loop implementation).
type Mind interface {
	// Start begins the cognitive processing loop.
	Start(ctx context.Context) error

	// SetMission updates the Mind's current objective.
	SetMission(mission schemas.Mission)

	// Stop gracefully shuts down the cognitive processes.
	Stop()
}

// SessionContext defines the interface for interacting with the environment (e.g., a browser session).
// This interface is implemented by the component managing the browser (e.g., Humanoid controller).
type SessionContext interface {
	Navigate(url string) error
	Click(selector string) error
	Type(selector, text string) error
	Submit(selector string) error
	ScrollPage(direction string) error
	// WaitForAsync waits for a specified duration for asynchronous activities to settle.
	WaitForAsync(durationMs int) error
}

// LLMClient and related types (ModelTier, GenerationRequest, GenerationOptions)
// are defined in api/schemas/schemas.go as they are part of the public API contract.