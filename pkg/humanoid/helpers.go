// pkg/humanoid/helpers.go
package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
)

// updateFatigue modifies the fatigue level and adjusts the dynamic configuration.
func (h *Humanoid) updateFatigue(change float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.fatigueLevel += change
	h.fatigueLevel = math.Max(0.0, math.Min(1.0, h.fatigueLevel)) // Clamp between 0 and 1

	// As fatigue increases, movements become less precise.
	// Adjust dynamic config based on the new fatigue level.
	fatigueFactor := 1.0 + h.fatigueLevel // Scale from 1.0 to 2.0
	h.dynamicConfig.GaussianStrength = h.baseConfig.GaussianStrength * fatigueFactor
	h.dynamicConfig.PerlinAmplitude = h.baseConfig.PerlinAmplitude * fatigueFactor
}

// pause introduces a variable delay to simulate human pauses.
func (h *Humanoid) pause(baseDuration time.Duration) {
	// Add variability: pause for 70% to 130% of the base duration.
	variability := 0.7 + h.rng.Float64()*0.6
	duration := time.Duration(float64(baseDuration) * variability)
	time.Sleep(duration)
}

// GetCurrentPos returns the current known position of the mouse.
func (h *Humanoid) GetCurrentPos() (Vector2D, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// In a real scenario, you might need to query the browser if the position is unknown.
	// For now, we return the last known position.
	return h.currentPos, nil
}

// MoveTo is a convenience wrapper around the main Move method.
func (h *Humanoid) MoveTo(ctx context.Context, point Vector2D, exec interfaces.Executor) error {
	return h.Move(ctx, point.X, point.Y, exec)
}

// updateCurrentPosition fetches the mouse position from the browser if it's unknown.
func (h *Humanoid) updateCurrentPosition(ctx context.Context, exec interfaces.Executor) error {
	// This is a placeholder. A real implementation would require a JS snippet
	// to get the mouse position and return it, as chromedp doesn't track it.
	// For now, we'll assume a starting position if one is not set.
	if h.currentPos.X < 0 || h.currentPos.Y < 0 {
		h.logger.Println("Current position unknown, assuming (0,0)")
		h.currentPos = Vector2D{X: 0, Y: 0}
	}
	return nil
}
