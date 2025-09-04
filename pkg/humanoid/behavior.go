// pkg/humanoid/behavior.go
package humanoid

import (
	"context"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
)

// Hesitate simulates a user pausing to think or locate an element.
// The duration of hesitation is influenced by the current fatigue level.
func (h *Humanoid) Hesitate() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Base hesitation duration
	basePause := time.Duration(h.rng.Intn(250)+50) * time.Millisecond // 50-300ms

	// Longer pauses when fatigued
	fatigueFactor := 1.0 + h.fatigueLevel*2 // Up to 3x longer
	adjustedPause := time.Duration(float64(basePause) * fatigueFactor)

	h.pause(adjustedPause)
}

// Overshoot simulates the mouse moving slightly past the target and then correcting.
func (h *Humanoid) Overshoot(target Vector2D, exec interfaces.Executor) error {
	// Lock is handled by the methods this function calls (Move)

	distToTarget := h.currentPos.Sub(target).Mag()
	if distToTarget < 10 { // Don't overshoot if already very close
		return nil
	}

	// Calculate an overshoot point beyond the target
	overshootVector := target.Sub(h.currentPos).Normalize()
	overshootAmount := (h.rng.Float64()*0.1 + 0.05) * distToTarget // 5-15% of the distance
	overshootPoint := target.Add(overshootVector.Mul(overshootAmount))

	// Move to the overshoot point
	err := h.Move(context.Background(), overshootPoint.X, overshootPoint.Y, exec)
	if err != nil {
		// The standard logger doesn't have Warn, so we use Printf.
		h.logger.Printf("WARN: Overshoot movement failed: %v", err)
		return err
	}

	// Pause briefly before correcting
	h.pause(time.Duration(h.rng.Intn(100)+50) * time.Millisecond) // 50-150ms pause

	// Correct back to the actual target
	return h.Move(context.Background(), target.X, target.Y, exec)
}
