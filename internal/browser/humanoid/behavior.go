package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// CognitivePause simulates a pause with subtle, noisy cursor movements (idling behavior).
func (h *Humanoid) CognitivePause(ctx context.Context, meanMs, stdDevMs float64) error {
	h.mu.Lock()
	fatigueFactor := 1.0 + h.fatigueLevel
	rng := h.rng
	h.mu.Unlock()

	duration := time.Duration(fatigueFactor*(meanMs+rng.NormFloat64()*stdDevMs)) * time.Millisecond
	if duration <= 0 {
		return nil
	}
	h.recoverFatigue(duration)

	// For longer pauses, simulate more active idling.
	if duration > 100*time.Millisecond {
		return h.Hesitate(ctx, duration)
	}

	return h.executor.Sleep(ctx, duration)
}

// Hesitate simulates a user pausing with continuous, subtle cursor movements.
func (h *Humanoid) Hesitate(ctx context.Context, duration time.Duration) error {
	h.mu.Lock()
	startPos := h.currentPos
	rng := h.rng
	// Get the current button state to maintain it during hesitation (e.g., for dragging).
	currentButtons := h.calculateButtonsBitfield(h.currentButtonState)
	h.mu.Unlock()

	startTime := time.Now()

	for time.Since(startTime) < duration {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		h.mu.Lock()
		// Calculate a small, random target nearby.
		targetPos := startPos.Add(Vector2D{
			X: (rng.Float64() - 0.5) * 5,
			Y: (rng.Float64() - 0.5) * 5,
		})

		randRange := 100
		randIntVal := rng.Intn(randRange)
		h.mu.Unlock()

		// Dispatch the movement event using the canonical schema type.
		eventData := schemas.MouseEventData{
			Type:    schemas.MouseMove,
			X:       targetPos.X,
			Y:       targetPos.Y,
			Button:  schemas.ButtonNone,
			Buttons: currentButtons,
		}

		if err := h.executor.DispatchMouseEvent(ctx, eventData); err != nil {
			return err
		}

		h.mu.Lock()
		h.currentPos = targetPos
		h.mu.Unlock()

		pauseDuration := time.Duration(50+randIntVal) * time.Millisecond

		// Ensure we don't overshoot the total duration.
		if time.Since(startTime)+pauseDuration > duration {
			pauseDuration = duration - time.Since(startTime)
		}
		if pauseDuration <= 0 {
			break
		}

		if err := h.executor.Sleep(ctx, pauseDuration); err != nil {
			return err
		}
	}
	return nil
}

// applyGaussianNoise adds high-frequency "tremor" to a mouse coordinate.
func (h *Humanoid) applyGaussianNoise(point Vector2D) Vector2D {
	h.mu.Lock()
	defer h.mu.Unlock()

	strength := h.dynamicConfig.GaussianStrength * (0.5 + h.rng.Float64())
	pX := h.rng.NormFloat64() * strength
	pY := h.rng.NormFloat64() * strength

	return Vector2D{X: point.X + pX, Y: point.Y + pY}
}

// applyFatigueEffects adjusts the dynamic configuration based on the current fatigue level.
func (h *Humanoid) applyFatigueEffects() {
	fatigueFactor := 1.0 + h.fatigueLevel

	h.dynamicConfig.GaussianStrength = h.baseConfig.GaussianStrength * fatigueFactor
	h.dynamicConfig.PerlinAmplitude = h.baseConfig.PerlinAmplitude * fatigueFactor
	h.dynamicConfig.FittsA = h.baseConfig.FittsA * fatigueFactor

	h.dynamicConfig.TypoRate = h.baseConfig.TypoRate * (1.0 + h.fatigueLevel*2.0)
	h.dynamicConfig.TypoRate = math.Min(0.25, h.dynamicConfig.TypoRate)
}

// updateFatigue modifies the fatigue level based on action intensity.
func (h *Humanoid) updateFatigue(intensity float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	increase := h.baseConfig.FatigueIncreaseRate * intensity
	h.fatigueLevel += increase
	h.fatigueLevel = math.Min(1.0, h.fatigueLevel)

	h.applyFatigueEffects()
}

// recoverFatigue simulates recovery from fatigue during pauses.
func (h *Humanoid) recoverFatigue(duration time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	recovery := h.baseConfig.FatigueRecoveryRate * duration.Seconds()
	h.fatigueLevel -= recovery
	h.fatigueLevel = math.Max(0.0, h.fatigueLevel)

	h.applyFatigueEffects()
}

// calculateButtonsBitfield converts the internal MouseButton state into the standard bitfield representation.
func (h *Humanoid) calculateButtonsBitfield(buttonState schemas.MouseButton) int64 {
	var buttons int64
	switch buttonState {
	case schemas.ButtonLeft:
		buttons = 1
	case schemas.ButtonRight:
		buttons = 2
	case schemas.ButtonMiddle:
		buttons = 4
	}
	return buttons
}
