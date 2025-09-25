package humanoid

import (
	"context"
	"math"
	"time"
)

// CognitivePause simulates a pause with subtle, noisy cursor movements (idling behavior).
// It models the time a user might take to think before the next action.
func (h *Humanoid) CognitivePause(ctx context.Context, meanMs, stdDevMs float64) error {
	h.mu.Lock()
	// Fatigue makes cognitive processes slower.
	fatigueFactor := 1.0 + h.fatigueLevel
	rng := h.rng
	h.mu.Unlock()

	// Calculate the duration of the pause using a normal distribution.
	duration := time.Duration(fatigueFactor*(meanMs+rng.NormFloat64()*stdDevMs)) * time.Millisecond
	if duration <= 0 {
		return nil
	}

	// Recover from fatigue during the pause.
	h.recoverFatigue(duration)

	// For longer pauses, simulate the cursor idling by calling Hesitate.
	if duration > 100*time.Millisecond {
		return h.Hesitate(ctx, duration)
	}

	// For very short pauses, a simple sleep is sufficient and more efficient.
	return h.executor.Sleep(ctx, duration)
}

// Hesitate simulates a user pausing with subtle, continuous cursor movements over a set duration.
// This is used for longer cognitive pauses or to simulate indecision.
func (h *Humanoid) Hesitate(ctx context.Context, duration time.Duration) error {
	h.mu.Lock()
	startPos := h.currentPos
	rng := h.rng
	// Capture the current button state to maintain it during hesitation (e.g., for dragging).
	currentButtons := h.calculateButtonsBitfield(h.currentButtonState)
	h.mu.Unlock()

	startTime := time.Now()

	// Loop until the total duration has elapsed.
	for time.Since(startTime) < duration {
		// Always check for context cancellation to allow for graceful shutdown.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		h.mu.Lock()
		// Calculate a small, random target position near the starting point.
		targetPos := startPos.Add(Vector2D{
			X: (rng.Float64() - 0.5) * 5, // Small random offset on X-axis
			Y: (rng.Float64() - 0.5) * 5, // Small random offset on Y-axis
		})
		
		// Generate a random pause duration for the micro-movement.
        randRange := 100
		randIntVal := rng.Intn(randRange)
		h.mu.Unlock()

		// Create the generic mouse event data.
		eventData := MouseEventData{
			Type:    MouseMove,
			X:       targetPos.X,
			Y:       targetPos.Y,
			Button:  ButtonNone,      // This is a move event, not a click.
			Buttons: currentButtons,  // Maintain the held button state (important for dragging).
		}

		// Dispatch the event via the executor interface.
		if err := h.executor.DispatchMouseEvent(ctx, eventData); err != nil {
			return err
		}

		// Update the internal position tracker.
		h.mu.Lock()
		h.currentPos = targetPos
		h.mu.Unlock()
		
		// Wait a bit before the next micro-movement.
		pauseDuration := time.Duration(50+randIntVal) * time.Millisecond

		// Ensure the next pause doesn't exceed the total remaining duration.
		if time.Since(startTime)+pauseDuration > duration {
			pauseDuration = duration - time.Since(startTime)
		}

		if pauseDuration <= 0 {
			break
		}

		// Execute the pause via the executor (which is context-aware).
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
	
	// Strength varies slightly randomly around the dynamic config value.
	strength := h.dynamicConfig.GaussianStrength * (0.5 + h.rng.Float64())
	pX := h.rng.NormFloat64() * strength
	pY := h.rng.NormFloat64() * strength
	
	return Vector2D{X: point.X + pX, Y: point.Y + pY}
}

// applyFatigueEffects adjusts the dynamic configuration based on the current fatigue level.
// As fatigue increases, movements become slower and less precise.
func (h *Humanoid) applyFatigueEffects() {
	// fatigueFactor ranges from 1.0 (rested) to 2.0 (exhausted).
	fatigueFactor := 1.0 + h.fatigueLevel

	// Apply effects: movements become less precise and slower.
	h.dynamicConfig.GaussianStrength = h.baseConfig.GaussianStrength * fatigueFactor
	h.dynamicConfig.PerlinAmplitude = h.baseConfig.PerlinAmplitude * fatigueFactor
	h.dynamicConfig.FittsA = h.baseConfig.FittsA * fatigueFactor

	// Typing accuracy decreases more sharply.
	h.dynamicConfig.TypoRate = h.baseConfig.TypoRate * (1.0 + h.fatigueLevel*2.0)
	h.dynamicConfig.TypoRate = math.Min(0.25, h.dynamicConfig.TypoRate) // Cap typo rate at 25%.
}

// updateFatigue modifies the fatigue level based on action intensity.
func (h *Humanoid) updateFatigue(intensity float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Intensity represents the cognitive/physical load (typically normalized from 0.0 to 1.0).
	increase := h.baseConfig.FatigueIncreaseRate * intensity
	h.fatigueLevel += increase
	h.fatigueLevel = math.Min(1.0, h.fatigueLevel) // Clamp fatigue at 1.0.

	h.applyFatigueEffects()
}

// recoverFatigue simulates recovery from fatigue during pauses or inactivity.
func (h *Humanoid) recoverFatigue(duration time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Recovery is proportional to the duration of the pause.
	recovery := h.baseConfig.FatigueRecoveryRate * duration.Seconds()
	h.fatigueLevel -= recovery
	h.fatigueLevel = math.Max(0.0, h.fatigueLevel) // Clamp fatigue at 0.0.

	h.applyFatigueEffects()
}

// calculateButtonsBitfield converts the internal MouseButton state into the standard bitfield
// representation required by browser automation protocols.
func (h *Humanoid) calculateButtonsBitfield(buttonState MouseButton) int64 {
	var buttons int64
	switch buttonState {
	case ButtonLeft:
		buttons = 1
	case ButtonRight:
		buttons = 2
	case ButtonMiddle:
		buttons = 4
	}
	return buttons
}