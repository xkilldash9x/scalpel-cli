// pkg/humanoid/behavior.go
package humanoid

import (
	"context"
	"math"
	"time"

	// CRITICAL IMPORT: Required for input.MouseButtonNone and input.DispatchMouseEvent
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// CognitivePause simulates a pause with subtle, noisy cursor movements (idling behavior).
// It also handles fatigue recovery.
func (h *Humanoid) CognitivePause(ctx context.Context, meanMs, stdDevMs float64) error {
	h.mu.Lock()
	// Fatigue makes cognitive processes slower.
	fatigueFactor := 1.0 + h.fatigueLevel
	rng := h.rng
	h.mu.Unlock()

	// Calculate the duration of the pause.
	duration := time.Duration(fatigueFactor*(meanMs+rng.NormFloat64()*stdDevMs)) * time.Millisecond
	if duration <= 0 {
		return nil
	}

	// Recover fatigue during the pause.
	h.recoverFatigue(duration)

	// For longer pauses (> 100ms), simulate the cursor idling (Hesitate).
	if duration > 100*time.Millisecond {
		return h.Hesitate(duration).Do(ctx)
	}

	// For shorter pauses, a simple sleep is sufficient (no mouse movement).
	return h.pause(ctx, duration)
}

// Hesitate simulates a pause with subtle, noisy cursor movements (idling behavior).
func (h *Humanoid) Hesitate(duration time.Duration) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		startTime := time.Now()
		deadline := startTime.Add(duration)

		h.mu.Lock()
		startPos := h.currentPos
		cfg := h.dynamicConfig
		// Amplitude for idling.
		amplitude := cfg.PerlinAmplitude * 1.5
		noiseX, noiseY := h.noiseX, h.noiseY
		// Get the current button state to dispatch realistic MouseMoved events.
		buttonState := h.currentButtonState
		h.mu.Unlock()

		if noiseX == nil || noiseY == nil {
			return h.pause(ctx, duration)
		}

		// Frequency of the idle movement (wandering speed).
		noiseFreq := 0.5

		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			t := time.Since(startTime).Seconds()
			tInput := t * noiseFreq

			dX := noiseX.Noise1D(tInput) * amplitude
			dY := noiseY.Noise1D(tInput) * amplitude
			nextPos := startPos.Add(Vector2D{X: dX, Y: dY})

			// Apply high-frequency tremor.
			noisyPos := h.applyGaussianNoise(nextPos)

			dispatchMouse := input.DispatchMouseEvent(input.MouseMoved, noisyPos.X, noisyPos.Y)
			// Include button state if pressed.
			if buttonState != input.MouseButtonNone {
				dispatchMouse = dispatchMouse.WithButton(buttonState)
			}

			if err := dispatchMouse.Do(ctx); err != nil {
				h.logger.Warn("Humanoid: Hesitate move dispatch failed", zap.Error(err))
				// If dispatch fails (e.g., navigation), stop the hesitation loop.
				return err
			} else {
				h.mu.Lock()
				h.currentPos = noisyPos
				h.mu.Unlock()
			}

			// Sleep interval between mouse events (8-18ms).
			h.mu.Lock()
			sleepDuration := time.Duration(h.rng.Intn(10)+8) * time.Millisecond
			h.mu.Unlock()

			select {
			case <-time.After(sleepDuration):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
}

// applyGaussianNoise adds high-frequency tremor.
func (h *Humanoid) applyGaussianNoise(point Vector2D) Vector2D {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Strength varies slightly randomly around the dynamic config value.
	strength := h.dynamicConfig.GaussianStrength * (0.5 + h.rng.Float64())
	pX := h.rng.NormFloat64() * strength
	pY := h.rng.NormFloat64() * strength
	return Vector2D{X: point.X + pX, Y: point.Y + pY}
}

// pause is a simple, context-aware sleep helper.
func (h *Humanoid) pause(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// applyFatigueEffects updates the dynamic configuration based on the current fatigueLevel.
// Assumes the mutex (h.mu) is already held.
func (h *Humanoid) applyFatigueEffects() {
	// Fatigue factor (1.0 when rested, up to 2.0 when exhausted).
	fatigueFactor := 1.0 + h.fatigueLevel

	// Apply effects: movements become less precise and slower.
	h.dynamicConfig.GaussianStrength = h.baseConfig.GaussianStrength * fatigueFactor
	h.dynamicConfig.PerlinAmplitude = h.baseConfig.PerlinAmplitude * fatigueFactor
	h.dynamicConfig.FittsA = h.baseConfig.FittsA * fatigueFactor
	// Typing accuracy decreases more sharply (e.g., factor of up to 3x at max fatigue).
	h.dynamicConfig.TypoRate = h.baseConfig.TypoRate * (1.0 + h.fatigueLevel*2.0)
	h.dynamicConfig.TypoRate = math.Min(0.25, h.dynamicConfig.TypoRate)
}

// updateFatigue modifies the fatigue level based on action intensity and adjusts the dynamic configuration.
func (h *Humanoid) updateFatigue(intensity float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Intensity represents the cognitive/physical load (normalized 0.0 to 1.0 typically)
	increase := h.baseConfig.FatigueIncreaseRate * intensity
	h.fatigueLevel += increase
	h.fatigueLevel = math.Min(1.0, h.fatigueLevel) // Clamp at 1.0

	h.applyFatigueEffects()
}

// recoverFatigue simulates recovery during pauses or inactivity.
func (h *Humanoid) recoverFatigue(duration time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Recovery is proportional to the duration of the pause (seconds).
	recovery := h.baseConfig.FatigueRecoveryRate * duration.Seconds()
	h.fatigueLevel -= recovery
	h.fatigueLevel = math.Max(0.0, h.fatigueLevel) // Clamp at 0.0

	h.applyFatigueEffects()
}