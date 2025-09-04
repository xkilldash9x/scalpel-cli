package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// CognitivePause simulates a pause with subtle, noisy cursor movements (idling behavior).
// This is used for visual search, reaction time, and input synchronization.
func (h *Humanoid) CognitivePause(ctx context.Context, meanMs, stdDevMs float64) error {
	h.mu.Lock()
	fatigueFactor := 1.0 + h.fatigueLevel // Fatigue makes pauses longer
	rng := h.rng
	h.mu.Unlock()

	duration := time.Duration(fatigueFactor*(meanMs+rng.NormFloat64()*stdDevMs)) * time.Millisecond
	if duration <= 0 {
		return nil
	}

	// For longer pauses, simulate the cursor idling.
	if duration > 100*time.Millisecond {
		return h.Hesitate(duration).Do(ctx)
	}

	// For shorter pauses, a simple sleep is sufficient.
	return h.pause(ctx, duration)
}

// Hesitate simulates a pause with subtle, noisy cursor movements.
func (h *Humanoid) Hesitate(duration time.Duration) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		startTime := time.Now()
		deadline := startTime.Add(duration)

		h.mu.Lock()
		startPos := h.currentPos
		cfg := h.dynamicConfig
		amplitude := cfg.PerlinAmplitude * 2.5
		noiseX, noiseY := h.noiseX, h.noiseY
		h.mu.Unlock()

		if noiseX == nil || noiseY == nil {
			return h.pause(ctx, duration)
		}

		noiseFreq := 0.8

		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			t := time.Since(startTime).Seconds()
			tInput := t * noiseFreq

			dX := noiseX.Noise1D(tInput) * amplitude
			dY := noiseY.Noise1D(tInput) * amplitude
			nextPos := startPos.Add(Vector2D{X: dX, Y: dY})

			noisyPos := h.applyGaussianNoise(nextPos)

			dispatchMouse := input.DispatchMouseEvent(input.MouseMoved, noisyPos.X, noisyPos.Y)
			if err := dispatchMouse.Do(ctx); err != nil {
				h.logger.Warn("Humanoid: Hesitate move dispatch failed", zap.Error(err))
				if ctx.Err() != nil {
					return ctx.Err()
				}
			} else {
				h.mu.Lock()
				h.currentPos = noisyPos
				h.mu.Unlock()
			}

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
	strength := h.dynamicConfig.GaussianStrength * (0.5 + h.rng.Float64())
	pX := h.rng.NormFloat64() * strength
	pY := h.rng.NormFloat64() * strength
	return Vector2D{X: point.X + pX, Y: point.Y + pY}
}

// updateFatigue modifies the fatigue level and adjusts the dynamic configuration.
func (h *Humanoid) updateFatigue(intensity float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	increase := h.baseConfig.FatigueIncreaseRate * intensity
	h.fatigueLevel += increase
	h.fatigueLevel = math.Min(1.0, h.fatigueLevel) // Clamp at 1.0

	// As fatigue increases, movements become less precise and slower.
	fatigueFactor := 1.0 + h.fatigueLevel
	h.dynamicConfig.GaussianStrength = h.baseConfig.GaussianStrength * fatigueFactor
	h.dynamicConfig.PerlinAmplitude = h.baseConfig.PerlinAmplitude * fatigueFactor
	h.dynamicConfig.FittsA = h.baseConfig.FittsA * fatigueFactor
	h.dynamicConfig.TypoRate = h.baseConfig.TypoRate * (1.0 + h.fatigueLevel*2.0)
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