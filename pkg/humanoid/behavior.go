// pkg/humanoid/behavior.go
package humanoid

import (
	"context"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// Hesitate simulates a pause with subtle, noisy cursor movements (idling behavior).
// The cursor stays in the general vicinity of its starting position.
// This is used during CognitivePause and long inter-key delays (Input Synchronization).
func (h *Humanoid) Hesitate(duration time.Duration) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		startTime := time.Now()
		deadline := startTime.Add(duration)

		h.mu.Lock()
		startPos := h.currentPos
		// Use dynamic config (affected by fatigue) for amplitude.
		cfg := h.dynamicConfig
		// Idle movement amplitude is typically larger than movement drift.
		amplitude := cfg.PerlinAmplitude * 2.5
		noiseX, noiseY := h.noiseX, h.noiseY
		h.mu.Unlock()

		if noiseX == nil || noiseY == nil {
			// Fallback to simple pause if noise generators are unavailable.
			return h.pause(ctx, float64(duration.Milliseconds()), 0)
		}

		// Lower frequency for idle movement compared to active movement drift.
		noiseFreq := 0.8

		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return ctx.Err()
			}

			t := time.Since(startTime).Seconds()
			tInput := t * noiseFreq

			// Calculate displacement using Perlin noise (low frequency wander).
			dX := noiseX.Noise1D(tInput) * amplitude
			dY := noiseY.Noise1D(tInput) * amplitude

			nextPos := startPos.Add(Vector2D{X: dX, Y: dY})

			// Apply Gaussian tremor on top (high frequency noise).
			noisyPos := h.applyGaussianNoise(nextPos)

			// Dispatch the mouse movement event.
			dispatchMouse := input.DispatchMouseEvent(input.MouseMoved, noisyPos.X, noisyPos.Y)
			if err := dispatchMouse.Do(ctx); err != nil {
				h.logger.Warn("Humanoid: Hesitate move dispatch failed", zap.Error(err))
				// If dispatch fails (e.g., navigation), check context and potentially stop.
				if ctx.Err() != nil {
					return ctx.Err()
				}
				// Continue loop if context is fine but dispatch failed transiently.
			} else {
				// Update internal position only on successful dispatch.
				h.mu.Lock()
				h.currentPos = noisyPos
				h.mu.Unlock()
			}

			// Sleep interval (8-18ms, mimicking mouse polling rate variability).
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

	// Use dynamic config (affected by fatigue) for strength.
	// Randomized strength factor (0.5x to 1.5x).
	strength := h.dynamicConfig.GaussianStrength * (0.5 + h.rng.Float64())
	pX := h.rng.NormFloat64() * strength
	pY := h.rng.NormFloat64() * strength

	return Vector2D{
		X: point.X + pX,
		Y: point.Y + pY,
	}
}
