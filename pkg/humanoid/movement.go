// pkg/humanoid/movement.go
package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
)

// Move moves the mouse from the current position to the target coordinates in a human-like manner.
func (h *Humanoid) Move(ctx context.Context, x, y float64, exec interfaces.Executor) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// If the current position is unknown, get it first.
	if h.currentPos.X < 0 || h.currentPos.Y < 0 {
		if err := h.updateCurrentPosition(ctx, exec); err != nil {
			return err
		}
	}

	target := Vector2D{X: x, Y: y}
	path, err := h.generateTrajectory(h.currentPos, target)
	if err != nil {
		return err
	}

	startTime := time.Now()
	lastDispatchTime := time.Now()

	for i, point := range path {
		// Check for context cancellation
		if err := ctx.Err(); err != nil {
			return err
		}

		// Apply noise for added realism
		elapsed := time.Since(startTime).Seconds()
		noisyPoint := h.applyNoise(point, elapsed)

		// Dispatch mouse move event
		dispatchTime := time.Now()
		if dispatchTime.Sub(lastDispatchTime) >= minDispatchInterval || i == len(path)-1 {
			moveEvent := input.DispatchMouseEvent(input.MouseMoved, noisyPoint.X, noisyPoint.Y)
			if err := exec.Execute(ctx, moveEvent); err != nil {
				// Don't stop on a single failed event, just log it.
				h.logger.Printf("Warning: could not dispatch mouse move event: %v", err)
			}
			lastDispatchTime = dispatchTime
		}

		// Sleep for the calculated interval
		if i < len(path)-1 {
			nextPoint := path[i+1]
			dist := nextPoint.Sub(point).Mag()
			// Velocity is inversely proportional to distance to target to simulate deceleration
			velocity := maxVelocity * (1.0 - (point.Sub(target).Mag() / h.currentPos.Sub(target).Mag()))
			velocity = math.Max(velocity, 100.0) // Minimum velocity
			sleepDuration := time.Duration(dist/velocity*1000) * time.Millisecond
			time.Sleep(sleepDuration)
		}
	}

	h.currentPos = target
	h.updateFatigue(0.05) // Moving the mouse increases fatigue

	return nil
}

// applyNoise combines Gaussian perturbation (tremor) and Perlin noise (drift).
func (h *Humanoid) applyNoise(point Vector2D, t float64) Vector2D {
	// Use dynamic config (affected by fatigue).
	cfg := h.dynamicConfig

	// 1. Gaussian Perturbation (High frequency tremor)
	perturbationStrength := cfg.GaussianStrength * (0.5 + h.rng.Float64())
	pX := h.rng.NormFloat64() * perturbationStrength
	pY := h.rng.NormFloat64() * perturbationStrength

	// 2. Perlin Noise (Low frequency drift/wander)
	driftX := h.noiseX.Noise1D(t*cfg.PerlinAmplitude) * cfg.PerlinAmplitude
	driftY := h.noiseY.Noise1D(t*cfg.PerlinAmplitude) * cfg.PerlinAmplitude

	return Vector2D{
		X: point.X + pX + driftX,
		Y: point.Y + pY + driftY,
	}
}
