// Filename: internal/humanoid/trajectory.go
package humanoid

import (
	"context"
	"math"
	"time"

	// CRITICAL: Low-level input access is fundamentally required for high-fidelity simulation.
	"github.com/chromedp/cdproto/input"
	// NOTE: The direct dependency on `chromedp` is removed from this file's logic.
	"go.uber.org/zap"
)

// computeEaseInOutCubic provides a smooth acceleration and deceleration profile.
func computeEaseInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	return 1 - math.Pow(-2*t+2, 3)/2
}

// calculateFittsLaw determines movement duration based on Fitts's Law.
func (h *Humanoid) calculateFittsLaw(distance float64) time.Duration {
	const W = 30.0 // Assumed default target width (W) in pixels.

	// Index of Difficulty (ID)
	id := math.Log2(1.0 + distance/W)

	h.mu.Lock()
	A := h.dynamicConfig.FittsA
	B := h.dynamicConfig.FittsB
	rng := h.rng
	h.mu.Unlock()

	// Movement Time (MT) in milliseconds
	mt := A + B*id

	// Add slight randomization (+/- 15%)
	mt += mt * (rng.Float64()*0.3 - 0.15)

	return time.Duration(mt) * time.Millisecond
}

// generateIdealPath creates a human like trajectory (Bezier curve) deformed by the potential field.
func (h *Humanoid) generateIdealPath(start, end Vector2D, field *PotentialField, numSteps int) []Vector2D {
	p0, p3 := start, end
	mainVec := end.Sub(start)
	dist := mainVec.Mag()

	if dist < 1.0 || numSteps <= 1 {
		return []Vector2D{end}
	}

	mainDir := mainVec.Normalize()

	// Sample forces at 1/3rd and 2/3rds along the path.
	samplePoint1 := start.Add(mainDir.Mul(dist / 3.0))
	force1 := field.CalculateNetForce(samplePoint1)
	samplePoint2 := start.Add(mainDir.Mul(dist * 2.0 / 3.0))
	force2 := field.CalculateNetForce(samplePoint2)

	// Create control points based on the forces.
	p1 := samplePoint1.Add(force1.Mul(dist * 0.1))
	p2 := samplePoint2.Add(force2.Mul(dist * 0.1))

	path := make([]Vector2D, numSteps)
	for i := 0; i < numSteps; i++ {
		t := float64(i) / float64(numSteps-1)
		// Cubic Bezier curve formula.
		omt := 1.0 - t
		omt2 := omt * omt
		omt3 := omt2 * omt
		t2 := t * t
		t3 := t2 * t

		path[i] = p0.Mul(omt3).Add(p1.Mul(3*omt2*t)).Add(p2.Mul(3*omt*t2)).Add(p3.Mul(t3))
	}

	return path
}

// applyGaussianNoise applies a small, random offset to a point.
// This function was not provided but is called in simulateTrajectory, so a plausible implementation is added.
func (h *Humanoid) applyGaussianNoise(point Vector2D) Vector2D {
	h.mu.Lock()
	stdDev := h.dynamicConfig.GaussianNoiseStdDev
	rng := h.rng
	h.mu.Unlock()

	offsetX := rng.NormFloat64() * stdDev
	offsetY := rng.NormFloat64() * stdDev
	return Vector2D{X: point.X + offsetX, Y: point.Y + offsetY}
}

// simulateTrajectory moves the mouse along a generated path, dispatching events.
// This function is now decoupled from chromedp and uses the injected h.executor.
func (h *Humanoid) simulateTrajectory(ctx context.Context, start, end Vector2D, field *PotentialField, buttonState input.MouseButton) (Vector2D, error) {
	dist := start.Dist(end)
	h.mu.Lock()
	h.lastMovementDistance = dist
	h.mu.Unlock()

	duration := h.calculateFittsLaw(dist)
	numSteps := int(duration.Seconds() * 100)
	if numSteps < 2 {
		numSteps = 2
	}

	if field == nil {
		field = NewPotentialField()
	}

	idealPath := h.generateIdealPath(start, end, field, numSteps)

	var velocity Vector2D
	startTime := time.Now()
	lastPos := start
	lastTime := startTime

	for i := 0; i < len(idealPath); i++ {
		t := float64(i) / float64(len(idealPath)-1)
		easedT := computeEaseInOutCubic(t)

		pathIndex := int(easedT * float64(len(idealPath)-1))
		if pathIndex >= len(idealPath) {
			pathIndex = len(idealPath) - 1
		}
		currentPos := idealPath[pathIndex]

		// Calculate the target time for this step.
		currentTime := startTime.Add(time.Duration(easedT * float64(duration)))

		// Use context-aware sleep to adhere to Fitts's law timing.
		sleepDur := time.Until(currentTime)
		if sleepDur > 0 {
			// REFACTORED: Use the executor interface instead of a direct chromedp call.
			if err := h.executor.Sleep(ctx, sleepDur); err != nil {
				return velocity, err
			}
		}

		// Update velocity based on actual time elapsed.
		now := time.Now()
		dt := now.Sub(lastTime).Seconds()
		if dt > 1e-6 {
			velocity = currentPos.Sub(lastPos).Mul(1.0 / dt)
		}
		lastPos = currentPos
		lastTime = now

		// -- Noise Combination (Relies on real-time elapsed) --
		h.mu.Lock()
		perlinMagnitude := h.dynamicConfig.PerlinAmplitude
		rng := h.rng
		h.mu.Unlock()

		perlinFrequency := 0.8
		timeElapsed := now.Sub(startTime).Seconds()
		perlinDrift := Vector2D{
			X: h.noiseX.Noise1D(timeElapsed*perlinFrequency) * perlinMagnitude,
			Y: h.noiseY.Noise1D(timeElapsed*perlinFrequency) * perlinMagnitude,
		}

		driftAppliedPos := currentPos.Add(perlinDrift)
		finalPerturbedPoint := h.applyGaussianNoise(driftAppliedPos)

		// Dispatch the mouse movement event.
		dispatchMouse := input.DispatchMouseEvent(input.MouseMoved, finalPerturbedPoint.X, finalPerturbedPoint.Y)

		if buttonState != "none" {
			dispatchMouse = dispatchMouse.WithButton(buttonState)
			var buttons int64
			switch buttonState {
			case "left":
				buttons = 1
			case "right":
				buttons = 2
			case "middle":
				buttons = 4
			}
			if buttons > 0 {
				dispatchMouse = dispatchMouse.WithButtons(buttons)
			}
		}

		// REFACTORED: Use the executor interface instead of a direct dispatchMouse.Do(ctx) call.
		if err := h.executor.DispatchMouseEvent(ctx, dispatchMouse); err != nil {
			h.logger.Warn("Humanoid: Failed to dispatch mouse move event during simulation", zap.Error(err))
			return velocity, err
		}

		// Update the internal position tracker.
		h.mu.Lock()
		h.currentPos = finalPerturbedPoint
		h.mu.Unlock()

		// Simulate browser rendering/event loop delay.
		// Ensure Intn argument is positive
		randPart := 0
		if 4 > 0 {
			randPart = rng.Intn(4)
		}
		sleepDuration := time.Duration(2+randPart) * time.Millisecond

		// REFACTORED: Use the executor interface for the final sleep.
		if err := h.executor.Sleep(ctx, sleepDuration); err != nil {
			return velocity, err
		}
	}

	return velocity, nil
}
