// pkg/humanoid/trajectory.go
package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/input"
	"go.uber.org/zap"
)

// computeEaseInOutCubic provides a smooth acceleration and deceleration profile.
func computeEaseInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	return 1 - math.Pow(-2*t+2, 3)/2
}

// generateIdealPath creates a human like trajectory (Bezier curve) deformed by the potential field.
func (h *Humanoid) generateIdealPath(start, end Vector2D, field *PotentialField, numSteps int) []Vector2D {
	p0, p3 := start, end
	mainVec := end.Sub(start)
	dist := mainVec.Mag()

	if dist < 1.0 || numSteps <= 0 {
		return []Vector2D{end}
	}

	mainDir := mainVec.Normalize()

	// Sample forces at 1/3rd and 2/3rds along the path.
	samplePoint1 := start.Add(mainDir.Mul(dist / 3.0))
	force1 := field.CalculateNetForce(samplePoint1)
	samplePoint2 := start.Add(mainDir.Mul(dist * 2.0 / 3.0))
	force2 := field.CalculateNetForce(samplePoint2)

	// Create control points based on the forces.
	// The magnitude of the force determines the "bend" of the curve.
	p1 := samplePoint1.Add(force1.Mul(dist * 0.1))
	p2 := samplePoint2.Add(force2.Mul(dist * 0.1))

	path := make([]Vector2D, numSteps)
	for i := 0; i < numSteps; i++ {
		t := float64(i) / float64(numSteps-1)
		// Cubic Bezier curve formula.
		// B(t) = (1-t)^3 * P0 + 3(1-t)^2 * t * P1 + 3(1-t) * t^2 * P2 + t^3 * P3
		omt := 1.0 - t
		omt2 := omt * omt
		omt3 := omt2 * omt
		t2 := t * t
		t3 := t2 * t

		path[i] = p0.Mul(omt3).Add(p1.Mul(3 * omt2 * t)).Add(p2.Mul(3 * omt * t2)).Add(p3.Mul(t3))
	}

	return path
}

// simulateTrajectory moves the mouse along a generated path, dispatching events.
func (h *Humanoid) simulateTrajectory(ctx context.Context, start, end Vector2D, field *PotentialField, buttonState input.MouseButton) (Vector2D, error) {
	dist := start.Dist(end)
	h.mu.Lock()
	h.lastMovementDistance = dist
	h.mu.Unlock()

	// Fitts's Law to determine movement duration.
	duration := h.calculateFittsLaw(dist)
	numSteps := int(duration.Seconds() * 100) // ~100 events per second.
	if numSteps < 2 {
		numSteps = 2
	}

	// Generate the ideal path.
	idealPath := h.generateIdealPath(start, end, field, numSteps)

	var velocity Vector2D
	startTime := time.Now()
	lastPos := start

	for i := 0; i < len(idealPath); i++ {
		t := float64(i) / float64(len(idealPath)-1)
		easedT := computeEaseInOutCubic(t)

		// Calculate the ideal position on the path.
		pathIndex := int(easedT * float64(len(idealPath)-1))
		currentPos := idealPath[pathIndex]

		// Calculate the time step.
		currentTime := startTime.Add(time.Duration(easedT * float64(duration)))
		time.Sleep(time.Until(currentTime))

		// Update velocity.
		dt := time.Since(startTime).Seconds()
		if dt > 0 {
			velocity = currentPos.Sub(lastPos).Div(dt)
		}
		lastPos = currentPos

		// -- Noise Combination --
		h.mu.Lock()
		perlinMagnitude := h.dynamicConfig.PerlinAmplitude
		h.mu.Unlock()

		perlinFrequency := 0.8

		// 1. Calculate Perlin noise drift.
		timeElapsed := currentTime.Sub(startTime).Seconds()
		perlinDrift := Vector2D{
			X: h.noiseX.Noise1D(timeElapsed*perlinFrequency) * perlinMagnitude,
			Y: h.noiseY.Noise1D(timeElapsed*perlinFrequency) * perlinMagnitude,
		}

		// 2. Add Perlin drift.
		driftAppliedPos := currentPos.Add(perlinDrift)

		// 3. Apply Gaussian noise (tremor).
		finalPerturbedPoint := h.applyGaussianNoise(driftAppliedPos)

		// Dispatch the mouse movement event.
		dispatchMouse := input.DispatchMouseEvent(input.MouseMoved, finalPerturbedPoint.X, finalPerturbedPoint.Y)
		// Include button state if dragging.
		// UPDATED: Use the correct "none" string constant.
		if buttonState != input.MouseButtonNone {
			dispatchMouse = dispatchMouse.WithButton(buttonState)
		}

		if err := dispatchMouse.Do(ctx); err != nil {
			h.logger.Warn("Humanoid: Failed to dispatch mouse move event during simulation", zap.Error(err))
			return velocity, err
		}

		// Update the internal position tracker.
		h.mu.Lock()
		h.currentPos = finalPerturbedPoint
		h.mu.Unlock()

		// Simulate browser rendering/event loop delay.
		time.Sleep(time.Millisecond * time.Duration(2+h.rng.Intn(4)))
	}

	return velocity, nil
}