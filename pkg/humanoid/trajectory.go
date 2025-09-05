// pkg/humanoid/trajectory.go
package humanoid

import (
	"context"
	"math"
	"time"

	// Import input package
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

// generateIdealPath creates a human-like trajectory (Bezier curve) deformed by the potential field.
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

	// Offset the control points based on the sampled forces.
	offsetScale := dist * 0.5
	p1 := samplePoint1.Add(force1.Mul(offsetScale))
	p2 := samplePoint2.Add(force2.Mul(offsetScale))

	// Introduce slight randomness to P2 (mid-flight correction variability).
	h.mu.Lock()
	// 30% chance of a randomized mid-course adjustment.
	shouldCorrect := h.rng.Float64() < 0.3
	var correctionStrength float64
	if shouldCorrect {
		// Correction magnitude randomized and capped.
		correctionStrength = math.Min(dist/5, 30.0) * (h.rng.Float64() - 0.5) * 2.0
	}
	h.mu.Unlock()

	if shouldCorrect {
		perpDir := Vector2D{X: -mainDir.Y, Y: mainDir.X} // Perpendicular direction
		p2 = p2.Add(perpDir.Mul(correctionStrength))
	}

	// Generate the Bezier curve points.
	path := make([]Vector2D, 0, numSteps+1)
	for i := 0; i <= numSteps; i++ {
		t := float64(i) / float64(numSteps)

		// Cubic Bezier coefficients
		c0 := math.Pow(1-t, 3)
		c1 := 3 * math.Pow(1-t, 2) * t
		c2 := 3 * (1 - t) * math.Pow(t, 2)
		c3 := math.Pow(t, 3)

		pointX := c0*p0.X + c1*p1.X + c2*p2.X + c3*p3.X
		pointY := c0*p0.Y + c1*p1.Y + c2*p2.Y + c3*p3.Y
		path = append(path, Vector2D{X: pointX, Y: pointY})
	}
	return path
}

// executePathChase simulates the physical movement using a Critically Damped Spring (CDS) model.
func (h *Humanoid) executePathChase(ctx context.Context, startPoint Vector2D, idealPath []Vector2D, startTime time.Time, deadline time.Time, buttonState input.MouseButton) (Vector2D, error) {
	currentPos := startPoint
	velocity := Vector2D{} // Start from rest.

	totalDuration := deadline.Sub(startTime)

	if totalDuration <= 0 || len(idealPath) == 0 {
		return Vector2D{}, nil
	}

	h.mu.Lock()
	// Omega (natural frequency) controls responsiveness/speed.
	omega := h.dynamicConfig.Omega
	h.mu.Unlock()

	lastTime := time.Now()

	// Simulation loop.
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return velocity, ctx.Err()
		}

		currentTime := time.Now()
		dt := currentTime.Sub(lastTime).Seconds()
		lastTime = currentTime

		// Handle time steps.
		if dt <= 0.002 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if dt > 0.05 {
			dt = 0.05
		}

		// Determine the goal point on the ideal curve based on time progression.
		elapsed := time.Since(startTime)
		progress := float64(elapsed) / float64(totalDuration)
		easedProgress := computeEaseInOutCubic(math.Min(progress, 1.0))

		goalIndex := int(easedProgress * float64(len(idealPath)-1))
		if goalIndex >= len(idealPath) {
			goalIndex = len(idealPath) - 1
		}
		goalPoint := idealPath[goalIndex]

		// Critically Damped Spring Dynamics (Zeta = 1.0)
		displacement := currentPos.Sub(goalPoint)
		expTerm := math.Exp(-omega * dt)

		// Coefficients
		c1 := displacement
		c2 := velocity.Add(displacement.Mul(omega))
		c3 := c2.Mul(dt).Add(c1)

		// Calculate new position and velocity
		newPos := goalPoint.Add(c3.Mul(expTerm))
		newVelocity := c2.Sub(c3.Mul(omega)).Mul(expTerm)

		velocity = newVelocity.Limit(maxVelocity)
		currentPos = newPos

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

		// Simulate browser rendering/event loop delay (4-9ms).
		h.mu.Lock()
		sleepDuration := time.Duration(h.rng.Intn(5)+4) * time.Millisecond
		h.mu.Unlock()

		select {
		case <-time.After(sleepDuration):
		case <-ctx.Done():
			return velocity, ctx.Err()
		}
	}

	return velocity, nil
}