// pkg/humanoid/movement.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

const (
	epsilon = 1e-6 // For float comparisons in dynamics stability checks
	// Throttle mouse move events to ~60Hz (16ms) to avoid overwhelming CDP.
	minDispatchInterval = 16 * time.Millisecond
)

// MoveTo simulates human-like movement from the current position to the target selector.
func (h *Humanoid) MoveTo(selector string, field *PotentialField) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Update fatigue before the movement sequence.
		h.updateFatigue(1.0)

		// 1. Ensure visibility (Scrolling).
		if err := h.intelligentScroll(selector).Do(ctx); err != nil {
			// Log but attempt to continue if element might be partially visible or scrolling failed benignly.
			h.logger.Debug("Humanoid: Scrolling to element completed or encountered issues", zap.Error(err), zap.String("selector", selector))
		}

		// 2. Pause (Visual search/reaction time).
		if err := h.CognitivePause(ctx, 150, 50); err != nil {
			return err
		}

		// 3. Get target coordinates.
		box, err := h.getElementBoxBySelector(ctx, selector)
		if err != nil {
			return fmt.Errorf("humanoid: failed to locate target element after scroll: %w", err)
		}

		targetCenter, targetWidth, _ := boxToDimensions(box)

		// 4. Movement Phase.
		// buttonState 0 indicates no button pressed during movement.
		finalVelocity, err := h.executeMovement(ctx, targetCenter, targetWidth, field, 0)
		if err != nil {
			return err
		}

		// 5. Final positioning (Speed-Accuracy Tradeoff).
		finalPos := h.generateClickPoint(box, targetCenter, finalVelocity)

		// Ensure the cursor is exactly at the final point if the simulation ended slightly off.
		if h.GetCurrentPos().Dist(finalPos) > 0.5 {
			dispatchMove := input.DispatchMouseEvent(input.MouseMoved, finalPos.X, finalPos.Y)
			if err := dispatchMove.Do(ctx); err != nil {
				return fmt.Errorf("humanoid: failed to move to final point: %w", err)
			}
		}

		// Update internal state synchronously.
		h.mu.Lock()
		h.currentPos = finalPos
		h.mu.Unlock()

		return nil
	})
}

// executeMovement handles the physics simulation of the move.
// buttonState (e.g., input.Left) should be provided if this movement is part of a drag operation.
func (h *Humanoid) executeMovement(ctx context.Context, targetCenter Vector2D, targetWidth float64, field *PotentialField, buttonState input.MouseButton) (Vector2D, error) {
	startPos := h.GetCurrentPos()
	distance := startPos.Dist(targetCenter)

	// If already very close, skip the movement phase.
	if distance < 2.0 {
		return Vector2D{}, nil
	}

	// Calculate duration using Fitts's law (which internally uses dynamic config affected by fatigue).
	duration := h.fittsLawMT(distance, targetWidth)

	if field == nil {
		field = NewPotentialField()
	}

	// Determine adaptive step count for path generation based on distance.
	numSteps := math.Max(10.0, math.Min(200.0, distance/3.0))

	idealPath := h.generateIdealPath(startPos, targetCenter, field, int(numSteps))

	startTime := time.Now()
	deadline := startTime.Add(time.Duration(duration) * time.Millisecond)

	finalVelocity, err := h.executePathChase(ctx, startPos, idealPath, startTime, deadline, buttonState)
	if err != nil {
		return Vector2D{}, fmt.Errorf("humanoid: movement execution failed: %w", err)
	}
	return finalVelocity, nil
}

// easeInOutCubic provides a smooth acceleration and deceleration profile (velocity profile).
func easeInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	p := -2*t + 2
	return 1 - (p*p*p)/2
}

// generateIdealPath creates a Bezier curve deformed by the potential field (the intended trajectory).
func (h *Humanoid) generateIdealPath(start, end Vector2D, field *PotentialField, numSteps int) []Vector2D {
	p0, p3 := start, end
	mainVec := end.Sub(start)
	dist := mainVec.Mag()

	if dist < 1.0 || numSteps <= 1 {
		return []Vector2D{end}
	}

	mainDir := mainVec.Normalize()

	// Sample forces and offset control points (P1 at 1/3rd, P2 at 2/3rds).
	samplePoint1 := start.Add(mainDir.Mul(dist / 3.0))
	force1 := field.CalculateNetForce(samplePoint1)
	samplePoint2 := start.Add(mainDir.Mul(dist * 2.0 / 3.0))
	force2 := field.CalculateNetForce(samplePoint2)

	// Offset scale determines how strongly the field affects the path shape.
	offsetScale := dist * 0.5
	p1 := samplePoint1.Add(force1.Mul(offsetScale))
	p2 := samplePoint2.Add(force2.Mul(offsetScale))

	// Mid-flight correction variability (simulating randomized mid-course adjustments)
	h.mu.Lock()
	shouldCorrect := h.rng.Float64() < 0.3
	var correctionRandomness float64
	if shouldCorrect {
		// Random directionality (-1 to 1).
		correctionRandomness = (h.rng.Float64() - 0.5) * 2.0
	}
	h.mu.Unlock()

	if shouldCorrect {
		perpDir := Vector2D{X: -mainDir.Y, Y: mainDir.X} // Perpendicular direction
		// Correction magnitude capped at 30px or 1/5th of the distance.
		correctionStrength := math.Min(dist/5, 30.0) * correctionRandomness
		p2 = p2.Add(perpDir.Mul(correctionStrength))
	}

	// Generate the Bezier curve points.
	path := make([]Vector2D, 0, numSteps+1)
	for i := 0; i <= numSteps; i++ {
		t := float64(i) / float64(numSteps)

		// Optimized Bezier calculation (avoid math.Pow)
		t2 := t * t
		t3 := t2 * t
		mt := 1 - t
		mt2 := mt * mt
		mt3 := mt2 * mt

		// Cubic Bezier coefficients
		c0, c1, c2, c3 := mt3, 3*mt2*t, 3*mt*t2, t3

		pointX := c0*p0.X + c1*p1.X + c2*p2.X + c3*p3.X
		pointY := c0*p0.Y + c1*p1.Y + c2*p2.Y + c3*p3.Y
		path = append(path, Vector2D{X: pointX, Y: pointY})
	}
	return path
}

// executePathChase simulates the physical movement using a generalized damped harmonic oscillator model
// with dynamic adjustments for the terminal phase (micro-corrections).
func (h *Humanoid) executePathChase(ctx context.Context, startPoint Vector2D, idealPath []Vector2D, startTime time.Time, deadline time.Time, buttonState input.MouseButton) (Vector2D, error) {
	currentPos := startPoint
	velocity := Vector2D{} // Start from rest.
	targetPoint := idealPath[len(idealPath)-1]

	totalDuration := deadline.Sub(startTime)

	if totalDuration <= 0 || len(idealPath) == 0 {
		return Vector2D{}, nil
	}

	// Determine dynamic parameters (Omega and Zeta).
	h.mu.Lock()
	// Use the session persona's base parameters (Temporal Consistency).
	// Fatigue affects Fitts Law (duration) and noise, not the base motor control characteristics.
	cfg := h.baseConfig
	omega := cfg.Omega
	zeta := cfg.Zeta
	correctionThreshold := cfg.MicroCorrectionThreshold
	h.mu.Unlock()

	lastTime := time.Now()
	lastDispatchTime := time.Time{}

	// Micro-correction (Terminal Phase) state
	inTerminalPhase := false

	// Simulation loop.
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return velocity, ctx.Err()
		}

		currentTime := time.Now()
		dt := currentTime.Sub(lastTime).Seconds()
		elapsedTime := currentTime.Sub(startTime).Seconds()
		lastTime = currentTime

		// Handle time steps: Ensure stability and responsiveness.
		if dt <= 0.002 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if dt > 0.05 { // Clamp max dt.
			dt = 0.05
		}

		// Determine the goal point on the ideal curve based on elapsed time.
		progress := elapsedTime / totalDuration.Seconds()
		easedProgress := easeInOutCubic(math.Min(progress, 1.0))

		goalIndex := int(easedProgress * float64(len(idealPath)-1))
		if goalIndex >= len(idealPath) {
			goalIndex = len(idealPath) - 1
		}
		goalPoint := idealPath[goalIndex]

		// Terminal Phase Detection (Micro-correction)
		distanceToTarget := currentPos.Dist(targetPoint)
		if !inTerminalPhase && distanceToTarget < correctionThreshold {
			inTerminalPhase = true
			// Adjust dynamics for higher accuracy: Increase damping (Zeta) to prevent overshoot.
			h.mu.Lock()
			zeta = 1.1 + h.rng.Float64()*0.4 // Shift to overdamped (1.1 to 1.5)
			// Slightly reduce Omega (slower, more deliberate movement).
			omega = omega * (0.7 + h.rng.Float64()*0.2) // Reduce speed by 10-30%
			h.mu.Unlock()
			h.logger.Debug("Humanoid: Entering terminal movement phase (micro-correction)")
		}

		// Damped Harmonic Oscillator Dynamics (Analytical Solution)
		// This makes the physical cursor "chase" the ideal goal point.
		displacement := currentPos.Sub(goalPoint)
		var newPos, newVelocity Vector2D

		// Physics calculations using the (potentially updated) omega and zeta.
		// Robust implementation handling transitions between damping states.
		if math.Abs(zeta-1.0) < epsilon {
			// Case 1: Critically Damped (ζ ≈ 1)
			newPos, newVelocity = criticallyDampedStep(omega, dt, goalPoint, displacement, velocity)

		} else if zeta < 1.0 {
			// Case 2: Underdamped (ζ < 1) - Causes overshoot and oscillation.
			// Ensure the term inside Sqrt is non-negative due to float precision.
			omegaD := omega * math.Sqrt(math.Max(0, 1.0-zeta*zeta)) // Damped frequency

			// Robustness check: if omegaD is near zero (ζ ≈ 1), the formulas become unstable.
			if omegaD < epsilon {
				newPos, newVelocity = criticallyDampedStep(omega, dt, goalPoint, displacement, velocity)
			} else {
				expTerm := math.Exp(-zeta * omega * dt)
				cosTerm, sinTerm := math.Cos(omegaD*dt), math.Sin(omegaD*dt)

				A := displacement
				B := velocity.Add(displacement.Mul(zeta * omega)).Mul(1.0 / omegaD)

				newPos = goalPoint.Add(A.Mul(cosTerm).Add(B.Mul(sinTerm)).Mul(expTerm))

				// Velocity calculation (v(t) = dx/dt)
				zetaOmega := zeta * omega
				// Derivative of the position equation
				vTermA := A.Mul(-zetaOmega*cosTerm - omegaD*sinTerm)
				vTermB := B.Mul(-zetaOmega*sinTerm + omegaD*cosTerm)
				newVelocity = vTermA.Add(vTermB).Mul(expTerm)
			}

		} else {
			// Case 3: Overdamped (ζ > 1) - Slower approach, no overshoot.
			sqrtTerm := math.Sqrt(zeta*zeta - 1.0)
			r1 := -omega * (zeta - sqrtTerm)
			r2 := -omega * (zeta + sqrtTerm)

			// Robustness check: if r1 and r2 are very close (ζ ≈ 1), the formulas become unstable.
			if math.Abs(r2-r1) < epsilon {
				newPos, newVelocity = criticallyDampedStep(omega, dt, goalPoint, displacement, velocity)
			} else {
				expR1, expR2 := math.Exp(r1*dt), math.Exp(r2*dt)

				// Coefficients calculation
				c2 := velocity.Sub(displacement.Mul(r1)).Mul(1.0 / (r2 - r1))
				c1 := displacement.Sub(c2)

				newPos = goalPoint.Add(c1.Mul(expR1).Add(c2.Mul(expR2)))
				newVelocity = c1.Mul(r1 * expR1).Add(c2.Mul(r2 * expR2))
			}
		}

		// Apply the physical constraint defined in humanoid.go
		velocity = newVelocity.Limit(maxVelocity)
		currentPos = newPos

		// Apply Noise (Perturbation and Perlin).
		noisyPoint := h.applyNoise(currentPos, elapsedTime)

		// --- Event Dispatching (Throttling) ---
		if currentTime.Sub(lastDispatchTime) >= minDispatchInterval {
			dispatchMouse := input.DispatchMouseEvent(input.MouseMoved, noisyPoint.X, noisyPoint.Y)

			// If dragging, include the button state.
			if buttonState != 0 {
				dispatchMouse = dispatchMouse.WithButton(buttonState)
			}

			if err := dispatchMouse.Do(ctx); err != nil {
				h.logger.Warn("Humanoid: Failed to dispatch mouse move event", zap.Error(err))
				// If dispatch fails (e.g., page navigation), stop the movement.
				return velocity, err
			}
			lastDispatchTime = currentTime

			// Update internal state.
			h.mu.Lock()
			h.currentPos = noisyPoint
			h.mu.Unlock()
		}

		// Simulate browser rendering/event loop delay (4-9ms).
		h.mu.Lock()
		sleepDuration := time.Duration(h.rng.Intn(5)+4) * time.Millisecond
		h.mu.Unlock()

		// Use select for the sleep to be responsive to cancellation.
		select {
		case <-time.After(sleepDuration):
		case <-ctx.Done():
			return velocity, ctx.Err()
		}
	}

	return velocity, nil
}

// criticallyDampedStep helper function for the ζ=1 case, used for stability when ζ approaches 1.
func criticallyDampedStep(omega, dt float64, goalPoint, displacement, velocity Vector2D) (Vector2D, Vector2D) {
	expTerm := math.Exp(-omega * dt)
	c1 := displacement
	c2 := velocity.Add(displacement.Mul(omega))
	c3 := c2.Mul(dt).Add(c1)

	newPos := goalPoint.Add(c3.Mul(expTerm))
	// Derivative of the position equation for velocity
	newVelocity := c2.Sub(c3.Mul(omega)).Mul(expTerm)
	return newPos, newVelocity
}

// applyNoise combines Gaussian perturbation (tremor) and Perlin noise (drift).
func (h *Humanoid) applyNoise(point Vector2D, t float64) Vector2D {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Use dynamic config (affected by fatigue).
	cfg := h.dynamicConfig

	// 1. Gaussian Perturbation (High frequency tremor)
	// Strength randomized slightly around the configured value (0.5x to 1.5x).
	perturbationStrength := cfg.GaussianStrength * (0.5 + h.rng.Float64())
	pX := h.rng.NormFloat64() * perturbationStrength
	pY := h.rng.NormFloat64() * perturbationStrength

	// 2. Perlin Noise (Low frequency drift/wander)
	// Frequency for Perlin noise sampling (Hz).
	noiseFreq := 1.5
	tInput := t * noiseFreq
	// Noise1D typically returns values between -1 and 1.
	dX := h.noiseX.Noise1D(tInput) * cfg.PerlinAmplitude
	dY := h.noiseY.Noise1D(tInput) * cfg.PerlinAmplitude

	return Vector2D{
		X: point.X + pX + dX,
		Y: point.Y + pY + dY,
	}
}
