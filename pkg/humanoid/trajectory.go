package humanoid

import (
	"context"
	"math"
	"time"

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

// computeIdealPath creates a human-like trajectory (Bezier curve) deformed by the potential field.
func (h *Humanoid) computeIdealPath(start, end Vector2D, field *PotentialField) []Vector2D {
	p0, p3 := start, end
	mainVec := end.Sub(start)
	dist := mainVec.Mag()

	// Determine the number of steps for sufficient resolution.
	numSteps := int(math.Max(50.0, dist/2.0))

	if dist < 1.0 {
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

	// introduce a bit of randomness to P2 ( mid flight correction vary).
	h.mu.Lock()
	shouldCorrect := h.rng.Float64() < 0.3
	var correctionStrength float64
	if shouldCorrect {
		// Correction magnitude randomized and capped at 30px.
		correctionStrength = math.Min(dist/5, 30.0) * (h.rng.Float64() - 0.5) * 2.0
	}
	h.mu.Unlock()

	if shouldCorrect {
		perpDir := Vector2D{X: -mainDir.Y, Y: mainDir.X} // Perpendicular direction
		p2 = p2.Add(perpDir.Mul(correctionStrength))
	}

	// generate the bezier curve points &
	// initialize with capacity for efficiency.
	path := make([]Vector2D, 0, numSteps+1)
	for i := 0; i <= numSteps; i++ {
		t := float64(i) / float64(numSteps)

		// cubic bezier coefficients
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

//  sims the physical movement using a CDS model.
// includes a layer of perlin noise for more organic, wandering movement.
func (h *Humanoid) simulatePathChase(ctx context.Context, startPoint Vector2D, idealPath []Vector2D, startTime time.Time, deadline time.Time) (Vector2D, error) {
	currentPos := startPoint
	velocity := Vector2D{} // start from rest.

	totalDuration := deadline.Sub(startTime)

	if totalDuration <= 0 || len(idealPath) == 0 {
		return Vector2D{}, nil
	}

	// Omega natural frequency of the spring to control responsivness
	// randomized about 25 rad/s. give or take
	h.mu.Lock()
	omega := 25.0 + (h.rng.Float64()-0.5)*6.0
	h.mu.Unlock()

	lastTime := time.Now()

	// simulation loop.
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return velocity, ctx.Err()
		}

		currentTime := time.Now()
		dt := currentTime.Sub(lastTime).Seconds()
		lastTime = currentTime

		// handle time steps: ensure stability.
		if dt <= 0.002 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if dt > 0.05 { // clamp max dt. dont really want it going over ..right?
			dt = 0.05
		}

		// determine the goal point on a ideal curve based on time.
		elapsed := time.Since(startTime)
		progress := float64(elapsed) / float64(totalDuration)
		easedProgress := computeEaseInOutCubic(math.Min(progress, 1.0))

		goalIndex := int(easedProgress * float64(len(idealPath)-1))
		if goalIndex >= len(idealPath) {
			goalIndex = len(idealPath) - 1
		}
		goalPoint := idealPath[goalIndex]

		// critically damped spring dynanamics
		// makes the physical cursor "chase" the ideal goal point.
		displacement := currentPos.Sub(goalPoint)
		expTerm := math.Exp(-omega * dt)

		// co efs
		c1 := displacement
		c2 := velocity.Add(displacement.Mul(omega))
		c3 := c2.Mul(dt).Add(c1)

		// calc new position and velocity
		newPos := goalPoint.Add(c3.Mul(expTerm))
		newVelocity := c2.Sub(c3.Mul(omega)).Mul(expTerm)

		velocity = newVelocity.Limit(maxVelocity)
		currentPos = newPos

		// -- Noise Combination --
		// Parameters for the perlin noise effect. These are great candidates for tuning.
		perlinFrequency := 0.8
		perlinMagnitude := 2.5

		// 1. Calculate the smooth, wandering Perlin noise drift based on elapsed time.
		timeElapsed := currentTime.Sub(startTime).Seconds()
		perlinDrift := Vector2D{
			X: h.noiseX.Noise1D(timeElapsed*perlinFrequency) * perlinMagnitude,
			Y: h.noiseY.Noise1D(timeElapsed*perlinFrequency) * perlinMagnitude,
		}

		// 2. Add the smooth Perlin drift to the base physical position.
		driftAppliedPos := currentPos.Add(perlinDrift)

		// 3. Apply the original high-frequency tremor (Gaussian noise) on top of the drifted path.
		finalPerturbedPoint := h.applyPerturbation(driftAppliedPos)
		// -- End Noise Combination --

		// Dispatch the final, fully noised-up mouse movement event.
		dispatchMouse := input.DispatchMouseEvent(input.MouseMoved, finalPerturbedPoint.X, finalPerturbedPoint.Y)
		if err := dispatchMouse.Do(ctx); err != nil {
			// CORRECTED: Replaced slog with the humanoid's zap logger instance.
			h.logger.Warn("Humanoid: Failed to dispatch mouse move event", zap.Error(err))
			// If dispatch fails (e.g., page navigation), stop the movement.
			return velocity, err
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

// applyPerturbation adds small Gaussian noise to the position, simulating motor tremor.
func (h *Humanoid) applyPerturbation(point Vector2D) Vector2D {
	h.mu.Lock()
	// Strength of the tremor.
	perturbationStrength := 0.3 + h.rng.Float64()*0.6
	normX := h.rng.NormFloat64()
	normY := h.rng.NormFloat64()
	h.mu.Unlock()

	return Vector2D{
		X: point.X + normX*perturbationStrength,
		Y: point.Y + normY*perturbationStrength,
	}
}

