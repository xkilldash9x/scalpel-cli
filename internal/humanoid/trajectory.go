package humanoid

import (
	"context"
	"math"
	"time"

	// "github.com/chromedp/cdproto/input" // Removed final dependency
	"go.uber.org/zap"
)

// computeEaseInOutCubic provides a smooth acceleration and deceleration profile for movement.
func computeEaseInOutCubic(t float64) float64 {
	if t < 0.5 {
		return 4 * t * t * t
	}
	return 1 - math.Pow(-2*t+2, 3)/2
}

// calculateFittsLaw determines a realistic movement duration based on Fitts's Law,
// which models the time required to move to a target area.
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

// generateIdealPath creates a human-like trajectory (a Bezier curve) that is
// deformed by forces from a potential field.
func (h *Humanoid) generateIdealPath(start, end Vector2D, field *PotentialField, numSteps int) []Vector2D {
	p0, p3 := start, end
	mainVec := end.Sub(start)
	dist := mainVec.Mag()

	if dist < 1.0 || numSteps <= 1 {
		return []Vector2D{end}
	}

	mainDir := mainVec.Normalize()

	// Sample forces at 1/3rd and 2/3rds along the path to create control points.
	samplePoint1 := start.Add(mainDir.Mul(dist / 3.0))
	force1 := field.CalculateNetForce(samplePoint1)
	samplePoint2 := start.Add(mainDir.Mul(dist * 2.0 / 3.0))
	force2 := field.CalculateNetForce(samplePoint2)

	// Create control points based on the forces.
	p1 := samplePoint1.Add(force1.Mul(dist * 0.1))
	p2 := samplePoint2.Add(force2.Mul(dist * 2.0 / 3.0))

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

// simulateTrajectory moves the mouse along a generated path, dispatching events via the executor.
// REFACTORED: Signature now uses the agnostic MouseButton type.
func (h *Humanoid) simulateTrajectory(ctx context.Context, start, end Vector2D, field *PotentialField, buttonState MouseButton) (Vector2D, error) {
	dist := start.Dist(end)
	duration := h.calculateFittsLaw(dist)
	numSteps := int(duration.Seconds() * 100)
	if numSteps < 2 {
		numSteps = 2
	}

	if field == nil {
		field = NewPotentialField()
	}

	idealPath := h.generateIdealPath(start, end, field, numSteps)

	// REFACTORED: Pre-calculate the bitfield for the held button.
	buttonsBitfield := h.calculateButtonsBitfield(buttonState)

	var velocity Vector2D
	startTime := time.Now()
	lastPos := start
	lastTime := startTime

	for i := 0; i < len(idealPath); i++ {
		if ctx.Err() != nil {
			return velocity, ctx.Err()
		}

		// Apply easing to time to simulate acceleration/deceleration.
		t := float64(i) / float64(len(idealPath)-1)
		easedT := computeEaseInOutCubic(t)
		
		pathIndex := int(easedT * float64(len(idealPath)-1))
		if pathIndex >= len(idealPath) {
			pathIndex = len(idealPath) - 1
		}
		currentPos := idealPath[pathIndex]

		// Calculate target time for this step and sleep if we're ahead.
		currentTime := startTime.Add(time.Duration(easedT * float64(duration)))
		sleepDur := time.Until(currentTime)
		if sleepDur > 0 {
			if err := h.executor.Sleep(ctx, sleepDur); err != nil {
				return velocity, err
			}
		}

		// Update velocity and timing information.
		now := time.Now()
		dt := now.Sub(lastTime).Seconds()
		if dt > 1e-6 {
			velocity = currentPos.Sub(lastPos).Mul(1.0 / dt)
		}
		lastPos = currentPos
		lastTime = now

		// Apply Perlin and Gaussian noise to the cursor position.
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

		// REFACTORED: Create the agnostic MouseEventData struct.
		eventData := MouseEventData{
			Type:   MouseMove,
			X:      finalPerturbedPoint.X,
			Y:      finalPerturbedPoint.Y,
			Button: ButtonNone, // For MouseMove, 'Button' is typically None.
		}

		// If a button is held down (e.g., for dragging), set the Buttons bitfield.
		if buttonsBitfield > 0 {
			eventData.Buttons = buttonsBitfield
		}

		// Dispatch the event via the executor.
		if err := h.executor.DispatchMouseEvent(ctx, eventData); err != nil {
			if ctx.Err() == nil {
				h.logger.Warn("Humanoid: Failed to dispatch mouse move event", zap.Error(err))
			}
			return velocity, err
		}

		// Update internal state and apply a tiny delay to simulate the browser's event loop.
		h.mu.Lock()
		h.currentPos = finalPerturbedPoint
		h.mu.Unlock()

		randPart := rng.Intn(4)
		if err := h.executor.Sleep(ctx, time.Duration(2+randPart)*time.Millisecond); err != nil {
			return velocity, err
		}
	}

	return velocity, nil
}
