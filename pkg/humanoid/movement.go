// pkg/humanoid/movement.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/dom"
	// Import input package
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// MoveTo simulates human-like movement from the current position to the target selector.
func (h *Humanoid) MoveTo(selector string, field *PotentialField) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Moving is a high-intensity action.
		h.updateFatigue(1.0)

		// 1. Ensure the target is visible (Scrolling).
		if err := h.intelligentScroll(selector).Do(ctx); err != nil {
			h.logger.Debug("Humanoid: Scrolling encountered issues", zap.Error(err), zap.String("selector", selector))
		}

		// 2. Cognitive pause (Visual search and planning after scroll).
		if err := h.CognitivePause(ctx, 150, 50); err != nil {
			return err
		}

		// 3. Locate the target element geometry.
		box, err := h.getElementBoxBySelector(ctx, selector)
		if err != nil {
			return fmt.Errorf("humanoid: failed to locate target element after scroll: %w", err)
		}

		targetCenter, targetWidth, _ := boxToDimensions(box)

		// 4. Execute the physical movement simulation.
		// buttonState is None for a simple move.
		finalVelocity, err := h.executeMovement(ctx, targetCenter, targetWidth, field, input.MouseButtonNone)
		if err != nil {
			return err
		}

		// 5. Final refinement: Generate the precise target point within the element bounds.
		finalPos := h.generateClickPoint(box, targetCenter, finalVelocity)

		// Ensure the cursor is exactly at the final position if the simulation undershot slightly.
		if h.GetCurrentPos().Dist(finalPos) > 0.5 {
			dispatchMove := input.DispatchMouseEvent(input.MouseMoved, finalPos.X, finalPos.Y)
			if err := dispatchMove.Do(ctx); err != nil {
				return fmt.Errorf("humanoid: failed to move to final refined point: %w", err)
			}
		}

		h.mu.Lock()
		h.currentPos = finalPos
		// lastMovementDistance is updated within executeMovement.
		h.mu.Unlock()

		return nil
	})
}

// MoveToVector simulates human-like movement to a specific coordinate.
func (h *Humanoid) MoveToVector(target Vector2D, field *PotentialField) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		h.updateFatigue(0.8)

		// Assume a default width for Fitts's Law calculation.
		targetWidth := 15.0

		// Get the current button state (to determine if we are dragging).
		h.mu.Lock()
		buttonState := h.currentButtonState
		h.mu.Unlock()

		// Execute the physical movement simulation.
		_, err := h.executeMovement(ctx, target, targetWidth, field, buttonState)
		if err != nil {
			return err
		}

		// The simulation updates currentPos.
		h.mu.Lock()
		finalPos := h.currentPos
		h.mu.Unlock()

		// Final dispatch to ensure the very last position is registered.
		dispatchMove := input.DispatchMouseEvent(input.MouseMoved, finalPos.X, finalPos.Y)
		if buttonState != input.MouseButtonNone {
			dispatchMove = dispatchMove.WithButton(buttonState)
		}
		if err := dispatchMove.Do(ctx); err != nil {
			return fmt.Errorf("humanoid: failed to dispatch final move event in MoveToVector: %w", err)
		}

		return nil
	})
}

// executeMovement handles the physics simulation of the move.
func (h *Humanoid) executeMovement(ctx context.Context, targetCenter Vector2D, targetWidth float64, field *PotentialField, buttonState input.MouseButton) (Vector2D, error) {
	startPos := h.GetCurrentPos()
	distance := startPos.Dist(targetCenter)

	// Update the movement distance tracker immediately.
	h.mu.Lock()
	h.lastMovementDistance = distance
	h.mu.Unlock()

	if distance < 2.0 {
		return Vector2D{}, nil // Already at the target.
	}

	// Calculate the movement duration based on Fitts's Law.
	duration := h.fittsLawMT(distance, targetWidth)

	if field == nil {
		field = NewPotentialField()
	}

	// Determine the number of steps for the ideal path generation.
	numSteps := int(math.Max(10.0, math.Min(200.0, distance/3.0)))

	// 1. Generate the ideal trajectory (deformed Bezier curve).
	idealPath := h.generateIdealPath(startPos, targetCenter, field, numSteps)

	startTime := time.Now()
	deadline := startTime.Add(time.Duration(duration) * time.Millisecond)

	// 2. Execute the path chasing simulation (Critically Damped Spring).
	finalVelocity, err := h.executePathChase(ctx, startPos, idealPath, startTime, deadline, buttonState)
	if err != nil {
		return Vector2D{}, fmt.Errorf("humanoid: movement execution failed: %w", err)
	}
	return finalVelocity, nil
}

// generateClickPoint determines the final precise point within the target element.
// This simulates slight inaccuracy, biased towards the center and influenced by velocity.
func (h *Humanoid) generateClickPoint(box *dom.BoxModel, center Vector2D, finalVelocity Vector2D) Vector2D {
	if box == nil {
		return center
	}

	width, height := float64(box.Width), float64(box.Height)

	// Define the effective target area (e.g., 90% of the element size).
	effectiveWidth := width * 0.9
	effectiveHeight := height * 0.9

	h.mu.Lock()
	rng := h.rng
	h.mu.Unlock()

	// 1. Gaussian distribution around the center.
	stdDevX := effectiveWidth / 6.0 // 99.7% of clicks fall within the effective area.
	stdDevY := effectiveHeight / 6.0

	offsetX := rng.NormFloat64() * stdDevX
	offsetY := rng.NormFloat64() * stdDevY

	// 2. Velocity bias (Momentum).
	velocityMag := finalVelocity.Mag()
	// Normalize velocity (max realistic velocity ~4000 px/s).
	normalizedVelocity := math.Min(1.0, velocityMag/4000.0)

	// Max bias amount (e.g., up to 10% of the element size).
	maxBiasX := width * 0.1
	maxBiasY := height * 0.1

	if velocityMag > 1e-6 {
		velDir := finalVelocity.Normalize()
		offsetX += velDir.X * normalizedVelocity * maxBiasX
		offsetY += velDir.Y * normalizedVelocity * maxBiasY
	}

	finalX := center.X + offsetX
	finalY := center.Y + offsetY

	// 3. Clamp the coordinates to ensure they are strictly within the element bounds (1 pixel margin).
	minX := center.X - width/2.0 + 1.0
	maxX := center.X + width/2.0 - 1.0
	minY := center.Y - height/2.0 + 1.0
	maxY := center.Y + height/2.0 - 1.0

	finalX = math.Max(minX, math.Min(maxX, finalX))
	finalY = math.Max(minY, math.Min(maxY, finalY))

	return Vector2D{X: finalX, Y: finalY}
}