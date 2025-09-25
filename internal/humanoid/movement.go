package humanoid

import (
	"context"
	"fmt"
	"math"

	// "github.com/chromedp/cdproto/dom"   // Removed
	// "github.com/chromedp/cdproto/input" // Removed
	"go.uber.org/zap"
)

// MoveTo simulates human-like movement from the current position to a target element.
// It executes immediately using the provided context.
func (h *Humanoid) MoveTo(ctx context.Context, selector string, field *PotentialField) error {
	var target Vector2D

	// 1. Preparation Phase: Scroll, locate, and plan.
	h.updateFatigue(1.0) // Moving is a high-intensity action.

	// 1a. Ensure the target is visible by scrolling it into view.
	if err := h.intelligentScroll(ctx, selector); err != nil {
		if ctx.Err() != nil { // If context was cancelled, return immediately.
			return ctx.Err()
		}
		// Log other scroll errors but attempt to continue.
		h.logger.Debug("Humanoid: Scrolling encountered non-critical issues", zap.Error(err), zap.String("selector", selector))
	}

	// 1b. Cognitive pause for visual search and planning.
	if err := h.CognitivePause(ctx, 150, 50); err != nil {
		return err
	}

	// 1c. Locate the target element geometry.
	// REFACTORED: Now uses the agnostic ElementGeometry type.
	geo, err := h.getElementBoxBySelector(ctx, selector)
	if err != nil {
		return fmt.Errorf("humanoid: failed to locate target element '%s': %w", selector, err)
	}

	center, valid := boxToCenter(geo) // Assumes boxToCenter is updated for ElementGeometry
	if !valid {
		return fmt.Errorf("humanoid: element '%s' has invalid geometry", selector)
	}

	// 1d. Calculate a realistic target point within the element.
	target = h.calculateTargetPoint(geo, center, Vector2D{X: 0, Y: 0})

	// 2. Execution Phase: Perform the physical mouse movement.
	return h.MoveToVector(ctx, target, field)
}

// MoveToVector simulates human-like movement to a specific coordinate, with corrective actions.
// It executes immediately.
func (h *Humanoid) MoveToVector(ctx context.Context, target Vector2D, field *PotentialField) error {
	var finalVelocity Vector2D

	// --- Main movement ---
	h.mu.Lock()
	start := h.currentPos
	buttonState := h.currentButtonState // Read current button state for dragging.
	h.mu.Unlock()

	if field == nil {
		field = NewPotentialField()
	}

	// Simulate the main trajectory.
	var err error
	// REFACTORED: No longer need to cast buttonState. It's passed directly.
	finalVelocity, err = h.simulateTrajectory(ctx, start, target, field, buttonState)
	if err != nil {
		return err
	}

	h.mu.Lock()
	h.lastMovementDistance = start.Dist(target)
	h.mu.Unlock()

	// --- Corrective movement ---
	if ctx.Err() != nil {
		return ctx.Err()
	}

	h.mu.Lock()
	finalPos := h.currentPos
	buttonState = h.currentButtonState // Re-read button state just in case.
	h.mu.Unlock()

	// Create a virtual geometry box around the target coordinate for recalculation.
	// REFACTORED: Now uses the agnostic ElementGeometry type.
	geo, _ := h.getElementBoxByVector(ctx, target)

	// Recalculate the target point, considering the momentum from the main movement.
	finalTarget := h.calculateTargetPoint(geo, target, finalVelocity)

	// Perform a small correction if we landed too far from the ideal final target.
	distanceToFinalTarget := finalTarget.Dist(finalPos)
	if distanceToFinalTarget > 1.5 { // Correction threshold in pixels.
		correctionField := NewPotentialField()

		// REFACTORED: No longer need to cast buttonState here either.
		_, err := h.simulateTrajectory(ctx, finalPos, finalTarget, correctionField, buttonState)

		if err == nil {
			h.mu.Lock()
			h.lastMovementDistance += distanceToFinalTarget
			h.mu.Unlock()
		}
		return err
	}
	return nil
}

// calculateTargetPoint determines a realistic click point within an element's geometry.
// It considers the element's size, a Gaussian distribution, and movement momentum.
// REFACTORED: Signature now uses the agnostic ElementGeometry type.
func (h *Humanoid) calculateTargetPoint(geo *ElementGeometry, center Vector2D, finalVelocity Vector2D) Vector2D {
	if geo == nil || geo.Width == 0 || geo.Height == 0 {
		return center
	}

	width, height := float64(geo.Width), float64(geo.Height)

	// Define the effective target area (e.g., 90% of the element's dimensions).
	effectiveWidth := width * 0.9
	effectiveHeight := height * 0.9

	h.mu.Lock()
	rng := h.rng
	h.mu.Unlock()

	// 1. Base Offset: Gaussian distribution around the center.
	stdDevX := effectiveWidth / 6.0
	stdDevY := effectiveHeight / 6.0
	offsetX := rng.NormFloat64() * stdDevX
	offsetY := rng.NormFloat64() * stdDevY

	// 2. Velocity Bias: Add a bias in the direction of mouse travel (momentum).
	velocityMag := finalVelocity.Mag()
	normalizedVelocity := math.Min(1.0, velocityMag/4000.0) // Normalize against a max realistic velocity.
	maxBiasX := width * 0.1
	maxBiasY := height * 0.1

	if velocityMag > 1e-6 {
		velDir := finalVelocity.Normalize()
		offsetX += velDir.X * normalizedVelocity * maxBiasX
		offsetY += velDir.Y * normalizedVelocity * maxBiasY
	}

	finalX := center.X + offsetX
	finalY := center.Y + offsetY

	// Clamp the final coordinates to be within the element's bounding box.
	minX := center.X - width/2.0 + 1.0
	maxX := center.X + width/2.0 - 1.0
	minY := center.Y - height/2.0 + 1.0
	maxY := center.Y + height/2.0 - 1.0

	finalX = math.Max(minX, math.Min(maxX, finalX))
	finalY = math.Max(minY, math.Min(maxY, finalY))

	return Vector2D{X: finalX, Y: finalY}
}
