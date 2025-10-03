package humanoid

import (
	"context"
	"fmt"
	"math"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// MoveTo is the public, locking method for moving the cursor to a specific element.
// It now acts as a wrapper around the non-locking internal implementation.
func (h *Humanoid) MoveTo(ctx context.Context, selector string, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.moveToSelector(ctx, selector, opts)
}

// MoveToVector is the public, locking method for moving to a specific coordinate.
func (h *Humanoid) MoveToVector(ctx context.Context, target Vector2D, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.moveToVector(ctx, target, opts)
}

// moveToSelector is the new internal, non-locking implementation.
// It contains the logic for finding an element and then moving to it.
func (h *Humanoid) moveToSelector(ctx context.Context, selector string, opts *InteractionOptions) error {
	// Note: assumes lock is held by the caller.
	geo, err := h.getElementBoxBySelector(ctx, selector)
	if err != nil {
		return fmt.Errorf("humanoid: failed to locate target '%s': %w", selector, err)
	}

	center, valid := boxToCenter(geo)
	if !valid {
		return fmt.Errorf("humanoid: element '%s' has invalid geometry", selector)
	}

	// Calculate the specific point to move to within the element's bounds.
	target := h.calculateTargetPoint(geo, center, Vector2D{X: 0, Y: 0})

	// Delegate the actual movement simulation to the vector-based method.
	return h.moveToVector(ctx, target, opts)
}

// moveToVector is the internal, non-locking core movement logic.
// It assumes the caller holds the lock.
func (h *Humanoid) moveToVector(ctx context.Context, target Vector2D, opts *InteractionOptions) error {
	startPos := h.currentPos
	dist := startPos.Dist(target)

	// No need to move if we're already there.
	if dist < 1.0 {
		return nil
	}

	// Update fatigue based on distance; this is now safe without an internal lock.
	h.updateFatigue(dist / 1000.0)

	var field *PotentialField
	if opts != nil {
		field = opts.Field
	}

	// Simulate the trajectory of the mouse movement.
	// This function is assumed to exist and be non-locking.
	finalVelocity, err := h.simulateTrajectory(ctx, startPos, target, field, schemas.ButtonNone)
	if err != nil {
		return err
	}

	// Final corrective snap to the exact target coordinate.
	h.currentPos = target
	mouseMoveData := schemas.MouseEventData{
		Type:    schemas.MouseMove,
		X:       h.currentPos.X,
		Y:       h.currentPos.Y,
		Button:  h.currentButtonState,
		Buttons: h.calculateButtonsBitfield(h.currentButtonState),
	}
	if err := h.executor.DispatchMouseEvent(ctx, mouseMoveData); err != nil {
		return err
	}

	// Simulate the final cognitive pause before a click.
	terminalPause := h.calculateTerminalFittsLaw(dist)
	h.recoverFatigue(terminalPause)
	
	h.logger.Debug("moveToVector completed", zap.Any("finalVelocity", finalVelocity))
	return h.executor.Sleep(ctx, terminalPause)
}

// calculateTargetPoint determines a realistic coordinate within an element's bounds.
// It assumes the caller holds the lock.
func (h *Humanoid) calculateTargetPoint(geo *schemas.ElementGeometry, center Vector2D, finalVelocity Vector2D) Vector2D {
	if geo == nil || geo.Width == 0 || geo.Height == 0 {
		return center
	}

	width, height := float64(geo.Width), float64(geo.Height)
	// Aim for the inner 90% of the element to avoid clicking the very edge.
	effectiveWidth := width * 0.9
	effectiveHeight := height * 0.9

	rng := h.rng

	// Use a normal distribution to pick a point near the center.
	stdDevX := effectiveWidth / 6.0
	stdDevY := effectiveHeight / 6.0
	offsetX := rng.NormFloat64() * stdDevX
	offsetY := rng.NormFloat64() * stdDevY

	// If moving quickly, introduce a slight overshoot bias in the direction of movement.
	velocityMag := finalVelocity.Mag()
	if velocityMag > 1e-6 {
		// Normalize the effect of the velocity on the bias.
		normalizedVelocity := math.Min(1.0, velocityMag/4000.0)
		maxBiasX := width * 0.1
		maxBiasY := height * 0.1
		velDir := finalVelocity.Normalize()
		offsetX += velDir.X * normalizedVelocity * maxBiasX
		offsetY += velDir.Y * normalizedVelocity * maxBiasY
	}

	finalX := center.X + offsetX
	finalY := center.Y + offsetY

	// Clamp the final point to be within the element's actual bounds.
	minX, maxX := center.X-width/2.0+1.0, center.X+width/2.0-1.0
	minY, maxY := center.Y-height/2.0+1.0, center.Y+height/2.0-1.0

	finalX = math.Max(minX, math.Min(maxX, finalX))
	finalY = math.Max(minY, math.Min(maxY, finalY))

	return Vector2D{X: finalX, Y: finalY}
}