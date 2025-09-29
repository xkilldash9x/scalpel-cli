// internal/browser/humanoid/movement.go
package humanoid

import (
	"context"
	"fmt"
	"math"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// MoveTo simulates human-like movement to a target element.
func (h *Humanoid) MoveTo(ctx context.Context, selector string, opts *InteractionOptions) error {
	// (Scrolling and planning logic would go here)

	geo, err := h.getElementBoxBySelector(ctx, selector)
	if err != nil {
		return fmt.Errorf("humanoid: failed to locate target '%s': %w", selector, err)
	}

	center, valid := boxToCenter(geo)
	if !valid {
		return fmt.Errorf("humanoid: element '%s' has invalid geometry", selector)
	}

	target := h.calculateTargetPoint(geo, center, Vector2D{X: 0, Y: 0})
	return h.MoveToVector(ctx, target, opts)
}

// MoveToVector simulates human-like movement to a specific coordinate.
func (h *Humanoid) MoveToVector(ctx context.Context, target Vector2D, opts *InteractionOptions) error {
	h.mu.Lock()
	startPos := h.currentPos
	h.mu.Unlock()

	dist := startPos.Dist(target)
	h.updateFatigue(dist / 1000.0) // Fatigue based on distance

	var field *PotentialField
	if opts != nil {
		field = opts.Field
	}

	finalVelocity, err := h.simulateTrajectory(ctx, startPos, target, field, schemas.ButtonNone)
	if err != nil {
		return err
	}

	// (Correction logic would go here if needed)
	h.logger.Debug("MoveToVector completed", zap.Any("finalVelocity", finalVelocity))

	return nil
}

// calculateTargetPoint determines a realistic click point within an element's geometry.
func (h *Humanoid) calculateTargetPoint(geo *schemas.ElementGeometry, center Vector2D, finalVelocity Vector2D) Vector2D {
	if geo == nil || geo.Width == 0 || geo.Height == 0 {
		return center
	}

	width, height := float64(geo.Width), float64(geo.Height)
	// Aim for the inner 90% of the element to avoid clicking the very edge.
	effectiveWidth := width * 0.9
	effectiveHeight := height * 0.9

	h.mu.Lock()
	rng := h.rng
	h.mu.Unlock()

	// Use a normal distribution to pick a point near the center.
	stdDevX := effectiveWidth / 6.0
	stdDevY := effectiveHeight / 6.0
	offsetX := rng.NormFloat64() * stdDevX
	offsetY := rng.NormFloat64() * stdDevY

	// If moving quickly, introduce a slight overshoot bias in the direction of movement.
	velocityMag := finalVelocity.Mag()
	if velocityMag > 1e-6 {
		normalizedVelocity := math.Min(1.0, velocityMag/4000.0)
		maxBiasX := width * 0.1
		maxBiasY := height * 0.1
		velDir := finalVelocity.Normalize()
		offsetX += velDir.X * normalizedVelocity * maxBiasX
		offsetY += velDir.Y * normalizedVelocity * maxBiasY
	}

	finalX := center.X + offsetX
	finalY := center.Y + offsetY

	// Clamp the final point to be within the element's bounds.
	minX, maxX := center.X-width/2.0+1.0, center.X+width/2.0-1.0
	minY, maxY := center.Y-height/2.0+1.0, center.Y+height/2.0-1.0

	finalX = math.Max(minX, math.Min(maxX, finalX))
	finalY = math.Max(minY, math.Min(maxY, finalY))

	return Vector2D{X: finalX, Y: finalY}
}
