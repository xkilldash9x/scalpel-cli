// pkg/humanoid/movement.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// MoveTo simulates human like movement from the current position to the target selector.
func (h *Humanoid) MoveTo(selector string, field *PotentialField) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Moving is a high intensity action.
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

		// 4. Calculate the target point (center with some noise).
		target := h.calculateTargetPoint(box, box.Center(), Vector2D{X: 0, Y: 0})

		// 5. Execute the movement.
		return h.MoveToVector(target, field).Do(ctx)
	})
}

// MoveToVector simulates human like movement from the current position to the target vector.
func (h *Humanoid) MoveToVector(target Vector2D, field *PotentialField) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		h.mu.Lock()
		start := h.currentPos
		h.mu.Unlock()

		if field == nil {
			field = NewPotentialField()
		}

		// Simulate the trajectory and dispatch mouse events.
		// The button state is passed to handle dragging movements.
		h.mu.Lock()
		buttonState := h.currentButtonState
		h.mu.Unlock()

		// Simulate the movement and get the final velocity.
		finalVelocity, err := h.simulateTrajectory(ctx, start, target, field, buttonState)
		if err != nil {
			return err
		}

		// Recalculate the target point with the final velocity to simulate overshooting.
		h.mu.Lock()
		finalPos := h.currentPos
		h.mu.Unlock()
		box, _ := h.getElementBoxByVector(ctx, finalPos)
		finalTarget := h.calculateTargetPoint(box, finalPos, finalVelocity)

		// A small correction movement if the final position is not the same as the target.
		if finalTarget.Dist(finalPos) > 1.0 {
			correctionField := NewPotentialField()
			_, err = h.simulateTrajectory(ctx, finalPos, finalTarget, correctionField, buttonState)
		}

		return err
	})
}

// calculateTargetPoint determines a realistic click point within an element,
// considering its center, size, and the velocity of the mouse.
func (h *Humanoid) calculateTargetPoint(box *dom.BoxModel, center Vector2D, finalVelocity Vector2D) Vector2D {
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

	// Clamp to the element's bounding box.
	finalX = math.Max(float64(box.Content[0]), math.Min(finalX, float64(box.Content[2])))
	finalY = math.Max(float64(box.Content[1]), math.Min(finalY, float64(box.Content[5])))

	return Vector2D{X: finalX, Y: finalY}
}