// -- pkg/humanoid/movement.go --
package humanoid

import (
	"context"
	"fmt"
	"math"

	// Required for BoxModel (necessary low-level access)
	"github.com/chromedp/cdproto/dom"
	// Required for input.MouseButton type for simulateTrajectory
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// MoveTo simulates human like movement from the current position to the target selector.
func (h *Humanoid) MoveTo(selector string, field *PotentialField) chromedp.Action {
	var target Vector2D

	// The entire operation is a sequence of tasks (chromedp.Tasks).
	return chromedp.Tasks{
		// 1. Preparation Phase: Scroll, locate, and plan.
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Moving is a high intensity action.
			h.updateFatigue(1.0)

			// 1a. Ensure the target is visible (Scrolling).
			if err := h.intelligentScroll(selector).Do(ctx); err != nil {
				h.logger.Debug("Humanoid: Scrolling encountered issues (non-critical)", zap.Error(err), zap.String("selector", selector))
				// Continue even if scrolling fails (e.g., context cancelled during scroll).
			}

			// 1b. Cognitive pause (Visual search and planning after scroll).
			if err := h.CognitivePause(150, 50).Do(ctx); err != nil {
				return err
			}

			// 1c. Locate the target element geometry.
			box, err := h.getElementBoxBySelector(ctx, selector)
			if err != nil {
				return fmt.Errorf("humanoid: failed to locate target element after scroll: %w", err)
			}

			center, valid := boxToCenter(box)
			if !valid {
				return fmt.Errorf("humanoid: element '%s' has invalid geometry", selector)
			}

			// 1d. Calculate the target point and store it for the next step.
			// Initial target calculation assumes zero initial velocity bias.
			target = h.calculateTargetPoint(box, center, Vector2D{X: 0, Y: 0})
			return nil
		}),

		// 2. Execution Phase: Perform the movement.
		chromedp.ActionFunc(func(ctx context.Context) error {
			// MoveToVector handles the main trajectory and correction.
			return h.MoveToVector(target, field).Do(ctx)
		}),
	}
}

// MoveToVector simulates human like movement from the current position to the target vector.
func (h *Humanoid) MoveToVector(target Vector2D, field *PotentialField) chromedp.Action {
	// We need to capture the final velocity from the main movement to inform the correction.
	var finalVelocity Vector2D

	return chromedp.Tasks{
		// Main movement action
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.mu.Lock()
			start := h.currentPos
			// Crucial: Read the current button state (e.g., for dragging).
			buttonState := h.currentButtonState
			h.mu.Unlock()

			if field == nil {
				field = NewPotentialField()
			}

			// Simulate the movement. This function call is blocking.
			var err error
			
			// Cast our internal MouseButton type to the required input.MouseButton type.
			finalVelocity, err = h.simulateTrajectory(ctx, start, target, field, input.MouseButton(buttonState))

			if err == nil {
				h.mu.Lock()
				h.lastMovementDistance = start.Dist(target)
				h.mu.Unlock()
			}

			return err
		}),
		// Corrective movement action
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.mu.Lock()
			finalPos := h.currentPos
			buttonState := h.currentButtonState
			h.mu.Unlock()

			// Use a virtual box around the target coordinate for the recalculation context.
			box, _ := h.getElementBoxByVector(ctx, target)

			// Recalculate the target point, considering the momentum (finalVelocity) from the previous step.
			finalTarget := h.calculateTargetPoint(box, target, finalVelocity)

			// A small correction movement if the deviation is significant.
			distanceToFinalTarget := finalTarget.Dist(finalPos)
			if distanceToFinalTarget > 1.5 { // Threshold for correction (pixels).
				correctionField := NewPotentialField()
				// Cast our internal MouseButton type to the required input.MouseButton type.
				_, err := h.simulateTrajectory(ctx, finalPos, finalTarget, correctionField, input.MouseButton(buttonState))

				if err == nil {
					h.mu.Lock()
					h.lastMovementDistance += distanceToFinalTarget
					h.mu.Unlock()
				}
				return err
			}
			return nil
		}),
	}
}

// calculateTargetPoint determines a realistic click point within an element.
func (h *Humanoid) calculateTargetPoint(box *dom.BoxModel, center Vector2D, finalVelocity Vector2D) Vector2D {
	if box == nil || box.Width == 0 || box.Height == 0 {
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

	// Clamp to the element's bounding box edges (with 1px margin).
	minX := center.X - width/2.0 + 1.0
	maxX := center.X + width/2.0 - 1.0
	minY := center.Y - height/2.0 + 1.0
	maxY := center.Y + height/2.0 - 1.0

	finalX = math.Max(minX, math.Min(maxX, finalX))
	finalY = math.Max(minY, math.Min(maxY, finalY))

	return Vector2D{X: finalX, Y: finalY}
}