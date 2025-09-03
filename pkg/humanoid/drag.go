// pkg/humanoid/drag.go
package humanoid

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// Drag simulates a human-like drag and drop operation from a start selector to an end selector.
func (h *Humanoid) Drag(startSelector, endSelector string, field *PotentialField) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Update fatigue at the start of the operation. Dragging is intensive.
		h.updateFatigue(1.5)

		// 1. Move to the starting element.
		if err := h.MoveTo(startSelector, field).Do(ctx); err != nil {
			return fmt.Errorf("humanoid: failed to move to drag start element: %w", err)
		}

		// 2. Mouse Down (Initiate Drag).
		startPos := h.GetCurrentPos()

		// Pre-press delay (physiological).
		if err := h.pause(ctx, 70, 25); err != nil {
			return err
		}

		dispatchDown := input.DispatchMouseEvent(input.MousePressed, startPos.X, startPos.Y).
			WithButton(input.Left).WithClickCount(1)
		if err := dispatchDown.Do(ctx); err != nil {
			return fmt.Errorf("humanoid: failed to dispatch mouse press for drag: %w", err)
		}

		// Robustness: Define a function to ensure the mouse is released even if subsequent steps fail.
		releaseFunc := func(pos Vector2D) {
			// Use a short-lived background context to ensure release happens even if the main context is cancelled.
			releaseCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			input.DispatchMouseEvent(input.MouseReleased, pos.X, pos.Y).WithButton(input.Left).Do(releaseCtx)
		}

		// Delay while holding before starting the drag movement (Cognitive Planning).
		if err := h.CognitivePause(ctx, 150, 50); err != nil {
			releaseFunc(startPos)
			return err
		}

		// 3. Drag Movement to the end element.
		box, err := h.getElementBoxBySelector(ctx, endSelector)
		if err != nil {
			// If the target element isn't found, we cannot complete the drag realistically.
			releaseFunc(h.GetCurrentPos())
			h.logger.Warn("Humanoid: failed to find drag target element", zap.Error(err), zap.String("selector", endSelector))
			return fmt.Errorf("humanoid: failed to find drag target element: %w", err)
		}

		targetCenter, targetWidth, _ := boxToDimensions(box)

		// Execute the movement while the button is held (input.Left).
		// This phase utilizes the dynamics model defined in movement.go.
		_, err = h.executeMovement(ctx, targetCenter, targetWidth, field, input.Left)

		if err != nil {
			// Release at the last known position from the simulation loop.
			releaseFunc(h.GetCurrentPos())
			return fmt.Errorf("humanoid: drag movement failed: %w", err)
		}

		// 4. Final Positioning and Mouse Up (Drop).
		finalPos := h.GetCurrentPos()

		// Delay before release (physiological).
		if err := h.pause(ctx, 80, 30); err != nil {
			releaseFunc(finalPos)
			return err
		}

		// Mouse Up.
		dispatchUp := input.DispatchMouseEvent(input.MouseReleased, finalPos.X, finalPos.Y).
			WithButton(input.Left).WithClickCount(1)
		if err := dispatchUp.Do(ctx); err != nil {
			return fmt.Errorf("humanoid: failed to dispatch mouse release for drop: %w", err)
		}

		return nil
	})
}
