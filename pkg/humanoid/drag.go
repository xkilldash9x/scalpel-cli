// pkg/humanoid/drag.go
package humanoid

import (
	"context"
	"fmt"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
)

// DragAndDrop simulates a human-like drag-and-drop action.
func (h *Humanoid) DragAndDrop(startSelector, endSelector string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// High-intensity action.
		h.updateFatigue(1.5)

		// 1. Locate the start and end elements.
		start, err := h.getCenterOfElement(ctx, startSelector)
		if err != nil {
			return fmt.Errorf("could not get starting element position: %w", err)
		}

		end, err := h.getCenterOfElement(ctx, endSelector)
		if err != nil {
			return fmt.Errorf("could not get ending element position: %w", err)
		}

		// 2. Create the potential field.
		field := NewPotentialField()

		h.mu.Lock()
		attractionStrength := h.dynamicConfig.FittsA
		h.mu.Unlock()

		// The end point is an attractor.
		field.AddSource(end, attractionStrength, 150.0)
		// The start point is a weak repulsor.
		field.AddSource(start, -attractionStrength*0.2, 100.0)

		// 3. Move to the starting element first.
		if err := h.MoveTo(startSelector, nil).Do(ctx); err != nil {
			return fmt.Errorf("failed to move to starting element: %w", err)
		}

		// 4. Mouse down (Grab).
		h.mu.Lock()
		currentPos := h.currentPos
		h.mu.Unlock()

		// Pause briefly before pressing down.
		if err := h.CognitivePause(ctx, 80, 30); err != nil {
			return err
		}

		// UPDATED: Use the "left" string constant for the left mouse button.
		if err := h.mouseDown(ctx, currentPos, input.MouseButtonLeft); err != nil {
			return fmt.Errorf("failed to press mouse button: %w", err)
		}

		// Pause briefly after pressing down before starting the drag.
		if err := h.CognitivePause(ctx, 100, 40); err != nil {
			return err
		}

		// 5. Execute the drag movement.
		// MoveToVector handles the movement while the button state is tracked.
		if err := h.MoveToVector(end, field).Do(ctx); err != nil {
			// Cleanup: Attempt to release the mouse even if the drag failed.
			h.mu.Lock()
			cleanupPos := h.currentPos
			h.mu.Unlock()
			// UPDATED: Use the "left" string constant for the left mouse button.
			h.mouseUp(ctx, cleanupPos, input.MouseButtonLeft)
			return fmt.Errorf("failed during drag movement: %w", err)
		}

		// 6. Mouse up (Release).
		h.mu.Lock()
		finalPos := h.currentPos
		h.mu.Unlock()

		// Pause briefly before releasing.
		if err := h.CognitivePause(ctx, 90, 35); err != nil {
			return err
		}

		// UPDATED: Use the "left" string constant for the left mouse button.
		return h.mouseUp(ctx, finalPos, input.MouseButtonLeft)
	})
}