// -- pkg/humanoid/drag.go --
package humanoid

import (
	"context"
	"fmt"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// DragAndDrop simulates a human-like drag-and-drop action.
func (h *Humanoid) DragAndDrop(startSelector, endSelector string) chromedp.Action {
	var start, end Vector2D

	// The entire operation is a sequence of tasks.
	return chromedp.Tasks{
		// 1. Preparation.
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.updateFatigue(1.5)

			var err error
			// Helper functions execute immediately.
			start, err = h.getCenterOfElement(ctx, startSelector)
			if err != nil {
				h.logger.Error("DragAndDrop failed: could not get starting element position",
					zap.String("selector", startSelector),
					zap.Error(err))
				return fmt.Errorf("could not get starting element position: %w", err)
			}

			end, err = h.getCenterOfElement(ctx, endSelector)
			if err != nil {
				h.logger.Error("DragAndDrop failed: could not get ending element position",
					zap.String("selector", endSelector),
					zap.Error(err))
				return fmt.Errorf("could not get ending element position: %w", err)
			}
			return nil
		}),

		// 2. Move to the starting element.
		h.MoveTo(startSelector, nil),

		// 3. Pause briefly before pressing down.
		h.CognitivePause(80, 30),

		// 4. Mouse down (Grab).
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.mu.Lock()
			currentPos := h.currentPos
			h.mu.Unlock()

			// FIXED: Use the string literal "left" as requested.
			if err := chromedp.MouseEvent(input.MousePressed, currentPos.X, currentPos.Y, chromedp.Button("left")).Do(ctx); err != nil {
				return err
			}

			h.mu.Lock()
			h.currentButtonState = MouseButtonLeft
			h.mu.Unlock()
			return nil
		}),

		// 5. Pause briefly after pressing down.
		h.CognitivePause(100, 40),

		// 6. Execute the drag movement.
		chromedp.ActionFunc(func(ctx context.Context) error {
			field := NewPotentialField()
			h.mu.Lock()
			attractionStrength := h.dynamicConfig.FittsA
			if attractionStrength <= 0 {
				attractionStrength = 100.0 // Safety fallback
			}
			h.mu.Unlock()

			field.AddSource(end, attractionStrength, 150.0)
			field.AddSource(start, -attractionStrength*0.2, 100.0)

			// Execute the vector-based move.
			return h.MoveToVector(end, field).Do(ctx)
		}),

		// 7. Short pause before release.
		h.CognitivePause(70, 30),

		// 8. Mouse up (Drop).
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.mu.Lock()
			currentPos := h.currentPos
			h.mu.Unlock()

			// FIXED: Use the string literal "left" as requested.
			if err := chromedp.MouseEvent(input.MouseReleased, currentPos.X, currentPos.Y, chromedp.Button("left")).Do(ctx); err != nil {
				return err
			}

			h.mu.Lock()
			h.currentButtonState = MouseButtonNone
			h.mu.Unlock()
			return nil
		}),
	}
}