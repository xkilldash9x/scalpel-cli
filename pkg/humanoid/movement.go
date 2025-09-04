package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// MoveTo simulates human-like movement from the current position to the target selector.
func (h *Humanoid) MoveTo(selector string, field *PotentialField) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		h.updateFatigue(1.0)

		if err := h.intelligentScroll(selector).Do(ctx); err != nil {
			h.logger.Debug("Humanoid: Scrolling to element completed or encountered issues", zap.Error(err), zap.String("selector", selector))
		}

		if err := h.CognitivePause(ctx, 150, 50); err != nil {
			return err
		}

		box, err := h.getElementBoxBySelector(ctx, selector)
		if err != nil {
			return fmt.Errorf("humanoid: failed to locate target element after scroll: %w", err)
		}

		targetCenter, targetWidth, _ := boxToDimensions(box)

		finalVelocity, err := h.executeMovement(ctx, targetCenter, targetWidth, field, 0)
		if err != nil {
			return err
		}

		finalPos := h.generateClickPoint(box, targetCenter, finalVelocity)

		if h.GetCurrentPos().Dist(finalPos) > 0.5 {
			dispatchMove := input.DispatchMouseEvent(input.MouseMoved, finalPos.X, finalPos.Y)
			if err := dispatchMove.Do(ctx); err != nil {
				return fmt.Errorf("humanoid: failed to move to final point: %w", err)
			}
		}

		h.mu.Lock()
		h.currentPos = finalPos
		h.mu.Unlock()

		return nil
	})
}

// executeMovement handles the physics simulation of the move.
func (h *Humanoid) executeMovement(ctx context.Context, targetCenter Vector2D, targetWidth float64, field *PotentialField, buttonState input.MouseButton) (Vector2D, error) {
	startPos := h.GetCurrentPos()
	distance := startPos.Dist(targetCenter)

	if distance < 2.0 {
		return Vector2D{}, nil
	}

	duration := h.fittsLawMT(distance, targetWidth)

	if field == nil {
		field = NewPotentialField()
	}

	numSteps := math.Max(10.0, math.Min(200.0, distance/3.0))

	idealPath := h.generateIdealPath(startPos, targetCenter, field, int(numSteps))

	startTime := time.Now()
	deadline := startTime.Add(time.Duration(duration) * time.Millisecond)

	finalVelocity, err := h.executePathChase(ctx, startPos, idealPath, startTime, deadline, buttonState)
	if err != nil {
		return Vector2D{}, fmt.Errorf("humanoid: movement execution failed: %w", err)
	}
	return finalVelocity, nil
}