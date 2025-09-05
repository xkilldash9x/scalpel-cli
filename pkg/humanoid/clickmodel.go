// pkg/humanoid/clickmodel.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
)

// IntelligentClick combines movement, timing, and clicking into a single, chained action.
func (h *Humanoid) IntelligentClick(selector string, field *PotentialField) chromedp.Action {
	if field == nil {
		field = NewPotentialField()
	}

	// We chain the actions using chromedp.Tasks.
	return chromedp.Tasks{
		// 1. Move to the element.
		h.MoveTo(selector, field),

		// 2. Execute the click after the move completes.
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Get the final position and distance traveled after the move.
			h.mu.Lock()
			currentPos := h.currentPos
			distance := h.lastMovementDistance
			h.mu.Unlock()

			// Apply Fitts's Law delay before the click occurs (Terminal phase latency).
			clickDelay := h.calculateTerminalFittsLaw(distance)
			if err := sleepContext(ctx, clickDelay); err != nil {
				return err
			}

			// Execute the physical click (down and up).
			// UPDATED: Use the "left" string constant for the left mouse button.
			if err := h.mouseDown(ctx, currentPos, input.MouseButtonLeft); err != nil {
				return fmt.Errorf("failed to dispatch mousedown: %w", err)
			}

			// Calculate a realistic delay between mouse down and up.
			h.mu.Lock()
			holdDuration := time.Duration(h.dynamicConfig.ClickHoldMinMs+
				h.rng.Intn(h.dynamicConfig.ClickHoldMaxMs-h.dynamicConfig.ClickHoldMinMs)) * time.Millisecond
			h.mu.Unlock()

			if err := sleepContext(ctx, holdDuration); err != nil {
				return err
			}

			// UPDATED: Use the "left" string constant for the left mouse button.
			if err := h.mouseUp(ctx, currentPos, input.MouseButtonLeft); err != nil {
				return fmt.Errorf("failed to dispatch mouseup: %w", err)
			}

			return nil
		}),
	}
}

// mouseDown dispatches a mouse pressed event.
func (h *Humanoid) mouseDown(ctx context.Context, pos Vector2D, button input.MouseButton) error {
	// A little bit of noise to make the click position more realistic.
	h.mu.Lock()
	noiseX := (h.rng.Float64() - 0.5) * h.dynamicConfig.ClickNoise
	noiseY := (h.rng.Float64() - 0.5) * h.dynamicConfig.ClickNoise
	h.mu.Unlock()

	// Update the button state BEFORE the event is dispatched.
	h.mu.Lock()
	// UPDATED: No more undefined input.MouseButtonNone
	if h.currentButtonState != input.MouseButtonNone {
		h.mu.Unlock()
		return fmt.Errorf("mouse button %s is already pressed", h.currentButtonState)
	}
	h.currentButtonState = button
	h.mu.Unlock()

	return input.DispatchMouseEvent(input.MousePressed, pos.X+noiseX, pos.Y+noiseY).
		WithButton(button).
		WithClickCount(1).
		WithTimestamp(timeNowInputPtr()).
		Do(ctx)
}

// mouseUp dispatches a mouse released event.
func (h *Humanoid) mouseUp(ctx context.Context, pos Vector2D, button input.MouseButton) error {
	// A little bit of noise to make the click position more realistic.
	h.mu.Lock()
	noiseX := (h.rng.Float64() - 0.5) * (h.dynamicConfig.ClickNoise * 0.5)
	noiseY := (h.rng.Float64() - 0.5) * (h.dynamicConfig.ClickNoise * 0.5)
	h.mu.Unlock()

	err := input.DispatchMouseEvent(input.MouseReleased, pos.X+noiseX, pos.Y+noiseY).
		WithButton(button).
		WithClickCount(1).
		WithTimestamp(timeNowInputPtr()).
		Do(ctx)

	// Update the button state AFTER the event is dispatched.
	h.mu.Lock()
	// UPDATED: Use the correct "none" string constant.
	h.currentButtonState = input.MouseButtonNone
	h.mu.Unlock()

	return err
}

// calculateTerminalFittsLaw determines the time required before initiating a click (terminal latency).
// MT = A + B * log2(1 + D/W).
func (h *Humanoid) calculateTerminalFittsLaw(distance float64) time.Duration {
	const W = 20.0 // Assumed default target width (W) in pixels for the terminal phase.

	// Index of Difficulty (ID)
	id := math.Log2(1.0 + distance/W)

	h.mu.Lock()
	// Use dynamic config parameters (already affected by fatigue).
	A := h.dynamicConfig.FittsA
	B := h.dynamicConfig.FittsB
	rng := h.rng
	h.mu.Unlock()

	// Movement Time (MT) in milliseconds
	mt := A + B*id

	// Add slight randomization (+/- 10%)
	mt += mt * (rng.Float64()*0.2 - 0.1)

	return time.Duration(mt) * time.Millisecond
}