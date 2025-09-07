// -- pkg/humanoid/clickmodel.go --
package humanoid

import (
	"context"
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

	// We build a sequence of Actions using chromedp.Tasks.
	// Each action in the slice needs to be separated by a comma.
	return chromedp.Tasks{
		// 1. Human-like movement action.
		h.MoveTo(selector, field),

		// 2. Fitts's Law delay before the click.
		// This must be an ActionFunc because the delay depends on the result of the previous action (MoveTo).
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.mu.Lock()
			// Relies on MoveTo having correctly updated lastMovementDistance.
			distance := h.lastMovementDistance
			h.mu.Unlock()

			clickDelay := h.calculateTerminalFittsLaw(distance)

			// Use the standard chromedp.Sleep action executor.
			if clickDelay > 0 {
				return chromedp.Sleep(clickDelay).Do(ctx)
			}
			return nil
		}),

		// 3. Mouse down.
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.mu.Lock()
			currentPos := h.currentPos
			h.mu.Unlock()

			// MODERNIZED: Use the standard input.ButtonLeft constant directly.
			// The modern chromedp.Button() helper accepts the input.MouseButton type.
			mouseDownAction := chromedp.MouseEvent(input.MousePressed, currentPos.X, currentPos.Y, chromedp.Button(input.ButtonLeft))
			if err := mouseDownAction.Do(ctx); err != nil {
				return err
			}

			h.mu.Lock()
			h.currentButtonState = MouseButtonLeft
			h.mu.Unlock()
			return nil
		}),

		// 4. Realistic hold duration.
		// This is an ActionFunc to calculate the duration just before execution.
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.mu.Lock()

			// Ensure the range for Intn is positive to prevent panic.
			rangeMs := h.dynamicConfig.ClickHoldMaxMs - h.dynamicConfig.ClickHoldMinMs
			var randomAddition int
			if rangeMs > 0 {
				randomAddition = h.rng.Intn(rangeMs)
			}

			holdDuration := time.Duration(h.dynamicConfig.ClickHoldMinMs+randomAddition) * time.Millisecond
			h.mu.Unlock()

			// Use chromedp.Sleep action executor.
			if holdDuration > 0 {
				return chromedp.Sleep(holdDuration).Do(ctx)
			}
			return nil
		}),

		// 5. Mouse up.
		chromedp.ActionFunc(func(ctx context.Context) error {
			h.mu.Lock()
			currentPos := h.currentPos
			h.mu.Unlock()

			// MODERNIZED: Use the standard input.ButtonLeft constant directly.
			mouseUpAction := chromedp.MouseEvent(input.MouseReleased, currentPos.X, currentPos.Y, chromedp.Button(input.ButtonLeft))
			if err := mouseUpAction.Do(ctx); err != nil {
				return err
			}

			h.mu.Lock()
			h.currentButtonState = MouseButtonNone
			h.mu.Unlock()
			return nil
		}),
	}
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

	// Make sure we don't return a negative duration, which would be... weird.
	if mt < 0 {
		mt = 0
	}

	return time.Duration(mt) * time.Millisecond
}