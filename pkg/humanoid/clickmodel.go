// pkg/humanoid/clickmodel.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	// CRITICAL IMPORT: Required for input.MouseButtonLeft, input.MouseButtonNone, etc.
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
			if err := h.mouseDown(ctx, currentPos, input.MouseButtonLeft); err != nil {
				return fmt.Errorf("failed to dispatch mousedown: %w", err)
			}

			// Delay between mouse down and mouse up (Dwell time).
			h.mu.Lock()
			duration := time.Duration(50+h.rng.Intn(100)) * time.Millisecond
			h.mu.Unlock()

			if err := sleepContext(ctx, duration); err != nil {
				return err
			}

			if err := h.mouseUp(ctx, currentPos, input.MouseButtonLeft); err != nil {
				return fmt.Errorf("failed to dispatch mouseup: %w", err)
			}

			// Clicking is a moderately intense action.
			h.updateFatigue(0.5)
			return nil
		}),
	}
}

// Helper to get the current time as an input.TimeSinceEpoch pointer.
// This is required because WithTimestamp expects a pointer.
func timeNowInputPtr() *input.TimeSinceEpoch {
	// input.TimeSinceEpoch is an alias for cdp.TimeSinceEpoch
	t := input.TimeSinceEpoch(time.Now())
	return &t
}

// mouseDown simulates pressing the mouse button down.
func (h *Humanoid) mouseDown(ctx context.Context, pos Vector2D, button input.MouseButton) error {
	h.mu.Lock()
	// Use dynamic config (affected by fatigue).
	noiseX := (h.rng.Float64() - 0.5) * h.dynamicConfig.ClickNoise
	noiseY := (h.rng.Float64() - 0.5) * h.dynamicConfig.ClickNoise
	// Update the button state BEFORE dispatching the event.
	h.currentButtonState = button
	h.mu.Unlock()

	err := input.DispatchMouseEvent(input.MousePressed, pos.X+noiseX, pos.Y+noiseY).
		WithButton(button).
		WithClickCount(1).
		WithTimestamp(timeNowInputPtr()).
		Do(ctx)

	if err != nil {
		// If dispatch failed, reset the state.
		h.mu.Lock()
		h.currentButtonState = input.MouseButtonNone
		h.mu.Unlock()
	}
	return err
}

// mouseUp simulates releasing the mouse button.
func (h *Humanoid) mouseUp(ctx context.Context, pos Vector2D, button input.MouseButton) error {
	// Noise upon release (typically less than on down).
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
	mt += (rng.Float64() - 0.5) * mt * 0.2

	if mt < 50 {
		mt = 50 // Enforce a minimum physiological delay.
	}

	return time.Duration(mt) * time.Millisecond
}

// sleepContext is a utility for context-aware sleeps.
func sleepContext(ctx context.Context, duration time.Duration) error {
	t := time.NewTimer(duration)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}