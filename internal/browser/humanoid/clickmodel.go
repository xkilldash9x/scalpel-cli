package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// IntelligentClick combines movement, timing, and clicking into a single fluid action.
func (h *Humanoid) IntelligentClick(ctx context.Context, selector string, opts *InteractionOptions) error {
	// (Full movement logic is in movement.go, this is the final click part)
	if err := h.MoveTo(ctx, selector, opts); err != nil {
		return err
	}

	// After moving, press the mouse button.
	h.mu.Lock()
	currentPos := h.currentPos
	h.mu.Unlock()

	mouseDownData := schemas.MouseEventData{
		Type:       schemas.MousePress,
		X:          currentPos.X,
		Y:          currentPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    1, // Bitfield: 1 indicates the left button is now pressed.
	}
	if err := h.executor.DispatchMouseEvent(ctx, mouseDownData); err != nil {
		return err
	}

	h.mu.Lock()
	h.currentButtonState = schemas.ButtonLeft
	h.mu.Unlock()

	// Determine a realistic hold duration.
	h.mu.Lock()
	rng := h.rng
	h.mu.Unlock()
	holdDuration := time.Duration(60+rng.NormFloat64()*20) * time.Millisecond
	if err := h.executor.Sleep(ctx, holdDuration); err != nil {
		return err
	}

	// Release the mouse button.
	// We read the position again in case a microscopic hesitation move occurred.
	h.mu.Lock()
	currentPos = h.currentPos
	h.mu.Unlock()

	mouseUpData := schemas.MouseEventData{
		Type:       schemas.MouseRelease,
		X:          currentPos.X,
		Y:          currentPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    0, // Bitfield: 0 indicates no buttons are pressed after release.
	}
	if err := h.executor.DispatchMouseEvent(ctx, mouseUpData); err != nil {
		return err
	}

	h.mu.Lock()
	h.currentButtonState = schemas.ButtonNone
	h.mu.Unlock()

	return nil
}

// calculateTerminalFittsLaw determines the time required before initiating a click
// after the cursor has arrived at the target.
func (h *Humanoid) calculateTerminalFittsLaw(distance float64) time.Duration {
	const W = 20.0 // Assumed default target width (W) in pixels for the terminal phase.

	id := math.Log2(1.0 + distance/W)

	h.mu.Lock()
	A := h.dynamicConfig.FittsA
	B := h.dynamicConfig.FittsB
	rng := h.rng
	h.mu.Unlock()

	mt := A + B*id
	mt += mt * (rng.Float64()*0.2 - 0.1) // Add +/- 10% jitter

	if mt < 0 {
		mt = 0
	}

	return time.Duration(mt) * time.Millisecond
}
