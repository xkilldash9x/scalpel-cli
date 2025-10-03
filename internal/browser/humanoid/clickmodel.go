package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// IntelligentClick is a public method that acquires a lock for the entire action.
func (h *Humanoid) IntelligentClick(ctx context.Context, selector string, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Call the internal, non-locking move method to avoid deadlocks.
	// This method (`moveToSelector`) is assumed to be the non-locking counterpart to MoveTo.
	if err := h.moveToSelector(ctx, selector, opts); err != nil {
		return err
	}

	// The rest of the logic can now safely access state without further locks.
	currentPos := h.currentPos

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

	h.currentButtonState = schemas.ButtonLeft

	// Determine a realistic hold duration.
	rng := h.rng
	holdDuration := time.Duration(60+rng.NormFloat64()*20) * time.Millisecond
	if err := h.executor.Sleep(ctx, holdDuration); err != nil {
		return err
	}

	// Release the mouse button.
	// We read the position again in case a microscopic hesitation move occurred.
	currentPos = h.currentPos

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

	h.currentButtonState = schemas.ButtonNone

	return nil
}

// calculateTerminalFittsLaw determines the time required before initiating a click.
// This is an internal helper that assumes the lock is held.
func (h *Humanoid) calculateTerminalFittsLaw(distance float64) time.Duration {
	const W = 20.0 // Assumed default target width (W) in pixels for the terminal phase.

	id := math.Log2(1.0 + distance/W)

	A := h.dynamicConfig.FittsA
	B := h.dynamicConfig.FittsB
	rng := h.rng

	mt := A + B*id
	mt += mt * (rng.Float64()*0.2 - 0.1) // Add +/- 10% jitter

	if mt < 0 {
		mt = 0
	}

	return time.Duration(mt) * time.Millisecond
}