package humanoid

import (
	"context"
	"math"
	"time"

	// "github.com/chromedp/cdproto/input" // Removed
)

// IntelligentClick combines movement, timing, and clicking.
// It executes immediately using the provided context and the Humanoid's executor.
func (h *Humanoid) IntelligentClick(ctx context.Context, selector string, field *PotentialField) error {
	// ... (Steps 1 and 2: Movement and Fitts's Law delay remain the same) ...

	// 3. Mouse down.
	h.mu.Lock()
	currentPos := h.currentPos
	h.mu.Unlock()

	// Prepare mouse press parameters using the agnostic struct.
	mouseDownData := MouseEventData{
		Type:       MousePress,
		X:          currentPos.X,
		Y:          currentPos.Y,
		Button:     ButtonLeft,
		ClickCount: 1,
		// When pressed, the 'Buttons' field must reflect the state (1=Left).
		Buttons: 1,
	}

	// Dispatch via the executor.
	if err := h.executor.DispatchMouseEvent(ctx, mouseDownData); err != nil {
		return err
	}

	h.mu.Lock()
	h.currentButtonState = ButtonLeft
	h.mu.Unlock()

	// 4. Realistic hold duration.
	// ... (Step 4: Hold duration calculation and sleep remain the same) ...

	// 5. Mouse up.
	h.mu.Lock()
	currentPos = h.currentPos
	h.mu.Unlock()

	// Prepare mouse release parameters.
	mouseUpData := MouseEventData{
		Type:       MouseRelease,
		X:          currentPos.X,
		Y:          currentPos.Y,
		Button:     ButtonLeft,
		ClickCount: 1,
		// When released, the 'Buttons' field must be 0.
		Buttons: 0,
	}

	// Dispatch via the executor.
	if err := h.executor.DispatchMouseEvent(ctx, mouseUpData); err != nil {
		return err
	}

	h.mu.Lock()
	h.currentButtonState = ButtonNone
	h.mu.Unlock()

	return nil
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

	if mt < 0 {
		mt = 0
	}

	return time.Duration(mt) * time.Millisecond
}