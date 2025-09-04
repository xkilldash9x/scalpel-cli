// pkg/humanoid/clickmodel.go
package humanoid

import (
	"context"
	"math/rand"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
)

// Click performs a human-like click at the specified coordinates.
func (h *Humanoid) Click(ctx context.Context, x, y float64, exec interfaces.Executor) error {
	target := Vector2D{X: x, Y: y}

	// First, move to the target location.
	if err := h.MoveTo(ctx, target, exec); err != nil {
		return err
	}

	// Simulate the physical mouse press and release.
	if err := h.dispatchMouseClick(ctx, x, y, exec); err != nil {
		return err
	}

	// Clicking action slightly increases fatigue.
	h.updateFatigue(0.02)

	return nil
}

// dispatchMouseClick sends the mouse down and up events to the browser.
func (h *Humanoid) dispatchMouseClick(ctx context.Context, x, y float64, exec interfaces.Executor) error {
	pos, err := h.GetCurrentPos()
	if err != nil {
		return err
	}

	// Introduce a tiny random pause before the click.
	h.pause(time.Duration(rand.Intn(30)+20) * time.Millisecond)

	// Mouse Down
	mouseDown := input.DispatchMouseEvent(input.MousePressed, pos.X, pos.Y).WithButton(input.MouseButtonLeft).WithClickCount(1)
	if err := exec.Execute(ctx, mouseDown); err != nil {
		h.logger.Printf("DEBUG: Mouse down event failed: %v", err)
		return err
	}

	// Hold the click for a human-like duration.
	holdDuration := time.Duration(h.rng.Intn(70)+50) * time.Millisecond // 50-120ms
	time.Sleep(holdDuration)

	// Mouse Up
	mouseUp := input.DispatchMouseEvent(input.MouseReleased, pos.X, pos.Y).WithButton(input.MouseButtonLeft).WithClickCount(1)
	if err := exec.Execute(ctx, mouseUp); err != nil {
		h.logger.Printf("DEBUG: Mouse up event failed: %v", err)
		return err
	}

	return nil
}
