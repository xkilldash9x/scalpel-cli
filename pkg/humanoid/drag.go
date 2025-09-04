package humanoid

import (
	"context"
	"fmt"
	"github.com/chromedp/cdproto/input"
	"time"
)

// DragAndDrop simulates a human-like drag-and-drop action.
func (h *Humanoid) DragAndDrop(ctx context.Context, startSelector, endSelector string) error {
	start, err := h.getCenterOfElement(ctx, startSelector)
	if err != nil {
		return fmt.Errorf("could not get starting element position: %w", err)
	}

	end, err := h.getCenterOfElement(ctx, endSelector)
	if err != nil {
		return fmt.Errorf("could not get ending element position: %w", err)
	}

	field := NewPotentialField(
		NewGravityPoint(end.X, end.Y, h.config.Attraction),
		NewGravityPoint(start.X, start.Y, h.config.Repulsion),
	)

	if err := h.MoveTo(ctx, start, nil); err != nil {
		return fmt.Errorf("failed to move to starting element: %w", err)
	}
	if err := h.mouseDown(ctx); err != nil {
		return fmt.Errorf("failed to press mouse button: %w", err)
	}

	if err := h.MoveTo(ctx, end, field); err != nil {
		return fmt.Errorf("failed during drag movement: %w", err)
	}

	if err := h.mouseUp(ctx); err != nil {
		return fmt.Errorf("failed to release mouse button: %w", err)
	}

	return nil
}

// mouseDown simulates pressing the left mouse button.
func (h *Humanoid) mouseDown(ctx context.Context) error {
	p := &input.DispatchMouseEventParams{
		Type:   input.MousePressed,
		X:      h.mousePos.X,
		Y:      h.mousePos.Y,
		Button: input.MouseButtonLeft,
	}
	return h.browser.Execute(ctx, "Input.dispatchMouseEvent", nil, p)
}

// mouseUp simulates releasing the left mouse button.
func (h *Humanoid) mouseUp(ctx context.Context) error {
	p := &input.DispatchMouseEventParams{
		Type:   input.MouseReleased,
		X:      h.mousePos.X,
		Y:      h.mousePos.Y,
		Button: input.MouseButtonLeft,
	}
	return h.browser.Execute(ctx, "Input.dispatchMouseEvent", nil, p)
}