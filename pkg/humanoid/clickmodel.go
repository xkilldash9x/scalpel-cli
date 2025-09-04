package humanoid

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/chromedp/cdproto/input"
)

// Click performs a human-like click on a given selector.
func (h *Humanoid) Click(ctx context.Context, selector string) error {
	pt, err := h.getCenterOfElement(ctx, selector)
	if err != nil {
		return fmt.Errorf("failed to get center of element '%s': %w", selector, err)
	}

	if err := h.MoveTo(ctx, pt, nil); err != nil {
		return fmt.Errorf("failed to move to element '%s': %w", selector, err)

	}

	return h.clickAt(ctx, pt)
}

// clickAt dispatches the low-level mouse press and release events with high-fidelity timestamps.
func (h *Humanoid) clickAt(ctx context.Context, pt Vector2D) error {
	// Dispatch mouse pressed event
	pressEvent := (&input.DispatchMouseEventParams{
		Type:       input.MousePressed,
		X:          pt.X,
		Y:          pt.Y,
		Button:     input.MouseButtonLeft,
		ClickCount: 1,
	}).WithTimestamp(input.TimeSinceEpoch(time.Now().Unix()))

	if err := h.browser.Execute(ctx, "Input.dispatchMouseEvent", nil, pressEvent); err != nil {
		return fmt.Errorf("failed to dispatch mouse pressed event: %w", err)
	}

	time.Sleep(time.Duration(rand.Intn(100)+50) * time.Millisecond)

	// Dispatch mouse released event
	releaseEvent := (&input.DispatchMouseEventParams{
		Type:       input.MouseReleased,
		X:          pt.X,
		Y:          pt.Y,
		Button:     input.MouseButtonLeft,
		ClickCount: 1,
	}).WithTimestamp(input.TimeSinceEpoch(time.Now().Unix()))

	if err := h.browser.Execute(ctx, "Input.dispatchMouseEvent", nil, releaseEvent); err != nil {
		return fmt.Errorf("failed to dispatch mouse released event: %w", err)
	}

	return nil
}