package humanoid

import (
	"context"
	"fmt"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// DragAndDrop is a public method that acquires a lock for the entire action.
func (h *Humanoid) DragAndDrop(ctx context.Context, startSelector, endSelector string, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var start, end Vector2D
	var err error

	// Preparation: Increase fatigue for a complex action.
	h.updateFatigue(1.5)

	// Get the center coordinates of the start and end elements.
	start, err = h.getCenterOfElement(ctx, startSelector, opts)
	if err != nil {
		h.logger.Error("DragAndDrop failed: could not get starting element position",
			zap.String("selector", startSelector),
			zap.Error(err),
		)
		return fmt.Errorf("dragdrop: could not get start position: %w", err)
	}

	end, err = h.getCenterOfElement(ctx, endSelector, opts)
	if err != nil {
		h.logger.Error("DragAndDrop failed: could not get ending element position",
			zap.String("selector", endSelector),
			zap.Error(err),
		)
		return fmt.Errorf("dragdrop: could not get end position: %w", err)
	}

	// Call the internal, non-locking move method.
	if err := h.moveToSelector(ctx, startSelector, opts); err != nil {
		return err
	}

	// Call the internal, non-locking pause method.
	if err := h.cognitivePause(ctx, 80, 30); err != nil {
		return err
	}

	// -- Mouse down (Grab) --
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

	// Pause briefly after pressing down to simulate holding the object.
	if err := h.cognitivePause(ctx, 100, 40); err != nil {
		h.releaseMouse(context.Background()) // Attempt cleanup if pause fails.
		return err
	}

	// -- Execute the drag movement --
	field := NewPotentialField()
	if opts != nil && opts.Field != nil {
		field = opts.Field
	}
	attractionStrength := h.dynamicConfig.FittsA
	if attractionStrength <= 0 {
		attractionStrength = 100.0 // Safety fallback
	}
	field.AddSource(end, attractionStrength, 150.0)
	field.AddSource(start, -attractionStrength*0.2, 100.0)

	moveOpts := &InteractionOptions{Field: field, EnsureVisible: false}
	// Call the internal, non-locking move method.
	if err := h.moveToVector(ctx, end, moveOpts); err != nil {
		h.logger.Warn("Humanoid: Drag movement failed, attempting cleanup (mouse release)", zap.Error(err))
		h.releaseMouse(context.Background()) // Use background context for cleanup.
		return err
	}

	// Short pause before releasing the mouse button.
	if err := h.cognitivePause(ctx, 70, 30); err != nil {
		h.releaseMouse(context.Background()) // Attempt cleanup if pause fails.
		return err
	}

	// -- Mouse up (Drop) --
	return h.releaseMouse(ctx)
}

// releaseMouse is an internal helper that assumes the caller holds the lock.
func (h *Humanoid) releaseMouse(ctx context.Context) error {
	currentPos := h.currentPos
	// Only release if our state shows the left button is currently pressed.
	if h.currentButtonState != schemas.ButtonLeft {
		return nil // Nothing to do.
	}

	mouseUpData := schemas.MouseEventData{
		Type:       schemas.MouseRelease,
		X:          currentPos.X,
		Y:          currentPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    0, // Bitfield: 0 indicates no buttons are pressed after release.
	}

	err := h.executor.DispatchMouseEvent(ctx, mouseUpData)
	if err != nil {
		// Log the failure but continue to update state to prevent getting stuck.
		h.logger.Error("Humanoid: Failed to dispatch mouse release event, but updating state anyway", zap.Error(err))
	}

	// Always update the internal state to "none".
	h.currentButtonState = schemas.ButtonNone

	return err
}