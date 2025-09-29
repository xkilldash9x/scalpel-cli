package humanoid

import (
	"context"
	"fmt"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// DragAndDrop simulates a human-like drag and drop action from a start element to an end element.
func (h *Humanoid) DragAndDrop(ctx context.Context, startSelector, endSelector string, opts *InteractionOptions) error {
	var start, end Vector2D
	var err error

	// Preparation: Increase fatigue for a complex action.
	h.updateFatigue(1.5)

	// Get the center coordinates of the start and end elements.
	// We pass 'opts' here to ensure visibility is checked correctly.
	start, err = h.getCenterOfElement(ctx, startSelector, opts)
	if err != nil {
		h.logger.Error("DragAndDrop failed: could not get starting element position",
			zap.String("selector", startSelector),
			zap.Error(err),
		)
		return fmt.Errorf("could not get starting element position: %w", err)
	}

	end, err = h.getCenterOfElement(ctx, endSelector, opts)
	if err != nil {
		h.logger.Error("DragAndDrop failed: could not get ending element position",
			zap.String("selector", endSelector),
			zap.Error(err),
		)
		return fmt.Errorf("could not get ending element position: %w", err)
	}

	// Move the cursor to the starting element.
	if err := h.MoveTo(ctx, startSelector, opts); err != nil {
		return err
	}

	// Pause briefly before pressing down.
	if err := h.CognitivePause(ctx, 80, 30); err != nil {
		return err
	}

	// -- Mouse down (Grab) --
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

	// Dispatch the "mouse down" event via the executor.
	if err := h.executor.DispatchMouseEvent(ctx, mouseDownData); err != nil {
		return err
	}

	// Update the internal state to reflect the button being held down.
	h.mu.Lock()
	h.currentButtonState = schemas.ButtonLeft
	h.mu.Unlock()

	// Pause briefly after pressing down to simulate holding the object.
	if err := h.CognitivePause(ctx, 100, 40); err != nil {
		h.releaseMouse(context.Background()) // Attempt cleanup if pause fails.
		return err
	}

	// -- Execute the drag movement --
	field := NewPotentialField()
	if opts != nil && opts.Field != nil {
		field = opts.Field
	}

	h.mu.Lock()
	attractionStrength := h.dynamicConfig.FittsA
	if attractionStrength <= 0 {
		attractionStrength = 100.0 // Safety fallback
	}
	h.mu.Unlock()

	field.AddSource(end, attractionStrength, 150.0)
	field.AddSource(start, -attractionStrength*0.2, 100.0)

	// Execute the vector-based move to the target.
	moveOpts := &InteractionOptions{Field: field, EnsureVisible: false} // Skip visibility, we know it's visible.
	if err := h.MoveToVector(ctx, end, moveOpts); err != nil {
		h.logger.Warn("Humanoid: Drag movement failed, attempting cleanup (mouse release)", zap.Error(err))
		h.releaseMouse(context.Background()) // Use background context for cleanup.
		return err
	}

	// Short pause before releasing the mouse button.
	if err := h.CognitivePause(ctx, 70, 30); err != nil {
		h.releaseMouse(context.Background()) // Attempt cleanup if pause fails.
		return err
	}

	// -- Mouse up (Drop) --
	return h.releaseMouse(ctx)
}

// releaseMouse is a helper function to handle the mouse up event and update internal state.
func (h *Humanoid) releaseMouse(ctx context.Context) error {
	h.mu.Lock()
	currentPos := h.currentPos
	// Only release if our state shows the left button is currently pressed.
	if h.currentButtonState != schemas.ButtonLeft {
		h.mu.Unlock()
		return nil // Nothing to do.
	}
	h.mu.Unlock()

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
	h.mu.Lock()
	h.currentButtonState = schemas.ButtonNone
	h.mu.Unlock()

	return err
}
