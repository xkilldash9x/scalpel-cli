// File: internal/browser/humanoid/drag.go
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

	// Preparation: Increase fatigue/habituation for a complex action.
	h.updateFatigueAndHabituation(1.5)

	// 1. Move to the starting element.
	// moveToSelector handles visibility, movement, and targeting internally.
	// ActionType is set within moveToSelector.
	if err := h.moveToSelector(ctx, startSelector, opts); err != nil {
		return fmt.Errorf("dragdrop: failed to move to start: %w", err)
	}
	// Record the position where we ended up before the grab for potential field calculations.
	startPos := h.currentPos

	// 2. Pause before grabbing. (Mean Scale 0.8, StdDev Scale 0.8)
	// cognitivePause handles the ActionType switch internally (from MOVE to DRAG).
	if err := h.cognitivePause(ctx, 0.8, 0.8, ActionTypeDrag); err != nil {
		return err
	}

	// 3. Mouse down (Grab).
	// Apply click noise (physical displacement).
	grabPos := h.applyClickNoise(h.currentPos)

	mouseDownData := schemas.MouseEventData{
		Type:       schemas.MousePress,
		X:          grabPos.X,
		Y:          grabPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    1,
	}
	if err := h.executor.DispatchMouseEvent(ctx, mouseDownData); err != nil {
		return err
	}
	h.currentPos = grabPos
	h.currentButtonState = schemas.ButtonLeft

	// 4. Pause briefly after pressing down (simulating grip adjustment). (Mean Scale 1.0, StdDev Scale 1.0)
	// ActionType remains DRAG.
	if err := h.cognitivePause(ctx, 1.0, 1.0, ActionTypeDrag); err != nil {
		h.releaseMouse(context.Background()) // Attempt cleanup if pause fails.
		return err
	}

	// 5. Ensure the ending element is visible (Scroll if needed while dragging).
	if err := h.ensureVisible(ctx, endSelector, opts); err != nil {
		h.logger.Warn("Humanoid: Failed to ensure end element visibility during DragAndDrop", zap.String("selector", endSelector), zap.Error(err))
		// Proceed if possible.
	}

	// 6. Get the coordinates of the end element (after potential scrolling).
	geo, err := h.getElementBoxBySelector(ctx, endSelector)
	if err != nil {
		h.logger.Error("DragAndDrop failed: could not get ending element position", zap.String("selector", endSelector), zap.Error(err))
		h.releaseMouse(context.Background())
		return fmt.Errorf("dragdrop: could not get end position geometry: %w", err)
	}
	center, valid := boxToCenter(geo)
	if !valid {
		h.releaseMouse(context.Background())
		return fmt.Errorf("dragdrop: end element has invalid geometry")
	}
	// Calculate the precise drop target. Estimate zero final velocity for targeting bias calculation.
	endTarget := h.calculateTargetPoint(geo, center, Vector2D{X: 0, Y: 0})

	// 7. Execute the drag movement.
	// Setup Potential Field.
	field := NewPotentialField()
	if opts != nil && opts.Field != nil {
		field = opts.Field
	}
	attractionStrength := h.dynamicConfig.FittsA // Reusing FittsA as a proxy for effort/strength.
	if attractionStrength <= 0 {
		attractionStrength = 100.0 // Safety fallback
	}
	field.AddSource(endTarget, attractionStrength, 150.0)
	// Slight repulsion from the start point.
	field.AddSource(startPos, -attractionStrength*0.2, 100.0)

	// EnsureVisible must be disabled for the movement phase as it's already handled.
	disableVisible := false
	moveOpts := &InteractionOptions{Field: field, EnsureVisible: &disableVisible}

	// Move to the calculated end target. ActionType remains DRAG.
	if err := h.moveToVector(ctx, endTarget, moveOpts, ActionTypeDrag); err != nil {
		h.logger.Warn("Humanoid: Drag movement failed, attempting cleanup (mouse release)", zap.Error(err))
		h.releaseMouse(context.Background())
		return err
	}

	// 8. Short pause before releasing (confirming drop location). (Mean Scale 0.7, StdDev Scale 0.7)
	// ActionType remains DRAG.
	if err := h.cognitivePause(ctx, 0.7, 0.7, ActionTypeDrag); err != nil {
		h.releaseMouse(context.Background())
		return err
	}

	// 9. Mouse up (Drop).
	// Apply click noise for release.
	releasePos := h.applyClickNoise(h.currentPos)
	h.currentPos = releasePos

	// releaseMouse is defined in humanoid.go.
	return h.releaseMouse(ctx)
}
