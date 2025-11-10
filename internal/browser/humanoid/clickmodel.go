package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// IntelligentClick performs a comprehensive, human-like click action on a UI element
// identified by a selector. This is a high-level function that orchestrates several
// sub-systems to create a realistic and robust interaction.
//
// The process includes:
//  1. Moving the mouse realistically to the target element, ensuring it's visible.
//  2. Performing a brief "cognitive pause" before the click to simulate final verification.
//  3. Applying physical "click noise," a small random displacement of the cursor as the mouse button is pressed.
//  4. Dispatching the 'mousedown' event.
//  5. Holding the mouse button down for a variable duration, modeled by an Ex-Gaussian distribution.
//  6. Simulating subtle cursor tremor or slip while the button is held.
//  7. Dispatching the 'mouseup' event.
//  8. Updating internal behavioral models for fatigue and habituation.
//
// Parameters:
//   - ctx: The context for the entire click operation.
//   - selector: The CSS selector for the target element.
//   - opts: Optional interaction settings, such as forcing visibility.
//
// Returns an error if any stage of the process fails (e.g., element not found, context cancelled).
func (h *Humanoid) IntelligentClick(ctx context.Context, selector string, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 1. Move to the target element.
	// This handles ensureVisible, movement simulation, and terminal pause.
	// The ActionType is set within moveToSelector.
	if err := h.moveToSelector(ctx, selector, opts); err != nil {
		return err
	}

	// 2. Cognitive pause before the action (final verification).
	// This pause represents a quick final check (Mean Scale 0.5, StdDev Scale 0.5).
	// cognitivePause handles the ActionType switch internally (from MOVE to CLICK).
	if err := h.cognitivePause(ctx, 0.5, 0.5, ActionTypeClick); err != nil {
		return err
	}

	// 3. Mouse Down (Press).
	// Apply click noise (physical displacement) before the press event.
	currentPos := h.currentPos
	clickPos := h.applyClickNoise(currentPos)

	mouseDownData := schemas.MouseEventData{
		Type:       schemas.MousePress,
		X:          clickPos.X,
		Y:          clickPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    1, // Bitfield: 1 indicates the left button is now pressed.
	}
	if err := h.executor.DispatchMouseEvent(ctx, mouseDownData); err != nil {
		return err
	}

	h.currentPos = clickPos // Update position after noise application
	h.currentButtonState = schemas.ButtonLeft

	// 4. Hold Duration and Click Slip/Tremor.
	holdDuration := h.calculateClickHoldDuration()

	// Simulate subtle movement (tremor or slip) while the button is held down.
	// We use the internal hesitate function, which correctly maintains the button state (pressed).
	if err := h.hesitate(ctx, holdDuration); err != nil {
		// If hesitation fails (e.g., context cancelled), we must ensure the mouse is released.
		h.logger.Warn("Humanoid: Click hold hesitation interrupted, attempting cleanup (mouse release)", zap.Error(err))
		// Use background context for cleanup as the original context might be cancelled.
		h.releaseMouse(context.Background())
		return err
	}

	// 5. Mouse Up (Release).
	// Apply click noise again for the release action.
	currentPos = h.currentPos // Position might have changed due to hesitate
	releasePos := h.applyClickNoise(currentPos)
	h.currentPos = releasePos

	// Use the internal releaseMouse helper which handles dispatch and state update.
	if err := h.releaseMouse(ctx); err != nil {
		// Error already logged within releaseMouse.
		return err
	}

	// 6. Update fatigue/habituation for the clicking action itself (intensity 0.1).
	h.updateFatigueAndHabituation(0.1)

	return nil
}

// calculateTerminalFittsLaw determines the time required for verification before initiating an action.
func (h *Humanoid) calculateTerminalFittsLaw(distance float64) time.Duration {
	// Use the configured target width (W) for the terminal phase.
	W := h.baseConfig.FittsWTerminal

	// Index of Difficulty.
	id := math.Log2(1.0 + distance/W)

	// Use dynamic config parameters affected by fatigue/habituation.
	A := h.dynamicConfig.FittsA
	B := h.dynamicConfig.FittsB
	rng := h.rng

	// Movement Time (MT) in milliseconds.
	mt := A + B*id

	// Add randomization based on the configured jitter percentage.
	jitterPercent := h.baseConfig.FittsJitterPercent
	// Calculate the total range (e.g., 0.15 -> 0.30)
	jitterRange := jitterPercent * 2
	// Calculate the randomization factor (e.g., (0 to 0.30) - 0.15)
	randomFactor := rng.Float64()*jitterRange - jitterPercent
	mt += mt * randomFactor

	if mt < 0 {
		mt = 0
	}

	// FIX: Convert float64 milliseconds (mt) to time.Duration (int64 nanoseconds) accurately to prevent truncation.
	return time.Duration(mt * float64(time.Millisecond))
}

// calculateClickHoldDuration determines how long the mouse button is held down using Ex-Gaussian distribution.
// Assumes the lock is held.
func (h *Humanoid) calculateClickHoldDuration() time.Duration {
	// Use base config for absolute min/max bounds.
	minMs := float64(h.baseConfig.ClickHoldMinMs)
	maxMs := float64(h.baseConfig.ClickHoldMaxMs)

	// Use dynamic config for the distribution parameters (affected by behavior).
	cfg := h.dynamicConfig

	// Use specific parameters for click hold if available, otherwise fallback to general reaction time parameters scaled down.
	mu := cfg.ExGaussianMu * 0.8
	sigma := cfg.ExGaussianSigma * 0.8
	tau := cfg.ExGaussianTau * 0.5 // Clicks have fewer long delays than cognitive pauses.

	durationMs := h.randExGaussian(mu, sigma, tau)

	// Clamp the duration to the configured bounds.
	durationMs = math.Max(minMs, math.Min(maxMs, durationMs))

	// Apply fatigue factor: clicks might become slightly longer when tired (factor 0.25).
	// Habituation is already factored into the dynamic Mu/Sigma/Tau.
	durationMs *= (1.0 + h.fatigueLevel*0.25)

	// FIX: Ensure accurate conversion from float64 milliseconds to time.Duration (nanoseconds).
	return time.Duration(durationMs * float64(time.Millisecond))
}
