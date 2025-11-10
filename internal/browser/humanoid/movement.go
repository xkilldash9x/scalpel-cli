// File: internal/browser/humanoid/movement.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// MoveTo simulates a human moving the mouse cursor to a UI element specified by a selector.
// This high-level action orchestrates a complex sequence to produce a realistic trajectory:
//
//  1. A "cognitive pause" to simulate the user locating the target and planning the movement.
//  2. An "anticipatory movement," which is a small, slow initial drift towards the target.
//  3. A primary "ballistic movement" phase, simulated using a critically-damped spring
//     model to create a smooth, curved path with realistic acceleration and deceleration.
//     This path is influenced by various noise models (Pink, Gaussian, Signal-Dependent).
//  4. A "terminal pause" or verification delay upon reaching the target, modeled by
//     Fitts's Law, which simulates the final moments of aiming. During this pause,
//     the cursor exhibits subtle idle drift.
//
// The target point within the element is not simply the center but is calculated
// based on element type, velocity biases (overshoot), and random noise to ensure
// variability.
//
// Parameters:
//   - ctx: The context for the movement operation.
//   - selector: The CSS selector of the target element.
//   - opts: Optional settings, such as disabling `ensureVisible` or providing a
//     `PotentialField` to influence the path.
//
// Returns an error if the element cannot be found or the context is cancelled.
func (h *Humanoid) MoveTo(ctx context.Context, selector string, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.moveToSelector(ctx, selector, opts)
}

// MoveToVector is the public entry point for moving the mouse cursor to a specific
// coordinate (Vector2D). It is a thread-safe wrapper around the internal `moveToVector`
// logic, acquiring a lock for the duration of the operation.
//
// This function is useful for scenarios where the target is a specific point rather
// than a UI element. The movement simulation follows the same realistic model as `MoveTo`,
// including anticipatory movement, ballistic trajectory, and terminal pause.
//
// Parameters:
//   - ctx: The context for the movement operation.
//   - target: The destination coordinate (Vector2D).
//   - opts: Optional settings, such as providing a `PotentialField` to influence the path.
//
// Returns an error if the context is cancelled during the movement.
func (h *Humanoid) MoveToVector(ctx context.Context, target Vector2D, opts *InteractionOptions) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Default to ActionTypeMove if called directly.
	return h.moveToVector(ctx, target, opts, ActionTypeMove)
}

// moveToSelector is the internal, non-locking implementation.
func (h *Humanoid) moveToSelector(ctx context.Context, selector string, opts *InteractionOptions) error {
	// 1. Cognitive Pause (Planning Delay) before initiating movement.
	// This simulates the time taken to locate the target visually and plan the action.
	// (Mean Scale 1.2, StdDev Scale 1.2). cognitivePause handles the ActionType switch to MOVE.
	if err := h.cognitivePause(ctx, 1.2, 1.2, ActionTypeMove); err != nil {
		return err
	}

	// 2. Ensure the target is visible before attempting to measure or move.
	if err := h.ensureVisible(ctx, selector, opts); err != nil {
		// Log the error but continue. If scrolling fails, we might still find the element if it's already in view.
		h.logger.Warn("Humanoid: Failed to ensure element visibility before moving", zap.String("selector", selector), zap.Error(err))
	}

	// 3. Get the element's geometry (after potential scrolling).
	geo, err := h.getElementBoxBySelector(ctx, selector)
	if err != nil {
		return fmt.Errorf("humanoid: failed to locate target '%s' after ensureVisible: %w", selector, err)
	}

	center, valid := boxToCenter(geo)
	if !valid {
		return fmt.Errorf("humanoid: element '%s' has invalid geometry", selector)
	}

	// 4. Determine the initial target point. We estimate zero final velocity for targeting bias calculation.
	// calculateTargetPoint now uses Element-Aware Targeting based on geo.TagName/Type.
	target := h.calculateTargetPoint(geo, center, Vector2D{X: 0, Y: 0})

	// 5. Execute the movement. ActionType remains MOVE.
	return h.moveToVector(ctx, target, opts, ActionTypeMove)
}

// moveToVector is the internal, non-locking core movement logic.
// It accepts the currentAction type to allow use during DRAG operations.
func (h *Humanoid) moveToVector(ctx context.Context, target Vector2D, opts *InteractionOptions, currentAction ActionType) error {
	startPos := h.currentPos
	dist := startPos.Dist(target)

	// No need to move if we're already within the configured minimum distance.
	if dist < h.baseConfig.MinMoveDistance {
		return nil
	}

	// Update fatigue/habituation based on the effort (distance). Intensity is scaled by distance (e.g., dist/1000).
	h.updateFatigueAndHabituation(dist / 1000.0)

	// Set the action type if it's different from the current state (e.g. starting a move).
	// We don't use cognitivePause here because the planning delay happened in moveToSelector,
	// or this is a continuation of an ongoing action (like DRAG).
	if h.lastActionType != currentAction {
		h.lastActionType = currentAction
	}

	var field *PotentialField
	if opts != nil {
		field = opts.Field
	}

	// Anticipatory Movement: Simulate slight movement in the direction of the target before the main ballistic phase.
	if dist > h.baseConfig.AnticipatoryMovementThreshold {
		if err := h.anticipatoryMovement(ctx, startPos, target, h.currentButtonState); err != nil {
			return err
		}
		// Update startPos after anticipatory movement.
		startPos = h.currentPos
	}

	// Simulate the trajectory using the Spring-Damped model.
	// The simulation handles its own timing, event dispatching, and updates h.currentPos.
	_, err := h.simulateTrajectory(ctx, startPos, target, field, h.currentButtonState)
	if err != nil {
		return err
	}

	// If the movement was significant, simulate the final cognitive pause (Terminal Fitts's Law).
	// This represents the time taken to verify the target before acting (Verification Delay).
	// We use the FittsWTerminal config as a reasonable threshold for "significant distance".
	if dist > h.baseConfig.FittsWTerminal {
		terminalPause := h.calculateTerminalFittsLaw(dist)

		// During the terminal pause, the cursor idles slightly (hesitate).
		// hesitate also handles fatigue recovery internally.
		if err := h.hesitate(ctx, terminalPause); err != nil {
			return err
		}
	}

	return nil
}

// anticipatoryMovement simulates the subtle, initial movement phase often observed before a ballistic movement.
// This involves a slow drift towards the target. Assumes the lock is held.
func (h *Humanoid) anticipatoryMovement(ctx context.Context, start, end Vector2D, buttonState schemas.MouseButton) error {
	cfg := h.baseConfig
	rng := h.rng

	// Calculate the direction vector.
	direction := end.Sub(start).Normalize()

	// Determine the distance and duration of the anticipatory movement.
	// Distance is randomized based on configuration.
	distance := cfg.AnticipatoryMovementDistance * (0.5 + rng.Float64()*1.0)
	// Duration is also randomized.
	duration := time.Duration(float64(cfg.AnticipatoryMovementDuration) * (0.5 + rng.Float64()*1.0))

	// Calculate the target position for this phase.
	target := start.Add(direction.Mul(distance))

	// Execute the movement using the standard trajectory simulation, but with heavily modified physics parameters.
	// We want a slow, overdamped movement (low Omega, high Zeta).
	// Temporarily modify dynamic config for this phase.
	originalOmega := h.dynamicConfig.Omega
	originalZeta := h.dynamicConfig.Zeta

	// Apply configured factors for slow movement.
	h.dynamicConfig.Omega *= cfg.AnticipatoryMovementOmegaFactor
	h.dynamicConfig.Zeta *= cfg.AnticipatoryMovementZetaFactor

	// Ensure the simulation time is sufficient for this slow movement.
	originalMaxSimTime := h.dynamicConfig.MaxSimTime
	h.dynamicConfig.MaxSimTime = duration * 2 // Safety buffer

	// Execute the trajectory.
	_, err := h.simulateTrajectory(ctx, start, target, nil, buttonState)

	// Restore original configuration parameters.
	h.dynamicConfig.Omega = originalOmega
	h.dynamicConfig.Zeta = originalZeta
	h.dynamicConfig.MaxSimTime = originalMaxSimTime

	return err
}

// calculateTargetPoint determines a realistic coordinate within an element's bounds (Target Variability).
// It incorporates Element-Aware Targeting bias.
// It assumes the caller holds the lock.
func (h *Humanoid) calculateTargetPoint(geo *schemas.ElementGeometry, center Vector2D, estimatedFinalVelocity Vector2D) Vector2D {
	if geo == nil || geo.Width <= 0 || geo.Height <= 0 {
		return center
	}

	width, height := float64(geo.Width), float64(geo.Height)
	rng := h.rng
	// Use dynamic config for noise strength (affected by fatigue).
	clickNoiseStrength := h.dynamicConfig.ClickNoise
	// Use base config for aiming behavior and limits.
	cfg := h.baseConfig
	innerAimPercent := cfg.TargetInnerAimPercent
	maxVelocity := cfg.MaxVelocity

	// 1. Element-Aware Targeting Bias (Cognitive Bias)
	biasX, biasY := 0.0, 0.0
	// Adjust innerAimPercent based on element type.
	switch strings.ToUpper(geo.TagName) {
	case "INPUT":
		switch strings.ToLower(geo.Type) {
		case "text", "password", "email", "search":
			// For text inputs, bias towards the left side (start of the text).
			biasX = -width * 0.3
			innerAimPercent = 0.9 // Wider spread allowed for inputs.
		case "checkbox", "radio":
			// For small controls, aim precisely at the center.
			innerAimPercent = 0.5
		}
	case "A", "BUTTON":
		// Standard aiming for links and buttons.
		innerAimPercent = 0.8
	case "TEXTAREA":
		// Bias towards the top-left corner.
		biasX = -width * 0.2
		biasY = -height * 0.2
		innerAimPercent = 0.9
	}

	// 2. Determine the primary aim point (Normal distribution near the biased center).
	effectiveWidth := width * innerAimPercent
	effectiveHeight := height * innerAimPercent
	stdDevX := effectiveWidth / 6.0 // 99.7% of points fall within +/- 3 std devs.
	stdDevY := effectiveHeight / 6.0

	offsetX := rng.NormFloat64()*stdDevX + biasX
	offsetY := rng.NormFloat64()*stdDevY + biasY

	// 3. Apply velocity bias (Overshoot tendency - Motor Bias).
	velocityMag := estimatedFinalVelocity.Mag()

	// Only apply bias if velocity exceeds the configured threshold.
	if velocityMag > cfg.TargetVelocityBiasThresh {
		// Normalize the effect of the velocity (0.0 to 1.0).
		normalizedVelocity := math.Min(1.0, velocityMag/maxVelocity)
		// Maximum bias based on configuration.
		maxBiasX := width * cfg.TargetVelocityBiasMax
		maxBiasY := height * cfg.TargetVelocityBiasMax
		velDir := estimatedFinalVelocity.Normalize()

		offsetX += velDir.X * normalizedVelocity * maxBiasX
		offsetY += velDir.Y * normalizedVelocity * maxBiasY
	}

	// 4. Apply random click noise (Motor Tremor).
	offsetX += rng.NormFloat64() * clickNoiseStrength
	offsetY += rng.NormFloat64() * clickNoiseStrength

	finalX := center.X + offsetX
	finalY := center.Y + offsetY

	// 5. Clamp the final point to be strictly within the element's bounds (1-pixel margin).
	minX, maxX := center.X-width/2.0+1.0, center.X+width/2.0-1.0
	minY, maxY := center.Y-height/2.0+1.0, center.Y+height/2.0-1.0

	finalX = math.Max(minX, math.Min(maxX, finalX))
	finalY = math.Max(minY, math.Min(maxY, finalY))

	return Vector2D{X: finalX, Y: finalY}
}
