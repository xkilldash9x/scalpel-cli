// pkg/humanoid/clickmodel.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// IntelligentClick combines movement and clicking into a single human-like action sequence.
func (h *Humanoid) IntelligentClick(selector string, field *PotentialField) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Note: Fatigue is updated within MoveTo at the start of the sequence.

		// 1. Move to the target (handles scrolling, movement, cognitive pause, and inaccuracy).
		if err := h.MoveTo(selector, field).Do(ctx); err != nil {
			return fmt.Errorf("humanoid: failed to move to element for click: %w", err)
		}

		// 2. Perform the click sequence (Mouse Down/Up).
		if err := h.performClickSequence(ctx); err != nil {
			return fmt.Errorf("humanoid: click execution failed: %w", err)
		}

		// Update fatigue slightly after the click action completes.
		h.updateFatigue(0.2)

		return nil
	})
}

// performClickSequence executes the mouse down/up sequence at the current cursor position.
func (h *Humanoid) performClickSequence(ctx context.Context) error {
	clickPoint := h.GetCurrentPos()

	// Pre-click delay (physiological reaction time).
	if err := h.pause(ctx, 60, 20); err != nil {
		return err
	}

	// Mouse Down.
	dispatchDown := input.DispatchMouseEvent(input.MousePressed, clickPoint.X, clickPoint.Y).
		WithButton(input.Left).WithClickCount(1)
	if err := dispatchDown.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: failed to dispatch mouse press: %w", err)
	}

	// Hold duration (physiological).
	if err := h.pause(ctx, 80, 30); err != nil {
		// Robustness: Ensure mouse is released if interrupted during the hold.
		releaseCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		input.DispatchMouseEvent(input.MouseReleased, clickPoint.X, clickPoint.Y).WithButton(input.Left).Do(releaseCtx)
		return err
	}

	// Mouse Up.
	dispatchUp := input.DispatchMouseEvent(input.MouseReleased, clickPoint.X, clickPoint.Y).
		WithButton(input.Left).WithClickCount(1)

	if err := dispatchUp.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: failed to dispatch mouse release: %w", err)
	}

	h.logger.Debug("Humanoid: Click sequence completed", zap.Float64("X", clickPoint.X), zap.Float64("Y", clickPoint.Y))
	return nil
}

// generateClickPoint determines the precise final location using a bivariate Gaussian distribution.
// This models the speed-accuracy tradeoff (Fitts's Law endpoint variability) and fatigue impact.
func (h *Humanoid) generateClickPoint(box *dom.BoxModel, targetCenter Vector2D, finalVelocity Vector2D) Vector2D {
	_, targetWidth, targetHeight := boxToDimensions(box)

	// Base standard deviation derived from target size. Smaller targets yield higher precision requirements.
	baseStdDev := math.Min(targetWidth, targetHeight) / 8.0
	if baseStdDev < 1.0 {
		baseStdDev = 1.0
	}

	// Speed factor increases inaccuracy.
	// Uses maxVelocity defined in humanoid.go.
	normalizedSpeed := finalVelocity.Mag() / maxVelocity
	speedFactor := 1.0 + normalizedSpeed*3.0

	// Fatigue also increases inaccuracy.
	h.mu.Lock()
	// Up to 100% increase in inaccuracy (StdDev) when fully fatigued.
	fatigueFactor := 1.0 + h.fatigueLevel*1.0
	h.mu.Unlock()

	inaccuracyFactor := speedFactor * fatigueFactor

	// Elliptical distribution aligned with movement axis (Motor noise is higher along the axis of movement).
	majorAxisStdDev := baseStdDev * inaccuracyFactor * 1.5
	minorAxisStdDev := baseStdDev * inaccuracyFactor * 0.8

	// Sample from Gaussian distribution.
	h.mu.Lock()
	randX, randY := h.rng.NormFloat64(), h.rng.NormFloat64()
	h.mu.Unlock()

	scaledX, scaledY := randX*majorAxisStdDev, randY*minorAxisStdDev

	// Determine the angle of approach based on final velocity.
	angle := 0.0
	if finalVelocity.Mag() > 10.0 { // Only align if there is significant velocity.
		angle = finalVelocity.Angle()
	}

	// Rotate the coordinates to align with the angle of approach.
	cosAngle, sinAngle := math.Cos(angle), math.Sin(angle)
	rotatedX := scaledX*cosAngle - scaledY*sinAngle
	rotatedY := scaledX*sinAngle + scaledY*cosAngle

	clickPoint := targetCenter.Add(Vector2D{X: rotatedX, Y: rotatedY})

	// Constrain the click point within the element bounds to ensure interaction succeeds.
	if box != nil && len(box.Content) >= 8 {
		minX, minY := box.Content[0], box.Content[1]
		maxX, maxY := box.Content[0], box.Content[1]

		// Find the bounds of the content box (handles rotated elements).
		for i := 2; i < 8; i += 2 {
			minX = math.Min(minX, box.Content[i])
			minY = math.Min(minY, box.Content[i+1])
			maxX = math.Max(maxX, box.Content[i])
			maxY = math.Max(maxY, box.Content[i+1])
		}

		// Apply a small epsilon to avoid clicking exactly on the edge.
		epsilon := 1.0
		clickPoint.X = math.Max(minX+epsilon, math.Min(clickPoint.X, maxX-epsilon))
		clickPoint.Y = math.Max(minY+epsilon, math.Min(clickPoint.Y, maxY-epsilon))
	}
	return clickPoint
}
