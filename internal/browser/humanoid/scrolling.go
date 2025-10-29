// internal/browser/humanoid/scrolling.go
package humanoid

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"go.uber.org/zap"
)

// The JavaScript logic for performing a single scroll iteration.
// Updated for Cursor-Correlated event dispatch and Detent Wheel simulation.
// Use go:embed to load the file into a variable.
//
//go:embed scrolling.js
var scrollIterationJS string

type scrollResult struct {
	IsIntersecting  bool    `json:"isIntersecting"`
	IsComplete      bool    `json:"isComplete"`
	VerticalDelta   float64 `json:"verticalDelta"`
	HorizontalDelta float64 `json:"horizontalDelta"`
	ContentDensity  float64 `json:"contentDensity"`
	ElementExists   bool    `json:"elementExists"`
}

// intelligentScroll is an internal helper that scrolls until the target selector is visible.
// It assumes the caller holds the lock for thread safety.
func (h *Humanoid) intelligentScroll(ctx context.Context, selector string) error {
	// Set ActionType to SCROLL. This might incur a task switch delay.
	// (Mean Scale 1.0, StdDev Scale 1.0)
	if err := h.cognitivePause(ctx, 1.0, 1.0, ActionTypeScroll); err != nil {
		return err
	}

	readDensityFactor := h.dynamicConfig.ScrollReadDensityFactor
	rng := h.rng
	shouldOvershoot := rng.Float64() < h.dynamicConfig.ScrollOvershootProbability
	shouldRegress := rng.Float64() < h.dynamicConfig.ScrollRegressionProbability
	// Determine the scrolling method (Mouse Wheel vs Trackpad/Scrollbar).
	useMouseWheel := rng.Float64() < h.dynamicConfig.ScrollMouseWheelProbability
	// If using mouse wheel, determine the type (Detent/Stepped vs Smooth/Free-spinning).
	isDetentWheel := useMouseWheel && (rng.Float64() < h.dynamicConfig.ScrollDetentWheelProbability)

	maxIterations := 15
	iteration := 0

	for iteration < maxIterations {
		// Check context cancellation.
		if ctx.Err() != nil {
			return ctx.Err()
		}

		iteration++

		// 1. Execute Scroll Iteration
		// Pass the current cursor position for Cursor Correlation.
		cursorPos := h.currentPos
		result, err := h.executeScrollJS(ctx, selector, 0.0, 0.0, readDensityFactor, useMouseWheel, cursorPos, isDetentWheel)

		if err != nil {
			// Handle context cancellation gracefully.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			h.logger.Warn("Humanoid: Scroll iteration JS execution failed", zap.Error(err), zap.Int("iteration", iteration))
			// If JS fails, maybe the DOM is unstable. Wait briefly and try again.
			if err := h.executor.Sleep(ctx, 100*time.Millisecond); err != nil {
				return err
			}
			continue
		}

		// 2. Process Results
		if !result.ElementExists {
			return nil
		}
		if result.IsIntersecting || result.IsComplete {
			// 3. Handle Overshoot (if applicable)
			if result.IsComplete && !result.IsIntersecting && shouldOvershoot {
				// Use the same method (wheel/scrollBy/detent) for the overshoot.
				if err := h.simulateOvershoot(ctx, selector, readDensityFactor, result.VerticalDelta, result.HorizontalDelta, useMouseWheel, isDetentWheel); err != nil {
					return err
				}
			}
			return nil
		}

		// 4. Pause between scrolls (Cognitive processing / Reading)
		pauseDuration := h.calculateScrollPause(result.ContentDensity)

		// Use internal cognitivePause as lock is held.
		meanMs := float64(pauseDuration.Milliseconds())
		// Convert mean/stddev to Ex-Gaussian scaling factors (approximate conversion).
		meanScale := meanMs / h.dynamicConfig.ExGaussianMu
		stdDevScale := (meanMs * 0.3) / h.dynamicConfig.ExGaussianSigma // Assuming 30% variation

		if err := h.cognitivePause(ctx, meanScale, stdDevScale, ActionTypeScroll); err != nil {
			return err
		}

		// 5. Handle Regression (if applicable)
		if shouldRegress && iteration > 2 && (result.VerticalDelta > 100 || result.HorizontalDelta > 100) {
			// Use the same method (wheel/scrollBy/detent) for the regression.
			if err := h.simulateRegression(ctx, selector, readDensityFactor, result.VerticalDelta, result.HorizontalDelta, useMouseWheel, isDetentWheel); err != nil {
				return err
			}
			// Reset regression flag so it only happens once per scroll action.
			shouldRegress = false
			// Add an extra pause after regression (re-reading). (Mean Scale 2.5, StdDev Scale 1.5)
			if err := h.cognitivePause(ctx, 2.5, 1.5, ActionTypeScroll); err != nil {
				return err
			}
		}
	}

	h.logger.Warn("Humanoid: Scroll timed out (max iterations reached)", zap.String("selector", selector))
	// Return nil even on timeout. The caller should handle visibility failure.
	return nil
}

// executeScrollJS handles the preparation and execution of the scrollIterationJS via the executor.
// Updated parameter list to include cursor position and wheel type.
func (h *Humanoid) executeScrollJS(ctx context.Context, selector string, deltaY, deltaX, readDensityFactor float64, useMouseWheel bool, cursorPos Vector2D, isDetentWheel bool) (*scrollResult, error) {
	// Prepare the arguments for the JS function.
	args := []interface{}{
		selector,
		deltaY,
		deltaX,
		readDensityFactor,
		useMouseWheel,
		math.Round(cursorPos.X), // Pass rounded coordinates.
		math.Round(cursorPos.Y),
		isDetentWheel,
	}

	// Execute via the agnostic executor.
	resultJSON, err := h.executor.ExecuteScript(ctx, scrollIterationJS, args)

	if err != nil {
		return nil, fmt.Errorf("javascript execution error during scroll: %w", err)
	}

	// Check for null or empty results.
	// S1009 Fix: Omit nil check; len() for nil slices is defined as zero.
	if len(resultJSON) == 0 || string(resultJSON) == "null" || string(resultJSON) == "undefined" {
		return nil, fmt.Errorf("javascript execution returned null or empty result during scroll")
	}

	// Unmarshal the JSON into the scrollResult struct.
	var result scrollResult
	if err := json.Unmarshal(resultJSON, &result); err != nil {
		h.logger.Error("Humanoid: Failed to unmarshal scroll result JSON", zap.Error(err), zap.String("json", string(resultJSON)))
		return nil, fmt.Errorf("failed to unmarshal scroll result JSON: %w", err)
	}

	return &result, nil
}

// calculateScrollPause is an internal helper. It assumes the caller holds the lock.
func (h *Humanoid) calculateScrollPause(contentDensity float64) time.Duration {
	// Base pause + pause based on content density. Random variation is handled by cognitivePause.
	pauseMs := 100 + (contentDensity * 1000 * h.dynamicConfig.ScrollReadDensityFactor)
	// Apply fatigue
	pauseMs *= (1.0 + h.fatigueLevel*0.5)
	// Clamp to a reasonable range
	if pauseMs > 2000 {
		pauseMs = 2000
	}
	if pauseMs < 50 {
		pauseMs = 50
	}
	return time.Duration(pauseMs) * time.Millisecond
}

// simulateOvershoot is an internal helper. It assumes the caller holds the lock.
// Updated parameter list to include wheel type.
func (h *Humanoid) simulateOvershoot(ctx context.Context, selector string, readDensityFactor, verticalDelta, horizontalDelta float64, useMouseWheel, isDetentWheel bool) error {
	rng := h.rng

	// Overshoot is a small fraction of the distance remaining before the last scroll.
	overshootY := verticalDelta * (0.1 + rng.Float64()*0.2)
	overshootX := horizontalDelta * (0.1 + rng.Float64()*0.2)

	// Use current cursor position for correlation.
	cursorPos := h.currentPos

	// Execute the JS via the helper which uses the executor.
	if _, err := h.executeScrollJS(ctx, selector, overshootY, overshootX, readDensityFactor, useMouseWheel, cursorPos, isDetentWheel); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		h.logger.Warn("Humanoid: simulateOvershoot failed", zap.Error(err))
	}

	// Brief pause after overshooting (using internal cognitivePause).
	// (Mean Scale 1.2, StdDev Scale 0.8). ActionType remains SCROLL.
	return h.cognitivePause(ctx, 1.2, 0.8, ActionTypeScroll)
}

// simulateRegression is an internal helper. It assumes the caller holds the lock.
// Updated parameter list to include wheel type.
func (h *Humanoid) simulateRegression(ctx context.Context, selector string, readDensityFactor, verticalDelta, horizontalDelta float64, useMouseWheel, isDetentWheel bool) error {
	rng := h.rng

	// Regression is scrolling back (opposite direction) a fraction of the distance remaining.
	regressionY := -verticalDelta * (0.2 + rng.Float64()*0.3)
	regressionX := -horizontalDelta * (0.2 + rng.Float64()*0.3)

	// Use current cursor position for correlation.
	cursorPos := h.currentPos

	// Execute the JS via the helper which uses the executor.
	_, err := h.executeScrollJS(ctx, selector, regressionY, regressionX, readDensityFactor, useMouseWheel, cursorPos, isDetentWheel)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		h.logger.Warn("Humanoid: simulateRegression failed", zap.Error(err))
	}
	return nil
}
