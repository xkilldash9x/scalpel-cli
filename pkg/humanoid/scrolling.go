// pkg/humanoid/scrolling.go
package humanoid

import (
	"context"
	_ "embed" // Required for embedding the scroll script
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// scrollStatus used for communication with the JS scrolling script.
type scrollStatus struct {
	IsIntersecting  bool    `json:"isIntersecting"`
	IsComplete      bool    `json:"isComplete"`
	VerticalDelta   float64 `json:"verticalDelta"`
	HorizontalDelta float64 `json:"horizontalDelta"`
	ContentDensity  float64 `json:"contentDensity"`
}

//go:embed scrolling_script.js
var scrollScript string

// intelligentScroll implements a human-like scrolling strategy (bidirectional, content-aware, multi-modal).
func (h *Humanoid) intelligentScroll(selector string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Update fatigue before the scrolling sequence begins.
		h.updateFatigue(0.5)

		h.logger.Debug("Humanoid: Starting intelligent scroll sequence", zap.String("selector", selector))

		h.mu.Lock()
		// Use dynamic config.
		cfg := h.dynamicConfig
		// Decide modality: Mouse wheel simulation vs JS-based smooth scrolling (trackpad/touch).
		useMouseWheel := h.rng.Float64() < cfg.ScrollMouseWheelProbability
		h.mu.Unlock()

		if useMouseWheel {
			return h.scrollWithMouseWheel(ctx, selector, cfg)
		}
		return h.scrollWithJS(ctx, selector, cfg)
	})
}

// scrollWithJS uses the injected JS script (simulating smooth scrolling or trackpad).
func (h *Humanoid) scrollWithJS(ctx context.Context, selector string, cfg Config) error {
	h.logger.Debug("Humanoid: Executing JS Smooth Scroll")
	var overshot bool
	// These variables are used to communicate overshoot/regression requests to the JS script.
	var injectedDeltaY, injectedDeltaX float64

	// Extract parameters from config.
	scrollOvershootProb := cfg.ScrollOvershootProbability
	readDensityFactor := cfg.ScrollReadDensityFactor
	regressionProb := cfg.ScrollRegressionProbability

	// Timeout for the entire scrolling operation.
	scrollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	for {
		if scrollCtx.Err() != nil {
			return fmt.Errorf("humanoid: JS scrolling operation failed or timed out: %w", scrollCtx.Err())
		}

		// Execute the in-browser scroll logic.
		var res string
		err := chromedp.Evaluate(
			scrollScript,
			&res,
			func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
				return p.WithAwaitPromise(true) // Wait for the JS promise (stabilization) to resolve.
			},
			selector,
			injectedDeltaY,
			injectedDeltaX,
			readDensityFactor,
		).Do(scrollCtx)

		// Reset injected deltas for the next iteration unless overridden below.
		injectedDeltaY = 0
		injectedDeltaX = 0

		if err != nil {
			if scrollCtx.Err() != nil {
				return scrollCtx.Err()
			}
			// Handle navigation during scroll gracefully.
			if strings.Contains(err.Error(), "execution context destroyed") {
				h.logger.Debug("Humanoid: Scroll script execution context destroyed, assuming completion.")
				return nil
			}
			return fmt.Errorf("humanoid: scroll script evaluation failed: %w", err)
		}

		var status scrollStatus
		if err := json.Unmarshal([]byte(res), &status); err != nil {
			return fmt.Errorf("humanoid: failed to unmarshal scroll status: %w", err)
		}

		if status.IsIntersecting || status.IsComplete {
			return nil
		}

		// --- Decision making: Overshoot, Regression, or Continue ---

		normalizedDensity := math.Min(1.0, status.ContentDensity)
		// Overshoot is less likely if the content is dense (user is focused).
		adjustedOvershootProb := scrollOvershootProb * (1.0 - normalizedDensity*0.5)
		maxDelta := math.Max(math.Abs(status.VerticalDelta), math.Abs(status.HorizontalDelta))

		h.mu.Lock()
		rngValOvershoot := h.rng.Float64()
		rngValRegression := h.rng.Float64()
		h.mu.Unlock()

		shouldOvershoot := !overshot && rngValOvershoot < adjustedOvershootProb && maxDelta > 300
		// Determine if a regression (scroll back slightly to re-read) should occur.
		shouldRegress := !overshot && !shouldOvershoot && rngValRegression < regressionProb && maxDelta > 100

		if shouldRegress {
			// Execute a regression (scroll backward).
			h.mu.Lock()
			// Regression magnitude is a randomized fraction of the distance to the target.
			regressionFactor := -(0.15 + h.rng.Float64()*0.3)
			h.mu.Unlock()
			// Inject the regression amount back to the JS script for the next iteration.
			injectedDeltaY = status.VerticalDelta * regressionFactor
			injectedDeltaX = status.HorizontalDelta * regressionFactor
			overshot = true // Treat regression as an 'event' similar to overshoot for the logic flow.
			h.logger.Debug("Humanoid: Performing scroll regression")
		} else if shouldOvershoot {
			// Execute an overshoot.
			overshot = true
			h.mu.Lock()
			overshootFactor := 0.10 + h.rng.Float64()*0.25
			h.mu.Unlock()
			injectedDeltaY = status.VerticalDelta * overshootFactor
			injectedDeltaX = status.HorizontalDelta * overshootFactor
			h.logger.Debug("Humanoid: Performing scroll overshoot")
		} else if overshot {
			// Reset overshoot flag after the corrective scroll (which happens next iteration).
			overshot = false
		}

		// Pause between scroll iterations (Simulating reading/scanning time).
		// Use CognitivePause for realistic pauses with idle movement.
		if err := h.calculateScrollPause(scrollCtx, status.ContentDensity, readDensityFactor); err != nil {
			return err
		}
	}
}

// scrollWithMouseWheel simulates scrolling using discrete mouse wheel events (Stealthier native events).
func (h *Humanoid) scrollWithMouseWheel(ctx context.Context, selector string, cfg Config) error {
	h.logger.Debug("Humanoid: Executing Mouse Wheel Scroll")
	scrollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// JS snippet for basic visibility checking and positioning estimation.
	visibilityCheckJS := `(selector) => {
		const el = document.querySelector(selector);
		if (!el) return { visible: false, y: 0 };
		const rect = el.getBoundingClientRect();
		const viewportHeight = window.innerHeight;
		const visibilityThreshold = 50;
		// Check if the element is reasonably centered vertically.
		const isVisible = (rect.top >= visibilityThreshold && rect.bottom <= viewportHeight - visibilityThreshold);
		// Return the vertical center of the element relative to the viewport.
		return { visible: isVisible, y: rect.top + rect.height / 2 };
	}`

	// Ensure cursor is initialized before dispatching wheel events.
	if h.GetCurrentPos().Mag() < 1.0 {
		if err := h.InitializePosition(scrollCtx); err != nil {
			// Log warning but attempt to continue if initialization fails.
			h.logger.Warn("Humanoid: Failed to initialize cursor for wheel scroll.", zap.Error(err))
		}
	}

	maxIterations := 30 // Prevent infinite loops if target is unreachable.
	for i := 0; i < maxIterations; i++ {
		if scrollCtx.Err() != nil {
			return fmt.Errorf("humanoid: mouse wheel scrolling failed or timed out: %w", scrollCtx.Err())
		}

		// 1. Check visibility and get target Y position relative to viewport.
		var visibilityResult map[string]interface{}
		err := chromedp.Evaluate(visibilityCheckJS, &visibilityResult, selector).Do(scrollCtx)

		if err != nil {
			if strings.Contains(err.Error(), "execution context destroyed") {
				return nil
			}
			// If evaluation fails (e.g., element disappeared), stop scrolling.
			break
		}

		isVisible, ok1 := visibilityResult["visible"].(bool)
		targetY, ok2 := visibilityResult["y"].(float64)

		if !ok1 || !ok2 {
			break // Element not found or error in result format.
		}

		if isVisible {
			return nil
		}

		// 2. Determine scroll direction and magnitude.
		cursorPos := h.GetCurrentPos()

		// Determine direction based on target position relative to viewport center.
		viewportCenterY := 400.0 // Default fallback.
		// Use layout metrics if available for better accuracy.
		layout, err := page.GetLayoutMetrics().Do(scrollCtx)
		if err == nil && layout != nil && layout.VisualViewport != nil {
			viewportCenterY = layout.VisualViewport.ClientHeight / 2.0
		}

		deltaY := 1.0 // Default to scroll down.
		if targetY < viewportCenterY {
			deltaY = -1.0 // Scroll up.
		}

		// Humans scroll in bursts (flicks of the wheel).
		h.mu.Lock()
		// Randomized burst length (e.g., 2-6 ticks). Gaussian distribution centered at 4.
		burstLength := int(h.rng.NormFloat64()*2.0 + 4.0)
		if burstLength < 1 {
			burstLength = 1
		}
		h.mu.Unlock()

		// Standard wheel tick size (pixels).
		tickSize := 100.0

		for j := 0; j < burstLength; j++ {
			// Dispatch the event at the current cursor position.
			dispatchWheel := input.DispatchMouseEvent(input.MouseWheel, cursorPos.X, cursorPos.Y).
				WithDeltaX(0).
				WithDeltaY(deltaY * tickSize)

			if err := dispatchWheel.Do(scrollCtx); err != nil {
				return fmt.Errorf("humanoid: failed to dispatch mouse wheel event: %w", err)
			}

			// Pause between ticks (short physiological delay).
			if err := h.pause(scrollCtx, 30, 10); err != nil {
				return err
			}
		}

		// 3. Pause after the burst (Cognitive pause to read/process).
		if err := h.CognitivePause(scrollCtx, 250, 100); err != nil {
			return err
		}
	}

	h.logger.Debug("Humanoid: Mouse wheel scroll finished (max iterations reached).")
	return nil
}

// calculateScrollPause determines the pause duration based on content density and executes the pause.
func (h *Humanoid) calculateScrollPause(ctx context.Context, contentDensity, readDensityFactor float64) error {
	// Adjust pause based on content density (Content-aware behavior).
	basePauseMean := 150.0
	basePauseStdDev := 50.0

	// Increase pause time if density is high. Max increase around 500ms based on config factor.
	densityAdjustment := contentDensity * readDensityFactor * 500.0
	pauseMean := basePauseMean + densityAdjustment

	// Use CognitivePause (incorporates fatigue and idle movements).
	return h.CognitivePause(ctx, pauseMean, basePauseStdDev)
}
