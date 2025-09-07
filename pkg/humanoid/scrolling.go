// -- pkg/humanoid/scrolling.go --
package humanoid

import (
	"context"
	_ "embed" // Required for embedding the scroll script
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	// Required for GetLayoutMetrics (low-level access)
	"github.com/chromedp/cdproto/page"
	// Required for customizing EvaluateParams in chromedp.Evaluate options
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

// intelligentScroll implements a human-like scrolling strategy.
func (h *Humanoid) intelligentScroll(selector string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		h.updateFatigue(0.5)

		h.mu.Lock()
		cfg := h.dynamicConfig
		// Decide modality: Mouse wheel vs JS smooth scrolling.
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
	var overshot bool
	var injectedDeltaY, injectedDeltaX float64

	scrollOvershootProb := cfg.ScrollOvershootProbability
	readDensityFactor := cfg.ScrollReadDensityFactor
	regressionProb := cfg.ScrollRegressionProbability

	// Timeout for the entire scrolling operation.
	scrollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	for {
		if scrollCtx.Err() != nil {
			return fmt.Errorf("humanoid: JS scrolling timed out: %w", scrollCtx.Err())
		}

		// Execute the in-browser scroll logic.
		var res string
		// Use the modern high-level chromedp.Evaluate Action.
		// FIX: Arguments passed to the JS script must be wrapped in `chromedp.EvalWithArgs`.
		err := chromedp.Evaluate(
			scrollScript,
			&res,
			chromedp.EvalWithArgs(selector, injectedDeltaY, injectedDeltaX, readDensityFactor),
			// Use the modern modifier pattern to customize EvaluateParams (e.g., await the promise).
			func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
				return p.WithAwaitPromise(true)
			},
		).Do(scrollCtx)

		// Reset injected deltas.
		injectedDeltaY = 0
		injectedDeltaX = 0

		if err != nil {
			// Handle navigation during scroll gracefully.
			if strings.Contains(err.Error(), "execution context destroyed") {
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
		adjustedOvershootProb := scrollOvershootProb * (1.0 - normalizedDensity*0.5)
		maxDelta := math.Max(math.Abs(status.VerticalDelta), math.Abs(status.HorizontalDelta))

		h.mu.Lock()
		rngValOvershoot := h.rng.Float64()
		rngValRegression := h.rng.Float64()
		h.mu.Unlock()

		shouldOvershoot := !overshot && rngValOvershoot < adjustedOvershootProb && maxDelta > 300
		shouldRegress := !overshot && !shouldOvershoot && rngValRegression < regressionProb && maxDelta > 100

		if shouldRegress {
			h.mu.Lock()
			regressionFactor := -(0.15 + h.rng.Float64()*0.3)
			h.mu.Unlock()
			injectedDeltaY = status.VerticalDelta * regressionFactor
			injectedDeltaX = status.HorizontalDelta * regressionFactor
			overshot = true
		} else if shouldOvershoot {
			overshot = true
			h.mu.Lock()
			overshootFactor := 0.10 + h.rng.Float64()*0.25
			h.mu.Unlock()
			injectedDeltaY = status.VerticalDelta * overshootFactor
			injectedDeltaX = status.HorizontalDelta * overshootFactor
		} else if overshot {
			overshot = false
		}

		// Pause between scroll iterations (Simulating reading/scanning time).
		if err := h.calculateScrollPause(scrollCtx, status.ContentDensity, readDensityFactor); err != nil {
			return err
		}
	}
}

// scrollWithMouseWheel simulates scrolling using discrete mouse wheel events.
func (h *Humanoid) scrollWithMouseWheel(ctx context.Context, selector string, cfg Config) error {
	scrollCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// JS snippet for basic visibility checking.
	visibilityCheckJS := `(selector) => {
		const el = document.querySelector(selector);
		if (!el) return { visible: false, y: 0 };
		const rect = el.getBoundingClientRect();
		const viewportHeight = window.innerHeight;
		const visibilityThreshold = 50;
		const isVisible = (rect.top >= visibilityThreshold && rect.bottom <= viewportHeight - visibilityThreshold);
		return { visible: isVisible, y: rect.top + rect.height / 2 };
	}`

	// Ensure cursor is initialized.
	if h.GetCurrentPos().Mag() < 1.0 {
		if err := h.InitializePosition(scrollCtx); err != nil {
			// If we can't initialize the position, fallback to JS scroll.
			h.logger.Warn("Humanoid: failed to initialize mouse position for scrolling, falling back to JS", zap.Error(err))
			return h.scrollWithJS(ctx, selector, cfg)
		}
	}

	maxIterations := 30
	for i := 0; i < maxIterations; i++ {
		if scrollCtx.Err() != nil {
			return fmt.Errorf("humanoid: mouse wheel scrolling timed out: %w", scrollCtx.Err())
		}

		// 1. Check visibility.
		var visibilityResult map[string]interface{}
		// FIX: The selector argument must be passed using `chromedp.EvalWithArgs`.
		err := chromedp.Evaluate(visibilityCheckJS, &visibilityResult, chromedp.EvalWithArgs(selector)).Do(scrollCtx)

		if err != nil {
			if strings.Contains(err.Error(), "execution context destroyed") {
				return nil
			}
			break
		}

		isVisible, ok1 := visibilityResult["visible"].(bool)
		targetY, ok2 := visibilityResult["y"].(float64)

		if !ok1 || !ok2 {
			break
		}

		if isVisible {
			return nil
		}

		// 2. Determine scroll direction.
		cursorPos := h.GetCurrentPos()

		viewportCenterY := 400.0
		// Use the modern low-level API pattern for page metrics.
		_, _, _, _, cssVisualViewport, _, err := page.GetLayoutMetrics().Do(scrollCtx)
		if err == nil && cssVisualViewport != nil {
			viewportCenterY = cssVisualViewport.ClientHeight / 2.0
		}

		deltaY := 1.0
		if targetY < viewportCenterY {
			deltaY = -1.0
		}

		// Scroll in bursts (flicks).
		h.mu.Lock()
		burstLength := int(h.rng.NormFloat64()*2.0 + 4.0)
		if burstLength < 1 {
			burstLength = 1
		}
		h.mu.Unlock()

		tickSize := 100.0

		for j := 0; j < burstLength; j++ {
			// Use the modern, high-level MouseWheelXY Action.
			scrollAction := chromedp.MouseWheelXY(cursorPos.X, cursorPos.Y, chromedp.MouseWheelY(deltaY*tickSize))
			if err := scrollAction.Do(scrollCtx); err != nil {
				return fmt.Errorf("humanoid: failed to dispatch mouse wheel action: %w", err)
			}

			// Pause between ticks (short physiological delay).
			h.mu.Lock()
			pauseDur := time.Duration(30+h.rng.NormFloat64()*10) * time.Millisecond
			h.mu.Unlock()

			// MODERNIZATION: Use standard chromedp.Sleep for consistency.
			if err := chromedp.Sleep(pauseDur).Do(scrollCtx); err != nil {
				return err
			}
		}

		// 3. Pause after the burst (Cognitive pause).
		// CORRECTION: CognitivePause returns an Action and must be executed with .Do(ctx).
		if err := h.CognitivePause(250, 100).Do(scrollCtx); err != nil {
			return err
		}
	}
	return nil
}

// calculateScrollPause determines the pause duration based on content density.
func (h *Humanoid) calculateScrollPause(ctx context.Context, contentDensity, readDensityFactor float64) error {
	basePauseMean := 150.0
	basePauseStdDev := 50.0

	// Increase pause time if density is high.
	densityAdjustment := contentDensity * readDensityFactor * 500.0
	pauseMean := basePauseMean + densityAdjustment

	// Use CognitivePause (incorporates fatigue recovery and idle movements).
	// CORRECTION: CognitivePause returns an Action and must be executed with .Do(ctx).
	return h.CognitivePause(pauseMean, basePauseStdDev).Do(ctx)
}
