// internal/browser/humanoid/scrolling.go
package humanoid

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"go.uber.org/zap"
)

// The JavaScript logic for performing a single scroll iteration.
// Updated for Cursor-Correlated event dispatch and Detent Wheel simulation.
const scrollIterationJS = `
async (selector, injectedDeltaY, injectedDeltaX, readDensityFactor, useMouseWheel, cursorX, cursorY, isDetentWheel) => {
    // --- Utility Functions ---

    // 1. getScrollableParent
    const getScrollableParent = (node, axis = 'y') => {
        if (node == null || node === document.body || node === document.documentElement) {
            return document.scrollingElement || document.documentElement;
        }
        if (node.nodeType !== Node.ELEMENT_NODE) {
            return getScrollableParent(node.parentNode, axis);
        }
        let style;
        try {
            style = window.getComputedStyle(node);
        } catch (e) {
            return getScrollableParent(node.parentNode, axis);
        }
        let overflow, clientSize, scrollSize;
        if (axis === 'y') {
            overflow = style.overflowY;
            clientSize = node.clientHeight;
            scrollSize = node.scrollHeight;
        } else {
            overflow = style.overflowX;
            clientSize = node.clientWidth;
            scrollSize = node.scrollWidth;
        }
        // Add 1 pixel tolerance for scroll size check.
        const isScrollable = (overflow === 'auto' || overflow === 'scroll') && scrollSize > clientSize + 1;
        if (isScrollable) {
            return node;
        }
        return getScrollableParent(node.parentNode, axis);
    };

    // 2. waitForScrollStabilization
    const waitForScrollStabilization = (element, timeout = 1000) => {
        return new Promise((resolve) => {
            let lastScrollTop = element.scrollTop;
            let lastScrollLeft = element.scrollLeft;
            let stabilizationChecks = 0;
            const requiredChecks = 3; // Number of consecutive frames with no change.
            let timeoutId = null;

            const checkScroll = () => {
                // Check if element is still valid/connected
                if (!element.isConnected && element !== document.scrollingElement && element !== document.documentElement) {
                    if (timeoutId) clearTimeout(timeoutId);
                    resolve();
                    return;
                }
                const currentScrollTop = element.scrollTop;
                const currentScrollLeft = element.scrollLeft;
                if (currentScrollTop !== lastScrollTop || currentScrollLeft !== lastScrollLeft) {
                    lastScrollTop = currentScrollTop;
                    lastScrollLeft = currentScrollLeft;
                    stabilizationChecks = 0;
                    requestAnimationFrame(checkScroll);
                } else {
                    stabilizationChecks++;
                    if (stabilizationChecks >= requiredChecks) {
                        if (timeoutId) clearTimeout(timeoutId);
                        resolve();
                    } else {
                        requestAnimationFrame(checkScroll);
                    }
                }
            };
            requestAnimationFrame(checkScroll);
            // Set a hard timeout.
            timeoutId = setTimeout(() => {
                resolve();
            }, timeout);
        });
    };
    // 3. estimateContentDensity
    const estimateContentDensity = () => {
        let totalTextLength = 0;
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
            acceptNode: (node) => {
                if (!node.parentElement || node.parentElement.offsetParent === null) return NodeFilter.FILTER_REJECT;

                const parentTagName = node.parentElement.tagName;

                if (parentTagName === 'SCRIPT' || parentTagName === 'STYLE' || parentTagName === 'NOSCRIPT') return NodeFilter.FILTER_REJECT;

                try {
                    const style = window.getComputedStyle(node.parentElement);

                    if (style.visibility === 'hidden' || style.display === 'none') return NodeFilter.FILTER_REJECT;
                } catch (e) {
                    return NodeFilter.FILTER_REJECT;
                }
                if (node.nodeValue.trim().length < 3) return NodeFilter.FILTER_SKIP;
                return NodeFilter.FILTER_ACCEPT;
            }
        });
        while (walker.nextNode()) {
            totalTextLength += walker.currentNode.nodeValue.length;
        }
        const normalizationFactor = 3000;
        const density = totalTextLength / normalizationFactor;
        return Math.min(1.5, density);
    };
    // 4. simulateWheelEvent (Updated for Cursor Correlation)
    const simulateWheelEvent = (element, deltaY, deltaX) => {
        // Determine the target for the wheel event based on cursor position (Cursor Correlation).
        let target = document.elementFromPoint(cursorX, cursorY);

        // If the cursor is not over any element (e.g. outside viewport or over chrome), fallback.
        if (!target) {
             if (element === document.scrollingElement || element === document.documentElement || element === document.body) {
                // Fallback to center of the screen if scrolling the main document.
                const centerX = window.innerWidth / 2;
                const centerY = window.innerHeight / 2;
                target = document.elementFromPoint(centerX, centerY) || document.body;
            } else {
                // Fallback to the element itself if it's a specific scrollable container.
                target = element;
            }
        }

        const wheelEvent = new WheelEvent('wheel', {
            deltaY: deltaY,
            deltaX: deltaX,
            bubbles: true,
            cancelable: true,
            view: window,
            // Coordinates of the event match the cursor position.
            clientX: cursorX,
            clientY: cursorY,
            screenX: cursorX + window.screenX,
            screenY: cursorY + window.screenY,
            // deltaMode 0 = pixels.
            deltaMode: 0
        });
        target.dispatchEvent(wheelEvent);
    };

    // 5. simulateDetentWheel (NEW)
    const simulateDetentWheel = async (element, totalDeltaY, totalDeltaX) => {
        // Detent wheels scroll in discrete steps (typically 100px per tick).
        const stepSize = 100;
        const stepsY = Math.round(totalDeltaY / stepSize);
        const stepsX = Math.round(totalDeltaX / stepSize);
        const totalSteps = Math.max(Math.abs(stepsY), Math.abs(stepsX));

        for (let i = 0; i < totalSteps; i++) {
            const currentDeltaY = (i < Math.abs(stepsY)) ? Math.sign(stepsY) * stepSize : 0;
            const currentDeltaX = (i < Math.abs(stepsX)) ? Math.sign(stepsX) * stepSize : 0;

            if (currentDeltaY !== 0 || currentDeltaX !== 0) {
                simulateWheelEvent(element, currentDeltaY, currentDeltaX);
                // Introduce a small delay between ticks (e.g., 10-50ms).
                await new Promise(res => setTimeout(res, 10 + Math.random() * 40));
            }
        }
    };
    // --- Main Logic ---
    const el = document.querySelector(selector);
    if (!el) {
        return { isIntersecting: false, isComplete: true, verticalDelta: 0, horizontalDelta: 0, contentDensity: 0, elementExists: false };
    }
    const viewportHeight = window.innerHeight;
    const viewportWidth = window.innerWidth;
    const elementBounds = el.getBoundingClientRect();
    const visibilityThreshold = 30; // Pixels from edge for comfortable visibility.
    const isVerticallyVisible = elementBounds.top >= visibilityThreshold && elementBounds.bottom <= viewportHeight - visibilityThreshold;
    const isHorizontallyVisible = elementBounds.left >= visibilityThreshold && elementBounds.right <= viewportWidth - visibilityThreshold;
    if (isVerticallyVisible && isHorizontallyVisible) {
        return { isIntersecting: true, isComplete: true, verticalDelta: 0, horizontalDelta: 0, contentDensity: 0, elementExists: true };
    }
    const contentDensity = estimateContentDensity();
    // 1. Calculate Vertical Scroll
    let scrollAmountY = 0, distanceToTargetY = 0, scrollableParentY = null, startScrollTop = 0;
    if (!isVerticallyVisible) {
        scrollableParentY = getScrollableParent(el, 'y');
        if (scrollableParentY) {
            startScrollTop = scrollableParentY.scrollTop;
            let elementYRelativeToParent;
            if (scrollableParentY === document.scrollingElement || scrollableParentY === document.documentElement) {
                elementYRelativeToParent = elementBounds.top + scrollableParentY.scrollTop;
            } else {
                const parentBounds = scrollableParentY.getBoundingClientRect();
                elementYRelativeToParent = elementBounds.top - parentBounds.top + startScrollTop;
            }
            const parentHeight = scrollableParentY.clientHeight || viewportHeight;
            // Aim for a random position within the middle 60% of the viewport.
            const targetViewportPosition = parentHeight * (0.2 + Math.random() * 0.6);
            let targetScrollTop = elementYRelativeToParent - targetViewportPosition;
            distanceToTargetY = targetScrollTop - startScrollTop;
            scrollAmountY = distanceToTargetY;
        }
    }

    // 2. Calculate Horizontal Scroll
    let scrollAmountX = 0, distanceToTargetX = 0, scrollableParentX = null, startScrollLeft = 0;
    if (!isHorizontallyVisible) {
        scrollableParentX = getScrollableParent(el, 'x');
        if (scrollableParentX) {
            startScrollLeft = scrollableParentX.scrollLeft;
            let elementXRelativeToParent;
            if (scrollableParentX === document.scrollingElement || scrollableParentX === document.documentElement) {
                elementXRelativeToParent = elementBounds.left + scrollableParentX.scrollLeft;
            } else {
                const parentBounds = scrollableParentX.getBoundingClientRect();
                // Corrected calculation: left - parentBounds.left
                elementXRelativeToParent = elementBounds.left - parentBounds.left + startScrollLeft;
            }
            const parentWidth = scrollableParentX.clientWidth || viewportWidth;
            const targetViewportPosition = parentWidth * (0.2 + Math.random() * 0.6);
            let targetScrollLeft = elementXRelativeToParent - targetViewportPosition;
            distanceToTargetX = targetScrollLeft - startScrollLeft;
            scrollAmountX = distanceToTargetX;
        }
    }

    // 3. Apply Injected Deltas and Chunking/Density
    if (injectedDeltaY !== 0 || injectedDeltaX !== 0) {
        // Used for overshoots/regressions.
        scrollAmountY = injectedDeltaY;
        scrollAmountX = injectedDeltaX;
    } else {
        // Simulate reading while scrolling: slower scrolling on dense content.
        const densityImpact = Math.max(0.1, 1.0 - contentDensity * readDensityFactor);
        const randomFactor = 0.6 + Math.random() * 0.4;
        const chunkFactor = randomFactor * densityImpact;
        // Scroll only a fraction of the required distance.
        scrollAmountY = distanceToTargetY * chunkFactor;
        scrollAmountX = distanceToTargetX * chunkFactor;
    }

    // 4. Execute Scroll
    const maxScroll = Math.max(Math.abs(scrollAmountY), Math.abs(scrollAmountX));
    const behavior = maxScroll > 150 ? 'smooth' : 'auto';
    const parentsToWaitFor = new Set();
    let scrollMethodUsed = 'none';
    if (useMouseWheel) {
        // --- Mouse Wheel Simulation ---
        scrollMethodUsed = 'wheel';

        // Identify the primary scrollable parent.
        let primaryParent;
        if (Math.abs(distanceToTargetY) >= Math.abs(distanceToTargetX)) {
            primaryParent = scrollableParentY;
        } else {
            primaryParent = scrollableParentX;
        }

        if (!primaryParent) {
             primaryParent = document.scrollingElement || document.documentElement;
        }

        if (Math.abs(scrollAmountY) > 1 || Math.abs(scrollAmountX) > 1) {
            if (isDetentWheel) {
                // Detent wheel simulation handles its own timing internally.
                await simulateDetentWheel(primaryParent, scrollAmountY, scrollAmountX);
            } else {
                // Smooth wheel simulation (single event).
                simulateWheelEvent(primaryParent, scrollAmountY, scrollAmountX);
            }

            parentsToWaitFor.add(primaryParent);
            // Add other parents if needed.
            if (primaryParent !== scrollableParentY && scrollableParentY) parentsToWaitFor.add(scrollableParentY);
            if (primaryParent !== scrollableParentX && scrollableParentX) parentsToWaitFor.add(scrollableParentX);
        }

    } else {
        // --- scrollBy Simulation (Trackpad/Scrollbar Drag) ---
        scrollMethodUsed = 'scrollBy';
        if (scrollableParentY === scrollableParentX && scrollableParentY) {
            if (Math.abs(scrollAmountY) > 1 || Math.abs(scrollAmountX) > 1) {
                scrollableParentY.scrollBy({ top: scrollAmountY, left: scrollAmountX, behavior: behavior });
                parentsToWaitFor.add(scrollableParentY);
            }
        } else {
            if (Math.abs(scrollAmountY) > 1 && scrollableParentY) {
                scrollableParentY.scrollBy({ top: scrollAmountY, behavior: behavior });
                parentsToWaitFor.add(scrollableParentY);
            }
            if (Math.abs(scrollAmountX) > 1 && scrollableParentX) {
                scrollableParentX.scrollBy({ left: scrollAmountX, behavior: behavior });
                parentsToWaitFor.add(scrollableParentX);
            }
        }
    }

    // 5. Wait for Stabilization
    // Wait longer for wheel events as their animation duration is often OS/browser dependent.
    const stabilizationTimeout = useMouseWheel ? 1500 : 1000;
    if (parentsToWaitFor.size > 0) {
        if ((scrollMethodUsed === 'scrollBy' && behavior === 'smooth') || scrollMethodUsed === 'wheel') {
            const waitPromises = Array.from(parentsToWaitFor).map(p => waitForScrollStabilization(p, stabilizationTimeout));
            await Promise.all(waitPromises);
        } else if (scrollMethodUsed === 'scrollBy') {
            // Short wait for 'auto' scrollBy.
            await new Promise(res => setTimeout(res, 50 + Math.random() * 100));
        }
    }

    // 6. Check Completion
    let isComplete = false;
    let boundaryHit = false;

    // Check if we hit the scroll boundaries.
    if (Math.abs(distanceToTargetY) > 1 && scrollableParentY) {
        const endScrollTop = scrollableParentY.scrollTop;
        // If scrollTop didn't change significantly despite attempting to scroll, we hit a boundary.
        if (Math.abs(startScrollTop - endScrollTop) < 5 && Math.abs(scrollAmountY) > 5) {
            boundaryHit = true;
        }
    }
    if (Math.abs(distanceToTargetX) > 1 && scrollableParentX) {
        const endScrollLeft = scrollableParentX.scrollLeft;
        if (Math.abs(startScrollLeft - endScrollLeft) < 5 && Math.abs(scrollAmountX) > 5) {
            boundaryHit = true;
        }
    }

    // If we hit a boundary OR the target is very close, we consider the scroll action complete.
    if (boundaryHit || (Math.abs(distanceToTargetY) < 5 && Math.abs(distanceToTargetX) < 5)) {
        isComplete = true;
    }

    return {
        isIntersecting: false, // We only know it's intersecting at the very start check.
        isComplete: isComplete,
        verticalDelta: distanceToTargetY,
        horizontalDelta: distanceToTargetX,
        contentDensity: contentDensity,
        elementExists: true
    };
}
`

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
