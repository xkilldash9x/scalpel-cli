// internal/browser/humanoid/scrolling.go
package humanoid

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "go.uber.org/zap"
)

// The JavaScript logic for performing a single scroll iteration.
const scrollIterationJS = `
async (selector, injectedDeltaY, injectedDeltaX, readDensityFactor) => {
    // --- Utility Functions (getScrollableParent, waitForScrollStabilization, estimateContentDensity) ---
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
            // Element might be detached or in a context that prevents style access.
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
        const isScrollable = (overflow === 'auto' || overflow === 'scroll') && scrollSize > clientSize + 1;
        if (isScrollable) {
            return node;
        }
        return getScrollableParent(node.parentNode, axis);
    };

    const waitForScrollStabilization = (element, timeout = 1000) => {
        return new Promise((resolve) => {
            let lastScrollTop = element.scrollTop;
            let lastScrollLeft = element.scrollLeft;
            let stabilizationChecks = 0;
            const requiredChecks = 3;
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
            timeoutId = setTimeout(() => {
                resolve();
            }, timeout);
        });
    };

    const estimateContentDensity = () => {
        let totalTextLength = 0;
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
            acceptNode: (node) => {
                if (!node.parentElement || node.parentElement.offsetParent === null) return NodeFilter.FILTER_REJECT;

                // Ignore non-readable elements.
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

    // --- Main Logic ---
    const el = document.querySelector(selector);
    if (!el) {
        return { isIntersecting: false, isComplete: true, verticalDelta: 0, horizontalDelta: 0, contentDensity: 0, elementExists: false };
    }
    const viewportHeight = window.innerHeight;
    const viewportWidth = window.innerWidth;
    const elementBounds = el.getBoundingClientRect();
    const visibilityThreshold = 30; // Pixels from edge.

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
                elementXRelativeToParent = elementBounds.left - parentBounds.top + startScrollLeft;
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
        scrollAmountY = injectedDeltaY;
        scrollAmountX = injectedDeltaX;
    } else {
        const densityImpact = Math.max(0.1, 1.0 - contentDensity * readDensityFactor);
        const randomFactor = 0.6 + Math.random() * 0.4;
        const chunkFactor = randomFactor * densityImpact;
        scrollAmountY = distanceToTargetY * chunkFactor;
        scrollAmountX = distanceToTargetX * chunkFactor;
    }

    // 4. Execute Scroll
    const maxScroll = Math.max(Math.abs(scrollAmountY), Math.abs(scrollAmountX));
    const behavior = maxScroll > 150 ? 'smooth' : 'auto';

    const parentsToWaitFor = new Set();

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

    // 5. Wait for Stabilization
    if (behavior === 'smooth' && parentsToWaitFor.size > 0) {
        const waitPromises = Array.from(parentsToWaitFor).map(p => waitForScrollStabilization(p));
        await Promise.all(waitPromises);
    } else if (parentsToWaitFor.size > 0) {
        // Short wait for 'auto' scroll
        await new Promise(res => setTimeout(res, 50 + Math.random() * 100));
    }

    // 6. Check Completion
    let isComplete = false;
    let boundaryHit = false;

    if (Math.abs(distanceToTargetY) > 1 && scrollableParentY) {
        const endScrollTop = scrollableParentY.scrollTop;
        if (Math.abs(startScrollTop - endScrollTop) < 1 && Math.abs(scrollAmountY) > 1) {
            boundaryHit = true;
        }
    }
    if (Math.abs(distanceToTargetX) > 1 && scrollableParentX) {
        const endScrollLeft = scrollableParentX.scrollLeft;
        if (Math.abs(startScrollLeft - endScrollLeft) < 1 && Math.abs(scrollAmountX) > 1) {
            boundaryHit = true;
        }
    }

    // If we hit a boundary (can't scroll further) OR the target is very close, we are done.
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
    // LOCK REMOVED: Caller holds the lock, so direct access is safe.
    readDensityFactor := h.dynamicConfig.ScrollReadDensityFactor
    rng := h.rng
    shouldOvershoot := rng.Float64() < h.dynamicConfig.ScrollOvershootProbability
    shouldRegress := rng.Float64() < h.dynamicConfig.ScrollRegressionProbability

    maxIterations := 15
    iteration := 0

    for iteration < maxIterations {
        // Check context cancellation.
        if ctx.Err() != nil {
            return ctx.Err()
        }

        iteration++

        // 1. Execute Scroll Iteration
        result, err := h.executeScrollJS(ctx, selector, 0.0, 0.0, readDensityFactor)

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

        // If the element does not exist, stop trying to scroll to it.
        if !result.ElementExists {
            h.logger.Debug("Humanoid: Scroll target element does not exist", zap.String("selector", selector))
            return nil
        }
        if result.IsIntersecting || result.IsComplete {
            h.logger.Debug("Humanoid: Scroll complete", zap.Bool("intersecting", result.IsIntersecting), zap.Int("iteration", iteration))

            // 3. Handle Overshoot (if applicable)
            if result.IsComplete && !result.IsIntersecting && shouldOvershoot {
                h.logger.Debug("Humanoid: Simulating scroll overshoot")
                if err := h.simulateOvershoot(ctx, selector, readDensityFactor, result.VerticalDelta, result.HorizontalDelta); err != nil {
                    return err
                }
            }
            return nil
        }

        // 4. Pause between scrolls (Cognitive processing / Reading)
        pauseDuration := h.calculateScrollPause(result.ContentDensity)
        // Use the executor for sleep.
        if err := h.executor.Sleep(ctx, pauseDuration); err != nil {
            return err
        }

        // 5. Handle Regression (if applicable)
        if shouldRegress && iteration > 2 && (result.VerticalDelta > 100 || result.HorizontalDelta > 100) {
            h.logger.Debug("Humanoid: Simulating scroll regression")
            if err := h.simulateRegression(ctx, selector, readDensityFactor, result.VerticalDelta, result.HorizontalDelta); err != nil {
                return err
            }
            // Reset regression flag so it only happens once per scroll action.
            shouldRegress = false
            // Add an extra pause after regression.
            if err := h.CognitivePause(ctx, 300, 100); err != nil {
                return err
            }
        }
    }

    h.logger.Warn("Humanoid: Scroll timed out (max iterations reached)", zap.String("selector", selector))
    // Return nil even on timeout. The caller should handle visibility failure.
    return nil
}

// executeScrollJS handles the preparation and execution of the scrollIterationJS via the executor.
func (h *Humanoid) executeScrollJS(ctx context.Context, selector string, deltaY, deltaX, readDensityFactor float64) (*scrollResult, error) {
    // Prepare the arguments for the JS function.
    args := []interface{}{
        selector,
        deltaY,
        deltaX,
        readDensityFactor,
    }

    // Execute via the agnostic executor.
    resultJSON, err := h.executor.ExecuteScript(ctx, scrollIterationJS, args)

    if err != nil {
        return nil, fmt.Errorf("javascript execution error during scroll: %w", err)
    }

    // Check for null or empty results.
    if resultJSON == nil || len(resultJSON) == 0 || string(resultJSON) == "null" || string(resultJSON) == "undefined" {
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
    // LOCK REMOVED: Caller holds the lock, so direct access is safe.
    // Base pause + pause based on content density + random variation
    pauseMs := 100 + (contentDensity * 1000 * h.dynamicConfig.ScrollReadDensityFactor) + (h.rng.Float64() * 150)
    // Apply fatigue
    pauseMs *= (1.0 + h.fatigueLevel*0.5)
    // Clamp to a reasonable range
    if pauseMs > 2000 {
        pauseMs = 2000
    }
    return time.Duration(pauseMs) * time.Millisecond
}

// simulateOvershoot is an internal helper. It assumes the caller holds the lock.
func (h *Humanoid) simulateOvershoot(ctx context.Context, selector string, readDensityFactor, verticalDelta, horizontalDelta float64) error {
    // LOCK REMOVED: Caller holds the lock, so direct access is safe.
    rng := h.rng

    overshootY := verticalDelta * (0.1 + rng.Float64()*0.2)
    overshootX := horizontalDelta * (0.1 + rng.Float64()*0.2)

    // Execute the JS via the helper which uses the executor.
    if _, err := h.executeScrollJS(ctx, selector, overshootY, overshootX, readDensityFactor); err != nil {
        // Log the error but don't necessarily fail the operation if context is cancelled.
        if ctx.Err() != nil {
            return ctx.Err()
        }
        h.logger.Warn("Humanoid: simulateOvershoot failed", zap.Error(err))
    }

    // Brief pause after overshooting
    return h.CognitivePause(ctx, 150, 50)
}

// simulateRegression is an internal helper. It assumes the caller holds the lock.
func (h *Humanoid) simulateRegression(ctx context.Context, selector string, readDensityFactor, verticalDelta, horizontalDelta float64) error {
    // LOCK REMOVED: Caller holds the lock, so direct access is safe.
    rng := h.rng

    regressionY := -verticalDelta * (0.2 + rng.Float64()*0.3)
    regressionX := -horizontalDelta * (0.2 + rng.Float64()*0.3)

    // Execute the JS via the helper which uses the executor.
    _, err := h.executeScrollJS(ctx, selector, regressionY, regressionX, readDensityFactor)
    if err != nil {
        // Log the error but don't necessarily fail the operation if context is cancelled.
        if ctx.Err() != nil {
            return ctx.Err()
        }
        h.logger.Warn("Humanoid: simulateRegression failed", zap.Error(err))
    }
    return nil
}