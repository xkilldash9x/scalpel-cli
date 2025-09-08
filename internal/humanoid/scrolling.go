// Filename: internal/humanoid/scrolling.go
package humanoid

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// scrollIterationJS is the beast of a JavaScript function that does the actual scrolling.
// It's designed to run in the browser context and figures out what to scroll and by how much,
// trying its best to mimic how a person would scroll to find something.
const scrollIterationJS = `
async (selector, injectedDeltaY, injectedDeltaX, readDensityFactor) => {
    // -- Utility Functions (getScrollableParent, waitForScrollStabilization, estimateContentDensity) --

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

    // -- Main Logic --

    const el = document.querySelector(selector);
    if (!el) {
        // If element doesn't exist, we treat it as complete but not intersecting.
        return JSON.stringify({ isIntersecting: false, isComplete: true, verticalDelta: 0, horizontalDelta: 0, contentDensity: 0, elementExists: false });
    }

    const viewportHeight = window.innerHeight;
    const viewportWidth = window.innerWidth;
    const elementBounds = el.getBoundingClientRect();
    const visibilityThreshold = 30; // Pixels from edge.

    const isVerticallyVisible = elementBounds.top >= visibilityThreshold && elementBounds.bottom <= viewportHeight - visibilityThreshold;
    const isHorizontallyVisible = elementBounds.left >= visibilityThreshold && elementBounds.right <= viewportWidth - visibilityThreshold;

    if (isVerticallyVisible && isHorizontallyVisible) {
        return JSON.stringify({ isIntersecting: true, isComplete: true, verticalDelta: 0, horizontalDelta: 0, contentDensity: 0, elementExists: true });
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

    return JSON.stringify({
        isIntersecting: false, // We only know it's intersecting at the very start check.
        isComplete: isComplete,
        verticalDelta: distanceToTargetY,
        horizontalDelta: distanceToTargetX,
        contentDensity: contentDensity,
        elementExists: true
    });
}
`

// scrollResult is what we get back from our JavaScript friend. It tells us how the scroll went.
type scrollResult struct {
	IsIntersecting  bool    `json:"isIntersecting"`
	IsComplete      bool    `json:"isComplete"`
	VerticalDelta   float64 `json:"verticalDelta"`
	HorizontalDelta float64 `json:"horizontalDelta"`
	ContentDensity  float64 `json:"contentDensity"`
	ElementExists   bool    `json:"elementExists"`
}

// executeScrollJS is our new gatekeeper for running the scroll script.
// It abstracts away the direct executor call, making things cleaner and easier to test.
func (h *Humanoid) executeScrollJS(ctx context.Context, selector string, injectedDeltaY, injectedDeltaX, readDensityFactor float64) (*scrollResult, error) {
	// We need to marshal our Go types into JSON for the runtime.CallArgument.
	arg1, err := json.Marshal(selector)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal selector arg: %w", err)
	}
	arg2, err := json.Marshal(injectedDeltaY)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal deltaY arg: %w", err)
	}
	arg3, err := json.Marshal(injectedDeltaX)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal deltaX arg: %w", err)
	}
	arg4, err := json.Marshal(readDensityFactor)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal density arg: %w", err)
	}

	// We're manually building the parameters here, this is what chromedp.CallFunctionOn does behind the scenes anyway.
	args := []*runtime.CallArgument{
		{Value: arg1},
		{Value: arg2},
		{Value: arg3},
		{Value: arg4},
	}

	params := runtime.CallFunctionOn(scrollIterationJS).
		WithArguments(args).
		WithAwaitPromise(true).
		WithReturnByValue(true) // We want the JSON string back, not a handle to a remote object.

	// Offload the actual execution to the executor. No more direct calls.
	remoteObject, exceptionDetails, err := h.executor.CallFunctionOn(ctx, params)
	if err != nil {
		return nil, err
	}
	if exceptionDetails != nil {
		return nil, fmt.Errorf("javascript execution failed: %s", exceptionDetails.Text)
	}
	if remoteObject == nil || remoteObject.Value == nil {
		return nil, fmt.Errorf("javascript returned null or undefined result")
	}

	// The result we get is a JSON string, but it's wrapped in another layer of JSON.
	// So we unmarshal it once to get the string...
	var resJSON string
	if err := json.Unmarshal(remoteObject.Value, &resJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal remote object value: %w", err)
	}

	// ...and then unmarshal that string into our actual result struct.
	var result scrollResult
	if err := json.Unmarshal([]byte(resJSON), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal scroll result JSON: %w", err)
	}

	return &result, nil
}

// intelligentScroll is the main entry point for our human like scrolling.
// It tries to scroll until the target selector is nicely in view.
func (h *Humanoid) intelligentScroll(selector string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		h.mu.Lock()
		readDensityFactor := h.dynamicConfig.ScrollReadDensityFactor
		rng := h.rng
		// Let's roll the dice to see if we should be a little sloppy.
		shouldOvershoot := rng.Float64() < h.dynamicConfig.ScrollOvershootProbability
		shouldRegress := rng.Float64() < h.dynamicConfig.ScrollRegressionProbability
		h.mu.Unlock()

		maxIterations := 15
		iteration := 0

		for iteration < maxIterations {
			iteration++

			// -- Step 1: Execute Scroll Iteration --
			// Using our new abstracted helper function. Much cleaner.
			result, err := h.executeScrollJS(ctx, selector, 0.0, 0.0, readDensityFactor)
			if err != nil {
				// Don't panic if the context was cancelled, that's a graceful exit.
				if ctx.Err() != nil {
					return ctx.Err()
				}
				h.logger.Warn("Humanoid: Scroll iteration JS execution failed", zap.Error(err), zap.Int("iteration", iteration))
				// The DOM might be having a moment. Let's give it a second.
				if err := h.executor.Sleep(ctx, 100*time.Millisecond); err != nil {
					return err
				}
				continue
			}

			// -- Step 2: Process Results --
			// If the element's not there, no point in continuing the charade.
			if !result.ElementExists {
				h.logger.Debug("Humanoid: Scroll target element does not exist", zap.String("selector", selector))
				return nil
			}

			if result.IsIntersecting || result.IsComplete {
				h.logger.Debug("Humanoid: Scroll complete", zap.Bool("intersecting", result.IsIntersecting), zap.Int("iteration", iteration))

				// -- Step 3: Handle Overshoot (if applicable) --
				// Sometimes you scroll a little too far. It happens.
				if result.IsComplete && !result.IsIntersecting && shouldOvershoot {
					h.logger.Debug("Humanoid: Simulating scroll overshoot")
					if err := h.simulateOvershoot(ctx, selector, readDensityFactor, result.VerticalDelta, result.HorizontalDelta); err != nil {
						// This one is important enough to return the error.
						return err
					}
				}
				return nil // We're done here.
			}

			// -- Step 4: Pause Between Scrolls --
			// Gotta simulate reading the content, right?
			pauseDuration := h.calculateScrollPause(result.ContentDensity)
			if err := h.executor.Sleep(ctx, pauseDuration); err != nil {
				return err
			}

			// -- Step 5: Handle Regression (if applicable) --
			// "Wait, what did I just read?" *scrolls back up*
			if shouldRegress && iteration > 2 && (result.VerticalDelta > 100 || result.HorizontalDelta > 100) {
				h.logger.Debug("Humanoid: Simulating scroll regression")
				if err := h.simulateRegression(ctx, selector, readDensityFactor, result.VerticalDelta, result.HorizontalDelta); err != nil {
					// Also important enough to bubble up.
					return err
				}
				// Only do this once per scroll attempt, let's not get stuck in a loop.
				shouldRegress = false
				// A little extra pause to "re-read".
				base := 300 * time.Millisecond
				random := time.Duration(h.rng.Intn(100)) * time.Millisecond
				if err := h.executor.Sleep(ctx, base+random); err != nil {
					return err
				}
			}
		}

		h.logger.Warn("Humanoid: Scroll timed out (max iterations reached)", zap.String("selector", selector))
		// Don't throw an error on timeout. Let the calling action decide if visibility is a problem.
		return nil
	})
}

// calculateScrollPause decides how long to wait between scroll chunks.
// More text means more "reading" time.
func (h *Humanoid) calculateScrollPause(contentDensity float64) time.Duration {
	h.mu.Lock()
	rng := h.rng
	h.mu.Unlock()

	// Base pause for "reaction time".
	basePause := 150.0 + rng.Float64()*100.0

	// Add time based on how much stuff is on the page.
	densityPause := contentDensity * (500.0 + rng.Float64()*500.0)

	return time.Duration(basePause+densityPause) * time.Millisecond
}

// simulateOvershoot makes a small corrective scroll after going a bit too far.
func (h *Humanoid) simulateOvershoot(ctx context.Context, selector string, readDensityFactor, lastVDelta, lastHDelta float64) error {
	h.mu.Lock()
	rng := h.rng
	h.mu.Unlock()

	// Let's correct by a small random fraction of the last movement.
	correctionFactor := 0.1 + rng.Float64()*0.2
	vCorrection := -lastVDelta * correctionFactor
	hCorrection := -lastHDelta * correctionFactor

	// Use our helper to run the script with the corrective deltas.
	_, err := h.executeScrollJS(ctx, selector, vCorrection, hCorrection, readDensityFactor)
	if err != nil {
		h.logger.Warn("Humanoid: Overshoot correction failed", zap.Error(err))
		// This isn't a critical failure, so we don't return the error.
	}
	return nil
}

// simulateRegression scrolls back a bit, like when you lose your place reading.
func (h *Humanoid) simulateRegression(ctx context.Context, selector string, readDensityFactor, lastVDelta, lastHDelta float64) error {
	h.mu.Lock()
	rng := h.rng
	h.mu.Unlock()

	// Go back by a larger chunk than the overshoot correction.
	regressionFactor := 0.3 + rng.Float64()*0.4
	vRegression := -lastVDelta * regressionFactor
	hRegression := -lastHDelta * regressionFactor

	// Use the helper again to inject these "oops, went too far" values.
	_, err := h.executeScrollJS(ctx, selector, vRegression, hRegression, readDensityFactor)
	if err != nil {
		h.logger.Warn("Humanoid: Scroll regression failed", zap.Error(err))
		// Also not a show-stopper.
	}
	return nil
}
