// pkg/humanoid/scrolling_script.js
/**
 * In-browser logic for performing a single human-like scroll iteration (JS-based).
 * Handles bidirectional scrolling, content density estimation, and stabilization waiting.
 */
async (selector, injectedDeltaY, injectedDeltaX, readDensityFactor) => {
    // --- Utility Functions ---

    // Utility function to find the nearest scrollable parent for a specific axis.
    const getScrollableParent = (node, axis = 'y') => {
        // Base cases: Reached the top level elements.
        if (node == null || node === document.body || node === document.documentElement) {
            return document.scrollingElement || document.documentElement;
        }
        
        // Ensure we are dealing with an element node.
        if (node.nodeType !== Node.ELEMENT_NODE) {
            return getScrollableParent(node.parentNode, axis);
        }

        let style;
        try {
            style = window.getComputedStyle(node);
        } catch (e) {
            // Handle potential cross-origin errors if node is inside an iframe.
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

        // Check if overflow allows scrolling and if content exceeds the client area (scrollbar present).
        // Add tolerance (+1) for pixel rounding issues.
        const isScrollable = (overflow === 'auto' || overflow === 'scroll') && scrollSize > clientSize + 1;
        if (isScrollable) {
            return node;
        }
        // Recurse up the DOM tree.
        return getScrollableParent(node.parentNode, axis);
    };

    // Waits for the scroll position stabilization using requestAnimationFrame (rAF).
    const waitForScrollStabilization = (element, timeout = 1000) => {
        return new Promise((resolve) => {
            let lastScrollTop = element.scrollTop;
            let lastScrollLeft = element.scrollLeft;
            let stabilizationChecks = 0;
            const requiredChecks = 3; // Number of consecutive rAF frames with no change.
            let timeoutId = null;

            const checkScroll = () => {
                // Robustness: Check if element is still connected (for dynamic content changes).
                if (!element.isConnected && element !== document.scrollingElement && element !== document.documentElement) {
                    if (timeoutId) clearTimeout(timeoutId);
                    resolve();
                    return;
                }

                const currentScrollTop = element.scrollTop;
                const currentScrollLeft = element.scrollLeft;

                if (currentScrollTop !== lastScrollTop || currentScrollLeft !== lastScrollLeft) {
                    // Scroll is still active.
                    lastScrollTop = currentScrollTop;
                    lastScrollLeft = currentScrollLeft;
                    stabilizationChecks = 0;
                    requestAnimationFrame(checkScroll);
                } else {
                    // Scroll position unchanged in this frame.
                    stabilizationChecks++;
                    if (stabilizationChecks >= requiredChecks) {
                        // Stabilized.
                        if (timeoutId) clearTimeout(timeoutId);
                        resolve();
                    } else {
                        requestAnimationFrame(checkScroll);
                    }
                }
            };

            requestAnimationFrame(checkScroll);
            // Set a hard timeout in case stabilization never occurs.
            timeoutId = setTimeout(() => {
                resolve();
            }, timeout);
        });
    };

    // Estimates the density of content (heuristic based on visible text length).
    const estimateContentDensity = () => {
        let totalTextLength = 0;
        // Use TreeWalker for efficient traversal of text nodes.
        const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
            acceptNode: (node) => {
                // Basic visibility checks.
                if (!node.parentElement || node.parentElement.offsetParent === null) return NodeFilter.FILTER_REJECT;
                
                try {
                    const style = window.getComputedStyle(node.parentElement);
                    if (style.visibility === 'hidden' || style.display === 'none') return NodeFilter.FILTER_REJECT;
                } catch (e) {
                    // Handle potential errors accessing computed style.
                    return NodeFilter.FILTER_REJECT;
                }

                // Ignore very short text snippets.
                if (node.nodeValue.trim().length < 3) return NodeFilter.FILTER_SKIP;
                return NodeFilter.FILTER_ACCEPT;
            }
        });

        while (walker.nextNode()) {
            totalTextLength += walker.currentNode.nodeValue.length;
        }

        // Normalize the score. A typical dense page might have ~3000 visible characters.
        const normalizationFactor = 3000;
        const density = totalTextLength / normalizationFactor;
        return Math.min(1.5, density); // Cap density score.
    };


    // --- Main Logic ---

    const el = document.querySelector(selector);
    if (!el) {
        // Element not found, scrolling is complete by definition.
        return JSON.stringify({ isIntersecting: false, isComplete: true, verticalDelta: 0, horizontalDelta: 0, contentDensity: 0 });
    }

    const viewportHeight = window.innerHeight;
    const viewportWidth = window.innerWidth;
    const elementBounds = el.getBoundingClientRect();
    const visibilityThreshold = 30; // Pixels from edge.

    // Check if the element is already sufficiently visible in the viewport.
    const isVerticallyVisible = elementBounds.top >= visibilityThreshold && elementBounds.bottom <= viewportHeight - visibilityThreshold;
    const isHorizontallyVisible = elementBounds.left >= visibilityThreshold && elementBounds.right <= viewportWidth - visibilityThreshold;

    if (isVerticallyVisible && isHorizontallyVisible) {
        return JSON.stringify({ isIntersecting: true, isComplete: true, verticalDelta: 0, horizontalDelta: 0, contentDensity: 0 });
    }

    // Estimate density BEFORE scrolling.
    const contentDensity = estimateContentDensity();

    // 1. Calculate Vertical Scroll
    let scrollAmountY = 0, distanceToTargetY = 0, scrollableParentY = null, startScrollTop = 0;
    if (!isVerticallyVisible) {
        scrollableParentY = getScrollableParent(el, 'y');
        if (scrollableParentY) {
            startScrollTop = scrollableParentY.scrollTop;

            let elementYRelativeToParent;
            // Calculate element's position relative to the scroll container's scroll position.
            if (scrollableParentY === document.scrollingElement || scrollableParentY === document.documentElement) {
                // Element position relative to the document top.
                elementYRelativeToParent = elementBounds.top + scrollableParentY.scrollTop;
            } else {
                // Element position relative to the scrollable parent's top.
                const parentBounds = scrollableParentY.getBoundingClientRect();
                elementYRelativeToParent = elementBounds.top - parentBounds.top + startScrollTop;
            }

            const parentHeight = scrollableParentY.clientHeight || viewportHeight;
            // Randomized target position within the viewport (Human-like aiming: between 20% and 80% height).
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

    // 3. Apply Injected Deltas (Overshoot/Regression) and Chunking/Density
    // If overshoot/regression deltas are provided (from Go logic), apply them directly.
    if (injectedDeltaY !== 0 || injectedDeltaX !== 0) {
        scrollAmountY = injectedDeltaY;
        scrollAmountX = injectedDeltaX;
    } else {
        // Chunked scrolling: Humans rarely scroll the exact distance in one go.
        // Adjust chunk factor based on density. Denser content leads to smaller, more careful chunks.
        const densityImpact = Math.max(0.1, 1.0 - contentDensity * readDensityFactor);
        const randomFactor = 0.6 + Math.random() * 0.4;
        const chunkFactor = randomFactor * densityImpact;

        scrollAmountY = distanceToTargetY * chunkFactor;
        scrollAmountX = distanceToTargetX * chunkFactor;
    }

    // 4. Execute Scroll
    const maxScroll = Math.max(Math.abs(scrollAmountY), Math.abs(scrollAmountX));
    // Use 'smooth' for larger scrolls, 'auto' (instant) for small adjustments.
    const behavior = maxScroll > 150 ? 'smooth' : 'auto';

    // Handle potentially different scroll parents for X and Y.
    const parentsToWaitFor = new Set();

    // Optimized scroll execution
    if (scrollableParentY === scrollableParentX && scrollableParentY) {
        // Same parent for both axes
        if (Math.abs(scrollAmountY) > 1 || Math.abs(scrollAmountX) > 1) {
            scrollableParentY.scrollBy({ top: scrollAmountY, left: scrollAmountX, behavior: behavior });
            parentsToWaitFor.add(scrollableParentY);
        }
    } else {
        // Different parents
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
        // Short delay for 'auto' scroll to allow browser rendering.
        await new Promise(res => setTimeout(res, 50 + Math.random() * 100));
    }

    // 6. Check Completion (Did the scroll succeed or hit a boundary?)
    let isComplete = false;
    let boundaryHit = false;

    // Verify Vertical Scroll
    if (Math.abs(distanceToTargetY) > 1 && scrollableParentY) {
        const endScrollTop = scrollableParentY.scrollTop;
        // If scroll position didn't change despite attempting a significant scroll, we are at the boundary.
        if (Math.abs(startScrollTop - endScrollTop) < 1 && Math.abs(scrollAmountY) > 1) {
             boundaryHit = true;
        }
    }

     // Verify Horizontal Scroll
     if (Math.abs(distanceToTargetX) > 1 && scrollableParentX) {
         const endScrollLeft = scrollableParentX.scrollLeft;
         if (Math.abs(startScrollLeft - endScrollLeft) < 1 && Math.abs(scrollAmountX) > 1) {
             boundaryHit = true;
         }
     }

     // If we hit a boundary, or if there's negligible distance left, we are complete.
     if (boundaryHit || (Math.abs(distanceToTargetY) < 5 && Math.abs(distanceToTargetX) < 5)) {
        isComplete = true;
     }

    return JSON.stringify({
        isIntersecting: false,
        isComplete: isComplete,
        verticalDelta: distanceToTargetY,
        horizontalDelta: distanceToTargetX,
        contentDensity: contentDensity,
    });
}
