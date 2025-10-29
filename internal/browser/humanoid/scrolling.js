
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