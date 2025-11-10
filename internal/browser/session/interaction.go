// internal/browser/session/interaction.go
// This file implements the high-level user interaction methods for a Session,
// such as navigating to a URL, clicking elements, typing text, and scrolling.
// These methods serve as the primary API for controlling the browser page.
//
// When a `humanoid` is attached to the session, these actions are delegated to it
// to simulate realistic, human-like behavior. If no humanoid is present, the
// methods fall back to using standard, direct `chromedp` actions. This design
// allows for a flexible execution model, supporting both simple automation and
// sophisticated, human-like interaction simulation through the same API.
//
// Each method is responsible for managing its own operational context and timeouts,
// ensuring that long-running actions (like navigation) can be cancelled without
// terminating the entire session.
package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// Navigate instructs the browser to load the specified URL. This is a comprehensive
// action that includes not only the navigation itself but also a subsequent
// "stabilization" period, where it waits for network activity to cease.
//
// If a `humanoid` is attached to the session, it will also perform a realistic
// cognitive pause after the page has stabilized.
//
// Parameters:
//   - ctx: The context for the navigation operation. A timeout specific to
//     navigation will be derived from this context.
//   - url: The URL to navigate to.
//
// Returns an error if the navigation fails, times out, or is cancelled.
func (s *Session) Navigate(ctx context.Context, url string) error {
	s.logger.Info("Navigating session.", zap.String("url", url)) // Changed log level for clarity

	// Apply a specific timeout for the navigation action itself, based on the operational context (ctx).
	navTimeout := s.cfg.Network().NavigationTimeout // Use accessor
	if navTimeout <= 0 {
		navTimeout = 90 * time.Second // Default fallback
	}
	navCtx, navCancel := context.WithTimeout(ctx, navTimeout)
	defer navCancel()

	// 1. Execute the navigation using RunActions (which handles context combination).
	// Pass the specifically timed navCtx to RunActions.
	err := s.RunActions(navCtx, chromedp.Navigate(url))
	if err != nil {
		// Check if the specific navigation context timed out.
		if navCtx.Err() == context.DeadlineExceeded {
			// Provide a clearer error message including the timeout duration
			return fmt.Errorf("navigation to %s timed out after %v: %w", url, navTimeout, navCtx.Err())
		}
		// If navCtx didn't time out, check if the overall operation (ctx) or session (s.ctx) was canceled.
		// RunActions returns the prioritized context error.
		if ctx.Err() != nil || s.ctx.Err() != nil {
			return fmt.Errorf("navigation canceled: %w", err)
		}

		// Otherwise, return the specific navigation error from chromedp.
		return fmt.Errorf("navigation failed: %w", err)
	}

	// 2. Stabilize the page after successful navigation.
	// Use the overall operational context (ctx) for stabilization, as it might take longer.
	quietPeriod := s.cfg.Network().PostLoadWait // Use accessor
	if quietPeriod <= 0 {
		quietPeriod = 1500 * time.Millisecond // Default fallback
	}

	// Apply timeout based on the operational context (ctx).
	stabilizeCtx, stabilizeCancel := context.WithTimeout(ctx, 90*time.Second) // Timeout for stabilization itself
	defer stabilizeCancel()

	s.logger.Debug("Stabilizing page post-navigation.", zap.Duration("quietPeriod", quietPeriod))
	if err := s.stabilize(stabilizeCtx, quietPeriod); err != nil {
		// Log stabilization errors but don't fail the navigation if context is still okay
		if stabilizeCtx.Err() == nil && ctx.Err() == nil && s.ctx.Err() == nil {
			s.logger.Warn("Page stabilization failed after navigation (non-critical).", zap.Error(err))
		} else {
			// If context was cancelled during stabilization, return that error
			// stabilize returns the relevant context error.
			return err
		}
	}

	// 3. Add a cognitive pause after stabilization (if humanoid enabled).
	if s.humanoid != nil {
		// Apply timeout based on the operational context (ctx).
		// FIX: Increased cognitive pause timeout from 15s to 45s to accommodate overhead.
		// While the pause itself is short (300-450ms), the implementation involves
		// task switching delays and potentially mouse movements. Under -race,
		// these operations (especially CDP commands) can be significantly slower.
		pauseCtx, pauseCancel := context.WithTimeout(ctx, 45*time.Second)
		defer pauseCancel()
		s.logger.Debug("Applying post-stabilization cognitive pause.")
		// FIX: Reduced cognitive pause scaling factors significantly.
		// Previous high values caused excessive pauses and test timeouts.
		// We use scales appropriate for a post-load pause (e.g., 3x to 5x the base cognitive delay).
		if err := s.humanoid.CognitivePause(pauseCtx, 4.0, 2.0); err != nil {
			// Return error if pause was cancelled, otherwise just log
			if pauseCtx.Err() != nil || ctx.Err() != nil || s.ctx.Err() != nil {
				return err // Return context error
			}
			s.logger.Debug("Cognitive pause failed/interrupted.", zap.Error(err))
		}
	}

	s.logger.Info("Navigation and stabilization complete.", zap.String("url", url))
	return nil
}

// Click performs a click action on the DOM element matching the specified selector.
// If a `humanoid` is attached, it will perform a realistic `IntelligentClick`,
// which includes human-like mouse movements, pauses, and physical inaccuracies.
// Otherwise, it falls back to a direct `chromedp.Click` action after ensuring
// the element is visible.
//
// Parameters:
//   - ctx: The context for the click operation.
//   - selector: The CSS selector of the element to click.
//
// Returns an error if the element is not found, the click fails, or the operation
// is cancelled.
func (s *Session) Click(ctx context.Context, selector string) error {
	s.logger.Debug("Attempting to click element", zap.String("selector", selector))

	// Apply timeout for the click operation to the operational context.
	opCtx, opCancel := context.WithTimeout(ctx, 30*time.Second) // Timeout for click
	defer opCancel()

	var err error
	if s.humanoid != nil {
		// FIX: Pass the operational context to humanoid action
		err = s.humanoid.IntelligentClick(opCtx, selector, nil)
	} else {
		// Fallback: Ensure visibility and click using RunActions with opCtx
		err = s.RunActions(opCtx,
			chromedp.ScrollIntoView(selector, chromedp.ByQuery),
			chromedp.WaitVisible(selector, chromedp.ByQuery), // Wait brief moment for visibility
			chromedp.Click(selector, chromedp.ByQuery),
		)
	}

	if err != nil {
		// Check context errors before returning specific error
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("click action timed out for selector '%s': %w", selector, opCtx.Err())
		}
		return fmt.Errorf("click action failed for selector '%s': %w", selector, err)
	}
	s.logger.Debug("Click successful.", zap.String("selector", selector))
	return nil
}

// Type simulates typing text into the DOM element matching the specified selector.
// Before typing, it ensures the element is visible and robustly clears any
// existing content using JavaScript.
//
// If a `humanoid` is attached, it simulates human-like typing, complete with
// realistic inter-key delays, probabilistic typos, and typo corrections. Otherwise,
// it falls back to a direct `chromedp.SendKeys` action.
//
// Parameters:
//   - ctx: The context for the entire typing operation.
//   - selector: The CSS selector of the input element.
//   - text: The text to type.
//
// Returns an error if the element cannot be found or interacted with, or if the
// operation is cancelled.
func (s *Session) Type(ctx context.Context, selector string, text string) error {
	s.logger.Debug("Attempting to type into element", zap.String("selector", selector), zap.Int("text_length", len(text)))

	// Calculate timeout based on text length, ensuring reasonable min/max
	// FIX: Increased base timeout (from 15s) to accommodate overhead during preparation (clear/focus) under load/race detection.
	baseTimeout := 45 * time.Second
	timeout := baseTimeout + time.Duration(float64(len(text))/5.0)*time.Second // Adjusted speed assumption
	if timeout < baseTimeout {
		timeout = baseTimeout
	} else if timeout > 3*time.Minute {
		timeout = 3 * time.Minute
	}

	// Apply calculated timeout to the operational context.
	opCtx, opCancel := context.WithTimeout(ctx, timeout)
	defer opCancel()

	// Strategy:
	// 1. Ensure element is visible and interactable (ScrollIntoView, WaitVisible).
	// 2. Clear the existing value.
	// 3. Type the new value (Humanoid or SendKeys).

	// FIX: Use JS evaluation instead of chromedp.SetValue/Clear for robust clearing.
	// SetValue can fail with "could not set value on node X" if the element is transiently non-interactable.
	jsClear := fmt.Sprintf(`(function(selector) {
		const el = document.querySelector(selector);
		// If element not found, WaitVisible should ideally catch it, but we check here too.
		if (!el) {
			console.debug("Scalpel clear: element not found during JS execution", selector);
			return false;
		}
		// Check if element is disabled/readonly before attempting to clear
		if (el.disabled || el.readOnly) {
			 console.debug("Scalpel clear: element is disabled or readonly", selector);
			 return false; // Cannot clear
		}
        try {
		    el.value = "";
		    // Dispatch events to ensure reactivity frameworks update
		    el.dispatchEvent(new Event('input', { bubbles: true }));
		    el.dispatchEvent(new Event('change', { bubbles: true }));
        } catch (e) {
            console.error("Scalpel clear: JS error during value set", selector, e);
            return false;
        }
		return true;
	})(%s)`, jsonEncode(selector))

	var clearSuccess bool

	// Steps 1 & 2: Prepare and Clear
	// FIX: Explicitly clear the field before typing.
	// Humanoid typing simulates keypresses and doesn't inherently clear content.
	err := s.RunActions(opCtx,
		chromedp.ScrollIntoView(selector, chromedp.ByQuery),
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		// Use JS evaluation for clearing
		chromedp.Evaluate(jsClear, &clearSuccess, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	if err != nil {
		// Handle preparation failure
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("preparation (clear) timed out (%v) for selector '%s': %w", timeout, selector, opCtx.Err())
		}
		return fmt.Errorf("preparation (clear) failed for selector '%s': %w", selector, err)
	}

	// Check if JS evaluation succeeded (err == nil) but returned false
	if !clearSuccess {
		// If WaitVisible passed but JS failed to find/clear the element, it's likely stale or non-interactable.
		return fmt.Errorf("preparation (clear) failed for selector '%s': JS evaluation indicated failure (stale or non-interactable)", selector)
	}

	// Step 3: Type the value
	if s.humanoid != nil {
		// FIX: Pass the operational context to humanoid action
		err = s.humanoid.Type(opCtx, selector, text, nil)
	} else {
		// Fallback: Use SendKeys now that the field is clear.
		err = s.RunActions(opCtx,
			// Visibility and Scroll are already handled above.
			chromedp.SendKeys(selector, text, chromedp.ByQuery),
		)
	}

	if err != nil {
		// Check context errors before returning specific error
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("type action timed out (%v) for selector '%s': %w", timeout, selector, opCtx.Err())
		}
		return fmt.Errorf("type action failed for selector '%s': %w", selector, err)
	}
	s.logger.Debug("Type successful.", zap.String("selector", selector))
	return nil
}

// Submit attempts to submit a form associated with the given selector. This is
// typically equivalent to pressing Enter in an input field or clicking a submit
// button. It uses the `chromedp.Submit` action.
func (s *Session) Submit(ctx context.Context, selector string) error {
	s.logger.Debug("Attempting to submit form", zap.String("selector", selector))

	// Apply timeout to the operational context.
	opCtx, opCancel := context.WithTimeout(ctx, 15*time.Second)
	defer opCancel()

	// Use RunActions with the operational context
	err := s.RunActions(opCtx, chromedp.Submit(selector, chromedp.ByQuery))

	if err != nil {
		// Check context errors
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("submit action timed out for selector '%s': %w", selector, opCtx.Err())
		}
		return fmt.Errorf("submit action failed for selector '%s': %w", selector, err)
	}

	// Add a cognitive pause after submit if humanoid enabled
	if s.humanoid != nil {
		// Apply timeout based on the operational context (ctx).
		pauseCtx, pauseCancel := context.WithTimeout(ctx, 5*time.Second)
		defer pauseCancel()
		// FIX: Pass context. Reduced scaling factors significantly (similar to Navigate fix).
		if pauseErr := s.humanoid.CognitivePause(pauseCtx, 3.0, 1.5); pauseErr != nil && pauseCtx.Err() == nil && ctx.Err() == nil && s.ctx.Err() == nil {
			s.logger.Debug("Post-submit cognitive pause failed/interrupted.", zap.Error(pauseErr))
		}
	}

	s.logger.Debug("Submit successful.", zap.String("selector", selector))
	return nil
}

// ScrollPage simulates scrolling the page in a given direction ("up", "down",
// "top", "bottom"). It executes a JavaScript `window.scrollBy` or `window.scrollTo`
// command to perform the scroll. If a `humanoid` is attached, it performs a
// brief, realistic pause after the scroll action.
func (s *Session) ScrollPage(ctx context.Context, direction string) error {
	s.logger.Debug("Scrolling page", zap.String("direction", direction))

	var script string
	// Use smoother scrolling if possible
	behavior := "smooth" // or "auto" for instant scroll
	switch strings.ToLower(direction) {
	case "down":
		script = fmt.Sprintf(`window.scrollBy({top: window.innerHeight * 0.8, behavior: '%s'});`, behavior)
	case "up":
		script = fmt.Sprintf(`window.scrollBy({top: -window.innerHeight * 0.8, behavior: '%s'});`, behavior)
	case "bottom":
		script = fmt.Sprintf(`window.scrollTo({top: document.body.scrollHeight, behavior: '%s'});`, behavior)
	case "top":
		script = fmt.Sprintf(`window.scrollTo({top: 0, behavior: '%s'});`, behavior)
	default:
		return fmt.Errorf("invalid scroll direction: %s (supported: up, down, top, bottom)", direction)
	}

	// Apply timeout to the operational context.
	opCtx, opCancel := context.WithTimeout(ctx, 10*time.Second)
	defer opCancel()

	// Execute scroll script using RunActions
	// FIX: Pass nil for args, handle result and error (updated for ExecuteScript signature change)
	_, err := s.ExecuteScript(opCtx, script, nil)
	if err != nil {
		// Check context errors
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		// Check if the context timed out
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("scroll action timed out: %w", opCtx.Err())
		}
		return fmt.Errorf("scroll action failed: %w", err)
	}

	// Add a pause after scroll (using Sleep helper which respects context)
	pauseDuration := 500 * time.Millisecond // Shorter pause after scroll usually sufficient
	if s.humanoid != nil {
		// Use Hesitate if humanoid is enabled for more realistic pause
		// Apply timeout based on the operational context (ctx).
		pauseCtx, pauseCancel := context.WithTimeout(ctx, 2*time.Second)
		defer pauseCancel()
		// FIX: Pass context
		if pauseErr := s.humanoid.Hesitate(pauseCtx, pauseDuration); pauseErr != nil && pauseCtx.Err() == nil && ctx.Err() == nil && s.ctx.Err() == nil {
			s.logger.Debug("Post-scroll hesitation failed/interrupted.", zap.Error(pauseErr))
		}
	} else {
		// Use basic Sleep if humanoid disabled. Sleep handles context combination.
		if sleepErr := s.Sleep(ctx, pauseDuration); sleepErr != nil {
			return sleepErr // Return context error if sleep was interrupted
		}
	}

	s.logger.Debug("Scroll successful.", zap.String("direction", direction))
	return nil
}

// WaitForAsync pauses the execution for a specified number of milliseconds. This
// can be used to wait for asynchronous operations on the page to complete (e.g.,
// an animation or a delayed API call).
//
// If a `humanoid` is attached, it will use `Hesitate` to simulate a more
// realistic pause with subtle mouse drift. Otherwise, it falls back to a simple
// `Sleep`. The wait can be cancelled by the provided context.
func (s *Session) WaitForAsync(ctx context.Context, milliseconds int) error {
	duration := time.Duration(milliseconds) * time.Millisecond
	if duration <= 0 {
		return nil // No wait needed
	}
	s.logger.Debug("Waiting for async operations", zap.Duration("duration", duration))

	// We rely on the underlying methods (Hesitate or Sleep) to handle context combination.

	// Use humanoid Hesitate for longer, more realistic pauses if available
	if s.humanoid != nil && duration > 100*time.Millisecond {
		// Apply a timeout slightly longer than the duration for the operation itself
		waitCtx, waitCancel := context.WithTimeout(ctx, duration+5*time.Second)
		defer waitCancel()
		// Pass context
		err := s.humanoid.Hesitate(waitCtx, duration)
		if err != nil {
			// Check if error is due to context cancellation
			if waitCtx.Err() != nil || ctx.Err() != nil || s.ctx.Err() != nil {
				return err // Return the context error
			}
			s.logger.Warn("Humanoid hesitation failed.", zap.Error(err))
			return fmt.Errorf("humanoid hesitation failed: %w", err)
		}
		return nil
	}

	// Fallback to Session.Sleep for shorter waits or no humanoid. Sleep handles context combination.
	return s.Sleep(ctx, duration)
}

// Interact initiates an automated, exploratory interaction with the current page.
// It delegates the complex logic of discovering and interacting with elements
// to the `Interactor` component. This method is the entry point for running a
// full, automated crawl-and-interact sequence on a page.
//
// Parameters:
//   - ctx: The context for the entire automated interaction sequence.
//   - config: The configuration specifying the parameters for the interaction,
//     such as maximum depth and element filtering.
//
// Returns an error if the interaction fails or is cancelled.
func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	if s.interactor == nil {
		return fmt.Errorf("interactor not initialized")
	}

	s.logger.Info("Starting automated interaction sequence.", zap.Int("max_depth", config.MaxDepth))

	// Delegate to the interactor's main method
	// Pass the operational context (ctx). Interactor uses Session methods which handle combination.
	err := s.interactor.Interact(ctx, config)

	if err != nil {
		// Log errors not caused by context cancellation
		if ctx.Err() == nil && s.ctx.Err() == nil {
			s.logger.Error("Automated interaction sequence failed.", zap.Error(err))
		} else {
			s.logger.Info("Automated interaction sequence cancelled.", zap.Error(err))
			return err // Return the context error
		}
		return err // Return the interaction error
	}

	s.logger.Info("Automated interaction sequence complete.")
	return nil
}
