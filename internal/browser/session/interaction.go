// internal/browser/interaction.go
package session

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// Navigate loads the specified URL and waits for the page to stabilize.
// FIX: Added context.Context parameter
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
		// FIX: Increased cognitive pause timeout from 15s to 45s to accommodate -race overhead.
		// While the pause itself is short (300-450ms), the implementation involves
		// task switching delays and potentially mouse movements. Under -race,
		// these operations (especially CDP commands) can be significantly slower.
		pauseCtx, pauseCancel := context.WithTimeout(ctx, 45*time.Second) // Was 15*time.Second
		defer pauseCancel()
		s.logger.Debug("Applying post-stabilization cognitive pause.")
		// Pass the timed pauseCtx to the humanoid action via RunActions
		// FIX: Correctly call CognitivePause (assuming it now takes context)
		if err := s.humanoid.CognitivePause(pauseCtx, 300, 150); err != nil {
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

// Click interacts with the element matching the selector.
// FIX: Added context.Context parameter
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

// Type inputs text into the element matching the selector.
// FIX: Added context.Context parameter
func (s *Session) Type(ctx context.Context, selector string, text string) error {
	s.logger.Debug("Attempting to type into element", zap.String("selector", selector), zap.Int("text_length", len(text)))

	// Calculate timeout based on text length, ensuring reasonable min/max
	timeout := 15*time.Second + time.Duration(float64(len(text))/5.0)*time.Second // Adjusted speed assumption
	if timeout < 15*time.Second {
		timeout = 15 * time.Second
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

	// Steps 1 & 2: Prepare and Clear
	// FIX: Explicitly clear the field before typing (TestSession/Interaction_BasicClickAndType failure).
	// Humanoid typing simulates keypresses and doesn't inherently clear content.
	err := s.RunActions(opCtx,
		chromedp.ScrollIntoView(selector, chromedp.ByQuery),
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		// Use Clear (or SetValue("")) to reset the field.
		chromedp.Clear(selector, chromedp.ByQuery),
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

// Submit attempts to submit the form associated with the selector.
// FIX: Added context.Context parameter
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
		// FIX: Pass context to CognitivePause
		if pauseErr := s.humanoid.CognitivePause(pauseCtx, 100, 50); pauseErr != nil && pauseCtx.Err() == nil && ctx.Err() == nil && s.ctx.Err() == nil {
			s.logger.Debug("Post-submit cognitive pause failed/interrupted.", zap.Error(pauseErr))
		}
	}

	s.logger.Debug("Submit successful.", zap.String("selector", selector))
	return nil
}

// ScrollPage simulates scrolling the page using JavaScript execution.
// FIX: Added context.Context parameter
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
	_, err := s.ExecuteScript(opCtx, script, nil) // Use ExecuteScript method
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
		// FIX: Pass context to Hesitate
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

// WaitForAsync pauses execution for a specified duration, respecting context cancellation.
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
		// Pass context to Hesitate
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

// Interact triggers the automated recursive interaction logic via the Interactor component.
// FIX: Added context.Context parameter
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
