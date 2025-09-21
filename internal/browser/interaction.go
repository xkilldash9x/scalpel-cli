// internal/browser/interaction.go
package browser

import (
	"context"
	"fmt"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// Navigate loads the specified URL and waits for the page to stabilize.
func (s *Session) Navigate(ctx context.Context, url string) error {
	s.logger.Debug("Navigating to URL", zap.String("url", url))

	// Combine session context and the operational context.
	opCtx, opCancel := CombineContext(s.ctx, ctx)
	defer opCancel()

	// Apply a specific timeout for the navigation action itself.
	navTimeout := s.cfg.Network.NavigationTimeout
	if navTimeout <= 0 {
		navTimeout = 90 * time.Second
	}
	navCtx, navCancel := context.WithTimeout(opCtx, navTimeout)
	defer navCancel()

	// 1. Execute the navigation.
	if err := chromedp.Run(navCtx, chromedp.Navigate(url)); err != nil {
		// Check if the specific navigation context timed out.
		if navCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("navigation timed out after %s: %w", navTimeout, err)
		}
		// Check if the overall operation or session was canceled.
		if opCtx.Err() != nil {
			return fmt.Errorf("navigation canceled: %w", opCtx.Err())
		}
		return fmt.Errorf("navigation failed: %w", err)
	}

	// 2. Stabilize the page after navigation.
	// CRITICAL: Use the overall operation context (opCtx) for stabilization, not navCtx.

	// Determine the quiet period for stabilization.
	quietPeriod := 1500 * time.Millisecond
	if s.cfg.Network.PostLoadWait > 0 {
		quietPeriod = s.cfg.Network.PostLoadWait
	}

	if err := s.stabilize(opCtx, quietPeriod); err != nil {
		if opCtx.Err() != nil {
			return opCtx.Err()
		}
		s.logger.Warn("Page stabilization failed after navigation (non-critical).", zap.Error(err))
	}

	// 3. Add a cognitive pause after stabilization.
	if s.humanoid != nil {
		if err := s.humanoid.CognitivePause(300, 150).Do(opCtx); err != nil {
			return err // Return if context was cancelled during pause.
		}
	}

	return nil
}

// Click interacts with the element matching the selector.
func (s *Session) Click(selector string) error {
	s.logger.Debug("Attempting to click element", zap.String("selector", selector))

	var action chromedp.Action

	if s.humanoid != nil {
		action = s.humanoid.IntelligentClick(selector, nil)
	} else {
		action = chromedp.Tasks{
			chromedp.ScrollIntoView(selector, chromedp.ByQuery),
			chromedp.WaitVisible(selector, chromedp.ByQuery),
			chromedp.Click(selector, chromedp.ByQuery),
		}
	}

	clickCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.runActions(clickCtx, action); err != nil {
		return fmt.Errorf("click action failed for selector '%s': %w", selector, err)
	}
	return nil
}

// Type inputs text into the element matching the selector.
func (s *Session) Type(selector string, text string) error {
	s.logger.Debug("Attempting to type into element", zap.String("selector", selector), zap.Int("text_length", len(text)))

	var action chromedp.Action

	if s.humanoid != nil {
		action = s.humanoid.Type(selector, text)
	} else {
		action = chromedp.Tasks{
			chromedp.ScrollIntoView(selector, chromedp.ByQuery),
			chromedp.WaitVisible(selector, chromedp.ByQuery),
			chromedp.SendKeys(selector, text, chromedp.ByQuery),
		}
	}

	timeout := 15*time.Second + time.Duration(float64(len(text))/2.5)*time.Second
	if timeout > 3*time.Minute {
		timeout = 3 * time.Minute
	}

	typeCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := s.runActions(typeCtx, action); err != nil {
		return fmt.Errorf("type action failed for selector '%s': %w", selector, err)
	}
	return nil
}

// Submit attempts to submit the form associated with the selector.
func (s *Session) Submit(selector string) error {
	s.logger.Debug("Attempting to submit form", zap.String("selector", selector))

	actions := []chromedp.Action{
		chromedp.Submit(selector, chromedp.ByQuery),
	}

	if s.humanoid != nil {
		actions = append(actions, s.humanoid.CognitivePause(100, 50))
	}

	submitCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := s.runActions(submitCtx, actions...); err != nil {
		return fmt.Errorf("submit action failed for selector '%s': %w", selector, err)
	}
	return nil
}

// ScrollPage simulates scrolling the page using JavaScript execution.
func (s *Session) ScrollPage(direction string) error {
	s.logger.Debug("Scrolling page", zap.String("direction", direction))

	var script string
	switch direction {
	case "down":
		script = `window.scrollBy({top: window.innerHeight * 0.8, behavior: 'smooth'});`
	case "up":
		script = `window.scrollBy({top: -window.innerHeight * 0.8, behavior: 'smooth'});`
	case "bottom":
		script = `window.scrollTo({top: document.body.scrollHeight, behavior: 'smooth'});`
	case "top":
		script = `window.scrollTo({top: 0, behavior: 'smooth'});`
	default:
		return fmt.Errorf("invalid scroll direction: %s (supported: up, down, top, bottom)", direction)
	}

	actions := []chromedp.Action{
		chromedp.Evaluate(script, nil),
	}

	if s.humanoid != nil {
		actions = append(actions, s.humanoid.CognitivePause(600, 250))
	} else {
		actions = append(actions, chromedp.Sleep(1*time.Second))
	}

	scrollCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := s.runActions(scrollCtx, actions...); err != nil {
		return fmt.Errorf("scroll action failed: %w", err)
	}
	return nil
}

// WaitForAsync pauses execution for a specified duration.
func (s *Session) WaitForAsync(milliseconds int) error {
	duration := time.Duration(milliseconds) * time.Millisecond
	s.logger.Debug("Waiting for async operations", zap.Duration("duration", duration))

	var action chromedp.Action
	if s.humanoid != nil && duration > 100*time.Millisecond {
		action = s.humanoid.Hesitate(duration)
	} else {
		action = chromedp.Sleep(duration)
	}

	return s.runActions(s.ctx, action)
}

// Interact triggers the automated recursive interaction logic.
func (s *Session) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	if s.interactor == nil {
		return fmt.Errorf("interactor not initialized")
	}

	s.logger.Info("Starting automated interaction sequence.")

	interactCtx, cancel := CombineContext(s.ctx, ctx)
	defer cancel()

	return s.interactor.RecursiveInteract(interactCtx, config)
}
