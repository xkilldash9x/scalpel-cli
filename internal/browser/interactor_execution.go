// internal/browser/interactor_execution.go
package browser

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// valueOnlyContext is a nifty little struct that wraps a context but strips its
// cancellation and deadline properties. This is super useful for running cleanup
// tasks that absolutely must complete, even if the parent context that triggered
// them gets cancelled (like after a successful navigation). It still lets us
// pass values through, which is key.
type valueOnlyContext struct {
	context.Context
}

// Deadline always reports that no deadline is set.
func (valueOnlyContext) Deadline() (deadline time.Time, ok bool) { return }

// Done returns nil, indicating this context is never cancelled.
func (valueOnlyContext) Done() <-chan struct{} { return nil }

// Err always returns nil.
func (valueOnlyContext) Err() error { return nil }

// executeInteraction handles the core logic of performing an action on a web element.
// It uses a robust strategy of temporarily tagging an element with a unique ID to ensure
// we're interacting with the exact element we discovered, even if the DOM shifts.
func (i *Interactor) executeInteraction(ctx context.Context, element interactiveElement, log *zap.Logger) (bool, error) {
	// Generate a unique ID that we'll slap onto the element for a moment.
	tempID := fmt.Sprintf("scalpel-interaction-%d-%d", time.Now().UnixNano(), i.rng.Int63())
	attributeName := "data-scalpel-id"
	selector := fmt.Sprintf(`[%s="%s"]`, attributeName, tempID)

	// Here, we use the element's unique NodeID to set the temporary attribute.
	// This is much more reliable than trying to re-select it with a CSS selector.
	err := chromedp.Run(ctx,
		chromedp.SetAttributeValue(element.Node.NodeID, attributeName, tempID),
	)
	if err != nil {
		// If this fails, the element is probably stale or has been removed from the DOM.
		return false, fmt.Errorf("failed to tag element for interaction (might be stale): %w", err)
	}
	// No matter what happens next, we defer the cleanup to remove our temporary tag.
	defer i.cleanupInteractionAttribute(ctx, selector, attributeName, log)

	var interactionAction chromedp.Action
	nodeName := strings.ToUpper(element.Node.NodeName)

	if element.IsInput {
		// Different input types require different kinds of interactions.
		if nodeName == "SELECT" {
			interactionAction = i.handleSelectInteraction(selector, element.Node)
		} else {
			payload := i.generateInputPayload(element.Node)
			interactionAction = i.humanoid.Type(selector, payload)
		}
	} else {
		// For non input elements, we'll perform a click.
		interactionAction = i.humanoid.IntelligentClick(selector, nil)
	}

	if interactionAction == nil {
		return false, fmt.Errorf("no viable interaction action for element")
	}

	// Execute the chosen action.
	if err = chromedp.Run(ctx, interactionAction); err != nil {
		return false, fmt.Errorf("humanoid action failed: %w", err)
	}

	return true, nil
}

// cleanupInteractionAttribute removes the temporary `data-scalpel-id` attribute we added.
// This is critical for leaving the DOM in a clean state.
func (i *Interactor) cleanupInteractionAttribute(ctx context.Context, selector, attributeName string, log *zap.Logger) {
	// First, a sanity check to make sure we have a valid context to work with.
	if chromedp.FromContext(ctx) == nil {
		log.Debug("Could not get valid chromedp context for cleanup, skipping.")
		return
	}

	// This is the core of the refactoring. We create a detached context that won't be
	// cancelled if the original context is. This gives our cleanup task a chance to run.
	detachedCtx := valueOnlyContext{ctx}
	taskCtx, cancelTask := context.WithTimeout(detachedCtx, 2*time.Second)
	defer cancelTask()

	// A simple bit of JavaScript to find our element and remove the attribute.
	jsCleanup := fmt.Sprintf(`document.querySelector('%s')?.removeAttribute('%s')`, selector, attributeName)
	err := chromedp.Run(taskCtx, chromedp.Evaluate(jsCleanup, nil))

	// We only log an error if the task itself didn't time out.
	if err != nil && taskCtx.Err() == nil {
		log.Debug("Failed to execute cleanup JS, element might have already disappeared.", zap.String("selector", selector), zap.Error(err))
	}
}

// handleSelectInteraction intelligently interacts with a <select> dropdown element.
// It finds all valid, non disabled options and picks one at random.
func (i *Interactor) handleSelectInteraction(selector string, node *cdp.Node) chromedp.Action {
	var options []string
	for _, child := range node.Children {
		// We only care about <option> elements.
		if strings.ToUpper(child.NodeName) == "OPTION" {
			childAttrs := attributeMap(child)
			// The option needs a non empty value and must not be disabled.
			if value, ok := childAttrs["value"]; ok && value != "" {
				if _, disabled := childAttrs["disabled"]; !disabled {
					options = append(options, value)
				}
			}
		}
	}

	if len(options) == 0 {
		// No valid options to choose from.
		return nil
	}

	// Pick a random option from the list.
	selectedValue := options[i.rng.Intn(len(options))]

	// A sequence of actions: click to open, pause, then set the value.
	return chromedp.Tasks{
		i.humanoid.IntelligentClick(selector, nil),
		i.humanoid.CognitivePause(150, 50),
		chromedp.SetValue(selector, selectedValue, chromedp.ByQuery),
	}
}

// generateInputPayload creates context aware test data for various input fields.
// It inspects attributes like type, name, and id to make an educated guess.
func (i *Interactor) generateInputPayload(node *cdp.Node) string {
	attrs := attributeMap(node)
	inputType, _ := attrs["type"]
	inputName, _ := attrs["name"]
	inputId, _ := attrs["id"]
	// Create a single string with all the context clues.
	contextString := strings.ToLower(inputType + " " + inputName + " " + inputId)

	if inputType == "email" || strings.Contains(contextString, "email") {
		return "test.user@example.com"
	}
	if inputType == "password" || strings.Contains(contextString, "pass") {
		return "ScalpelTest123!"
	}
	if inputType == "tel" || strings.Contains(contextString, "phone") {
		return "555-0199"
	}
	if inputType == "search" || strings.Contains(contextString, "query") {
		return "test query"
	}
	if strings.Contains(contextString, "name") || strings.Contains(contextString, "user") {
		return "Test User"
	}

	// A generic fallback for inputs we can't identify.
	return "scalpel test input"
}

// attributeMap is a helper function that converts the flat string slice of attributes
// from a CDP node into a convenient map for easy lookups.
func attributeMap(node *cdp.Node) map[string]string {
	attrs := make(map[string]string)
	if node == nil {
		return attrs
	}
	// The attributes are stored in a flat slice: [key1, value1, key2, value2, ...]
	for i := 0; i < len(node.Attributes); i += 2 {
		attrs[node.Attributes[i]] = node.Attributes[i+1]
	}
	return attrs
}
