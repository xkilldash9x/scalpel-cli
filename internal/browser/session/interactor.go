// internal/browser/session/interactor.go
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	// Assuming humanoid package exists
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
)

// -- Structs and Constructors --

// StabilizationFunc is a function type that waits for the application state to stabilize.
type StabilizationFunc func(ctx context.Context) error

// ErrStaleElement indicates that the element reference (NodeID) is no longer valid,
// likely due to a page navigation or DOM modification.
var ErrStaleElement = errors.New("element is stale or detached from the document")

// Interactor is responsible for intelligently interacting with web pages.
type Interactor struct {
	logger      *zap.Logger
	humanoid    *humanoid.Humanoid // This can be nil if humanoid is disabled
	stabilizeFn StabilizationFunc
	rng         *rand.Rand
	// executor is used to run browser actions.
	//  Changed from *Session to ActionExecutor interface.
	executor ActionExecutor
	// sessionCtx is the master context for the session lifetime, needed for cleanup tasks.
	sessionCtx context.Context
}

// elementSnapshot holds the extracted data from the DOM element at the time of discovery.
//
//	This is used instead of *cdp.Node to prevent data races with the chromedp event loop.
type elementSnapshot struct {
	NodeName    string            `json:"nodeName"`
	Attributes  map[string]string `json:"attributes"`
	TextContent string            `json:"textContent"`
}

// interactiveElement bundles a node with its unique fingerprint.
type interactiveElement struct {
	//  Replaced *cdp.Node with an atomic snapshot and a unique selector.
	Snapshot    elementSnapshot `json:"-"` // Data used for filtering/fingerprinting
	Selector    string          `json:"-"` // Unique selector for interaction
	Fingerprint string
	Description string
	IsInput     bool
}

// NewInteractor creates a new interactor instance.
//
//	Updated signature to accept ActionExecutor and session context.
func NewInteractor(logger *zap.Logger, h *humanoid.Humanoid, stabilizeFn StabilizationFunc, executor ActionExecutor, sessionCtx context.Context) *Interactor {
	source := rand.NewSource(time.Now().UnixNano())
	// Fallback stabilization function if none provided.
	if stabilizeFn == nil {
		stabilizeFn = func(ctx context.Context) error {
			// Basic sleep if no real stabilization needed/provided
			select {
			case <-time.After(200 * time.Millisecond):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	//  Validate executor and sessionCtx.
	if executor == nil {
		panic("Interactor created with nil ActionExecutor reference")
	}
	if sessionCtx == nil {
		panic("Interactor created with nil session context reference")
	}
	return &Interactor{
		logger:      logger.Named("interactor"),
		humanoid:    h,
		stabilizeFn: stabilizeFn,
		rng:         rand.New(source),
		executor:    executor,
		sessionCtx:  sessionCtx,
	}
}

// -- Orchestration Logic --

// Interact is the main entry point for the interaction logic.
func (i *Interactor) Interact(ctx context.Context, config schemas.InteractionConfig) error {
	opCtx := ctx
	if _, ok := opCtx.Deadline(); !ok {
		i.logger.Warn("Interactor.Interact called without a timeout context.")
		// Optionally apply a default timeout
		// var cancel context.CancelFunc
		// opCtx, cancel = context.WithTimeout(ctx, 5*time.Minute)
		// defer cancel()
	}

	interactedElements := make(map[string]bool)
	i.logger.Info("Starting recursive interaction.", zap.Int("max_depth", config.MaxDepth))

	// Initial cognitive pause
	if i.humanoid != nil {
		pauseCtx, cancelPause := context.WithTimeout(opCtx, 10*time.Second) // Timeout for initial pause
		// : Pass context and handle error
		err := i.humanoid.CognitivePause(pauseCtx, 1.5, 1.5)
		cancelPause() // Release pause context resources promptly
		if err != nil {
			// Check if error is context cancellation before returning
			if opCtx.Err() != nil {
				return opCtx.Err() // Propagate cancellation
			}
			// Log other errors but potentially continue? Or return? Let's return.
			i.logger.Error("Initial cognitive pause failed.", zap.Error(err))
			return fmt.Errorf("initial cognitive pause failed: %w", err)
		}
	}

	// Start recursion from depth 0
	return i.interactDepth(opCtx, config, 0, interactedElements)
}

// R1: Helper function to shuffle elements in place (Used for prioritization)
func (i *Interactor) shuffleElements(elements []interactiveElement) {
	i.rng.Shuffle(len(elements), func(j, k int) {
		elements[j], elements[k] = elements[k], elements[j]
	})
}

// interactDepth handles the interaction logic for a specific depth.
func (i *Interactor) interactDepth(
	ctx context.Context, // This context propagates timeouts and cancellations
	config schemas.InteractionConfig,
	depth int,
	interactedElements map[string]bool,
) error {
	log := i.logger.With(zap.Int("depth", depth))

	// Base Cases
	if err := ctx.Err(); err != nil {
		log.Debug("Interaction depth cancelled.", zap.Error(err))
		return err
	}
	if depth >= config.MaxDepth {
		log.Info("Maximum interaction depth reached.", zap.Int("max_depth", config.MaxDepth))
		return nil
	}

	// 1. Discover new elements
	// : Increased timeout to 180s (was insufficient).
	discoverCtx, cancelDiscover := context.WithTimeout(ctx, 180*time.Second)
	newElements, err := i.discoverElements(discoverCtx, interactedElements)
	cancelDiscover()

	if err != nil {
		if discoverCtx.Err() != nil {
			log.Warn("Element discovery cancelled or timed out.", zap.Error(discoverCtx.Err()))
			return discoverCtx.Err()
		}
		log.Warn("Failed to query for interactive elements at this depth (non-fatal).", zap.Error(err))
		return nil // Continue gracefully
	}
	if len(newElements) == 0 {
		log.Info("No new interactive elements found at this depth.")
		return nil
	}
	log.Info("Discovered new interactive elements.", zap.Int("count", len(newElements)))

	// R1: 2. Prioritize and Shuffle elements
	// We must prioritize inputs and deprioritize submit buttons to prevent premature form submission.

	// Categorize elements
	var inputs, standard, submits []interactiveElement
	for _, el := range newElements {
		// Use the robust helper to check if it's a submit element.
		if isSubmitElement(&el.Snapshot) {
			submits = append(submits, el)
		} else if el.IsInput {
			// IsInput covers text inputs, selects, textareas (and correctly excludes submit/button type inputs).
			inputs = append(inputs, el)
		} else {
			// Standard covers links, non-submit buttons, clickable divs etc.
			standard = append(standard, el)
		}
	}

	// Shuffle each category independently
	i.shuffleElements(inputs)
	i.shuffleElements(standard)
	i.shuffleElements(submits)

	// Combine them in the desired order: Inputs first, then Standard, then Submits.
	prioritizedElements := append(inputs, standard...)
	prioritizedElements = append(prioritizedElements, submits...)

	log.Debug("Prioritized interaction order.", zap.Int("inputs", len(inputs)), zap.Int("standard", len(standard)), zap.Int("submits", len(submits)))

	// 3. Interact with elements
	interactionsThisDepth := 0
	maxInteractions := config.MaxInteractionsPerDepth
	if maxInteractions <= 0 {
		maxInteractions = 3 // Default
	}

	// R1: Iterate over the prioritized list instead of the original newElements
	for _, element := range prioritizedElements {
		if err := ctx.Err(); err != nil {
			log.Debug("Interaction loop cancelled before next element.", zap.Error(err))
			return err
		}
		if interactionsThisDepth >= maxInteractions {
			log.Debug("Interaction limit reached for this depth.", zap.Int("limit", maxInteractions))
			break
		}

		// Small pause before considering element
		if i.humanoid != nil {
			pauseCtx, cancelPause := context.WithTimeout(ctx, 5*time.Second)
			// : Pass context and handle error
			err := i.humanoid.CognitivePause(pauseCtx, 0.5, 0.5)
			cancelPause()
			if err != nil {
				if pauseCtx.Err() != nil || ctx.Err() != nil {
					return err // Propagate cancellation
				}
				log.Debug("Pre-interaction cognitive pause failed (non-critical).", zap.Error(err))
				// Continue to next element if pause fails non-critically? Or proceed with interaction? Let's proceed.
			}
		} else {
			select {
			case <-time.After(100 * time.Millisecond):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// Execute interaction with timeout
		// : Increased timeout to 180s.
		actionCtx, cancelAction := context.WithTimeout(ctx, 180*time.Second)
		log.Debug("Attempting interaction.", zap.String("desc", element.Description), zap.String("fingerprint", element.Fingerprint))
		success, interactionErr := i.executeInteraction(actionCtx, element, log)
		cancelAction()

		// P1/R: Handle stale elements, including navigation detection.
		if errors.Is(interactionErr, ErrStaleElement) {
			if success {
				// Interaction succeeded but caused navigation/staleness (e.g. clicking a link).
				log.Debug("Interaction successful but induced navigation/staleness. Stopping interactions for this depth.", zap.String("desc", element.Description))
				interactionsThisDepth++
				// CRITICAL: Mark as interacted even if it navigated, to prevent infinite loops if the link exists on the next page.
				interactedElements[element.Fingerprint] = true
			} else {
				// Element was stale before interaction completed (likely due to previous navigation).
				log.Warn("Element became stale during interaction attempt. Stopping interactions for this depth.", zap.String("desc", element.Description))
			}
			// In either stale case, the remaining elements in the list are likely stale. Break the loop.
			break
		}

		// Handle other (non-stale) errors
		if interactionErr != nil {
			if actionCtx.Err() == nil && ctx.Err() == nil {
				log.Warn("Interaction failed.", zap.String("desc", element.Description), zap.Error(interactionErr))
			} else {
				log.Debug("Interaction cancelled.", zap.String("desc", element.Description), zap.Error(interactionErr)) // Log the actual error (likely context error)
				return interactionErr                                                                                   // Propagate cancellation
			}
			interactedElements[element.Fingerprint] = true // Mark as attempted even if failed (non-stale error)
			continue                                       // Try next element
		}

		// Handle successful, non-navigational interaction
		if success {
			log.Debug("Interaction successful (non-navigational).", zap.String("desc", element.Description))
			interactionsThisDepth++
			interactedElements[element.Fingerprint] = true

			// Pause after successful interaction
			delay := time.Duration(config.InteractionDelayMs) * time.Millisecond
			if delay <= 0 {
				delay = 500 * time.Millisecond // Default
			}
			if i.humanoid != nil {
				pauseCtx, cancelPause := context.WithTimeout(ctx, delay+5*time.Second)
				// : Pass context and handle error
				err := i.humanoid.Hesitate(pauseCtx, delay)
				cancelPause()
				if err != nil {
					if pauseCtx.Err() != nil || ctx.Err() != nil {
						return err // Propagate cancellation
					}
					log.Debug("Post-interaction hesitation failed (non-critical).", zap.Error(err))
				}
			} else {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		} else {
			// Interaction yielded no action (e.g. empty select box)
			log.Debug("Interaction yielded no action.", zap.String("desc", element.Description))
			// Mark as interacted to avoid checking it again.
			interactedElements[element.Fingerprint] = true
		}
	} // End element loop

	// 4. Stabilize and Recurse if interactions occurred
	if interactionsThisDepth > 0 {
		log.Debug("Interactions performed, stabilizing and recursing.", zap.Int("interactions", interactionsThisDepth))
		if err := ctx.Err(); err != nil {
			return err
		}

		// : Increased timeout from 90s to 180s.
		stabilizeCtx, cancelStabilize := context.WithTimeout(ctx, 180*time.Second)
		err := i.stabilizeFn(stabilizeCtx)
		cancelStabilize()
		if err != nil {
			if stabilizeCtx.Err() == nil && ctx.Err() == nil {
				log.Warn("Stabilization failed after interaction (non-critical).", zap.Error(err))
			} else {
				return err // Return cancellation error
			}
		}

		// Post-stabilization wait
		waitDuration := time.Duration(config.PostInteractionWaitMs) * time.Millisecond
		if waitDuration <= 0 {
			waitDuration = 1000 * time.Millisecond // Default
		}
		if waitDuration > 0 {
			if i.humanoid != nil {
				waitCtx, cancelWait := context.WithTimeout(ctx, waitDuration+5*time.Second)
				// : Pass context and handle error
				err := i.humanoid.Hesitate(waitCtx, waitDuration)
				cancelWait()
				if err != nil {
					if waitCtx.Err() != nil || ctx.Err() != nil {
						return err // Propagate cancellation
					}
					log.Debug("Post-stabilization wait failed (non-critical).", zap.Error(err))
				}
			} else {
				select {
				case <-time.After(waitDuration):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}

		// Recurse
		return i.interactDepth(ctx, config, depth+1, interactedElements)
	}

	log.Info("Interaction depth complete, no further recursion needed from this state.")
	return nil
}

// -- Element Discovery Logic --

//	discoveryScript is the JavaScript code used to discover, snapshot, and tag elements atomically.
//
// This approach avoids data races by performing data extraction within the browser's main thread
// rather than relying on the volatile Go *cdp.Node cache.
const discoveryScript = `(function(selectors) {
    const results = [];
    const attributeName = 'data-scalpel-discovery-id';
    const maxTextLength = 64; // Must match the constant used in Go fingerprinting

    /* Helper functions */
    function getAttributes(el) {
        const attrs = {};
        // Include all attributes for comprehensive fingerprinting
        for (const attr of el.attributes) {
            attrs[attr.name] = attr.value;
        }
        return attrs;
    }

    function isVisible(el) {
         // Basic visibility check required for interaction.
         // This must be synchronized with the visibility check used in cdp_executor.GetElementGeometry.
         const rect = el.getBoundingClientRect();
         const style = window.getComputedStyle(el);
         // Check dimensions and CSS visibility properties
         const isVisible = rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
         return isVisible;
    }

    function getTextContent(el, attrs) {
        // Strategy similar to previous Go implementation (getNodeText): prioritize direct text content, then aria-label/title.
        // Use textContent for potentially better performance than iterating children in JS.
        let text = (el.textContent || '').trim();

        if (text === '') {
            // Fallback to aria-label or title if present and non-empty
            if (attrs['aria-label'] && attrs['aria-label'].trim() !== '') {
                text = attrs['aria-label'].trim();
            } else if (attrs['title'] && attrs['title'].trim() !== '') {
                text = attrs['title'].trim();
            }
        }

        // Truncate text (handling unicode correctly is default in JS strings)
        if (text.length > maxTextLength) {
            // Truncate to maxTextLength including the ellipsis (which is 1 char in JS)
            // Note: This truncation logic differs slightly from the Go implementation (byte-based vs char-based),
            // but it's sufficient for fingerprinting consistency within the JS context.
            text = text.substring(0, maxTextLength - 1) + '…';
        }
        return text;
    }

    /* Main logic */
    let elements;
    try {
        // Execute the query
        elements = document.querySelectorAll(selectors);
    } catch (e) {
        console.error("Scalpel discovery: Invalid selector syntax provided", selectors, e);
        return []; // Return empty if selector itself is invalid
    }


    elements.forEach((el, index) => {
        try {
            // 1. Check visibility (Optimization: skip invisible elements early)
            if (!isVisible(el)) return;

            // 2. Generate unique ID and tag the element
            // Use a robust randomization suffix to minimize collision risk in highly dynamic pages
            const randSuffix = Math.random().toString(36).substring(2, 10);
            // Shortened prefix 'sd-' for efficiency
            const tempId = 'sd-' + index + '-' + Date.now() + '-' + randSuffix;
            el.setAttribute(attributeName, tempId);
            // Create the unique selector (we trust tempId doesn't contain quotes here)
            const selector = '[' + attributeName + '="' + tempId + '"]';

            // 3. Extract data (Snapshot)
            const attrs = getAttributes(el);
            const text = getTextContent(el, attrs);
            const nodeName = el.tagName;

            const snapshot = {
                nodeName: nodeName,
                attributes: attrs,
                textContent: text
            };

            results.push({
                selector: selector,
                snapshot: snapshot
            });
        } catch (e) {
            // Log errors during processing but continue with other elements
            console.error("Scalpel discovery: Error processing element", el, e);
        }
    });

    return results;
})(%s)` // Selector is injected here via fmt.Sprintf and jsonEncode

// Define the structure to capture the result from the discovery JS script.
type discoveryResult struct {
	Selector string          `json:"selector"`
	Snapshot elementSnapshot `json:"snapshot"`
}

func (i *Interactor) discoverElements(ctx context.Context, interacted map[string]bool) ([]interactiveElement, error) {
	selectors := "a[href], button:not([disabled]), [onclick], [role=button], [role=link], input:not([disabled]):not([readonly]):not([type=hidden]), textarea:not([disabled]):not([readonly]), select:not([disabled]):not([readonly]), summary, details, [tabindex]"

	//  Replaced racy chromedp.Nodes + Go-side deep copy with atomic JS evaluation.

	var results []discoveryResult

	// Inject the selector safely into the discovery script.
	script := fmt.Sprintf(discoveryScript, jsonEncode(selectors))

	// Use executor.RunActions to execute the script and capture the results.
	err := i.executor.RunActions(ctx,
		chromedp.Evaluate(script, &results, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		//  Updated error message.
		return nil, fmt.Errorf("failed to execute discovery script: %w", err)
	}

	//  Process the stable results from JS.
	return i.filterAndFingerprint(results, interacted), nil
}

// Updated signature to accept discoveryResult.
func (i *Interactor) filterAndFingerprint(results []discoveryResult, interacted map[string]bool) []interactiveElement {
	newElements := make([]interactiveElement, 0, len(results))
	seenFingerprints := make(map[string]bool)

	//  Iterate over the stable results.
	for _, result := range results {
		// Use the snapshot data.
		snapshot := result.Snapshot
		attrs := snapshot.Attributes

		// Explicitly skip disabled/readonly based on function
		//  Updated isDisabled signature.
		if isDisabled(&snapshot, attrs) {
			continue
		}

		// Filter based on tabindex
		if tabIndexStr, ok := attrs["tabindex"]; ok {
			tabIndexVal, err := strconv.Atoi(tabIndexStr)
			if err == nil && tabIndexVal < 0 {
				continue // Skip negative tabindex
			}
		}

		//  Updated generateNodeFingerprint signature.
		fingerprint, description := generateNodeFingerprint(&snapshot, attrs)
		if fingerprint == "" {
			//  Updated logging field.
			i.logger.Debug("Skipping element with empty fingerprint.", zap.String("nodeName", snapshot.NodeName))
			continue
		}

		if !interacted[fingerprint] && !seenFingerprints[fingerprint] {
			newElements = append(newElements, interactiveElement{
				//  Store snapshot and selector.
				Snapshot:    snapshot,
				Selector:    result.Selector,
				Fingerprint: fingerprint,
				Description: description,
				//  Updated isInputElement signature.
				IsInput: isInputElement(&snapshot),
			})
			seenFingerprints[fingerprint] = true
		}
	}
	return newElements
}

// -- Action Execution Logic --

func (i *Interactor) executeInteraction(ctx context.Context, element interactiveElement, log *zap.Logger) (bool, error) {
	if i.humanoid == nil && !element.IsInput {
		log.Debug("Skipping non-input interaction: Humanoid disabled.", zap.String("desc", element.Description))
		return false, nil
	}

	//  Use the unique selector generated during discovery.
	selector := element.Selector
	// The attribute name must match the one used in the discoveryScript.
	attributeName := "data-scalpel-discovery-id"

	//  Use the stored session context (i.sessionCtx) for cleanup.
	// We must clean up the attribute set during discovery so the element can be rediscovered later if needed.
	defer i.cleanupInteractionAttribute(i.sessionCtx, selector, attributeName, log)

	//  The element is already tagged during discovery (dom.SetAttributeValue is no longer needed).
	// We proceed directly to interaction.
	log.Debug("Targeting element for interaction.", zap.String("selector", selector))

	var interactionErr error
	actionTaken := false

	if element.IsInput {
		//  Updated NodeName access and handleSelectInteraction call.
		if strings.ToUpper(element.Snapshot.NodeName) == "SELECT" {
			// P2 : Updated handleSelectInteraction call to handle the new error return value.
			selectedValue, foundOption, err := i.handleSelectInteraction(ctx, selector) // Pass context and selector
			if err != nil {
				// If option extraction failed (e.g., stale element or unexpected error), return the error.
				// This ensures ErrStaleElement is propagated correctly.
				interactionErr = err
			} else if foundOption {
				log.Debug("Performing select interaction.", zap.String("selector", selector), zap.String("value", selectedValue))

				// : Use JS evaluation instead of chromedp.SetValue for <select> elements.
				// chromedp.SetValue can be unreliable for <select>.

				// Construct JS snippet to set value and dispatch change event
				jsSetValue := fmt.Sprintf(`
						(function(selector, value) {
							const element = document.querySelector(selector);
							if (!element) return false;
							element.value = value;
							// Dispatch change event manually as programmatic change doesn't trigger it
							const event = new Event('change', { bubbles: true });
							element.dispatchEvent(event);
							return true;
						})(%s, %s);
				`, jsonEncode(selector), jsonEncode(selectedValue))

				var success bool
				interactionErr = i.executor.RunActions(ctx, chromedp.Evaluate(jsSetValue, &success, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
					return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
				}))

				if interactionErr == nil && !success {
					// If JS ran without CDP error but returned false (e.g. element disappeared)
					// P1 : Treat this specific JS failure as a stale element error.
					interactionErr = fmt.Errorf("JS evaluation failed to set value (element likely not found during execution): %w", ErrStaleElement)
				}

				actionTaken = true
			} else {
				log.Debug("Skipping select interaction: no valid options found.", zap.String("selector", selector))
			}
		} else {
			//  Updated generateInputPayload call.
			payload := i.generateInputPayload(&element.Snapshot)
			log.Debug("Performing type interaction.", zap.String("selector", selector), zap.Int("payload_len", len(payload)))
			//  Use internal helper method which handles humanoid/fallback logic.
			interactionErr = i.typeIntoElement(ctx, selector, payload)
			actionTaken = true
		}
	} else {
		log.Debug("Performing click interaction.", zap.String("selector", selector))
		//  Use internal helper method which handles humanoid/fallback logic.
		interactionErr = i.clickElement(ctx, selector)

		// R: clickElement might return ErrStaleElement proactively if it detected a navigation-inducing click.
		// We must consider the action taken if the click succeeded (err == nil) OR if it returned ErrStaleElement proactively.
		if interactionErr == nil || errors.Is(interactionErr, ErrStaleElement) {
			actionTaken = true
		}
	}

	if interactionErr != nil {
		if ctx.Err() != nil {
			// R: Return actionTaken status even on cancellation, though interactDepth primarily uses the error.
			return actionTaken, ctx.Err() // Propagate cancellation
		}

		// P1/R: The action helpers now wrap stale errors or return them proactively (for navigation).
		// We check if it is ErrStaleElement and return it immediately so interactDepth can handle it gracefully.
		if errors.Is(interactionErr, ErrStaleElement) {
			// Log at debug level as this is handled by the caller.
			log.Debug("Session action resulted in stale element or navigation.", zap.String("selector", selector), zap.Error(interactionErr))
			// R: Return the actual actionTaken status along with ErrStaleElement.
			return actionTaken, interactionErr
		}

		actionType := "click"
		if element.IsInput {
			actionType = "type/select"
		}
		log.Warn("Session action failed (non-stale error).", zap.String("action", actionType), zap.String("selector", selector), zap.Error(interactionErr))
		// Don't wrap the error here, return the original from session action
		return actionTaken, interactionErr
	}

	return actionTaken, nil
}

// cleanupInteractionAttribute removes the temporary attribute.
//
//	sessionCtx should be the session context, not the operational context.
func (i *Interactor) cleanupInteractionAttribute(sessionCtx context.Context, selector, attributeName string, log *zap.Logger) {
	//  Use Detach(sessionCtx) to create a context for cleanup.
	// This preserves CDP values (required by chromedp) but ensures cleanup runs even if the session is closing (Context Best Practices 3.3).
	detachedCtx := Detach(sessionCtx)

	// Apply a short timeout to the detached context for the cleanup operation.
	taskCtx, cancelTask := context.WithTimeout(detachedCtx, 3*time.Second)
	defer cancelTask()

	jsCleanup := fmt.Sprintf(`try { document.querySelector('%s')?.removeAttribute('%s'); } catch(e) {}`,
		strings.ReplaceAll(selector, `'`, `\'`), // Basic JS escaping
		attributeName)

	//  Use executor.RunActions(Evaluate(...)) as ActionExecutor doesn't expose ExecuteScript.
	var res json.RawMessage // Result not used but needed for Evaluate
	err := i.executor.RunActions(taskCtx,
		chromedp.Evaluate(jsCleanup, &res, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	//  Improved logging to distinguish between timeout, session closure, and actual error.
	if err != nil {
		if taskCtx.Err() != nil {
			log.Debug("Cleanup JS timed out.", zap.String("selector", selector), zap.Error(taskCtx.Err()))
		} else if sessionCtx.Err() != nil {
			// If the session itself closed during this detached cleanup (e.g. program shutdown)
			log.Debug("Cleanup JS failed because session context is done.", zap.String("selector", selector))
		} else {
			// Actual failure executing the script
			log.Debug("Failed cleanup JS for interaction attribute (non-critical).", zap.String("selector", selector), zap.Error(err))
		}
	} else {
		log.Debug("Cleaned up interaction attribute.", zap.String("selector", selector))
	}
}

// Define the marker string used in JS to indicate element not found.
const notFoundMarker = "__SCALPEL_ELEMENT_NOT_FOUND__"

// extractOptionsScript is the JavaScript code used to extract available options from a <select> element.
const extractOptionsScript = `(function(selector) {
        const selectElement = document.querySelector(selector);
        // Return specific string if element not found or not a select, to distinguish from JS error.
        if (!selectElement) return "` + notFoundMarker + `";

        // Check tagName in a case-insensitive manner for robustness.
        if (!/^select$/i.test(selectElement.tagName)) return [];

        const options = [];
        for (const option of selectElement.options) {
            if (option.disabled) continue;

            // Strategy (matching previous implementation):
            // 1. If 'value' attribute exists and is not empty, use it.
            // 2. If 'value' attribute is missing, fallback to text content.
            // (If 'value' is present but empty, it's often a placeholder, skip it).

            const hasValueAttr = option.hasAttribute('value');
            const value = option.value; // JS option.value reflects attribute or text content based on spec

            if (hasValueAttr && value !== "") {
                options.push(value);
            } else if (!hasValueAttr) {
                // Explicitly check text content if no value attribute, though option.value often covers this.
                const text = option.textContent.trim();
                if (text !== "") {
                    options.push(text);
                }
            }
        }
        return options;
    })(%s)`

// R: checkNavigationInducingScript is JavaScript used to check if an element, immediately after being clicked,
// is likely to cause navigation (e.g., <a> tag or form submission).
const checkNavigationInducingScript = `(function(selector) {
    try {
        const element = document.querySelector(selector);
        // If element is null/undefined immediately after click, it might already be detached.
        if (!element) return 'DETACHED';

        const tagName = element.tagName.toUpperCase();

        // 1. <a> tags (links)
        if (tagName === 'A' && element.hasAttribute('href')) {
            // We assume most <a> tags might navigate or trigger JS navigation.
            // Checking target=_blank is complex, safer to assume navigation.
            return 'NAVIGATION';
        }

        // 2. Submit buttons/inputs within a form
        if (tagName === 'BUTTON' || tagName === 'INPUT') {
            // element.type reflects the effective type (e.g., 'submit' for buttons by default in forms)
            const type = element.type.toUpperCase();

            if (type === 'SUBMIT' || type === 'IMAGE') {
                // Check if it's associated with a form using element.form property.
                if (element.form) {
                     return 'NAVIGATION';
                }
                // Submit buttons without forms don't typically cause navigation.
            }
        }

        // 3. Other elements (e.g. div with onclick) are harder to detect statically.
        // We rely on the stabilization function to handle JS-induced navigations for these.

        return 'STANDARD';
    } catch (e) {
        console.error("Scalpel navigation check error:", e);
        return 'ERROR';
    }
})(%s)`

// handleSelectInteraction finds a valid option value. Pass context for Run actions.
//
//	Updated signature to use selector instead of *cdp.Node.
//
// P2 : Updated return signature to include error, addressing the JSON unmarshal bug and improving stale handling.
func (i *Interactor) handleSelectInteraction(ctx context.Context, selector string) (selectedValue string, found bool, err error) {
	// P2 : Use json.RawMessage to capture the result flexibly.
	var rawResult json.RawMessage

	//  Use JS evaluation to extract options atomically, avoiding data races.
	script := fmt.Sprintf(extractOptionsScript, jsonEncode(selector))

	// Use executor.RunActions to execute the script.
	err = i.executor.RunActions(ctx,
		chromedp.Evaluate(script, &rawResult, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	if err != nil {
		// This handles CDP errors or context cancellation.
		i.logger.Warn("Failed to execute script for select options (CDP error).", zap.Error(err), zap.String("selector", selector))
		return "", false, err
	}

	// P2 : Check for the "not found" marker string. It will be JSON-encoded (e.g., "__MARKER__").
	// We use the constant defined in Go for comparison.
	if string(rawResult) == `"`+notFoundMarker+`"` {
		i.logger.Debug("Select element not found during option extraction (stale).", zap.String("selector", selector))
		// P1 : Return ErrStaleElement so the caller handles it gracefully.
		return "", false, ErrStaleElement
	}

	// P2 : Now attempt to unmarshal into the expected slice of strings.
	var options []string
	if err := json.Unmarshal(rawResult, &options); err != nil {
		// This addresses the specific bug: json: cannot unmarshal string into Go value of type []string
		// This occurs if the JS returns something unexpected that isn't the marker and isn't an array of strings.
		i.logger.Error("Failed to unmarshal select options result (unexpected format).", zap.Error(err), zap.String("selector", selector), zap.ByteString("raw_result", rawResult))
		return "", false, fmt.Errorf("failed to unmarshal select options: %w", err)
	}

	// Logic for selecting an option remains the same
	if len(options) == 0 {
		return "", false, nil
	}
	selectedValue = options[i.rng.Intn(len(options))]
	return selectedValue, true, nil
}

// generateInputPayload creates realistic dummy data.
//
//	Updated signature to use elementSnapshot.
func (i *Interactor) generateInputPayload(snapshot *elementSnapshot) string {
	//  Use the attributes from the snapshot.
	attrs := snapshot.Attributes
	inputType := strings.ToLower(attrs["type"])
	inputName := strings.ToLower(attrs["name"])
	inputId := strings.ToLower(attrs["id"])

	if inputType == "email" || strings.Contains(inputName, "email") || strings.Contains(inputId, "email") {
		return fmt.Sprintf("testuser%d@example.com", i.rng.Intn(10000))
	}
	if inputType == "password" || strings.Contains(inputName, "pass") || strings.Contains(inputId, "pass") {
		return fmt.Sprintf("ScalpelPass%d!", i.rng.Intn(1000))
	}
	if inputType == "tel" || strings.Contains(inputName, "phone") || strings.Contains(inputId, "phone") {
		return fmt.Sprintf("555-%03d-%04d", i.rng.Intn(1000), i.rng.Intn(10000))
	}
	if inputType == "number" {
		return fmt.Sprintf("%d", i.rng.Intn(1000))
	}
	if inputType == "search" || strings.Contains(inputName, "search") || strings.Contains(inputId, "search") || strings.Contains(inputName, "query") || strings.Contains(inputId, "query") {
		return fmt.Sprintf("scalpel test query %d", i.rng.Intn(100))
	}
	if strings.Contains(inputName, "name") || strings.Contains(inputId, "name") || strings.Contains(inputName, "user") || strings.Contains(inputId, "user") {
		return fmt.Sprintf("Test User %d", i.rng.Intn(100))
	}
	if strings.Contains(inputName, "url") || strings.Contains(inputId, "url") || inputType == "url" {
		return "https://example-test.com"
	}
	return fmt.Sprintf("scalpel test input %d", i.rng.Intn(1000))
}

// -- Action Helpers --

// clickElement handles clicking, using humanoid if available, otherwise falling back to CDP actions via the executor.
// It also includes logic to detect navigation-inducing clicks.
func (i *Interactor) clickElement(ctx context.Context, selector string) error {
	// Apply standard timeout for the click operation.
	// R: Increased timeout slightly (to 45s) to accommodate the post-click check.
	opCtx, opCancel := context.WithTimeout(ctx, 45*time.Second)
	defer opCancel()

	var err error

	// --- 1. Perform the click action ---
	if i.humanoid != nil {
		err = i.humanoid.IntelligentClick(opCtx, selector, nil)
	} else {
		// Fallback: Ensure visibility and click using executor.RunActions.
		err = i.executor.RunActions(opCtx,
			chromedp.ScrollIntoView(selector, chromedp.ByQuery),
			chromedp.WaitVisible(selector, chromedp.ByQuery),
			chromedp.Click(selector, chromedp.ByQuery),
		)
	}

	// Handle click errors (Timeout, Stale before click, Cancellation, Other)
	if err != nil {
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("interactor click timed out for selector '%s': %w", selector, opCtx.Err())
		}

		// P1 : Check if the error indicates the element is gone (stale).
		// This error string originates from cdp_executor.GetElementGeometry (if humanoid) or chromedp actions (if fallback).
		if strings.Contains(err.Error(), "not found or not visible") {
			return fmt.Errorf("interactor click failed for selector '%s': %w", selector, ErrStaleElement)
		}

		// If ctx is cancelled, RunActions/humanoid should return that error.
		return fmt.Errorf("interactor click failed for selector '%s': %w", selector, err)
	}

	// --- 2. Post-click navigation check ---
	// R: If the click was successful, immediately check if the element is navigation-inducing (<a>, submit button).

	// Use a very short timeout for this check, as it should be immediate.
	checkCtx, checkCancel := context.WithTimeout(opCtx, 2*time.Second)
	defer checkCancel()

	script := fmt.Sprintf(checkNavigationInducingScript, jsonEncode(selector))
	var checkResult string

	// Execute the check script.
	checkErr := i.executor.RunActions(checkCtx,
		chromedp.Evaluate(script, &checkResult, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	if checkErr != nil {
		// If the check fails (e.g., CDP error, timeout, or context cancelled/destroyed during check),
		// it strongly suggests the page context is invalid due to navigation starting.
		i.logger.Debug("Post-click navigation check failed. Assuming navigation started.", zap.Error(checkErr), zap.String("selector", selector))
		// We must return ErrStaleElement to force the interactor loop to break and stabilize.
		return ErrStaleElement
	}

	// Analyze the result from the JS check.
	switch checkResult {
	case "NAVIGATION":
		i.logger.Debug("Navigation-inducing element detected (link or submit button). Returning ErrStaleElement.", zap.String("selector", selector))
		// Immediately return ErrStaleElement. This forces the interactor loop to break and stabilize.
		return ErrStaleElement
	case "DETACHED":
		// If the element is already detached, the page state is unstable.
		i.logger.Debug("Element detached immediately after click. Returning ErrStaleElement.", zap.String("selector", selector))
		return ErrStaleElement
	case "STANDARD", "ERROR":
		// Standard interaction or error during check (but CDP succeeded).
		// We proceed normally and rely on stabilization later if needed.
		return nil
	default:
		i.logger.Warn("Unknown result from navigation check script.", zap.String("result", checkResult), zap.String("selector", selector))
		return nil
	}
}

// typeIntoElement handles typing, using humanoid if available, otherwise falling back to CDP actions via the executor.
// This logic is extracted from the original session.Type implementation.
func (i *Interactor) typeIntoElement(ctx context.Context, selector string, text string) error {
	// Calculate dynamic timeout based on text length.
	// : Increased base timeout (from 15s) to accommodate overhead during preparation (clear/focus) under load/race detection.
	baseTimeout := 45 * time.Second
	timeout := baseTimeout + time.Duration(float64(len(text))/5.0)*time.Second
	if timeout < baseTimeout {
		timeout = baseTimeout
	} else if timeout > 3*time.Minute {
		timeout = 3 * time.Minute
	}

	opCtx, opCancel := context.WithTimeout(ctx, timeout)
	defer opCancel()

	// Strategy: Clear field before typing, whether humanoid or fallback.
	// This ensures idempotency and mirrors the logic in session.Type.

	// : Use JS evaluation instead of chromedp.SetValue/Clear for robust clearing.
	// SetValue can fail with "could not set value on node X" if the element is transiently non-interactable.
	jsClear := fmt.Sprintf(`(function(selector) {
		const el = document.querySelector(selector);
		// If element not found, WaitVisible should ideally catch it, but we check here too.
		if (!el) {
			console.debug("Scalpel clear: element not found during JS execution", selector);
			return false;
		}
		// Check if element is disabled/readonly (discovery should filter, but we double-check).
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

	// 1. Prepare and Clear
	err := i.executor.RunActions(opCtx,
		chromedp.ScrollIntoView(selector, chromedp.ByQuery),
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		// Use JS evaluation for clearing
		chromedp.Evaluate(jsClear, &clearSuccess, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	if err != nil {
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("interactor preparation (clear) timed out (%v) for selector '%s': %w", timeout, selector, opCtx.Err())
		}
		// P1 : If Clear fails because the element is stale, we identify it here.
		if strings.Contains(err.Error(), "not found or not visible") {
			return fmt.Errorf("interactor preparation (clear) failed for selector '%s': %w", selector, ErrStaleElement)
		}
		return fmt.Errorf("interactor preparation (clear) failed for selector '%s': %w", selector, err)
	}

	// Check if JS evaluation succeeded (err == nil) but returned false
	if !clearSuccess {
		// If WaitVisible passed but JS failed to find/clear the element, it's likely stale or non-interactable.
		// P1 : We must classify this as ErrStaleElement so the interactor loop handles it gracefully.
		return fmt.Errorf("interactor preparation (clear) failed for selector '%s': JS evaluation indicated failure: %w", selector, ErrStaleElement)
	}

	// 2. Type the value
	if i.humanoid != nil {
		err = i.humanoid.Type(opCtx, selector, text, nil)
	} else {
		// Fallback: Use SendKeys now that the field is clear.
		err = i.executor.RunActions(opCtx,
			// Visibility and Scroll are already handled above.
			chromedp.SendKeys(selector, text, chromedp.ByQuery),
		)
	}

	if err != nil {
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("interactor type timed out (%v) for selector '%s': %w", timeout, selector, opCtx.Err())
		}
		// P1 : Check if the error indicates the element is gone (stale) during typing.
		if strings.Contains(err.Error(), "not found or not visible") {
			return fmt.Errorf("interactor type failed for selector '%s': %w", selector, ErrStaleElement)
		}
		return fmt.Errorf("interactor type failed for selector '%s': %w", selector, err)
	}
	return nil
}

// -- Fingerprinting & Helpers -- (No changes needed based on errors)

var hasherPool = sync.Pool{
	New: func() interface{} { return fnv.New64a() },
}

// Updated signature to use elementSnapshot.
func generateNodeFingerprint(snapshot *elementSnapshot, attrs map[string]string) (string, string) {
	if snapshot == nil {
		return "", ""
	}
	var sb strings.Builder
	nodeName := strings.ToLower(snapshot.NodeName)
	sb.WriteString(nodeName)

	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}
	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes)
		for _, c := range classes {
			if c != "" {
				sb.WriteString("." + c)
			}
		}
	}

	attributesToInclude := []string{"name", "href", "type", "role", "aria-label", "placeholder", "title", "action", "for", "value"}
	sort.Strings(attributesToInclude)
	hasOtherAttrs := false
	for _, attr := range attributesToInclude {
		if val, ok := attrs[attr]; ok && val != "" {
			escapedVal := strings.ReplaceAll(val, `"`, `\"`)
			sb.WriteString(fmt.Sprintf(`[%s="%s"]`, attr, escapedVal))
			hasOtherAttrs = true
		}
	}

	//  Use the text content from the snapshot (already truncated in JS).
	textContent := snapshot.TextContent
	hasText := textContent != ""
	if hasText {
		escapedText := strings.ReplaceAll(textContent, `"`, `\"`)
		sb.WriteString(fmt.Sprintf(`[text="%s"]`, escapedText))
	}

	description := sb.String()

	if nodeName == description && !hasOtherAttrs && !hasText {
		// Check normalized names
		if nodeName != "body" && nodeName != "html" {
			return "", description
		}
	}

	hasher := hasherPool.Get().(hash.Hash64)
	_, _ = hasher.Write([]byte(description))
	fingerprint := strconv.FormatUint(hasher.Sum64(), 16)
	hasher.Reset()
	hasherPool.Put(hasher)

	return fingerprint, description
}

// Updated signature to use elementSnapshot.
func isDisabled(snapshot *elementSnapshot, attrs map[string]string) bool {
	if snapshot == nil {
		return true
	}
	if _, disabled := attrs["disabled"]; disabled {
		return true
	}
	if ariaDisabled, ok := attrs["aria-disabled"]; ok && strings.ToLower(ariaDisabled) == "true" {
		return true
	}
	//  Updated isInputElement call.
	if isInputElement(snapshot) {
		if _, readonly := attrs["readonly"]; readonly {
			return true
		}
	}
	return false
}

// Updated signature to use elementSnapshot.
func isInputElement(snapshot *elementSnapshot) bool {
	if snapshot == nil {
		return false
	}
	name := strings.ToUpper(snapshot.NodeName)
	//  Use attributes from the snapshot.
	attrs := snapshot.Attributes

	if name == "INPUT" {
		inputType := strings.ToLower(attrs["type"])
		switch inputType {
		// R1: Ensure submit/button types are excluded, as they are handled by click logic/prioritization.
		case "hidden", "submit", "button", "reset", "image":
			return false
		default:
			return true
		}
	}
	if name == "TEXTAREA" || name == "SELECT" {
		return true
	}
	if contentEditable, ok := attrs["contenteditable"]; ok && strings.ToLower(contentEditable) == "true" {
		return true
	}
	return false
}

// R1: isSubmitElement checks if the snapshot represents a form submission element (robustly).
func isSubmitElement(snapshot *elementSnapshot) bool {
	if snapshot == nil {
		return false
	}
	name := strings.ToUpper(snapshot.NodeName)
	attrs := snapshot.Attributes

	// 1. INPUT elements (submit or image types)
	if name == "INPUT" {
		inputType := strings.ToLower(attrs["type"])
		if inputType == "submit" || inputType == "image" {
			return true
		}
		return false
	}

	// 2. BUTTON elements
	if name == "BUTTON" {
		// HTML Spec: A button's type defaults to "submit" if the attribute is missing or invalid.
		buttonType, exists := attrs["type"]
		normalizedType := strings.ToLower(buttonType)

		// Explicitly NOT submit
		if exists && (normalizedType == "button" || normalizedType == "reset" || normalizedType == "menu") {
			return false
		}

		// Explicitly submit OR default behavior (missing/invalid type).
		// We treat defaults as potentially submissive to prioritize filling inputs first.
		return true
	}
	return false
}
