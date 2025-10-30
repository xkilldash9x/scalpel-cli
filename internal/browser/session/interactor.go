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
	"unicode/utf8"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom" // Needed for ExecutionContextID
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
	// REFACTOR: Changed from *Session to ActionExecutor interface.
	executor ActionExecutor
	// sessionCtx is the master context for the session lifetime, needed for cleanup tasks.
	sessionCtx context.Context
}

// interactiveElement bundles a node with its unique fingerprint.
type interactiveElement struct {
	Node        *cdp.Node
	Fingerprint string
	Description string
	IsInput     bool
}

// NewInteractor creates a new interactor instance.
// REFACTOR: Updated signature to accept ActionExecutor and session context.
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
	// REFACTOR: Validate executor and sessionCtx.
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
		// FIX: Pass context and handle error
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
	// FIX: Increased timeout to 180s (was insufficient).
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
	log.Debug("Discovered new interactive elements.", zap.Int("count", len(newElements)))

	// 2. Shuffle elements
	i.rng.Shuffle(len(newElements), func(j, k int) {
		newElements[j], newElements[k] = newElements[k], newElements[j]
	})

	// 3. Interact with elements
	interactionsThisDepth := 0
	maxInteractions := config.MaxInteractionsPerDepth
	if maxInteractions <= 0 {
		maxInteractions = 3 // Default
	}

	for _, element := range newElements {
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
			// FIX: Pass context and handle error
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
		// FIX: Increased timeout to 180s.
		actionCtx, cancelAction := context.WithTimeout(ctx, 180*time.Second)
		log.Debug("Attempting interaction.", zap.String("desc", element.Description), zap.String("fingerprint", element.Fingerprint))
		success, interactionErr := i.executeInteraction(actionCtx, element, log)
		cancelAction()

		// FIX: Handle stale elements.
		if errors.Is(interactionErr, ErrStaleElement) {
			log.Warn("Element became stale during interaction attempt (likely due to navigation by a previous element). Stopping interactions for this depth.", zap.String("desc", element.Description))
			// If the element we tried to interact with is stale, the rest of the list is also likely stale.
			// We must stop this loop and rely on the next recursion (if depth allows) to rediscover elements.
			// We treat this as a successful depth transition (interactionsThisDepth might be > 0 from previous elements).
			break
		}

		interactedElements[element.Fingerprint] = true // Mark interacted

		if interactionErr != nil {
			if actionCtx.Err() == nil && ctx.Err() == nil {
				log.Warn("Interaction failed.", zap.String("desc", element.Description), zap.Error(interactionErr))
			} else {
				log.Debug("Interaction cancelled.", zap.String("desc", element.Description), zap.Error(interactionErr)) // Log the actual error (likely context error)
				return interactionErr                                                                                   // Propagate cancellation
			}
			continue // Try next element
		}

		if success {
			log.Debug("Interaction successful.", zap.String("desc", element.Description))
			interactionsThisDepth++
			// Pause after successful interaction
			delay := time.Duration(config.InteractionDelayMs) * time.Millisecond
			if delay <= 0 {
				delay = 500 * time.Millisecond // Default
			}
			if i.humanoid != nil {
				pauseCtx, cancelPause := context.WithTimeout(ctx, delay+5*time.Second)
				// FIX: Pass context and handle error
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
			log.Debug("Interaction yielded no action.", zap.String("desc", element.Description))
		}
	} // End element loop

	// 4. Stabilize and Recurse if interactions occurred
	if interactionsThisDepth > 0 {
		log.Debug("Interactions performed, stabilizing and recursing.", zap.Int("interactions", interactionsThisDepth))
		if err := ctx.Err(); err != nil {
			return err
		}

		// FIX: Increased timeout from 90s to 180s.
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
				// FIX: Pass context and handle error
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

func (i *Interactor) discoverElements(ctx context.Context, interacted map[string]bool) ([]interactiveElement, error) {
	selectors := "a[href], button:not([disabled]), [onclick], [role=button], [role=link], input:not([disabled]):not([readonly]):not([type=hidden]), textarea:not([disabled]):not([readonly]), select:not([disabled]):not([readonly]), summary, details, [tabindex]"
	var nodes []*cdp.Node

	// Use executor.RunActions for context safety.
	err := i.executor.RunActions(ctx,
		chromedp.Nodes(selectors, &nodes, chromedp.ByQueryAll),
	)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed to query interactive nodes: %w", err)
	}

	return i.filterAndFingerprint(nodes, interacted), nil
}

func (i *Interactor) filterAndFingerprint(nodes []*cdp.Node, interacted map[string]bool) []interactiveElement {
	newElements := make([]interactiveElement, 0, len(nodes))
	seenFingerprints := make(map[string]bool)

	for _, node := range nodes {
		if node == nil {
			continue
		}
		attrs := attributeMap(node)

		// Explicitly skip disabled/readonly based on function
		if isDisabled(node, attrs) {
			continue
		}

		// Filter based on tabindex
		if tabIndexStr, ok := attrs["tabindex"]; ok {
			tabIndexVal, err := strconv.Atoi(tabIndexStr)
			if err == nil && tabIndexVal < 0 {
				continue // Skip negative tabindex
			}
		}

		fingerprint, description := generateNodeFingerprint(node, attrs)
		if fingerprint == "" {
			i.logger.Debug("Skipping element with empty fingerprint.", zap.String("nodeName", node.NodeName))
			continue
		}

		if !interacted[fingerprint] && !seenFingerprints[fingerprint] {
			newElements = append(newElements, interactiveElement{
				Node:        node,
				Fingerprint: fingerprint,
				Description: description,
				IsInput:     isInputElement(node),
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

	tempID := fmt.Sprintf("scalpel-interaction-%d-%d", time.Now().UnixNano(), i.rng.Int63())
	attributeName := "data-scalpel-id"
	selector := fmt.Sprintf(`[%s="%s"]`, attributeName, tempID)

	// REFACTOR: Use the stored session context (i.sessionCtx) for cleanup.
	defer i.cleanupInteractionAttribute(i.sessionCtx, selector, attributeName, log)

	// Use executor.RunActions for context safety
	err := i.executor.RunActions(ctx,
		dom.SetAttributeValue(element.Node.NodeID, attributeName, tempID),
	)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		// FIX: Check if the error indicates the NodeID is invalid (stale element).
		// CDP error -32000 or "Could not find node" indicates stale element.
		if strings.Contains(err.Error(), "Could not find node") || strings.Contains(err.Error(), "-32000") {
			return false, fmt.Errorf("failed to tag element '%s': %w", element.Description, ErrStaleElement)
		}
		return false, fmt.Errorf("failed to tag element '%s' for interaction: %w", element.Description, err)
	}
	log.Debug("Tagged element for interaction.", zap.String("selector", selector))

	var interactionErr error
	actionTaken := false

	if element.IsInput {
		if strings.ToUpper(element.Node.NodeName) == "SELECT" {
			selectedValue, foundOption := i.handleSelectInteraction(ctx, element.Node) // Pass context
			if foundOption {
				log.Debug("Performing select interaction.", zap.String("selector", selector), zap.String("value", selectedValue))

				// FIX: Use JS evaluation instead of chromedp.SetValue for <select> elements.
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
					interactionErr = fmt.Errorf("JS evaluation failed to set value (element likely not found during execution)")
				}

				actionTaken = true
			} else {
				log.Debug("Skipping select interaction: no valid options found.", zap.String("selector", selector))
			}
		} else {
			payload := i.generateInputPayload(element.Node)
			log.Debug("Performing type interaction.", zap.String("selector", selector), zap.Int("payload_len", len(payload)))
			// REFACTOR: Use internal helper method which handles humanoid/fallback logic.
			interactionErr = i.typeIntoElement(ctx, selector, payload)
			actionTaken = true
		}
	} else {
		log.Debug("Performing click interaction.", zap.String("selector", selector))
		// REFACTOR: Use internal helper method which handles humanoid/fallback logic.
		interactionErr = i.clickElement(ctx, selector)
		actionTaken = true
	}

	if interactionErr != nil {
		if ctx.Err() != nil {
			return false, ctx.Err() // Propagate cancellation
		}
		actionType := "click"
		if element.IsInput {
			actionType = "type/select"
		}
		log.Warn("Session action failed.", zap.String("action", actionType), zap.String("selector", selector), zap.Error(interactionErr))
		// Don't wrap the error here, return the original from session action
		return false, interactionErr
	}

	return actionTaken, nil
}

// cleanupInteractionAttribute removes the temporary attribute.
// REFACTOR: sessionCtx should be the session context, not the operational context.
func (i *Interactor) cleanupInteractionAttribute(sessionCtx context.Context, selector, attributeName string, log *zap.Logger) {
	// REFACTOR: Use Detach(sessionCtx) to create a context for cleanup.
	// This preserves CDP values (required by chromedp) but ensures cleanup runs even if the session is closing (Context Best Practices 3.3).
	detachedCtx := Detach(sessionCtx)

	// Apply a short timeout to the detached context for the cleanup operation.
	taskCtx, cancelTask := context.WithTimeout(detachedCtx, 3*time.Second)
	defer cancelTask()

	jsCleanup := fmt.Sprintf(`try { document.querySelector('%s')?.removeAttribute('%s'); } catch(e) {}`,
		strings.ReplaceAll(selector, `'`, `\'`), // Basic JS escaping
		attributeName)

	// REFACTOR: Use executor.RunActions(Evaluate(...)) as ActionExecutor doesn't expose ExecuteScript.
	var res json.RawMessage // Result not used but needed for Evaluate
	err := i.executor.RunActions(taskCtx,
		chromedp.Evaluate(jsCleanup, &res, func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
			return p.WithReturnByValue(true).WithAwaitPromise(true).WithSilent(true)
		}),
	)

	// REFACTOR: Improved logging to distinguish between timeout, session closure, and actual error.
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

// handleSelectInteraction finds a valid option value. Pass context for Run actions.
func (i *Interactor) handleSelectInteraction(ctx context.Context, node *cdp.Node) (selectedValue string, found bool) {
	var options []string
	// Query options relative to the node using NodeID for robustness
	var optionNodes []*cdp.Node
	// REFACTOR: Use executor.RunActions.
	err := i.executor.RunActions(ctx,
		chromedp.Nodes("option", &optionNodes, chromedp.ByQueryAll, chromedp.FromNode(node)),
	)
	if err != nil {
		i.logger.Warn("Failed to query options for select element", zap.Error(err))
		return "", false
	}

	for _, optionNode := range optionNodes {
		attrs := attributeMap(optionNode)
		if _, disabled := attrs["disabled"]; disabled {
			continue
		}
		value, hasValueAttr := attrs["value"]

		// FIX: Optimization and improved logic for selecting option values.
		// (TestInteractor/FormInteraction_VariousTypes failure due to slow performance/timeout)

		// Strategy:
		// 1. If 'value' attribute exists and is not empty, use it.
		if hasValueAttr && value != "" {
			options = append(options, value)
			continue
		}

		// 2. If 'value' attribute is missing, fallback to text content.
		// (If 'value' attribute is present but empty, we generally skip it as it's often a placeholder).
		if !hasValueAttr {
			// Fetch text content (still inefficient in a loop, but necessary if no value attr)
			var text string
			// REFACTOR: Use executor.RunActions for nested query.
			if err := i.executor.RunActions(ctx, chromedp.TextContent([]cdp.NodeID{optionNode.NodeID}, &text)); err == nil {
				trimmedText := strings.TrimSpace(text)
				if trimmedText != "" {
					options = append(options, trimmedText)
				}
			}
		}
		// If 'value' is "" (placeholder), we skip it in this implementation to ensure interaction progresses.
	}

	if len(options) == 0 {
		return "", false
	}
	selectedValue = options[i.rng.Intn(len(options))]
	return selectedValue, true
}

// generateInputPayload creates realistic dummy data.
func (i *Interactor) generateInputPayload(node *cdp.Node) string {
	attrs := attributeMap(node)
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
// This logic is extracted from the original session.Click implementation.
func (i *Interactor) clickElement(ctx context.Context, selector string) error {
	// Apply standard timeout for the click operation.
	opCtx, opCancel := context.WithTimeout(ctx, 30*time.Second)
	defer opCancel()

	var err error
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

	if err != nil {
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("interactor click timed out for selector '%s': %w", selector, opCtx.Err())
		}
		// If ctx is cancelled, RunActions/humanoid should return that error.
		return fmt.Errorf("interactor click failed for selector '%s': %w", selector, err)
	}
	return nil
}

// typeIntoElement handles typing, using humanoid if available, otherwise falling back to CDP actions via the executor.
// This logic is extracted from the original session.Type implementation.
func (i *Interactor) typeIntoElement(ctx context.Context, selector string, text string) error {
	// Calculate dynamic timeout based on text length.
	timeout := 15*time.Second + time.Duration(float64(len(text))/5.0)*time.Second
	if timeout < 15*time.Second {
		timeout = 15 * time.Second
	} else if timeout > 3*time.Minute {
		timeout = 3 * time.Minute
	}

	opCtx, opCancel := context.WithTimeout(ctx, timeout)
	defer opCancel()

	var err error
	if i.humanoid != nil {
		err = i.humanoid.Type(opCtx, selector, text, nil)
	} else {
		// Fallback: Ensure visibility and use SendKeys via executor.RunActions.
		err = i.executor.RunActions(opCtx,
			chromedp.ScrollIntoView(selector, chromedp.ByQuery),
			chromedp.WaitVisible(selector, chromedp.ByQuery),
			chromedp.SendKeys(selector, text, chromedp.ByQuery),
		)
	}

	if err != nil {
		if opCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("interactor type timed out (%v) for selector '%s': %w", timeout, selector, opCtx.Err())
		}
		return fmt.Errorf("interactor type failed for selector '%s': %w", selector, err)
	}
	return nil
}

// -- Fingerprinting & Helpers -- (No changes needed based on errors)

var hasherPool = sync.Pool{
	New: func() interface{} { return fnv.New64a() },
}

const maxTextLength = 64

func generateNodeFingerprint(node *cdp.Node, attrs map[string]string) (string, string) {
	if node == nil {
		return "", ""
	}
	var sb strings.Builder
	sb.WriteString(strings.ToLower(node.NodeName))

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

	textContent := getNodeText(node)
	hasText := textContent != ""
	if hasText {
		escapedText := strings.ReplaceAll(textContent, `"`, `\"`)
		sb.WriteString(fmt.Sprintf(`[text="%s"]`, escapedText))
	}

	description := sb.String()

	if strings.ToLower(node.NodeName) == description && !hasOtherAttrs && !hasText {
		if node.NodeName != "BODY" && node.NodeName != "HTML" {
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

func getNodeText(node *cdp.Node) string {
	if node == nil {
		return ""
	}
	var sb strings.Builder
	for _, child := range node.Children {
		if child != nil && child.NodeType == cdp.NodeTypeText {
			sb.WriteString(child.NodeValue)
		}
		if sb.Len() >= maxTextLength {
			break
		}
	}
	if sb.Len() == 0 {
		attrs := attributeMap(node)
		if label, ok := attrs["aria-label"]; ok && label != "" {
			sb.WriteString(label)
		} else if title, ok := attrs["title"]; ok && title != "" {
			sb.WriteString(title)
		}
	}

	// FIX: Truncate text correctly respecting maxTextLength (in bytes) and UTF-8 boundaries.
	text := strings.TrimSpace(sb.String())

	const ellipsis = "…"
	const ellipsisLen = len(ellipsis) // 3 bytes

	if len(text) > maxTextLength {
		if maxTextLength < ellipsisLen {
			// If less than 3 bytes available, just truncate without ellipsis
			return truncateBytes(text, maxTextLength)
		}
		// Truncate text to fit content + ellipsis
		return truncateBytes(text, maxTextLength-ellipsisLen) + ellipsis
	}
	return text
}

func isDisabled(node *cdp.Node, attrs map[string]string) bool {
	if node == nil {
		return true
	}
	if _, disabled := attrs["disabled"]; disabled {
		return true
	}
	if ariaDisabled, ok := attrs["aria-disabled"]; ok && strings.ToLower(ariaDisabled) == "true" {
		return true
	}
	if isInputElement(node) {
		if _, readonly := attrs["readonly"]; readonly {
			return true
		}
	}
	return false
}

func isInputElement(node *cdp.Node) bool {
	if node == nil {
		return false
	}
	name := strings.ToUpper(node.NodeName)
	attrs := attributeMap(node)

	if name == "INPUT" {
		inputType := strings.ToLower(attrs["type"])
		switch inputType {
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

func attributeMap(node *cdp.Node) map[string]string {
	attrs := make(map[string]string)
	if node == nil || len(node.Attributes) == 0 { // REVISION: Corrected F0 to 0
		return attrs
	}
	for i := 0; i < len(node.Attributes); i += 2 {
		if i+1 < len(node.Attributes) {
			attrs[node.Attributes[i]] = node.Attributes[i+1]
		}
	}
	return attrs
}

// Helper function to truncate string to max bytes, respecting UTF8 boundaries.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Iterate backwards from the desired byte length until a valid UTF-8 boundary (RuneStart) is found.
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
