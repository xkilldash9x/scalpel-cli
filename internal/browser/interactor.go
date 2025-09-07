// internal/browser/interactor.go
package browser

import (
	"context"
	"fmt"
	"hash"
	"hash/fnv"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	// Project specific imports (Standardized paths assumed).
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// Interactor provides advanced, recursive interaction logic (crawling) using the humanoid engine.
// It operates within an existing browser session context.
type Interactor struct {
	logger   *zap.Logger
	humanoid *humanoid.Humanoid
	rng      *rand.Rand // Dedicated RNG for interaction randomization.
}

// interactiveElement is a helper struct to store a node and its pre-calculated fingerprint.
type interactiveElement struct {
	Node        *cdp.Node
	Fingerprint string
	Description string
	IsInput     bool // Flag to distinguish inputs from clickable elements
}

// Pool for reusing FNV hasher instances to reduce allocations during fingerprinting.
var hasherPool = sync.Pool{
	New: func() interface{} {
		// FNV-1a is fast and sufficient for non-cryptographic hashing.
		return fnv.New64a()
	},
}

// NewInteractor creates a new Interactor helper.
func NewInteractor(logger *zap.Logger, h *humanoid.Humanoid) *Interactor {
	// Initialize a dedicated RNG source.
	source := rand.NewSource(time.Now().UnixNano())
	return &Interactor{
		logger:   logger.With(zap.String("component", "Interactor")),
		humanoid: h,
		rng:      rand.New(source),
	}
}

// RecursiveInteract implements a depth-first search (DFS) interaction strategy.
func (i *Interactor) RecursiveInteract(
	ctx context.Context,
	config schemas.InteractionConfig,
) error {
	// Track interacted elements across all depths using fingerprints.
	interactedElements := make(map[string]bool)
	i.logger.Info("Starting recursive interaction.", zap.Int("max_depth", config.MaxDepth))

	// Initial cognitive pause before starting the exploration (simulating initial page assessment).
	if err := i.humanoid.CognitivePause(800, 300).Do(ctx); err != nil {
		return err
	}

	return i.interactDepth(ctx, config, 0, interactedElements)
}

// interactDepth handles the interaction logic for a specific depth in the DFS.
func (i *Interactor) interactDepth(
	ctx context.Context,
	config schemas.InteractionConfig,
	depth int,
	interactedElements map[string]bool,
) error {
	// Check termination conditions.
	if depth >= config.MaxDepth {
		i.logger.Debug("Reached max interaction depth.", zap.Int("depth", depth))
		return nil
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	log := i.logger.With(zap.Int("depth", depth))

	// 1. Identify interactive elements.
	// Comprehensive selectors covering common patterns.
	clickableSelectors := "a[href], button, [onclick], [role=button], [role=link], input[type=submit], input[type=button], input[type=reset], summary, details"
	// Selectors for inputs, excluding hidden and control buttons, but including select dropdowns.
	inputSelectors := "input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]):not([type=checkbox]):not([type=radio]), textarea, select"

	var clickableNodes, inputNodes []*cdp.Node

	// Use chromedp.Tasks for sequential querying.
	tasks := chromedp.Tasks{
		// We query for visible nodes only, as Humanoid requires visibility for interaction.
		chromedp.Nodes(clickableSelectors, &clickableNodes, chromedp.ByQueryAll, chromedp.NodeVisible),
		chromedp.Nodes(inputSelectors, &inputNodes, chromedp.ByQueryAll, chromedp.NodeVisible),
	}

	err := chromedp.Run(ctx, tasks)

	if err != nil {
		// Robust error handling: check context cancellation first.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Warn("Failed to query interactive elements. Page state might be unstable.", zap.Error(err))
		return nil // Stop at this depth if querying fails.
	}

	// 2. Filter and fingerprint.
	// Process inputs first, as filling forms often enables further interaction.
	newElements := i.filterAndFingerprint(inputNodes, interactedElements, true)
	newElements = append(newElements, i.filterAndFingerprint(clickableNodes, interactedElements, false)...)

	if len(newElements) == 0 {
		log.Debug("No new interactive elements found at this depth.")
		return nil
	}

	// 3. Randomize the order slightly, while maintaining a bias towards inputs first.
	i.rng.Shuffle(len(newElements), func(j, k int) {
		// Heuristic: 70% chance to avoid swapping if 'j' is input and 'k' is not.
		if newElements[j].IsInput && !newElements[k].IsInput && i.rng.Float64() < 0.7 {
			return // Don't swap
		}
		newElements[j], newElements[k] = newElements[k], newElements[j]
	})

	// 4. Interact with the elements.
	interactions := 0
	for _, element := range newElements {
		if interactions >= config.MaxInteractionsPerDepth {
			log.Debug("Reached max interactions for this depth.")
			break
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Cognitive pause before interacting with the specific element (Visual search/planning).
		if err := i.humanoid.CognitivePause(150, 70).Do(ctx); err != nil {
			return err
		}

		// Perform the interaction.
		success, err := i.executeInteraction(ctx, element, log)

		// Mark as interacted immediately, even if the interaction failed (to avoid retrying failing elements).
		interactedElements[element.Fingerprint] = true

		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Debug("Interaction failed.", zap.String("desc", element.Description), zap.Error(err))
			continue // Try the next element.
		}

		if success {
			interactions++
			// Wait between successful interactions (Human delay).
			delay := time.Duration(config.InteractionDelayMs) * time.Millisecond
			if delay > 0 {
				// Use Hesitate for realistic idling during the delay, matching Humanoid style.
				if err := i.humanoid.Hesitate(delay).Do(ctx); err != nil {
					return err
				}
			}
		}
	}

	// 5. Recurse if interactions occurred.
	if interactions > 0 {
		log.Debug("Interactions occurred. Waiting for state stabilization before recursing.", zap.Int("interactions", interactions))

		// Wait for the page state to settle after the batch of interactions.
		waitDuration := time.Duration(config.PostInteractionWaitMs) * time.Millisecond
		if waitDuration > 0 {
			// Use Hesitate to simulate idling while waiting for asynchronous events.
			if err := i.humanoid.Hesitate(waitDuration).Do(ctx); err != nil {
				return err
			}
		}
		return i.interactDepth(ctx, config, depth+1, interactedElements)
	}

	log.Debug("No successful interactions occurred at this depth.")
	return nil
}

// filterAndFingerprint processes the nodes, calculates fingerprints, and filters out already interacted ones.
func (i *Interactor) filterAndFingerprint(nodes []*cdp.Node, interactedElements map[string]bool, isInput bool) []interactiveElement {
	// Initialize with capacity for efficiency.
	newElements := make([]interactiveElement, 0, len(nodes))

	for _, node := range nodes {
		// Basic validation: Ensure it's an element.
		if node.NodeType != cdp.NodeTypeElement {
			continue
		}
		// Robust check for disabled or readonly state.
		if isDisabled(node) {
			continue
		}

		fingerprint, description := generateNodeFingerprint(node)
		if fingerprint == "" {
			continue
		}

		if !interactedElements[fingerprint] {
			newElements = append(newElements, interactiveElement{
				Node:        node,
				Fingerprint: fingerprint,
				Description: description,
				IsInput:     isInput,
			})
		}
	}
	return newElements
}

// isDisabled checks if a node has the 'disabled' attribute, or 'readonly' for inputs.
func isDisabled(node *cdp.Node) bool {
	if node.Attribute("disabled") != "" {
		return true
	}
	// Specific checks for inputs/textareas that might be readonly.
	nodeName := strings.ToUpper(node.NodeName)
	if nodeName == "INPUT" || nodeName == "TEXTAREA" {
		if node.Attribute("readonly") != "" {
			return true
		}
	}
	return false
}

// executeInteraction handles the logic of identifying the element on the page and performing the humanoid action.
func (i *Interactor) executeInteraction(ctx context.Context, element interactiveElement, log *zap.Logger) (bool, error) {
	// Strategy: Temporarily assign a unique attribute to the node using its NodeID, create a selector for it,
	// interact, and then remove the attribute using a robust JS cleanup mechanism.

	tempID := fmt.Sprintf("scalpel-interaction-%d-%d", time.Now().UnixNano(), i.rng.Int63())
	attributeName := "data-scalpel-interaction-id"
	selector := fmt.Sprintf(`[%s="%s"]`, attributeName, tempID)

	// Set the temporary attribute using the specific CDP NodeID.
	err := chromedp.Run(ctx,
		// Use chromedp.ByID to ensure we target the specific node instance we identified.
		chromedp.SetAttributeValue(element.Node.NodeID, attributeName, tempID, chromedp.ByID),
	)
	if err != nil {
		// Node might have become stale/detached between identification and interaction.
		return false, fmt.Errorf("failed to set interaction ID attribute (node might be stale): %w", err)
	}

	// Ensure the attribute is removed after the interaction attempt, even if the interaction fails.
	defer i.cleanupInteractionAttribute(ctx, selector, attributeName, log)

	// Perform the interaction.
	var interactionAction chromedp.Action
	nodeName := strings.ToUpper(element.Node.NodeName)

	if element.IsInput {
		if nodeName == "SELECT" {
			// Handle SELECT elements (Dropdowns).
			interactionAction = i.handleSelectInteraction(selector, element.Node)
			log.Debug("Attempting select option.", zap.String("desc", element.Description))
		} else {
			// Handle standard INPUT/TEXTAREA.
			payload := i.generateInputPayload(element.Node)
			interactionAction = i.humanoid.Type(selector, payload)
			// Truncate payload summary for logging.
			summary := payload
			if len(summary) > 20 {
				summary = summary[:20] + "..."
			}
			log.Debug("Attempting input fill.", zap.String("desc", element.Description), zap.String("payload_summary", summary))
		}
	} else {
		// Handle clickable elements.
		interactionAction = i.humanoid.IntelligentClick(selector, nil)
		log.Debug("Attempting click.", zap.String("desc", element.Description))
	}

	if interactionAction == nil {
		return false, fmt.Errorf("no viable interaction action determined")
	}

	// Execute the humanoid action.
	err = chromedp.Run(ctx, interactionAction)

	if err != nil {
		// The interaction itself failed (e.g., element became obscured or detached during the action).
		return false, fmt.Errorf("humanoid action failed: %w", err)
	}

	return true, nil
}

// handleSelectInteraction determines a random valid option for a SELECT element and creates the action.
func (i *Interactor) handleSelectInteraction(selector string, node *cdp.Node) chromedp.Action {
	// Find child OPTION elements.
	var options []string
	for _, child := range node.Children {
		if strings.ToUpper(child.NodeName) == "OPTION" {
			value := child.Attribute("value")
			// Skip disabled options or options without a value.
			if child.Attribute("disabled") == "" && value != "" {
				options = append(options, value)
			}
		}
	}

	if len(options) == 0 {
		return nil
	}

	// Select a random option using the dedicated RNG.
	selectedValue := options[i.rng.Intn(len(options))]

	// Create the task sequence: Click to open, pause, then set the value.
	// This sequence matches the Humanoid module's composable style.
	return chromedp.Tasks{
		i.humanoid.IntelligentClick(selector, nil),
		i.humanoid.CognitivePause(150, 50), // Pause for dropdown animation/rendering.
		// Use chromedp.SetValue to reliably set the select element's value.
		chromedp.SetValue(selector, selectedValue, chromedp.ByQuery),
	}
}

// generateInputPayload creates a context-aware payload for input fields.
func (i *Interactor) generateInputPayload(node *cdp.Node) string {
	// Basic heuristics based on type, name, and id attributes.
	inputType := strings.ToLower(node.Attribute("type"))
	inputName := strings.ToLower(node.Attribute("name"))
	inputId := strings.ToLower(node.Attribute("id"))

	// Combine attributes for better context matching.
	contextString := inputName + " " + inputId

	if inputType == "email" || strings.Contains(contextString, "email") {
		return "test.user@example.com"
	}
	if inputType == "password" || strings.Contains(contextString, "pass") {
		return "ScalpelTest123!"
	}
	if inputType == "tel" || strings.Contains(contextString, "phone") || strings.Contains(contextString, "tel") {
		return "555-0199"
	}
	if inputType == "search" || strings.Contains(contextString, "search") || strings.Contains(contextString, "query") {
		return "test query"
	}
	if strings.Contains(contextString, "name") || strings.Contains(contextString, "user") {
		return "Test User"
	}

	// Default generic payload.
	return "scalpel_test_input"
}

// cleanupInteractionAttribute uses JavaScript to remove the temporary attribute, ensuring robustness against navigation.
func (i *Interactor) cleanupInteractionAttribute(ctx context.Context, selector, attributeName string, log *zap.Logger) {
	// Use a short timeout for cleanup, running in the background context.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Get the executor from the original context to ensure we target the correct tab.
	execCtx := chromedp.FromContext(ctx)
	if execCtx == nil {
		log.Warn("Could not retrieve executor for cleanup. Attribute might persist.")
		return
	}

	// JS to find the element by the unique selector and remove the attribute safely.
	jsCleanup := fmt.Sprintf(`(function(s) {
        try {
            const el = document.querySelector(s);
            if (el) {
                el.removeAttribute('%s');
                return true;
            }
        } catch (e) {
            console.error("Scalpel cleanup error:", e);
        }
        return false;
    })('%s')`, attributeName, selector)

	var success bool
	// Execute the cleanup script using the executor.
	if err := chromedp.Run(chromedp.WithExecutor(cleanupCtx, execCtx),
		// Evaluate the JS and capture the result.
		chromedp.Evaluate(jsCleanup, &success),
	); err != nil {
		// Log error if it wasn't context cancellation.
		if cleanupCtx.Err() == nil && ctx.Err() == nil {
			log.Debug("Failed to execute cleanup JS after interaction.", zap.Error(err))
		}
	}
	if !success {
		log.Debug("Cleanup JS executed but could not find the element (might have been removed by interaction).")
	}
}

// generateNodeFingerprint creates a stable, non-cryptographic identifier for a DOM node.
// It returns the hash and a human-readable description.
func generateNodeFingerprint(node *cdp.Node) (string, string) {
	var sb strings.Builder
	sb.WriteString(strings.ToLower(node.NodeName))

	attrs := node.AttributeMap()

	// Prioritize stable attributes.
	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}

	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		// Sort classes to ensure consistent fingerprint regardless of order in the DOM.
		sort.Strings(classes)
		sb.WriteString("." + strings.Join(classes, "."))
	}

	// Include specific attributes relevant to interaction.
	attributesToInclude := []string{"name", "href", "action", "type", "role", "aria-label", "onclick", "placeholder", "title"}
	// Sort attributes to ensure consistent order.
	sort.Strings(attributesToInclude)

	for _, attr := range attributesToInclude {
		if val, ok := attrs[attr]; ok && val != "" {
			// Truncate long values to keep the fingerprint manageable.
			if len(val) > 80 {
				val = val[:80]
			}
			sb.WriteString(fmt.Sprintf("[%s=%s]", attr, val))
		}
	}

	description := sb.String()
	if len(description) > 150 {
		description = description[:150]
	}

	// Hash using a pooled FNV-1a hasher for efficiency.
	hasher := hasherPool.Get().(hash.Hash64)
	defer func() {
		hasher.Reset()
		hasherPool.Put(hasher)
	}()

	_, _ = hasher.Write([]byte(description))
	hash := strconv.FormatUint(hasher.Sum64(), 16)

	return hash, description
}
