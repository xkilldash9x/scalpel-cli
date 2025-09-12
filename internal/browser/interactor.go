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

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// interactiveElement is a helper struct to store a node and its pre-calculated fingerprint.
type interactiveElement struct {
	Node        *cdp.Node
	Fingerprint string
	Description string
	IsInput     bool // Flag to distinguish inputs from clickable elements
}

// hasherPool reuses FNV hasher instances to reduce memory allocations during fingerprinting.
var hasherPool = sync.Pool{
	New: func() interface{} {
		// FNV-1a is plenty fast and good enough for non crypto hashing.
		return fnv.New64a()
	},
}

// valueOnlyContext is a context that inherits values from its parent but not cancellation.
// This is necessary for cleanup tasks that must run using the chromedp session information
// stored in the parent context, even if the parent context is cancelled.
type valueOnlyContext struct{ context.Context }

func (valueOnlyContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (valueOnlyContext) Done() <-chan struct{}       { return nil }
func (valueOnlyContext) Err() error                  { return nil }

// Interactor is responsible for intelligently interacting with web pages
// to discover new states and trigger application logic, like a digital explorer.
type Interactor struct {
	logger   *zap.Logger
	humanoid *humanoid.Humanoid
	rng      *rand.Rand // A dedicated RNG for interaction randomization.
}

// NewInteractor creates a new interactor instance.
func NewInteractor(logger *zap.Logger, h *humanoid.Humanoid) *Interactor {
	// Seed a dedicated random number generator so our "human" isn't too predictable.
	source := rand.NewSource(time.Now().UnixNano())
	return &Interactor{
		logger:   logger.Named("interactor"),
		humanoid: h,
		rng:      rand.New(source),
	}
}

// RecursiveInteract is the main entry point for the interaction logic.
// It uses a depth-first search (DFS) strategy to explore the application.
func (i *Interactor) RecursiveInteract(ctx context.Context, config schemas.InteractionConfig) error {
	// This map tracks all elements we've poked across the entire session.
	interactedElements := make(map[string]bool)
	i.logger.Info("Starting recursive interaction.", zap.Int("max_depth", config.MaxDepth))

	// A brief pause before we start clicking things, simulating a user assessing the page.
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
	// -- Check for exit conditions --
	if depth >= config.MaxDepth {
		i.logger.Debug("Reached max interaction depth.", zap.Int("depth", depth))
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err() // Bailing out.
	}

	log := i.logger.With(zap.Int("depth", depth))

	// 1. Find all the shiny buttons and interesting looking fields on the page.
	clickableSelectors := "a[href], button, [onclick], [role=button], [role=link], input[type=submit], input[type=button], input[type=reset], summary, details"
	inputSelectors := "input:not([type=hidden]):not([type=submit]):not([type=button]):not([type=reset]), textarea, select"

	var clickableNodes, inputNodes []*cdp.Node
	err := chromedp.Run(ctx,
		chromedp.Nodes(clickableSelectors, &clickableNodes, chromedp.ByQueryAll, chromedp.NodeVisible),
		chromedp.Nodes(inputSelectors, &inputNodes, chromedp.ByQueryAll, chromedp.NodeVisible),
	)

	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Warn("Failed to query for interactive elements. Page state might be wonky.", zap.Error(err))
		return nil // Stop this branch of exploration.
	}

	// 2. Figure out which ones are new to us.
	newElements := i.filterAndFingerprint(inputNodes, interactedElements, true)
	newElements = append(newElements, i.filterAndFingerprint(clickableNodes, interactedElements, false)...)

	if len(newElements) == 0 {
		log.Debug("No new interactive elements found at this depth.")
		return nil
	}

	// 3. Shuffle the order to be less robotic, but keep a bias towards filling out forms first.
	i.rng.Shuffle(len(newElements), func(j, k int) {
		newElements[j], newElements[k] = newElements[k], newElements[j]
	})

	// 4. Time to interact.
	interactions := 0
	for _, element := range newElements {
		if interactions >= config.MaxInteractionsPerDepth {
			log.Debug("Reached max interactions for this depth.")
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Brief pause while we "find" the element on the page.
		if err := i.humanoid.CognitivePause(150, 70).Do(ctx); err != nil {
			return err
		}

		// Do the thing.
		success, err := i.executeInteraction(ctx, element, log)

		// Mark it as handled so we don't try it again, even if it failed.
		interactedElements[element.Fingerprint] = true

		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Debug("Interaction failed.", zap.String("desc", element.Description), zap.Error(err))
			continue // On to the next one.
		}

		if success {
			interactions++
			// Take a breather between actions.
			delay := time.Duration(config.InteractionDelayMs) * time.Millisecond
			if delay > 0 {
				if err := i.humanoid.Hesitate(delay).Do(ctx); err != nil {
					return err
				}
			}
		}
	}

	// 5. If we changed something, wait for the dust to settle then go deeper.
	if interactions > 0 {
		log.Debug("Interactions occurred. Waiting for state stabilization before recursing.", zap.Int("interactions", interactions))

		waitDuration := time.Duration(config.PostInteractionWaitMs) * time.Millisecond
		if waitDuration > 0 {
			if err := i.humanoid.Hesitate(waitDuration).Do(ctx); err != nil {
				return err
			}
		}
		return i.interactDepth(ctx, config, depth+1, interactedElements)
	}

	log.Debug("No successful interactions at this depth. Backing out.")
	return nil
}

// executeInteraction performs the actual click or type action on an element.
func (i *Interactor) executeInteraction(ctx context.Context, element interactiveElement, log *zap.Logger) (bool, error) {
	// This is our trick: we tag the specific node with a unique ID,
	// interact with it, then clean up our tag. It's robust against DOM changes.
	tempID := fmt.Sprintf("scalpel-interaction-%d-%d", time.Now().UnixNano(), i.rng.Int63())
	attributeName := "data-scalpel-id"
	selector := fmt.Sprintf(`[%s="%s"]`, attributeName, tempID)

	// Set the temporary attribute using the node's unique ID.
	err := chromedp.Run(ctx,
		chromedp.SetAttributeValue(element.Node.NodeID, attributeName, tempID, chromedp.ByID),
	)
	if err != nil {
		return false, fmt.Errorf("failed to tag element for interaction (it might be stale): %w", err)
	}

	// Always clean up our attribute when we're done.
	defer i.cleanupInteractionAttribute(ctx, selector, attributeName, log)

	// -- Figure out what kind of interaction to perform --
	var interactionAction chromedp.Action
	nodeName := strings.ToUpper(element.Node.NodeName)

	if element.IsInput {
		if nodeName == "SELECT" {
			interactionAction = i.handleSelectInteraction(selector, element.Node)
			log.Debug("Attempting to select an option.", zap.String("desc", element.Description))
		} else {
			payload := i.generateInputPayload(element.Node)
			interactionAction = i.humanoid.Type(selector, payload)
			log.Debug("Attempting to fill input.", zap.String("desc", element.Description))
		}
	} else {
		interactionAction = i.humanoid.IntelligentClick(selector, nil)
		log.Debug("Attempting to click.", zap.String("desc", element.Description))
	}

	if interactionAction == nil {
		return false, fmt.Errorf("no viable interaction action for element")
	}

	// Engage!
	if err = chromedp.Run(ctx, interactionAction); err != nil {
		return false, fmt.Errorf("humanoid action failed: %w", err)
	}

	return true, nil
}

// -- Helper Methods --

// filterAndFingerprint identifies new elements and creates stable fingerprints for them.
func (i *Interactor) filterAndFingerprint(nodes []*cdp.Node, interacted map[string]bool, isInput bool) []interactiveElement {
	newElements := make([]interactiveElement, 0, len(nodes))

	for _, node := range nodes {
		attrs := attributeMap(node)
		// Ignore disabled or readonly elements.
		if isDisabled(node, attrs) {
			continue
		}

		fingerprint, description := generateNodeFingerprint(node, attrs)
		if fingerprint == "" {
			continue
		}

		if !interacted[fingerprint] {
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

// handleSelectInteraction picks a random valid option from a dropdown.
func (i *Interactor) handleSelectInteraction(selector string, node *cdp.Node) chromedp.Action {
	var options []string
	for _, child := range node.Children {
		if strings.ToUpper(child.NodeName) == "OPTION" {
			childAttrs := attributeMap(child)
			if value, ok := childAttrs["value"]; ok && value != "" {
				if _, disabled := childAttrs["disabled"]; !disabled {
					options = append(options, value)
				}
			}
		}
	}

	if len(options) == 0 {
		return nil // No options to choose from.
	}

	// Pick one at random.
	selectedValue := options[i.rng.Intn(len(options))]

	// A user clicks to open, pauses, then selects. We do the same.
	return chromedp.Tasks{
		i.humanoid.IntelligentClick(selector, nil),
		i.humanoid.CognitivePause(150, 50),
		chromedp.SetValue(selector, selectedValue, chromedp.ByQuery),
	}
}

// generateInputPayload creates context-aware test data for input fields.
func (i *Interactor) generateInputPayload(node *cdp.Node) string {
	attrs := attributeMap(node)
	inputType, _ := attrs["type"]
	inputName, _ := attrs["name"]
	inputId, _ := attrs["id"]
	contextString := strings.ToLower(inputType) + " " + strings.ToLower(inputName) + " " + strings.ToLower(inputId)

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

	// When in doubt, use a generic string.
	return "scalpel test input"
}

// cleanupInteractionAttribute removes our temporary attribute using JavaScript.
func (i *Interactor) cleanupInteractionAttribute(ctx context.Context, selector, attributeName string, log *zap.Logger) {
	if chromedp.FromContext(ctx) == nil {
		log.Debug("Could not get valid chromedp context for cleanup.")
		return
	}

	// Create a new, detached context that preserves values but ignores cancellation.
	detachedCtx := valueOnlyContext{ctx}
	taskCtx, cancelTask := context.WithTimeout(detachedCtx, 2*time.Second)
	defer cancelTask()

	jsCleanup := fmt.Sprintf(`
         const el = document.querySelector('%s');
         if (el) { el.removeAttribute('%s'); }`, selector, attributeName)

	var res interface{}
	err := chromedp.Run(taskCtx, chromedp.Evaluate(jsCleanup, &res))
	
	if err != nil && taskCtx.Err() == nil {
		log.Debug("Failed to execute cleanup JS.", zap.String("selector", selector), zap.Error(err))
	}
}

// -- Utility Functions --

// attributeMap converts a node's attribute slice into a more convenient map.
func attributeMap(node *cdp.Node) map[string]string {
	attrs := make(map[string]string)
	if len(node.Attributes) > 0 {
		for i := 0; i < len(node.Attributes); i += 2 {
			attrs[node.Attributes[i]] = node.Attributes[i+1]
		}
	}
	return attrs
}

// isDisabled checks if a node is disabled or readonly.
func isDisabled(node *cdp.Node, attrs map[string]string) bool {
	if _, ok := attrs["disabled"]; ok {
		return true
	}
	nodeName := strings.ToUpper(node.NodeName)
	if nodeName == "INPUT" || nodeName == "TEXTAREA" {
		if _, ok := attrs["readonly"]; ok {
			return true
		}
	}
	return false
}

// generateNodeFingerprint creates a stable identifier for a DOM node.
func generateNodeFingerprint(node *cdp.Node, attrs map[string]string) (string, string) {
	var sb strings.Builder
	sb.WriteString(strings.ToLower(node.NodeName))

	// Use stable, identifying attributes first.
	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}
	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes) // Sort for consistency.
		sb.WriteString("." + strings.Join(classes, "."))
	}

	// Add other relevant attributes.
	attributesToInclude := []string{"name", "href", "type", "role", "aria-label", "placeholder", "title"}
	sort.Strings(attributesToInclude) // Sort for consistency.
	for _, attr := range attributesToInclude {
		if val, ok := attrs[attr]; ok && val != "" {
			sb.WriteString(fmt.Sprintf(`[%s="%s"]`, attr, val))
		}
	}

	description := sb.String()
	if description == "" {
		return "", ""
	}

	// Hash the descriptive string for a compact fingerprint.
	hasher := hasherPool.Get().(hash.Hash64)
	defer func() {
		hasher.Reset()
		hasherPool.Put(hasher)
	}()

	_, _ = hasher.Write([]byte(description))
	hashVal := strconv.FormatUint(hasher.Sum64(), 16)

	return hashVal, description
}
