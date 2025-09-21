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
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// -- Structs and Constructors --

// StabilizationFunc is a function type that waits for the application state to stabilize.
type StabilizationFunc func(ctx context.Context) error

// Interactor is responsible for intelligently interacting with web pages.
type Interactor struct {
	logger      *zap.Logger
	humanoid    *humanoid.Humanoid
	stabilizeFn StabilizationFunc
	rng         *rand.Rand
}

// interactiveElement bundles a node with its unique fingerprint.
type interactiveElement struct {
	Node        *cdp.Node
	Fingerprint string
	Description string
	IsInput     bool
}

// NewInteractor creates a new interactor instance.
func NewInteractor(logger *zap.Logger, h *humanoid.Humanoid, stabilizeFn StabilizationFunc) *Interactor {
	source := rand.NewSource(time.Now().UnixNano())
	// Fallback stabilization function if none provided.
	if stabilizeFn == nil {
		stabilizeFn = func(ctx context.Context) error { return nil }
	}
	return &Interactor{
		logger:      logger.Named("interactor"),
		humanoid:    h,
		stabilizeFn: stabilizeFn,
		rng:         rand.New(source),
	}
}

// -- Orchestration Logic --

// RecursiveInteract is the main entry point for the interaction logic.
func (i *Interactor) RecursiveInteract(ctx context.Context, config schemas.InteractionConfig) error {
	// Ensure the context has a deadline for safety.
	if _, ok := ctx.Deadline(); !ok {
		i.logger.Warn("RecursiveInteract called without a timeout context.")
	}

	interactedElements := make(map[string]bool)
	i.logger.Info("Starting recursive interaction.", zap.Int("max_depth", config.MaxDepth))

	// Initial cognitive pause (simulating the user orienting themselves on the page).
	if i.humanoid != nil {
		if err := i.humanoid.CognitivePause(800, 300).Do(ctx); err != nil {
			return err
		}
	}
	return i.interactDepth(ctx, config, 0, interactedElements)
}

// interactDepth handles the interaction logic for a specific depth.
func (i *Interactor) interactDepth(
	ctx context.Context,
	config schemas.InteractionConfig,
	depth int,
	interactedElements map[string]bool,
) error {
	// Check for cancellation or depth limit.
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth >= config.MaxDepth {
		return nil
	}

	log := i.logger.With(zap.Int("depth", depth))

	// 1. Discover new elements on the page.
	newElements, err := i.discoverElements(ctx, interactedElements)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Warn("Failed to query for interactive elements.", zap.Error(err))
		return nil // Continue gracefully if discovery fails but context is valid.
	}
	if len(newElements) == 0 {
		return nil
	}

	// 2. Shuffle elements for randomized interaction.
	i.rng.Shuffle(len(newElements), func(j, k int) {
		newElements[j], newElements[k] = newElements[k], newElements[j]
	})

	// 3. Interact with elements up to the configured limit.
	interactions := 0
	for _, element := range newElements {
		if err := ctx.Err(); err != nil {
			return err
		}
		if interactions >= config.MaxInteractionsPerDepth {
			break
		}

		// Small pause before considering the next element.
		if i.humanoid != nil {
			if err := i.humanoid.CognitivePause(150, 70).Do(ctx); err != nil {
				return err
			}
		}

		// Execute the interaction with a specific timeout.
		actionCtx, cancelAction := context.WithTimeout(ctx, 30*time.Second)
		success, err := i.executeInteraction(actionCtx, element, log)
		cancelAction()

		interactedElements[element.Fingerprint] = true
		if err != nil {
			// Only log the error if it wasn't due to the context being canceled.
			if actionCtx.Err() == nil {
				log.Debug("Interaction failed.", zap.String("desc", element.Description), zap.Error(err))
			}
			continue
		}

		if success {
			interactions++
			// Pause after successful interaction.
			delay := time.Duration(config.InteractionDelayMs) * time.Millisecond
			if delay > 0 && i.humanoid != nil {
				if err := i.humanoid.Hesitate(delay).Do(ctx); err != nil {
					return err
				}
			}
		}
	}

	// 4. If interactions occurred, stabilize and recurse.
	if interactions > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Wait for the application state to stabilize.
		if err := i.stabilizeFn(ctx); err != nil && ctx.Err() == nil {
			log.Warn("Stabilization failed after interaction (non-critical).", zap.Error(err))
		}

		// Post-interaction wait (e.g., waiting for async content to load).
		waitDuration := time.Duration(config.PostInteractionWaitMs) * time.Millisecond
		if waitDuration > 0 && i.humanoid != nil {
			if err := i.humanoid.Hesitate(waitDuration).Do(ctx); err != nil {
				return err
			}
		}
		return i.interactDepth(ctx, config, depth+1, interactedElements)
	}
	return nil
}

// -- Element Discovery Logic --

func (i *Interactor) discoverElements(ctx context.Context, interacted map[string]bool) ([]interactiveElement, error) {
	// Comprehensive selector for interactive elements.
	selectors := "a[href], button, [onclick], [role=button], [role=link], input, textarea, select, summary, details, [tabindex='0']"
	var nodes []*cdp.Node

	// Use a timeout for the discovery query.
	queryCtx, cancelQuery := context.WithTimeout(ctx, 30*time.Second)
	defer cancelQuery()

	// Query for all visible nodes matching the selectors.
	err := chromedp.Run(queryCtx,
		chromedp.Nodes(selectors, &nodes, chromedp.ByQueryAll, chromedp.NodeVisible),
	)
	if err != nil {
		return nil, err
	}

	return i.filterAndFingerprint(nodes, interacted), nil
}

func (i *Interactor) filterAndFingerprint(nodes []*cdp.Node, interacted map[string]bool) []interactiveElement {
	newElements := make([]interactiveElement, 0, len(nodes))
	for _, node := range nodes {
		attrs := attributeMap(node)
		// Skip disabled or readonly elements.
		if isDisabled(node, attrs) {
			continue
		}
		// Generate a unique fingerprint for the element.
		fingerprint, description := generateNodeFingerprint(node, attrs)
		if fingerprint == "" {
			continue
		}
		// Only include elements that haven't been interacted with yet.
		if !interacted[fingerprint] {
			newElements = append(newElements, interactiveElement{
				Node:        node,
				Fingerprint: fingerprint,
				Description: description,
				IsInput:     isInputElement(node),
			})
		}
	}
	return newElements
}

// -- Action Execution Logic --

// executeInteraction performs the interaction using a temporary attribute for robust targeting.
func (i *Interactor) executeInteraction(ctx context.Context, element interactiveElement, log *zap.Logger) (bool, error) {
	if i.humanoid == nil {
		return false, fmt.Errorf("humanoid controller is not available")
	}

	// 1. Tag the element with a temporary unique ID for precise targeting.
	tempID := fmt.Sprintf("scalpel-interaction-%d-%d", time.Now().UnixNano(), i.rng.Int63())
	attributeName := "data-scalpel-id"
	selector := fmt.Sprintf(`[%s="%s"]`, attributeName, tempID)

	// Ensure the temporary attribute is removed after the interaction.
	defer i.cleanupInteractionAttribute(ctx, selector, attributeName, log)

	err := chromedp.Run(ctx,
		// Use the low-level DOM command to set the attribute by NodeID.
		dom.SetAttributeValue(element.Node.NodeID, attributeName, tempID),
	)
	if err != nil {
		return false, fmt.Errorf("failed to tag element for interaction: %w", err)
	}

	// 2. Determine and execute the appropriate action.
	var interactionAction chromedp.Action
	if element.IsInput {
		if strings.ToUpper(element.Node.NodeName) == "SELECT" {
			interactionAction = i.handleSelectInteraction(selector, element.Node)
		} else {
			// Generate realistic payload based on input type/name.
			payload := i.generateInputPayload(element.Node)
			interactionAction = i.humanoid.Type(selector, payload)
		}
	} else {
		// Standard click action for non-input elements.
		interactionAction = i.humanoid.IntelligentClick(selector, nil)
	}

	if interactionAction == nil {
		return false, nil // No suitable action found (e.g., empty select).
	}

	// 3. Execute the humanoid action.
	if err = chromedp.Run(ctx, interactionAction); err != nil {
		return false, fmt.Errorf("humanoid action failed: %w", err)
	}
	return true, nil
}

// cleanupInteractionAttribute removes the temporary attribute using JS execution.
func (i *Interactor) cleanupInteractionAttribute(parentCtx context.Context, selector, attributeName string, log *zap.Logger) {
	// Use valueOnlyContext to ensure cleanup attempts to run even if the parent context was canceled.
	detachedCtx := valueOnlyContext{parentCtx}
	// Apply a short timeout for the cleanup task.
	taskCtx, cancelTask := context.WithTimeout(detachedCtx, 2*time.Second)
	defer cancelTask()

	// Use JS execution for cleanup as the element might have been removed from the DOM.
	jsCleanup := fmt.Sprintf(`document.querySelector('%s')?.removeAttribute('%s')`, selector, attributeName)
	err := chromedp.Run(taskCtx, chromedp.Evaluate(jsCleanup, nil))

	// Only log an error if the cleanup itself didn't time out.
	if err != nil && taskCtx.Err() == nil {
		log.Debug("Failed to execute cleanup JS for interaction attribute", zap.Error(err))
	}
}

func (i *Interactor) handleSelectInteraction(selector string, node *cdp.Node) chromedp.Action {
	var options []string
	// Find available options within the select element.
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
		return nil
	}
	// Randomly select one option.
	selectedValue := options[i.rng.Intn(len(options))]
	// Use chromedp.SetValue to change the selected option.
	// Includes a click first if humanoid is enabled to simulate opening the dropdown.
	tasks := chromedp.Tasks{}
	if i.humanoid != nil {
		tasks = append(tasks, i.humanoid.IntelligentClick(selector, nil))
	}
	tasks = append(tasks, chromedp.SetValue(selector, selectedValue, chromedp.ByQuery))
	return tasks
}

// generateInputPayload creates realistic dummy data based on the input element's context.
func (i *Interactor) generateInputPayload(node *cdp.Node) string {
	attrs := attributeMap(node)
	inputType := strings.ToLower(attrs["type"])
	contextString := strings.ToLower(attrs["name"] + " " + attrs["id"] + " " + attrs["placeholder"])

	// Prioritize common field types.
	if inputType == "email" || strings.Contains(contextString, "email") {
		return "test.user@example.com"
	}
	if inputType == "password" || strings.Contains(contextString, "pass") {
		return "ScalpelTest123!"
	}
	if inputType == "tel" || strings.Contains(contextString, "phone") {
		return "555-0199"
	}
	if inputType == "search" || strings.Contains(contextString, "search") || strings.Contains(contextString, "query") {
		return "test query"
	}
	if strings.Contains(contextString, "name") || strings.Contains(contextString, "user") {
		return "Test User"
	}
	// Default fallback payload.
	return "scalpel test input"
}

// -- Fingerprinting & Helpers --

// Use a pool of hashers to reduce allocation overhead.
var hasherPool = sync.Pool{
	New: func() interface{} { return fnv.New64a() },
}

const maxTextLength = 64

// generateNodeFingerprint creates a unique, stable identifier for a DOM node.
func generateNodeFingerprint(node *cdp.Node, attrs map[string]string) (string, string) {
	var sb strings.Builder
	sb.WriteString(strings.ToLower(node.NodeName))

	// Include ID and Classes for specificity.
	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}
	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes) // Ensure consistent order.
		sb.WriteString("." + strings.Join(classes, "."))
	}

	// Include relevant attributes that define the element's behavior or appearance.
	attributesToInclude := []string{"name", "href", "type", "role", "aria-label", "placeholder", "title", "action"}
	sort.Strings(attributesToInclude)
	for _, attr := range attributesToInclude {
		if val, ok := attrs[attr]; ok && val != "" {
			sb.WriteString(fmt.Sprintf(`[%s="%s"]`, attr, val))
		}
	}

	// Include truncated text content for elements like buttons or links.
	if text := getNodeText(node); text != "" {
		sb.WriteString(fmt.Sprintf(`[text="%s"]`, text))
	}

	description := sb.String()
	// If the description is just the tag name, it's too generic.
	if strings.ToLower(node.NodeName) == description {
		return "", ""
	}

	// Hash the description to create the fingerprint.
	hasher := hasherPool.Get().(hash.Hash64)
	defer func() {
		hasher.Reset()
		hasherPool.Put(hasher)
	}()

	_, _ = hasher.Write([]byte(description))
	return strconv.FormatUint(hasher.Sum64(), 16), description
}

// getNodeText extracts visible text content from a node and its children.
func getNodeText(node *cdp.Node) string {
	var sb strings.Builder
	var findText func(*cdp.Node)
	findText = func(n *cdp.Node) {
		if n.NodeType == cdp.NodeTypeText {
			sb.WriteString(n.NodeValue)
		}
		// Stop traversing if we exceed the max length.
		if sb.Len() < maxTextLength {
			for _, child := range n.Children {
				findText(child)
			}
		}
	}
	findText(node)

	text := strings.TrimSpace(sb.String())
	if len(text) > maxTextLength {
		return text[:maxTextLength]
	}
	return text
}

func isDisabled(node *cdp.Node, attrs map[string]string) bool {
	_, disabled := attrs["disabled"]
	// Check aria-disabled as well.
	ariaDisabled := attrs["aria-disabled"] == "true"
	return disabled || ariaDisabled
}

func isInputElement(node *cdp.Node) bool {
	name := strings.ToUpper(node.NodeName)
	attrs := attributeMap(node)

	if name == "INPUT" {
		// Exclude hidden inputs and buttons disguised as inputs.
		inputType := strings.ToLower(attrs["type"])
		switch inputType {
		case "hidden", "submit", "button", "reset", "image":
			return false
		default:
			// Check for readonly on inputs.
			if _, readonly := attrs["readonly"]; readonly {
				return false
			}
			return true
		}
	}

	if name == "TEXTAREA" || name == "SELECT" {
		// Check for readonly on textareas/selects.
		if _, readonly := attrs["readonly"]; readonly {
			return false
		}
		return true
	}

	// Check for contenteditable elements.
	return attrs["contenteditable"] == "true"
}

// attributeMap converts the flat attribute array from CDP into a map.
func attributeMap(node *cdp.Node) map[string]string {
	attrs := make(map[string]string)
	if node == nil {
		return attrs
	}
	// Attributes are stored as a flat slice [key1, value1, key2, value2, ...].
	for i := 0; i < len(node.Attributes); i += 2 {
		if i+1 < len(node.Attributes) {
			attrs[node.Attributes[i]] = node.Attributes[i+1]
		}
	}
	return attrs
}
