// browser/dom/interactor.go
package dom

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

	"github.com/antchfx/htmlquery"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/layout"
	"golang.org/x/net/html"
)

// -- Structs and Types --

// Interactor intelligently interacts with web pages using the DOM structure.
type Interactor struct {
	logger      Logger
	page        CorePagePrimitives
	humanoidCfg HumanoidConfig
	stabilizeFn StabilizationFunc
	rng         *rand.Rand
}

// interactiveElement represents a discovered element ready for interaction.
type interactiveElement struct {
	// Selector is the generated unique XPath for targeting the element.
	Selector    string
	Fingerprint string
	Description string
	InputData   ElementData
}

// ElementData holds essential information about a DOM node.
type ElementData struct {
	NodeName      string
	Attributes    map[string]string
	TextContent   string
	SelectOptions []SelectOptionData
}

// SelectOptionData holds data for <option> elements.
type SelectOptionData struct {
	Value    string
	Disabled bool
}

// discoveryResult holds the raw node and extracted data during the discovery phase.
// This is augmented with the layout box to check for visibility.
type discoveryResult struct {
	Node *html.Node
	Box  *layout.LayoutBox
	Data ElementData
}

// NewInteractor creates a new interactor instance.
func NewInteractor(logger Logger, hCfg HumanoidConfig, stabilizeFn StabilizationFunc, page CorePagePrimitives) *Interactor {
	if logger == nil {
		logger = &NopLogger{}
	}
	if stabilizeFn == nil {
		// Default stabilization is a no op.
		stabilizeFn = func(ctx context.Context) error { return nil }
	}

	source := rand.NewSource(time.Now().UnixNano())
	return &Interactor{
		logger:      logger,
		page:        page,
		humanoidCfg: hCfg,
		stabilizeFn: stabilizeFn,
		rng:         rand.New(source),
	}
}

// -- Orchestration Logic --

// ExploreStep analyzes the current layoutRoot, finds a new element, interacts with it, and returns.
// It returns true if an interaction was successfully executed, false otherwise.
// This is designed to be called iteratively by the session manager.
func (i *Interactor) ExploreStep(ctx context.Context, config schemas.InteractionConfig, layoutRoot *layout.LayoutBox, interactedElements map[string]bool) (bool, error) {
	if i.page == nil {
		return false, fmt.Errorf("interactor page primitives are not initialized")
	}
	if layoutRoot == nil {
		return false, fmt.Errorf("layout root cannot be nil for interaction")
	}

	// Note: Depth tracking is managed by the caller (Session).

	i.logger.Debug("Starting exploration step.")

	// Initial pause (simulating reading the page), only if this is the first interaction overall (approximation).
	if i.humanoidCfg.Enabled && len(interactedElements) == 0 {
		if err := i.cognitivePause(ctx, 800, 300); err != nil {
			return false, err
		}
	}

	return i.interact(ctx, config, interactedElements, layoutRoot)
}

// interact handles the discovery and execution of a single interaction.
// This implements the single step logic for the iterative exploration model.
func (i *Interactor) interact(
	ctx context.Context,
	config schemas.InteractionConfig,
	interactedElements map[string]bool,
	layoutRoot *layout.LayoutBox,
) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	// 1. Discover new elements based on the current layout tree.
	newElements, err := i.discoverElements(ctx, layoutRoot, interactedElements)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		i.logger.Warn(fmt.Sprintf("Failed to discover elements: %v", err))
		return false, nil // Stop this step if discovery fails.
	}
	if len(newElements) == 0 {
		i.logger.Debug("No new interactive elements found.")
		return false, nil
	}

	// 2. Shuffle elements for randomized exploration.
	i.rng.Shuffle(len(newElements), func(j, k int) {
		newElements[j], newElements[k] = newElements[k], newElements[j]
	})

	// 3. Interact with the first viable element.
	for _, element := range newElements {
		if err := ctx.Err(); err != nil {
			return false, err
		}

		// Pause before interaction.
		if i.humanoidCfg.Enabled {
			if err := i.cognitivePause(ctx, 150, 70); err != nil {
				return false, err
			}
		}

		// Execute the interaction.
		i.logger.Debug(fmt.Sprintf("Attempting interaction: %s", element.Description))
		actionCtx, cancelAction := context.WithTimeout(ctx, 60*time.Second) // Generous timeout for the action itself.
		err := i.executeInteraction(actionCtx, element)
		cancelAction()

		// Mark as interacted to avoid retrying the same element fingerprint.
		interactedElements[element.Fingerprint] = true

		if err != nil {
			// If the parent context was cancelled, we must stop immediately and propagate the error.
			if ctx.Err() != nil {
				i.logger.Debug(fmt.Sprintf("Interaction stopped due to parent context cancellation: %v", ctx.Err()))
				return false, ctx.Err()
			}

			// Log failure but continue exploration with other elements in this list.
			if actionCtx.Err() == nil {
				i.logger.Debug(fmt.Sprintf("Interaction failed: %v", err))
			}
			continue
		}

		// Interaction successful.
		if err := i.stabilizeFn(ctx); err != nil {
			return true, fmt.Errorf("stabilization failed after interaction: %w", err)
		}
		// Delay immediately after interaction.
		if config.InteractionDelayMs > 0 && i.humanoidCfg.Enabled {
			if err := i.hesitate(ctx, time.Duration(config.InteractionDelayMs)*time.Millisecond); err != nil {
				// Return true because interaction happened, but report the hesitation error.
				return true, err
			}
		}

		// Strategy: Any successful interaction may change the DOM.
		// We return to the caller for stabilization and re-rendering.
		i.logger.Debug("Interaction successful. Returning to session for stabilization and re-render.")
		return true, nil
	}

	// No successful interactions occurred in this step.
	return false, nil
}

// -- Element Discovery Logic --

// A broader XPath to find candidates, with refined filtering done in Go.
const interactiveXPath = `
    //a[@href] | //button | //input | //textarea | //select |
    //summary | //details |
    //*[normalize-space(@contenteditable)='true' or normalize-space(@contenteditable)=''] |
    //*[(@role='button' or @role='link' or @role='tab' or @role='menuitem' or @role='checkbox' or @role='radio')]
`
// findLayoutBoxForNode recursively searches the layout tree for the box corresponding to a given html.Node.
func findLayoutBoxForNode(root *layout.LayoutBox, target *html.Node) *layout.LayoutBox {
	if root == nil || root.StyledNode == nil {
		return nil
	}
	if root.StyledNode.Node == target {
		return root
	}
	for _, child := range root.Children {
		if found := findLayoutBoxForNode(child, target); found != nil {
			return found
		}
	}
	return nil
}

// discoverElements finds, analyzes, and fingerprints interactive elements from the layout tree.
func (i *Interactor) discoverElements(ctx context.Context, layoutRoot *layout.LayoutBox, interacted map[string]bool) ([]interactiveElement, error) {
	if layoutRoot == nil || layoutRoot.StyledNode == nil || layoutRoot.StyledNode.Node == nil {
		return nil, nil // Nothing to discover in an empty layout.
	}

	// 1. Find all candidate nodes using a broad XPath query.
	candidateNodes := htmlquery.Find(layoutRoot.StyledNode.Node, interactiveXPath)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	var results []discoveryResult
	// 2. For each candidate, find its layout box to check for visibility.
	for _, node := range candidateNodes {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		// This is inefficient (O(N*M)), but for a unit test and given DOM sizes, it's acceptable.
		// A map from *html.Node to *LayoutBox could optimize this if needed.
		box := findLayoutBoxForNode(layoutRoot, node)

		// We need the layout box to confirm the element is actually visible.
		if box != nil && box.StyledNode != nil && box.StyledNode.IsVisible() {
			data := extractElementData(node)
			results = append(results, discoveryResult{
				Node: node,
				Box:  box,
				Data: data,
			})
		}
	}

	// 3. Filter out disabled/interacted elements and generate stable fingerprints.
	return i.filterAndFingerprint(results, interacted), nil
}


// extractElementData pulls relevant information from an html.Node.
func extractElementData(node *html.Node) ElementData {
	attrs := make(map[string]string)
	for _, attr := range node.Attr {
		attrs[attr.Key] = attr.Val
	}

	// Extract text content (truncated).
	textContent := strings.TrimSpace(htmlquery.InnerText(node))
	if len(textContent) > 64 {
		textContent = textContent[:64] + "..."
	}

	data := ElementData{
		NodeName:    strings.ToUpper(node.Data),
		Attributes:  attrs,
		TextContent: textContent,
	}

	// Extract select options if applicable.
	if strings.EqualFold(node.Data, "select") {
		data.SelectOptions = extractSelectOptions(node)
	}

	return data
}

// extractSelectOptions parses the children of a <select> node, handling <optgroup> and disabled states.
func extractSelectOptions(selectNode *html.Node) []SelectOptionData {
	var options []SelectOptionData
	// Find all descendant option tags.
	optionNodes := htmlquery.Find(selectNode, ".//option")

	for _, node := range optionNodes {
		value := htmlquery.SelectAttr(node, "value")
		// If value attribute is missing, the text content is the value.
		if value == "" {
			value = strings.TrimSpace(htmlquery.InnerText(node))
		}

		disabled := htmlquery.SelectAttr(node, "disabled") != ""

		// Check if the parent <optgroup> is disabled.
		if !disabled && node.Parent != nil && node.Parent.Type == html.ElementNode && strings.EqualFold(node.Parent.Data, "optgroup") {
			if htmlquery.SelectAttr(node.Parent, "disabled") != "" {
				disabled = true
			}
		}

		options = append(options, SelectOptionData{
			Value:    value,
			Disabled: disabled,
		})
	}
	return options
}

func (i *Interactor) filterAndFingerprint(results []discoveryResult, interacted map[string]bool) []interactiveElement {
	newElements := make([]interactiveElement, 0, len(results))
	for _, result := range results {
		data := result.Data
		attrs := data.Attributes

		// -- FILTERING LOGIC --
		// 0. Skip structural elements that are not typically interactive.
		nodeNameLower := strings.ToLower(data.NodeName)
		if nodeNameLower == "html" || nodeNameLower == "body" {
			continue
		}

		// 1. Skip disabled elements
		if _, disabled := attrs["disabled"]; disabled {
			continue
		}

		// 2. Skip aria-disabled elements
		if val, ariaDisabled := attrs["aria-disabled"]; ariaDisabled && val == "true" {
			continue
		}

		// 3. Skip readonly text inputs
		if isTextInputElement(data) {
			if _, readonly := attrs["readonly"]; readonly {
				continue
			}
		}

		// 4. Skip hidden inputs
		if data.NodeName == "INPUT" {
			if inputType, ok := attrs["type"]; ok && inputType == "hidden" {
				continue
			}
		}

		// -- FINGERPRINTING & APPENDING --
		fingerprint, description := generateNodeFingerprint(data)
		if fingerprint == "" {
			continue
		}

		// Check if already.
		if !interacted[fingerprint] {
			// Generate the unique XPath selector for targeting later.
			selector := GenerateUniqueXPath(result.Node)
			if selector == "" {
				i.logger.Warn(fmt.Sprintf("Could not generate unique XPath for element: %s", description))
				continue
			}

			newElements = append(newElements, interactiveElement{
				Selector:    selector,
				Fingerprint: fingerprint,
				Description: description,
				InputData:   data,
			})
		}
	}
	return newElements
}

// -- Action Execution Logic --

func (i *Interactor) executeInteraction(ctx context.Context, element interactiveElement) error {
	var err error

	data := element.InputData
	nodeName := data.NodeName

	// Determine timing parameters based on configuration.
	keyHold := 0.0
	clickMin, clickMax := 0, 0
	if i.humanoidCfg.Enabled {
		keyHold = i.humanoidCfg.KeyHoldMeanMs
		clickMin = i.humanoidCfg.ClickHoldMinMs
		clickMax = i.humanoidCfg.ClickHoldMaxMs
	}

	// Determine the correct interaction type based on element semantics.
	if nodeName == "SELECT" {
		err = i.handleSelectInteraction(ctx, element.Selector, data)
	} else if isTextInputElement(data) {
		// Handle text inputs, textareas, contenteditable.
		payload := i.generateInputPayload(data)
		i.logger.Debug(fmt.Sprintf("Typing '%s' into %s", payload, element.Description))
		err = i.page.ExecuteType(ctx, element.Selector, payload, keyHold)
	} else {
		// Handle links, buttons, summary, checkboxes, radios, submit inputs, ARIA roles, etc.
		i.logger.Debug(fmt.Sprintf("Clicking %s", element.Description))
		err = i.page.ExecuteClick(ctx, element.Selector, clickMin, clickMax)
	}

	if err != nil {
		return fmt.Errorf("interaction dispatch failed: %w", err)
	}

	return nil
}

func (i *Interactor) handleSelectInteraction(ctx context.Context, selector string, data ElementData) error {
	var options []string

	for _, opt := range data.SelectOptions {
		// Select options that have a value and are not disabled.
		if !opt.Disabled && opt.Value != "" {
			options = append(options, opt.Value)
		}
	}

	// Heuristic: If there are multiple options, we often want to avoid the first one,
	// as it's frequently a placeholder (e.g., "--Select One--").
	if len(options) > 1 {
		// Randomly select one option starting from the second one.
		selectedIndex := i.rng.Intn(len(options)-1) + 1
		selectedValue := options[selectedIndex]
		i.logger.Debug(fmt.Sprintf("Selecting value '%s' (index %d) in %s", selectedValue, selectedIndex, selector))
		return i.page.ExecuteSelect(ctx, selector, selectedValue)
	} else if len(options) == 1 {
		// If only one option exists, select it.
		i.logger.Debug(fmt.Sprintf("Selecting only available value '%s' in %s", options[0], selector))
		return i.page.ExecuteSelect(ctx, selector, options[0])
	}

	// No valid options found.
	i.logger.Debug(fmt.Sprintf("No valid options to select in %s", selector))
	return nil
}

// generateInputPayload creates realistic dummy data based on the input element's context.
func (i *Interactor) generateInputPayload(data ElementData) string {
	attrs := data.Attributes
	inputType := strings.ToLower(attrs["type"])
	// Use common attributes to infer the context of the input field.
	contextString := strings.ToLower(attrs["name"] + " " + attrs["id"] + " " + attrs["placeholder"] + " " + attrs["aria-label"])

	if inputType == "email" || strings.Contains(contextString, "email") {
		return "test.user@example.com"
	}
	if inputType == "password" || strings.Contains(contextString, "pass") {
		return "BrowserTest123!"
	}
	if inputType == "tel" || strings.Contains(contextString, "phone") || strings.Contains(contextString, "mobile") {
		return "555-0199"
	}
	if inputType == "url" || strings.Contains(contextString, "website") || strings.Contains(contextString, "url") {
		return "https://example.com/test"
	}
	if inputType == "search" || strings.Contains(contextString, "search") || strings.Contains(contextString, "query") {
		return "test query"
	}
	if inputType == "number" || inputType == "range" {
		return strconv.Itoa(i.rng.Intn(100) + 1)
	}
	if strings.Contains(contextString, "name") || strings.Contains(contextString, "user") || strings.Contains(contextString, "login") {
		return "Test User"
	}
	if data.NodeName == "TEXTAREA" {
		return "This is a test message generated by the automation browser."
	}
	// Default fallback text.
	return "automation test input"
}

// -- Humanoid Helpers --

func (i *Interactor) cognitivePause(ctx context.Context, baseMs, varianceMs int) error {
	if varianceMs <= 0 {
		varianceMs = 1
	}
	duration := time.Duration(baseMs+i.rng.Intn(varianceMs)) * time.Millisecond
	return i.hesitate(ctx, duration)
}

func (i *Interactor) hesitate(ctx context.Context, duration time.Duration) error {
	select {
	case <-time.After(duration):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// -- Fingerprinting & Helpers --

var hasherPool = sync.Pool{
	New: func() interface{} { return fnv.New64a() },
}

// generateNodeFingerprint creates a unique, stable identifier for a DOM node based on extracted data.
func generateNodeFingerprint(data ElementData) (string, string) {
	var sb strings.Builder
	tagNameLower := strings.ToLower(data.NodeName)
	sb.WriteString(tagNameLower)
	attrs := data.Attributes

	// Include ID for specificity.
	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}

	// Include Classes, filtering potentially dynamic ones.
	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes) // Ensure consistent ordering.
		var stableClasses []string
		for _, c := range classes {
			// Heuristic: avoid classes that look like generated CSS-in-JS hashes (e.g., short, containing numbers)
			if len(c) > 5 || !strings.ContainsAny(c, "0123456789") {
				stableClasses = append(stableClasses, c)
			}
		}

		// Limit the number of classes to avoid issues with highly dynamic CSS frameworks.
		if len(stableClasses) > 0 && len(stableClasses) < 5 {
			sb.WriteString("." + strings.Join(stableClasses, "."))
		}
	}

	// Include relevant attributes that define the element's behavior or identity.
	attributesToInclude := []string{"name", "href", "type", "role", "aria-label", "placeholder", "title", "action", "value", "method", "data-testid"}
	sort.Strings(attributesToInclude)
	for _, attr := range attributesToInclude {
		if val, ok := attrs[attr]; ok && val != "" {
			// Normalize attribute values slightly.
			val = strings.TrimSpace(val)
			if len(val) > 128 {
				val = val[:128]
			}
			val = strings.ReplaceAll(val, `"`, "'") // Basic escaping
			sb.WriteString(fmt.Sprintf(`[%s="%s"]`, attr, val))
		}
	}

	// Include truncated text content for elements where text is descriptive (buttons, links).
	if data.TextContent != "" {
		text := strings.ReplaceAll(data.TextContent, `"`, "'")
		sb.WriteString(fmt.Sprintf(`[text="%s"]`, text))
	}

	description := sb.String()
	// Skip elements where the description is just the tag name (e.g., a plain <div> used for layout).
	if tagNameLower == description {
		return "", ""
	}

	// Generate the hash (fingerprint).
	hasher := hasherPool.Get().(hash.Hash64)
	defer func() {
		hasher.Reset()
		hasherPool.Put(hasher)
	}()

	_, _ = hasher.Write([]byte(description))
	return strconv.FormatUint(hasher.Sum64(), 16), description
}

// isTextInputElement determines if the element is primarily used for text entry (Type action).
// This distinguishes text fields from interactive inputs like checkboxes, radios, or buttons (Click action).
func isTextInputElement(data ElementData) bool {
	name := data.NodeName
	attrs := data.Attributes

	if name == "INPUT" {
		inputType := strings.ToLower(attrs["type"])
		switch inputType {
		// These are Click actions or structural.
		case "hidden", "submit", "button", "reset", "image", "checkbox", "radio":
			return false
		default:
			// Includes text, password, email, search, tel, url, number, date, etc.
			return true
		}
	}

	if name == "TEXTAREA" {
		return true
	}

	// SELECT is handled separately (Select action).
	// Supports rich text editing areas.
	// contenteditable can be "true", "false", or "" (empty string often implies true).
	if val, ok := attrs["contenteditable"]; ok {
		val = strings.TrimSpace(strings.ToLower(val))
		return val == "true" || val == ""
	}
	return false
}