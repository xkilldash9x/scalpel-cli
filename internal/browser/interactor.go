// internal/browser/interactor.go
package browser

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

	"github.com/playwright-community/playwright-go"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// -- Structs and Constructors --

// StabilizationFunc is a function type that waits for the application state to stabilize.
type StabilizationFunc func(ctx context.Context) error

// Interactor is responsible for intelligently interacting with web pages using Playwright.
type Interactor struct {
	logger      *zap.Logger
	page        playwright.Page  // The page being interacted with.
	humanoidCfg *humanoid.Config // Configuration for human-like behavior.
	stabilizeFn StabilizationFunc
	rng         *rand.Rand
}

// interactiveElement represents a discovered element suitable for interaction.
type interactiveElement struct {
	// We store the unique selector generated during discovery for robust targeting.
	Selector    string
	Fingerprint string
	Description string
	IsInput     bool
	// Data needed for input generation if it's an input element.
	InputData ElementData
}

// ElementData holds essential information about a DOM node, extracted via JS evaluation.
type ElementData struct {
	NodeName   string            `json:"nodeName"`
	Attributes map[string]string `json:"attributes"`
	TextContent string           `json:"textContent"`
	// For SELECT elements.
	SelectOptions []SelectOptionData `json:"selectOptions"`
}

type SelectOptionData struct {
	Value    string `json:"value"`
	Disabled bool   `json:"disabled"`
}

// NewInteractor creates a new interactor instance. Page must be set later via SetPage().
func NewInteractor(logger *zap.Logger, hCfg *humanoid.Config, stabilizeFn StabilizationFunc) *Interactor {
	source := rand.NewSource(time.Now().UnixNano())
	if stabilizeFn == nil {
		stabilizeFn = func(ctx context.Context) error { return nil }
	}
	return &Interactor{
		logger:      logger.Named("interactor"),
		humanoidCfg: hCfg,
		stabilizeFn: stabilizeFn,
		rng:         rand.New(source),
	}
}

// SetPage sets the Playwright page for the interactor.
func (i *Interactor) SetPage(page playwright.Page) {
	i.page = page
}

// -- Orchestration Logic --

// RecursiveInteract is the main entry point for the interaction logic.
func (i *Interactor) RecursiveInteract(ctx context.Context, config schemas.InteractionConfig) error {
	if i.page == nil || i.page.IsClosed() {
		return fmt.Errorf("interactor page is not set or closed")
	}

	interactedElements := make(map[string]bool)
	i.logger.Info("Starting recursive interaction.", zap.Int("max_depth", config.MaxDepth))

	// Initial cognitive pause.
	if i.humanoidCfg != nil {
		if err := i.cognitivePause(ctx, 800, 300); err != nil {
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
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth >= config.MaxDepth {
		return nil
	}

	log := i.logger.With(zap.Int("depth", depth))

	// 1. Discover new elements.
	newElements, err := i.discoverElements(ctx, interactedElements)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Handle target closed error (e.g., navigation happened during discovery).
		if errors.Is(err, playwright.ErrTargetClosed) {
			log.Debug("Page closed during element discovery.")
			return nil
		}
		log.Warn("Failed to query for interactive elements.", zap.Error(err))
		return nil
	}
	if len(newElements) == 0 {
		log.Debug("No new elements found at this depth.")
		return nil
	}

	// 2. Shuffle elements.
	i.rng.Shuffle(len(newElements), func(j, k int) {
		newElements[j], newElements[k] = newElements[k], newElements[j]
	})

	// 3. Interact with elements.
	interactions := 0
	for _, element := range newElements {
		if err := ctx.Err(); err != nil {
			return err
		}
		if interactions >= config.MaxInteractionsPerDepth {
			break
		}

		// Pause before considering the next element.
		if i.humanoidCfg != nil {
			if err := i.cognitivePause(ctx, 150, 70); err != nil {
				return err
			}
		}

		// Execute the interaction with a specific timeout derived from the main context.
		actionCtx, cancelAction := context.WithTimeout(ctx, 30*time.Second)
		success, err := i.executeInteraction(actionCtx, element, log)
		cancelAction()

		interactedElements[element.Fingerprint] = true

		if err != nil {
			// Handle navigation/page close during interaction.
			if errors.Is(err, playwright.ErrTargetClosed) || strings.Contains(err.Error(), "Execution context was destroyed") {
				log.Debug("Target closed or navigation occurred during interaction.")
				interactions++
				break // Stop this depth and proceed to stabilization/recursion.
			}
			if actionCtx.Err() == nil {
				log.Debug("Interaction failed.", zap.String("desc", element.Description), zap.Error(err))
			}
			continue
		}

		if success {
			interactions++
			delay := time.Duration(config.InteractionDelayMs) * time.Millisecond
			if delay > 0 && i.humanoidCfg != nil {
				if err := i.hesitate(ctx, delay); err != nil {
					return err
				}
			}
		}
	}

	// 4. Stabilize and recurse.
	if interactions > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := i.stabilizeFn(ctx); err != nil && ctx.Err() == nil {
			log.Debug("Stabilization finished (potentially interrupted).", zap.Error(err))
		}

		waitDuration := time.Duration(config.PostInteractionWaitMs) * time.Millisecond
		if waitDuration > 0 && i.humanoidCfg != nil {
			if err := i.hesitate(ctx, waitDuration); err != nil {
				return err
			}
		}
		return i.interactDepth(ctx, config, depth+1, interactedElements)
	}
	return nil
}

// -- Element Discovery Logic (Optimized) --

const interactiveSelectors = "a[href], button, [onclick], [role=button], [role=link], input, textarea, select, summary, details, [tabindex='0'], [contenteditable=true]"

// discoveryScript performs discovery, visibility checks, data extraction, and temporary tagging in a single JS evaluation.
const discoveryScript = `
	(selectors) => {
	    const elementsData = [];
	    const candidates = document.querySelectorAll(selectors);
		const maxTextLength = 64;

		// Helper to check visibility (approximating Playwright's checks).
		const isVisible = (el) => {
			const style = window.getComputedStyle(el);
			if (style.visibility === 'hidden' || style.display === 'none' || style.opacity === '0') return false;

			const rect = el.getBoundingClientRect();
			// Element must have some size.
			if (rect.width === 0 || rect.height === 0) return false;

			return true;
		};

		// Helper to check if element is disabled (simplified check).
		const isDisabled = (el) => {
			return el.disabled || el.getAttribute('aria-disabled') === 'true';
		};

	    candidates.forEach((el, index) => {
			// 1. Filter: Visibility and Disabled status.
			if (!isVisible(el) || isDisabled(el)) return;

	        // 2. Data Extraction
	        const attributes = {};
	        for (const attr of el.attributes) {
	            attributes[attr.name] = attr.value;
	        }

			let textContent = (el.textContent || "").trim();
			if (textContent.length > maxTextLength) {
				textContent = textContent.substring(0, maxTextLength);
			}

			// 3. Handle SELECT options
			const selectOptions = [];
			if (el.tagName === 'SELECT') {
				for (const option of el.options) {
					selectOptions.push({
						value: option.value,
						disabled: option.disabled
					});
				}
			}

			// 4. Generate unique tag ID for robust targeting.
			const tagId = 'scalpel-id-' + index + '-' + Date.now() + Math.random().toString(36).substring(2, 15);

	        elementsData.push({
				tagId: tagId,
	            data: {
					nodeName: el.tagName,
					attributes: attributes,
					textContent: textContent,
					selectOptions: selectOptions
				}
	        });

			// 5. Tag the element immediately.
			el.setAttribute('data-scalpel-discovery-id', tagId);
	    });

	    return elementsData;
	}
	`

type discoveryResult struct {
	TagId string      `json:"tagId"`
	Data  ElementData `json:"data"`
}

func (i *Interactor) discoverElements(ctx context.Context, interacted map[string]bool) ([]interactiveElement, error) {
	if i.page == nil || i.page.IsClosed() {
		return nil, fmt.Errorf("page not available for discovery")
	}

	// Use a specific timeout for the discovery query.
	queryCtx, cancelQuery := context.WithTimeout(ctx, 30*time.Second)
	defer cancelQuery()

	var results []discoveryResult

	// Execute the optimized script.
	// We must use the context (queryCtx) with the Evaluate call for proper timeout handling.
	rawResult, err := i.page.Evaluate(queryCtx, discoveryScript, interactiveSelectors)
	if err != nil {
		return nil, fmt.Errorf("failed to execute discovery script: %w", err)
	}

	// Clean up the temporary attributes immediately after discovery.
	// We do this asynchronously so it doesn't block the interaction flow.
	defer i.cleanupDiscoveryAttributes()

	// Marshal and Unmarshal to convert interface{} (from JS) to the struct slice.
	data, err := json.Marshal(rawResult)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal discovery results: %w", err)
	}
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, fmt.Errorf("failed to unmarshal discovery results: %w", err)
	}

	return i.filterAndFingerprint(results, interacted), nil
}

// cleanupDiscoveryAttributes removes the temporary attributes added during discovery.
func (i *Interactor) cleanupDiscoveryAttributes() {
	if i.page == nil || i.page.IsClosed() {
		return
	}

	script := `() => {
			document.querySelectorAll('[data-scalpel-discovery-id]').forEach(el => {
				el.removeAttribute('data-scalpel-discovery-id');
			});
		}`
	// Use a short timeout for the cleanup task, running in the background.
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Execute cleanup non-blockingly.
	go func() {
		_, err := i.page.Evaluate(cleanupCtx, script)
		if err != nil && cleanupCtx.Err() == nil && !errors.Is(err, playwright.ErrTargetClosed) {
			i.logger.Debug("Failed to clean up discovery attributes.", zap.Error(err))
		}
	}()
}

func (i *Interactor) filterAndFingerprint(results []discoveryResult, interacted map[string]bool) []interactiveElement {
	newElements := make([]interactiveElement, 0, len(results))
	for _, result := range results {
		data := result.Data
		attrs := data.Attributes

		// Skip readonly inputs (visibility/disabled checks happened in JS).
		isInput := isInputElement(data)
		if isInput {
			if _, readonly := attrs["readonly"]; readonly {
				continue
			}
		}

		// Generate fingerprint.
		fingerprint, description := generateNodeFingerprint(data, attrs)
		if fingerprint == "" {
			continue
		}

		// Check if already interacted.
		if !interacted[fingerprint] {
			newElements = append(newElements, interactiveElement{
				// The selector uses the unique tag ID assigned during discovery.
				Selector:    fmt.Sprintf(`[data-scalpel-discovery-id="%s"]`, result.TagId),
				Fingerprint: fingerprint,
				Description: description,
				IsInput:     isInput,
				InputData:   data,
			})
		}
	}
	return newElements
}

// -- Action Execution Logic --

func (i *Interactor) executeInteraction(ctx context.Context, element interactiveElement, log *zap.Logger) (bool, error) {
	if i.page == nil || i.page.IsClosed() {
		return false, fmt.Errorf("page not available for interaction")
	}

	// The selector targets the element using the temporary attribute set during discovery.
	var err error

	if element.IsInput {
		if strings.ToUpper(element.InputData.NodeName) == "SELECT" {
			err = i.handleSelectInteraction(ctx, element.Selector, element.InputData)
		} else {
			payload := i.generateInputPayload(element.InputData)
			err = i.executeType(ctx, element.Selector, payload)
		}
	} else {
		err = i.executeClick(ctx, element.Selector)
	}

	if err != nil {
		// Check if the error is because the element disappeared (common in SPAs) or is no longer visible/interactive.
		// Playwright throws specific errors for these cases due to its auto-waiting.
		if strings.Contains(err.Error(), "element not found") || strings.Contains(err.Error(), "not visible") || strings.Contains(err.Error(), "not enabled") {
			log.Debug("Element disappeared or became non-interactive before action.", zap.String("selector", element.Selector))
			return false, nil // Not successful, but also not a critical error.
		}
		return false, fmt.Errorf("interaction failed: %w", err)
	}

	return true, nil
}

func (i *Interactor) executeClick(ctx context.Context, selector string) error {
	options := playwright.PageClickOptions{
		Timeout: playwright.Float(10000), // 10s timeout for the action.
	}

	if i.humanoidCfg != nil {
		minMs := int(i.humanoidCfg.ClickHoldMinMs)
		maxMs := int(i.humanoidCfg.ClickHoldMaxMs)
		if maxMs > minMs {
			delay := float64(minMs + i.rng.Intn(maxMs-minMs))
			options.Delay = playwright.Float(delay)
		}
	}

	return i.page.Click(ctx, selector, options)
}

func (i *Interactor) executeType(ctx context.Context, selector string, text string) error {
	// Use Type for humanoid behavior (key-by-key delay), otherwise use Fill.
	if i.humanoidCfg != nil && i.humanoidCfg.KeyHoldMeanMs > 0 {
		// Clear the field first using Fill for reliability.
		if err := i.page.Fill(ctx, selector, "", playwright.PageFillOptions{Timeout: playwright.Float(5000)}); err != nil {
			return fmt.Errorf("failed to clear input field before typing: %w", err)
		}

		// Use Type with a delay.
		delay := float64(i.humanoidCfg.KeyHoldMeanMs * (1.0 + i.rng.Float64()*0.5)) // Add variance
		typeOptions := playwright.PageTypeOptions{
			Timeout: playwright.Float(10000),
			Delay:   playwright.Float(delay),
		}
		return i.page.Type(ctx, selector, text, typeOptions)
	}

	// Standard Fill.
	return i.page.Fill(ctx, selector, text, playwright.PageFillOptions{Timeout: playwright.Float(10000)})
}

func (i *Interactor) handleSelectInteraction(ctx context.Context, selector string, data ElementData) error {
	var options []string
	// Find available, non-empty options.
	for _, opt := range data.SelectOptions {
		if !opt.Disabled && opt.Value != "" {
			options = append(options, opt.Value)
		}
	}

	if len(options) == 0 {
		return nil // Empty or fully disabled select.
	}

	// Randomly select one option.
	selectedValue := options[i.rng.Intn(len(options))]

	if i.humanoidCfg != nil {
		// Optionally click first to simulate opening the dropdown.
		if err := i.executeClick(ctx, selector); err != nil {
			i.logger.Debug("Humanoid click before select failed (non-critical).", zap.Error(err))
		}
		i.hesitate(ctx, 100*time.Millisecond)
	}

	// Use Playwright's SelectOption.
	_, err := i.page.SelectOption(ctx, selector, playwright.SelectOptionValues{
		Values: playwright.StringSlice(selectedValue),
	}, playwright.PageSelectOptionOptions{
		Timeout: playwright.Float(5000),
	})
	return err
}

// generateInputPayload creates realistic dummy data based on the input element's context.
func (i *Interactor) generateInputPayload(data ElementData) string {
	attrs := data.Attributes
	inputType := strings.ToLower(attrs["type"])
	contextString := strings.ToLower(attrs["name"] + " " + attrs["id"] + " " + attrs["placeholder"])

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
	return "scalpel test input"
}

// -- Humanoid Helpers --

func (i *Interactor) cognitivePause(ctx context.Context, baseMs, varianceMs int) error {
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
func generateNodeFingerprint(data ElementData, attrs map[string]string) (string, string) {
	var sb strings.Builder
	tagNameLower := strings.ToLower(data.NodeName)
	sb.WriteString(tagNameLower)

	// Include ID and Classes for specificity.
	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}
	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes)
		sb.WriteString("." + strings.Join(classes, "."))
	}

	// Include relevant attributes.
	attributesToInclude := []string{"name", "href", "type", "role", "aria-label", "placeholder", "title", "action"}
	sort.Strings(attributesToInclude)
	for _, attr := range attributesToInclude {
		if val, ok := attrs[attr]; ok && val != "" {
			sb.WriteString(fmt.Sprintf(`[%s="%s"]`, attr, val))
		}
	}

	// Include truncated text content.
	if data.TextContent != "" {
		sb.WriteString(fmt.Sprintf(`[text="%s"]`, data.TextContent))
	}

	description := sb.String()
	if tagNameLower == description {
		return "", ""
	}

	hasher := hasherPool.Get().(hash.Hash64)
	defer func() {
		hasher.Reset()
		hasherPool.Put(hasher)
	}()

	_, _ = hasher.Write([]byte(description))
	return strconv.FormatUint(hasher.Sum64(), 16), description
}

func isInputElement(data ElementData) bool {
	name := strings.ToUpper(data.NodeName)
	attrs := data.Attributes

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

	return attrs["contenteditable"] == "true"
}
