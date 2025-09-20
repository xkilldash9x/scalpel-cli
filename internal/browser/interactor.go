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
	if _, ok := ctx.Deadline(); !ok {
		i.logger.Warn("RecursiveInteract called without a timeout context.", zap.Stack("caller_stack"))
	}
	interactedElements := make(map[string]bool)
	i.logger.Info("Starting recursive interaction.", zap.Int("max_depth", config.MaxDepth))
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
	// A non-blocking check for cancellation at the start of each recursive step.
	// This is the preferred pattern for immediate checks.
	if err := ctx.Err(); err != nil {
		return err
	}
	if depth >= config.MaxDepth {
		return nil
	}

	log := i.logger.With(zap.Int("depth", depth))
	newElements, err := i.discoverElements(ctx, interactedElements)
	if err != nil {
		// If context was canceled during discovery, just return the context error.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Warn("Failed to query for interactive elements.", zap.Error(err))
		return nil // Continue gracefully
	}
	if len(newElements) == 0 {
		return nil
	}

	i.rng.Shuffle(len(newElements), func(j, k int) {
		newElements[j], newElements[k] = newElements[k], newElements[j]
	})

	interactions := 0
	for _, element := range newElements {
		if err := ctx.Err(); err != nil {
			return err
		}
		if interactions >= config.MaxInteractionsPerDepth {
			break
		}
		if i.humanoid != nil {
			if err := i.humanoid.CognitivePause(150, 70).Do(ctx); err != nil {
				return err
			}
		}

		actionCtx, cancelAction := context.WithTimeout(ctx, 20*time.Second)
		success, err := i.executeInteraction(actionCtx, element, log)
		cancelAction()

		interactedElements[element.Fingerprint] = true
		if err != nil {
			// Only log the error if it wasn't due to the action context being canceled.
			if actionCtx.Err() == nil {
				log.Debug("Interaction failed.", zap.String("desc", element.Description), zap.Error(err))
			}
			continue
		}
		if success {
			interactions++
			delay := time.Duration(config.InteractionDelayMs) * time.Millisecond
			if delay > 0 && i.humanoid != nil {
				if err := i.humanoid.Hesitate(delay).Do(ctx); err != nil {
					return err
				}
			}
		}
	}

	if interactions > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := i.stabilizeFn(ctx); err != nil && ctx.Err() == nil {
			log.Warn("Stabilization failed after interaction.", zap.Error(err))
		}
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
	selectors := "a[href], button, [onclick], [role=button], [role=link], input, textarea, select, summary, details, [tabindex='0']"
	var nodes []*cdp.Node

	queryCtx, cancelQuery := context.WithTimeout(ctx, 25*time.Second)
	defer cancelQuery()

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
				IsInput:     isInputElement(node),
			})
		}
	}
	return newElements
}

// -- Action Execution Logic --

func (i *Interactor) executeInteraction(ctx context.Context, element interactiveElement, log *zap.Logger) (bool, error) {
	tempID := fmt.Sprintf("scalpel-interaction-%d-%d", time.Now().UnixNano(), i.rng.Int63())
	attributeName := "data-scalpel-id"
	selector := fmt.Sprintf(`[%s="%s"]`, attributeName, tempID)

	// Defer the cleanup operation. This will run even if the interaction fails.
	defer i.cleanupInteractionAttribute(ctx, selector, attributeName, log)

	err := chromedp.Run(ctx,
		dom.SetAttributeValue(element.Node.NodeID, attributeName, tempID),
	)
	if err != nil {
		return false, fmt.Errorf("failed to tag element: %w", err)
	}

	if i.humanoid == nil {
		return false, fmt.Errorf("humanoid is not initialized")
	}

	var interactionAction chromedp.Action
	if element.IsInput {
		if strings.ToUpper(element.Node.NodeName) == "SELECT" {
			interactionAction = i.handleSelectInteraction(selector, element.Node)
		} else {
			payload := i.generateInputPayload(element.Node)
			interactionAction = i.humanoid.Type(selector, payload)
		}
	} else {
		interactionAction = i.humanoid.IntelligentClick(selector, nil)
	}

	if interactionAction == nil {
		return false, nil
	}
	if err = chromedp.Run(ctx, interactionAction); err != nil {
		return false, fmt.Errorf("humanoid action failed: %w", err)
	}
	return true, nil
}

func (i *Interactor) cleanupInteractionAttribute(parentCtx context.Context, selector, attributeName string, log *zap.Logger) {
	// This cleanup task should attempt to run even if the parent interaction
	// context was canceled. We create a "detached" context for this purpose
	// using valueOnlyContext, which strips the cancellation signal but keeps
	// other values like the CDP target info.
	detachedCtx := valueOnlyContext{parentCtx}
	taskCtx, cancelTask := context.WithTimeout(detachedCtx, 2*time.Second)
	defer cancelTask()

	jsCleanup := fmt.Sprintf(`document.querySelector('%s')?.removeAttribute('%s')`, selector, attributeName)
	err := chromedp.Run(taskCtx, chromedp.Evaluate(jsCleanup, nil))

	// Only log an error if the cleanup itself didn't time out. This prevents
	// noisy logs if the browser is unresponsive or shutting down.
	if err != nil && taskCtx.Err() == nil {
		log.Debug("Failed to execute cleanup JS for interaction attribute", zap.String("selector", selector), zap.Error(err))
	}
}

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
		return nil
	}
	selectedValue := options[i.rng.Intn(len(options))]
	return chromedp.SetValue(selector, selectedValue, chromedp.ByQuery)
}

func (i *Interactor) generateInputPayload(node *cdp.Node) string {
	attrs := attributeMap(node)
	contextString := strings.ToLower(attrs["type"] + " " + attrs["name"] + " " + attrs["id"])
	if attrs["type"] == "email" || strings.Contains(contextString, "email") {
		return "test.user@example.com"
	}
	if attrs["type"] == "password" || strings.Contains(contextString, "pass") {
		return "ScalpelTest123!"
	}
	if attrs["type"] == "tel" || strings.Contains(contextString, "phone") {
		return "555-0199"
	}
	if attrs["type"] == "search" || strings.Contains(contextString, "query") {
		return "test query"
	}
	if strings.Contains(contextString, "name") || strings.Contains(contextString, "user") {
		return "Test User"
	}
	return "scalpel test input"
}

// -- Fingerprinting & Helpers --

var hasherPool = sync.Pool{
	New: func() interface{} { return fnv.New64a() },
}

func generateNodeFingerprint(node *cdp.Node, attrs map[string]string) (string, string) {
	var sb strings.Builder
	sb.WriteString(strings.ToLower(node.NodeName))

	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}
	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes)
		sb.WriteString("." + strings.Join(classes, "."))
	}

	attributesToInclude := []string{"name", "href", "type", "role", "aria-label", "placeholder", "title"}
	sort.Strings(attributesToInclude)
	for _, attr := range attributesToInclude {
		if val, ok := attrs[attr]; ok && val != "" {
			sb.WriteString(fmt.Sprintf(`[%s="%s"]`, attr, val))
		}
	}

	if text := getNodeText(node); text != "" {
		sb.WriteString(fmt.Sprintf(`[text="%s"]`, text))
	}

	description := sb.String()
	if strings.ToLower(node.NodeName) == description {
		return "", ""
	}

	hasher := hasherPool.Get().(hash.Hash64)
	defer hasher.Reset()
	hasherPool.Put(hasher)

	_, _ = hasher.Write([]byte(description))
	return strconv.FormatUint(hasher.Sum64(), 16), description
}

const maxTextLength = 64

func getNodeText(node *cdp.Node) string {
	var sb strings.Builder
	var findText func(*cdp.Node)
	findText = func(n *cdp.Node) {
		if n.NodeType == cdp.NodeTypeText {
			sb.WriteString(n.NodeValue)
		}
		for _, child := range n.Children {
			findText(child)
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
	_, readonly := attrs["readonly"]
	return disabled || readonly
}

func isInputElement(node *cdp.Node) bool {
	switch strings.ToUpper(node.NodeName) {
	case "INPUT", "TEXTAREA", "SELECT":
		return true
	default:
		return false
	}
}

func attributeMap(node *cdp.Node) map[string]string {
	attrs := make(map[string]string)
	if node == nil {
		return attrs
	}
	for i := 0; i < len(node.Attributes); i += 2 {
		attrs[node.Attributes[i]] = node.Attributes[i+1]
	}
	return attrs
}
