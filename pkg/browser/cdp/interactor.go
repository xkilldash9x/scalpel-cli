// pkg/browser/cdp/interactor.go
package cdp

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/humanoid"
)

// Interactor provides advanced, recursive interaction logic (crawling) using the humanoid engine.
// It operates within an existing browser session context.
// It no longer manages browser lifecycle (allocators/sessions).
type Interactor struct {
	logger   *zap.Logger
	humanoid *humanoid.Humanoid
}

// NewInteractor creates a new Interactor helper.
func NewInteractor(logger *zap.Logger, h *humanoid.Humanoid) *Interactor {
	return &Interactor{
		logger:   logger.With(zap.String("component", "Interactor")),
		humanoid: h,
	}
}

// RecursiveInteract implements a depth-first search interaction strategy.
// ctx must be the active chromedp session context.
func (i *Interactor) RecursiveInteract(
	ctx context.Context,
	config browser.InteractionConfig,
) error {
	interactedElements := make(map[string]bool)
	return i.interactDepth(ctx, config, 0, interactedElements)
}

// interactDepth handles the interaction logic for a specific depth.
func (i *Interactor) interactDepth(
	ctx context.Context,
	config browser.InteractionConfig,
	depth int,
	interactedElements map[string]bool,
) error {
	if depth >= config.MaxDepth {
		return nil
	}

	log := i.logger.With(zap.Int("depth", depth))

	// 1. Identify interactive elements.
	selectors := "a[href], button, [onclick], [role=button], input[type=submit], input[type=button], [tabindex]"
	var nodes []*cdp.Node

	// Query for visible nodes only.
	if err := chromedp.Run(ctx, chromedp.Nodes(selectors, &nodes, chromedp.ByQueryAll, chromedp.NodeVisible)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err() // Context cancelled
		}
		log.Warn("failed to query interactive elements", zap.Error(err))
		return nil // Don't fail the entire process if query fails.
	}

	// 2. Filter out already interacted elements.
	var newElements []*cdp.Node
	for _, node := range nodes {
		fingerprint := generateNodeFingerprint(node)
		if !interactedElements[fingerprint] {
			newElements = append(newElements, node)
		}
	}

	if len(newElements) == 0 {
		return nil
	}

	// 3. Randomize the order to simulate less predictable behavior.
	rand.Shuffle(len(newElements), func(i, j int) {
		newElements[i], newElements[j] = newElements[j], newElements[i]
	})

	// 4. Interact with the elements.
	interactions := 0
	for _, element := range newElements {
		if interactions >= config.MaxInteractionsPerDepth || ctx.Err() != nil {
			break
		}

		fingerprint := generateNodeFingerprint(element)

		// Use a temporary attribute to create a stable, unique selector for the humanoid engine.
		tempID := fmt.Sprintf("scalpel-interaction-%d", time.Now().UnixNano())
		selector := fmt.Sprintf(`[data-scalpel-interaction-id="%s"]`, tempID)

		// Define "distractors" for realism.
		distractors := "div, p, span, section, article"

		// Perform the interaction sequence.
		err := chromedp.Run(ctx,
			// When using *cdp.Node with SetAttributes, chromedp uses NodeID internally.
			chromedp.SetAttributes(element, map[string]string{"data-scalpel-interaction-id": tempID}),
			i.humanoid.MoveAndClick(selector, distractors),
			chromedp.RemoveAttribute(element, "data-scalpel-interaction-id"),
		)

		if err != nil {
			// Interaction might fail if the element is obscured or stale.
			log.Debug("Humanoid interaction failed", zap.String("fingerprint", fingerprint), zap.Error(err))
		}

		interactedElements[fingerprint] = true
		interactions++

		// Wait between interactions.
		time.Sleep(time.Duration(config.InteractionDelayMs) * time.Millisecond)
	}

	// 5. Recurse if interactions occurred.
	if interactions > 0 {
		// Wait for the page state to settle after the interactions.
		time.Sleep(time.Duration(config.PostInteractionWaitMs) * time.Millisecond)
		return i.interactDepth(ctx, config, depth+1, interactedElements)
	}

	return nil
}

// generateNodeFingerprint creates a stable identifier for a DOM node to track interactions.
func generateNodeFingerprint(node *cdp.Node) string {
	var sb strings.Builder
	sb.WriteString(node.NodeName)

	// Extract attributes.
	attrs := make(map[string]string)
	for i := 0; i < len(node.Attributes); i += 2 {
		if i+1 < len(node.Attributes) {
			attrs[node.Attributes[i]] = node.Attributes[i+1]
		}
	}

	// Use ID if present.
	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}

	// Use sorted class names to ensure 'class="a b"' matches 'class="b a"'.
	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes)
		sb.WriteString("." + strings.Join(classes, "."))
	}

	// Use specific attributes for links/buttons.
	if href, ok := attrs["href"]; ok && href != "" {
		sb.WriteString("[href=" + href + "]")
	}
	if name, ok := attrs["name"]; ok && name != "" {
		sb.WriteString("[name=" + name + "]")
	}

	// Hash the resulting string to create a compact fingerprint.
	hasher := sha1.New()
	hasher.Write([]byte(sb.String()))
	return hex.EncodeToString(hasher.Sum(nil))
}
