// pkg/browser/interactor.go
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

	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/humanoid"
)

// Interactor provides advanced, recursive interaction logic (crawling) using the humanoid engine.
// It operates within an existing browser session context.
type Interactor struct {
	logger   *zap.Logger
	humanoid *humanoid.Humanoid
}

// interactiveElement is a helper struct to store a node and its pre-calculated fingerprint.
type interactiveElement struct {
	Node        *cdp.Node
	Fingerprint string
}

// Pool for reusing FNV hasher instances to reduce allocations.
var hasherPool = sync.Pool{
	New: func() interface{} {
		return fnv.New64a()
	},
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

// sleepContext is a helper for context-aware sleeps.
func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop() // Prevent timer leaks
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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

	if err := chromedp.Run(ctx, chromedp.Nodes(selectors, &nodes, chromedp.ByQueryAll, chromedp.NodeVisible)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err() // Context cancelled
		}
		log.Warn("failed to query interactive elements", zap.Error(err))
		return nil
	}

	// 2. Filter out already interacted elements and calculate fingerprints.
	var newElements []interactiveElement
	for _, node := range nodes {
		fingerprint := generateNodeFingerprint(node)
		if !interactedElements[fingerprint] {
			newElements = append(newElements, interactiveElement{Node: node, Fingerprint: fingerprint})
		}
	}

	if len(newElements) == 0 {
		return nil
	}

	// 3. Randomize the order.
	rand.Shuffle(len(newElements), func(i, j int) {
		newElements[i], newElements[j] = newElements[j], newElements[i]
	})

	// 4. Interact with the elements.
	interactions := 0
	for _, element := range newElements {
		if interactions >= config.MaxInteractionsPerDepth || ctx.Err() != nil {
			break
		}

		fingerprint := element.Fingerprint
		tempID := fmt.Sprintf("scalpel-interaction-%d", time.Now().UnixNano())
		selector := fmt.Sprintf(`[data-scalpel-interaction-id="%s"]`, tempID)
		distractors := "div, p, span, section, article"

		// Set the temporary attribute.
		err := chromedp.Run(ctx,
			chromedp.SetAttributes(element.Node, map[string]string{"data-scalpel-interaction-id": tempID}),
		)
		if err != nil {
			log.Warn("Failed to set interaction ID", zap.Error(err))
			continue
		}

		// Ensure the attribute is removed after interaction attempt.
		defer func(node *cdp.Node) {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			// Use the original context's executor for the cleanup.
			execCtx := chromedp.FromContext(ctx)
			if err := chromedp.Run(chromedp.WithExecutor(cleanupCtx, execCtx),
				chromedp.RemoveAttribute(node, "data-scalpel-interaction-id")); err != nil {
				log.Debug("Failed to remove interaction ID after interaction", zap.Error(err))
			}
		}(element.Node)

		// Perform the interaction.
		err = chromedp.Run(ctx,
			i.humanoid.IntelligentClick(selector, nil), // Simplified for this example; MoveAndClick is better
		)

		if err != nil {
			log.Debug("Humanoid interaction failed", zap.String("fingerprint", fingerprint), zap.Error(err))
		}

		interactedElements[fingerprint] = true
		interactions++

		// Wait between interactions (Context-aware).
		if err := sleepContext(ctx, time.Duration(config.InteractionDelayMs)*time.Millisecond); err != nil {
			return err
		}
	}

	// 5. Recurse if interactions occurred.
	if interactions > 0 {
		// Wait for the page state to settle (Context-aware).
		if err := sleepContext(ctx, time.Duration(config.PostInteractionWaitMs)*time.Millisecond); err != nil {
			return err
		}
		return i.interactDepth(ctx, config, depth+1, interactedElements)
	}

	return nil
}

// generateNodeFingerprint creates a stable, non-cryptographic identifier for a DOM node.
func generateNodeFingerprint(node *cdp.Node) string {
	var sb strings.Builder
	sb.WriteString(node.NodeName)

	attrs := node.AttributeMap()

	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}

	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes)
		sb.WriteString("." + strings.Join(classes, "."))
	}

	if href, ok := attrs["href"]; ok && href != "" {
		sb.WriteString("[href=" + href + "]")
	}
	if name, ok := attrs["name"]; ok && name != "" {
		sb.WriteString("[name=" + name + "]")
	}

	// Hash using a pooled FNV-1a hasher.
	hasher := hasherPool.Get().(hash.Hash64)
	defer func() {
		hasher.Reset()
		hasherPool.Put(hasher)
	}()

	_, _ = hasher.Write([]byte(sb.String()))
	return strconv.FormatUint(hasher.Sum64(), 16)
}