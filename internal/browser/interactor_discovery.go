// internal/browser/interactor_discovery.go
package browser

import (
	"fmt"
	"hash"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/chromedp/cdproto/cdp"
)

// interactiveElement is a simple struct to bundle up a node we found
// along with a unique fingerprint we've calculated for it.
type interactiveElement struct {
	Node        *cdp.Node
	Fingerprint string
	Description string
	IsInput     bool
}

// hasherPool keeps a stash of FNV hasher instances ready to go.
// This is a neat little trick to reduce memory allocations since we do a lot
// of hashing to fingerprint elements. Reusing objects is way faster
// than creating new ones all the time.
var hasherPool = sync.Pool{
	New: func() interface{} {
		return fnv.New64a()
	},
}

// filterAndFingerprint takes a list of raw nodes, figures out which ones are
// new and worth interacting with, and gives each one a unique fingerprint.
func (i *Interactor) filterAndFingerprint(nodes []*cdp.Node, interacted map[string]bool, isInput bool) []interactiveElement {
	newElements := make([]interactiveElement, 0, len(nodes))
	for _, node := range nodes {
		attrs := attributeMap(node)
		// Skip anything that's disabled or readonly. No point in trying to click it.
		if isDisabled(node, attrs) {
			continue
		}

		fingerprint, description := generateNodeFingerprint(node, attrs)
		if fingerprint == "" {
			// If we can't generate a stable fingerprint, we can't track it, so we skip it.
			continue
		}

		// Check our map of already interacted elements. If we haven't touched this one, add it to the list.
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

// generateNodeFingerprint is where the magic happens. It creates a stable,
// repeatable identifier for a DOM node based on its most distinct attributes.
func generateNodeFingerprint(node *cdp.Node, attrs map[string]string) (string, string) {
	var sb strings.Builder
	// Start with the basics: the node's tag name.
	sb.WriteString(strings.ToLower(node.NodeName))

	// An ID is the best unique identifier, so we always use it if it's there.
	if id, ok := attrs["id"]; ok && id != "" {
		sb.WriteString("#" + id)
	}
	// Classes are also good identifiers. We sort them to ensure the order is always the same.
	if cls, ok := attrs["class"]; ok && cls != "" {
		classes := strings.Fields(cls)
		sort.Strings(classes)
		sb.WriteString("." + strings.Join(classes, "."))
	}

	// Now add other important attributes that hint at the element's purpose.
	// We sort the attribute keys themselves to guarantee a consistent order.
	attributesToInclude := []string{"name", "href", "type", "role", "aria-label", "placeholder", "title"}
	sort.Strings(attributesToInclude)
	for _, attr := range attributesToInclude {
		if val, ok := attrs[attr]; ok && val != "" {
			sb.WriteString(fmt.Sprintf(`[%s="%s"]`, attr, val))
		}
	}

	// This human readable string is great for logging and debugging.
	description := sb.String()
	if description == "" {
		return "", ""
	}

	// Grab a hasher from our pool.
	hasher := hasherPool.Get().(hash.Hash64)
	// Make sure we return it to the pool when we're done.
	defer func() {
		hasher.Reset()
		hasherPool.Put(hasher)
	}()

	// Hash the descriptive string to get a short, unique fingerprint.
	_, _ = hasher.Write([]byte(description))
	hashVal := strconv.FormatUint(hasher.Sum64(), 16)
	return hashVal, description
}

// isDisabled checks if a node has the 'disabled' or 'readonly' attribute.
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
