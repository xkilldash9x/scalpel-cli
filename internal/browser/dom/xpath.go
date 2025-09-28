// browser/dom/xpath.go
package dom

import (
	"fmt"
	"strings"

	"github.com/antchfx/htmlquery"
	"golang.org/x/net/html"
)

// GenerateUniqueXPath generates a robust XPath expression for a given node.
// It prioritizes using IDs as anchors for stability and brevity.
func GenerateUniqueXPath(node *html.Node) string {
	if node == nil {
		return ""
	}

	var path []string
	// Traverse up the tree from the node to the root.
	for n := node; n != nil && n.Type != html.DocumentNode; n = n.Parent {
		if n.Type != html.ElementNode {
			continue
		}

		// Use lowercase for tag names as is conventional in HTML XPath.
		tag := strings.ToLower(n.Data)
		if tag == "" {
			continue
		}

		// Optimization: If an element has an ID, use it as the base and stop traversal.
		id := htmlquery.SelectAttr(n, "id")
		if id != "" {
			// Use the standard XPath selector for ID, which is more compatible than the id() function.
			path = append(path, fmt.Sprintf(`//*[@id='%s']`, id))
			break
		}

		// Calculate the index among siblings with the same tag name.
		// XPath indices are 1-based.
		index := 1
		count := 0
		// Iterate backwards through previous siblings.
		for prev := n.PrevSibling; prev != nil; prev = prev.PrevSibling {
			if prev.Type == html.ElementNode && strings.ToLower(prev.Data) == tag {
				count++
			}
		}
		index += count

		path = append(path, fmt.Sprintf("%s[%d]", tag, index))
	}

	if len(path) == 0 {
		return "/"
	}

	// Reverse the path to go from root (or ID base) to the node.
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}

	// Join the path segments.
	xpath := strings.Join(path, "/")
	// If the path started with an ID selector, it's already absolute. Otherwise, make it absolute.
	if !strings.HasPrefix(xpath, "//*[@id=") {
		xpath = "/" + xpath
	}
	return xpath
}
