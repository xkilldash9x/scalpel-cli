// Filename: javascript/helpers.go
package javascript

import (
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// LocationInfo holds the detailed location and snippet of a finding.
type LocationInfo struct {
	File    string
	Line    int
	Column  int
	Snippet string
}

func (l LocationInfo) String() string {
	return fmt.Sprintf("%s:%d:%d", l.File, l.Line, l.Column)
}

// NodeContent extracts the string content of a node from the source byte slice.
func NodeContent(node *sitter.Node, source []byte) string {
	if node == nil {
		return ""
	}
	return node.Content(source)
}

// flattenPropertyAccess attempts to flatten a chain of property accesses (member_expression and subscript_expression)
// into a list of strings (e.g., window.location.hash or obj['prop'] -> ["window", "location", "hash"] or ["obj", "prop"]).
func flattenPropertyAccess(node *sitter.Node, source []byte) []string {
	var path []string
	current := node

	for {
		if current == nil {
			// Reached the end of the chain unexpectedly.
			return nil
		}

		switch current.Type() {
		case "identifier":
			path = append([]string{NodeContent(current, source)}, path...)
			return path // Base case
		case "this":
			path = append([]string{"this"}, path...)
			return path // Base case

		case "member_expression":
			// Handles obj.prop
			object := current.ChildByFieldName("object")
			property := current.ChildByFieldName("property")

			if property == nil || object == nil {
				return nil
			}

			// Property in member_expression must be an identifier type.
			if property.Type() == "identifier" || property.Type() == "property_identifier" {
				propName := NodeContent(property, source)
				path = append([]string{propName}, path...)
				current = object
			} else {
				// Defense in depth: Handle unexpected grammar structures.
				return nil
			}

		case "subscript_expression":
			// Handles obj['prop']. Fix for Failure 1.
			object := current.ChildByFieldName("object")
			index := current.ChildByFieldName("index")

			if index == nil || object == nil {
				return nil
			}

			// We only flatten if the index is a static string literal.
			if index.Type() == "string" {
				raw := NodeContent(index, source)
				// Strip quotes: ", ', and `
				propName := strings.Trim(raw, "\"'`")
				path = append([]string{propName}, path...)
				current = object
			} else {
				// Computed property (obj[0] or obj[variable]) cannot be flattened statically.
				return nil
			}

		default:
			// Not a simple property access chain (e.g., function call, literal)
			return nil
		}
	}
}

// FormatLocation converts a Tree-sitter Node location to detailed LocationInfo.
func FormatLocation(filename string, node *sitter.Node, source []byte) LocationInfo {
	if node == nil {
		return LocationInfo{File: filename, Snippet: "N/A"}
	}

	startByte := node.StartByte()
	endByte := node.EndByte()
	startPoint := node.StartPoint()

	// Safe extraction of snippet
	snippet := "N/A"
	if int(endByte) <= len(source) && int(startByte) < int(endByte) {
		// Grab the specific line or just the node content if it's small
		// Tree-sitter points give us row/column, but getting the full line text
		// requires finding the newline boundaries around startByte.
		lineStart := findLineStart(source, int(startByte))
		lineEnd := findLineEnd(source, int(startByte))
		if lineStart >= 0 && lineEnd > lineStart {
			snippet = string(source[lineStart:lineEnd])
			snippet = strings.TrimSpace(snippet)
		} else {
			snippet = node.Content(source)
		}
	}

	return LocationInfo{
		File:    filename,
		Line:    int(startPoint.Row) + 1, // 0-indexed to 1-indexed
		Column:  int(startPoint.Column),
		Snippet: snippet,
	}
}

func findLineStart(source []byte, idx int) int {
	// Defense in depth: Bound check
	if idx >= len(source) {
		if len(source) == 0 {
			return 0
		}
		idx = len(source) - 1
	}
	if idx < 0 {
		return 0
	}

	for i := idx; i >= 0; i-- {
		if source[i] == '\n' {
			return i + 1
		}
	}
	return 0
}

func findLineEnd(source []byte, idx int) int {
	for i := idx; i < len(source); i++ {
		if source[i] == '\n' {
			return i
		}
	}
	return len(source)
}
