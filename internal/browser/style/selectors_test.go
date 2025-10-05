package style

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
	"golang.org/x/net/html"
)

// Helper to parse HTML and find a node by ID.
func parseHTMLAndFind(h, id string) *html.Node {
	doc, _ := html.Parse(strings.NewReader("<html><body>" + h + "</body></html>"))
	var found *html.Node
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if found != nil { return }
		if n.Type == html.ElementNode {
			for _, attr := range n.Attr {
				if attr.Key == "id" && attr.Val == id {
					found = n
					return
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling { traverse(c) }
	}
	traverse(doc)
	return found
}

// Test internal matchesAttribute (White-box testing)
func TestMatchesAttribute(t *testing.T) {
	htmlInput := `<input type="text" lang="en-US" class="foo bar" data-value="example-test">`
	node := parseHTMLAndFind(htmlInput, "input")

	tests := []struct {
		sel      parser.AttributeSelector
		expected bool
	}{
		// Presence [attr]
		{parser.AttributeSelector{Name: "lang"}, true},
		{parser.AttributeSelector{Name: "disabled"}, false},
		// Exact match [attr="value"]
		{parser.AttributeSelector{Name: "type", Operator: "=", Value: "text"}, true},
		// Contains word [attr~="value"]
		{parser.AttributeSelector{Name: "class", Operator: "~=", Value: "foo"}, true},
		{parser.AttributeSelector{Name: "class", Operator: "~=", Value: "baz"}, false},
		// Prefix hyphen [attr|="value"]
		{parser.AttributeSelector{Name: "lang", Operator: "|=", Value: "en"}, true},
		// Starts with [attr^="value"]
		{parser.AttributeSelector{Name: "data-value", Operator: "^=", Value: "example"}, true},
		// Ends with [attr$="value"]
		{parser.AttributeSelector{Name: "data-value", Operator: "$=", Value: "test"}, true},
		// Contains substring [attr*="value"]
		{parser.AttributeSelector{Name: "data-value", Operator: "*=", Value: "-"}, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.sel), func(t *testing.T) {
			actual := matchesAttribute(node, tt.sel)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

// Test internal matchesSimple (White-box testing)
func TestMatchesSimple(t *testing.T) {
	htmlInput := `<div id="main" class="container active"></div>`
	node := parseHTMLAndFind(htmlInput, "main")
	se := Engine{}

	tests := []struct {
		name     string
		sel      parser.SimpleSelector
		expected bool
	}{
		{"Tag Match", parser.SimpleSelector{TagName: "div"}, true},
		{"Tag Mismatch", parser.SimpleSelector{TagName: "span"}, false},
		{"ID Match", parser.SimpleSelector{ID: "main"}, true},
		{"Multiple Class Match", parser.SimpleSelector{Classes: []string{"container", "active"}}, true},
		{"Partial Class Mismatch", parser.SimpleSelector{Classes: []string{"container", "inactive"}}, false},
		{"Combined Match", parser.SimpleSelector{TagName: "div", ID: "main", Classes: []string{"active"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := se.matchesSimple(node, tt.sel)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

// MockShadowDOMProcessor for Engine setup
type MockShadowDOMProcessor struct{ ShadowDOMProcessor }
func (m *MockShadowDOMProcessor) DetectShadowHost(node *html.Node) bool { return false }


// Test internal matches (White-box testing for combinators)
func TestMatchesCombinators(t *testing.T) {
	htmlInput := `
		<div id="grandparent">
			<div id="parent">
				<p id="child1">C1</p>
				<p id="child2">C2</p>
				<span id="child3">C3</span>
			</div>
		</div>
	`
	// Initialize the engine (needed for the receiver methods)
	se := NewEngine(&MockShadowDOMProcessor{})

	// Helper to parse a selector string into a SelectorGroup
	parseSelector := func(selStr string) parser.SelectorGroup {
		p := parser.NewParser(selStr + "{}")
		// We must call the internal parseSelectorGroups method
		return p.parseSelectorGroups()[0]
	}

	tests := []struct {
		selector string
		targetID string
		expected bool
	}{
		// Descendant
		{"#grandparent #child1", "child1", true},
		{"div span", "child3", true},
		{"#parent #grandparent", "grandparent", false},
		// Child >
		{"#parent > #child1", "child1", true},
		{"#grandparent > #child1", "child1", false},
		// Adjacent Sibling +
		{"#child1 + #child2", "child2", true},
		{"#child1 + #child3", "child3", false}, // child2 is in the way
		// General Sibling ~
		{"#child1 ~ #child3", "child3", true},
		{"#child2 ~ #child1", "child1", false}, // Order matters
	}

	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			group := parseSelector(tt.selector)
			targetNode := parseHTMLAndFind(htmlInput, tt.targetID)
			require.NotNil(t, targetNode)

			// Call the internal matches method
			_, matched := se.matches(targetNode, group)
			assert.Equal(t, tt.expected, matched)
		})
	}
}