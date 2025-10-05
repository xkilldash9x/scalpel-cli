package shadowdom

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/style"
	"golang.org/x/net/html"
)

// --- Helpers ---

// Helper to parse HTML and return the body content.
func parseHTML(h string) *html.Node {
	doc, err := html.Parse(strings.NewReader("<html><body>" + h + "</body></html>"))
	if err != nil {
		panic(err)
	}
	// Navigate to body (doc -> html -> body)
	return doc.FirstChild.NextSibling.FirstChild
}

// Helper to find the first element node child.
func firstElement(n *html.Node) *html.Node {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode {
			return c
		}
	}
	return nil
}

// --- Tests for Internal Helpers (White-box testing) ---

func TestGetAttr(t *testing.T) {
	doc := parseHTML(`<div id="test" CLASS="TestClass"></div>`)
	node := firstElement(doc)

	assert.Equal(t, "test", getAttr(node, "id"))
	assert.Equal(t, "TestClass", getAttr(node, "class"), "getAttr should be case-insensitive")
	assert.Equal(t, "", getAttr(node, "missing"))
	assert.Equal(t, "", getAttr(nil, "id"))
}

func TestCloneNode(t *testing.T) {
	htmlInput := `<div id="original" class="test"><span>Hello</span>TextNode</div>`
	doc := parseHTML(htmlInput)
	original := firstElement(doc)

	clone := cloneNode(original)

	assert.NotEqual(t, original, clone, "Clone should be a different instance")
	assert.Equal(t, original.Data, clone.Data)
	assert.Len(t, clone.Attr, 2)

	// Ensure deep copy: modifications to the clone's attributes do not affect the original
	clone.Attr[0].Val = "modified"
	assert.Equal(t, "original", original.Attr[0].Val)
	assert.Equal(t, "modified", clone.Attr[0].Val)

	// Ensure deep copy: children are also cloned
	originalSpan := firstElement(original)
	cloneSpan := firstElement(clone)
	assert.NotEqual(t, originalSpan, cloneSpan)
	assert.Equal(t, "span", cloneSpan.Data)
}

// --- Tests for DetectShadowHost ---

func TestDetectShadowHost(t *testing.T) {
	e := Engine{}
	tests := []struct {
		name     string
		html     string
		expected bool
	}{
		{"Valid Host Open", `<div><template shadowrootmode="open"></template></div>`, true},
		{"Valid Host Closed", `<div><template shadowrootmode="closed"></template></div>`, true},
		{"Case Insensitive", `<div><template ShadowRootMode="open"></template></div>`, true},
		{"No Template", `<div><span></span></div>`, false},
		{"Template Without Attribute", `<div><template></template></div>`, false},
		{"Nested (Invalid)", `<div><span><template shadowrootmode="open"></template></span></div>`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := parseHTML(tt.html)
			host := firstElement(doc)
			actual := e.DetectShadowHost(host)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

// --- Tests for InstantiateShadowRoot ---

func TestInstantiateShadowRoot(t *testing.T) {
	e := Engine{}

	t.Run("Basic Instantiation", func(t *testing.T) {
		htmlInput := `<div><template shadowrootmode="open"><h1>Shadow</h1></template></div>`
		host := firstElement(parseHTML(htmlInput))

		shadowRoot, stylesheets := e.InstantiateShadowRoot(host)

		require.NotNil(t, shadowRoot)
		assert.Empty(t, stylesheets)
		assert.Equal(t, "shadow-root-boundary", shadowRoot.Data)

		h1 := firstElement(shadowRoot)
		require.NotNil(t, h1)
		assert.Equal(t, "h1", h1.Data)
	})

	t.Run("Style Extraction and Removal", func(t *testing.T) {
		htmlInput := `<div><template shadowrootmode="open">
			<style>h1 { color: red; }</style>
			<h1>Styled</h1>
			<style>p { margin: 10px; }</style>
		</template></div>`
		host := firstElement(parseHTML(htmlInput))

		shadowRoot, stylesheets := e.InstantiateShadowRoot(host)

		require.NotNil(t, shadowRoot)
		assert.Len(t, stylesheets, 2)

		// Check content of first stylesheet
		assert.Len(t, stylesheets[0].Rules, 1)
		assert.Equal(t, parser.Property("color"), stylesheets[0].Rules[0].Declarations[0].Property)

		// Verify <style> tags are removed
		for c := shadowRoot.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode {
				assert.NotEqual(t, "style", c.Data)
			}
		}
	})

	t.Run("Nested Templates Inert", func(t *testing.T) {
		htmlInput := `<div><template shadowrootmode="open">
			<div id="inner"><template shadowrootmode="open"><style>.inner {}</style></template></div>
		</template></div>`
		host := firstElement(parseHTML(htmlInput))

		shadowRoot, stylesheets := e.InstantiateShadowRoot(host)

		// Styles inside nested templates should not be processed yet
		assert.Empty(t, stylesheets)

		// The inner template should still exist as a <template> tag
		innerDiv := firstElement(shadowRoot)
		innerTemplate := firstElement(innerDiv)
		require.NotNil(t, innerTemplate)
		assert.Equal(t, "template", innerTemplate.Data)
	})
}

// --- Tests for AssignSlots ---

// Helper to create a mock StyledNode structure for testing slotting.
func setupSlotTest(t *testing.T, htmlInput string) (*style.StyledNode, *Engine) {
	e := Engine{}
	doc := parseHTML(htmlInput)
	hostNode := firstElement(doc)

	// Manually construct the StyledNode tree (Simplified mock)
	var buildMockTree func(*html.Node) *style.StyledNode
	buildMockTree = func(n *html.Node) *style.StyledNode {
		if n == nil { return nil }
		sn := &style.StyledNode{Node: n, ComputedStyles: make(map[parser.Property]parser.Value)}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
            // Include ElementNodes and non-empty TextNodes (which are slottable)
			if c.Type == html.ElementNode || (c.Type == html.TextNode && strings.TrimSpace(c.Data) != "") {
				if childSN := buildMockTree(c); childSN != nil {
					sn.Children = append(sn.Children, childSN)
				}
			}
		}
		return sn
	}

	hostSN := buildMockTree(hostNode)

	// Instantiate and attach the shadow root using the actual logic
	shadowRootNode, _ := e.InstantiateShadowRoot(hostNode)
	if shadowRootNode != nil {
		hostSN.ShadowRoot = buildMockTree(shadowRootNode)
	}
	return hostSN, &e
}

// Helper to find slots in the shadow tree
func findSlots(sn *style.StyledNode) map[string]*style.StyledNode {
	slots := make(map[string]*style.StyledNode)
	var traverse func(*style.StyledNode)
	traverse = func(n *style.StyledNode) {
		if n == nil { return }
		if n.Node.Type == html.ElementNode && n.Node.Data == "slot" {
			name := getAttr(n.Node, "name")
			if name == "" { name = "default" }
			// Handle multiple default slots for testing consumption order
			key := name
			if _, exists := slots[key]; exists && name == "default" {
				key = "default_next"
			}
			slots[key] = n
		}
		for _, child := range n.Children { traverse(child) }
	}
	if sn.ShadowRoot != nil {
		traverse(sn.ShadowRoot)
	}
	return slots
}

func TestAssignSlots(t *testing.T) {
	t.Run("Named and Default Slots", func(t *testing.T) {
		htmlInput := `<div>
			<template shadowrootmode="open">
				<slot name="header"></slot><slot></slot><slot name="footer"></slot>
			</template>
			<h1 slot="header">H1</h1>
			<p>P1</p>
			<span slot="footer">S1</span>
			<p>P2</p>
            <div slot="missing">D1</div>
		</div>`

		hostSN, e := setupSlotTest(t, htmlInput)
		e.AssignSlots(hostSN)
		slots := findSlots(hostSN)

		require.Len(t, slots["header"].SlotAssignment, 1)
		assert.Equal(t, "h1", slots["header"].SlotAssignment[0].Node.Data)

		require.Len(t, slots["footer"].SlotAssignment, 1)
		assert.Equal(t, "span", slots["footer"].SlotAssignment[0].Node.Data)

        // Default slot gets P1 and P2. D1 is not assigned as "missing" slot doesn't exist.
		require.Len(t, slots["default"].SlotAssignment, 2)
		assert.Equal(t, "p", slots["default"].SlotAssignment[0].Node.Data)
		assert.Equal(t, "p", slots["default"].SlotAssignment[1].Node.Data)
	})

	t.Run("Fallback Content (No Assignment)", func(t *testing.T) {
		htmlInput := `<div><template shadowrootmode="open">
			<slot name="empty"><span>Fallback</span></slot>
		</template></div>`

		hostSN, e := setupSlotTest(t, htmlInput)
		e.AssignSlots(hostSN)
		slots := findSlots(hostSN)

		// SlotAssignment should be empty, Children (fallback) should remain.
		assert.Empty(t, slots["empty"].SlotAssignment)
		assert.Len(t, slots["empty"].Children, 1)
	})

	t.Run("Slot Consumption Order", func(t *testing.T) {
		// Only the first default slot consumes the content.
		htmlInput := `<div><template shadowrootmode="open">
			<slot id="first"></slot><slot id="second"></slot>
		</template><p>Content</p></div>`

		hostSN, e := setupSlotTest(t, htmlInput)
		e.AssignSlots(hostSN)
		slots := findSlots(hostSN)

		// First default slot consumes the content.
		assert.Len(t, slots["default"].SlotAssignment, 1)
		// Second default slot remains empty.
		assert.Empty(t, slots["default_next"].SlotAssignment)
	})

	t.Run("Text Nodes", func(t *testing.T) {
		htmlInput := `<div><template shadowrootmode="open"><slot></slot></template> Hello World </div>`
		hostSN, e := setupSlotTest(t, htmlInput)
		e.AssignSlots(hostSN)
		slots := findSlots(hostSN)

		// Text nodes should be assigned.
		assert.NotEmpty(t, slots["default"].SlotAssignment)
		assert.Equal(t, html.TextNode, slots["default"].SlotAssignment[0].Node.Type)
	})
}