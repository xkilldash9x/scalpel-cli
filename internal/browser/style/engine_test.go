package style

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/html"
)

// Helpers (reusing MockShadowDOMProcessor and parseHTMLAndFind from selectors_test.go)

// Helper to set up the style engine with specific CSS.
func setupEngine(css string) *Engine {
	engine := NewEngine(&MockShadowDOMProcessor{})
	p := parser.NewParser(css)
	sheet := p.Parse()
	engine.AddAuthorSheet(sheet)
	return engine
}

// Helper to find a StyledNode by ID in the built tree.
func findStyledNodeByID(n *StyledNode, id string) *StyledNode {
	if n == nil { return nil }
	if n.Node.Type == html.ElementNode {
		for _, attr := range n.Node.Attr {
			if attr.Key == "id" && attr.Val == id {
				return n
			}
		}
	}
	for _, child := range n.Children {
		if found := findStyledNodeByID(child, id); found != nil {
			return found
		}
	}
	return nil
}


// --- Tests for The Cascade Algorithm ---

func TestCSSCascade(t *testing.T) {
	htmlInput := `<p id="target" class="highlight" style="color: inline;">Test</p>`
	targetNode := parseHTMLAndFind(htmlInput, "target")

	t.Run("Specificity Ordering", func(t *testing.T) {
		css := `
			#target { color: id; } /* 1,0,0 - Wins over class/tag */
			p.highlight { color: class; } /* 0,1,1 */
			p { color: tag; } /* 0,0,1 */
		`
		engine := setupEngine(css)
		
		// To test specificity in isolation from inline styles, we temporarily remove the style attribute.
		originalAttrs := targetNode.Attr
		targetNode.Attr = []html.Attribute{{Key: "id", Val: "target"}, {Key: "class", Val: "highlight"}}
		defer func() { targetNode.Attr = originalAttrs }()

		styles := engine.CalculateStyles(targetNode, engine.authorSheets)
		assert.Equal(t, "id", string(styles["color"]))
	})

	t.Run("!important Precedence", func(t *testing.T) {
		css := `
			p { color: tag !important; } /* Wins because it's !important */
			#target { color: id; }
		`
		engine := setupEngine(css)
		styles := engine.CalculateStyles(targetNode, engine.authorSheets)
		assert.Equal(t, "tag", string(styles["color"]))
	})

	t.Run("Inline vs Author", func(t *testing.T) {
		// Inline styles beat author styles (unless author is !important)
		css := `#target { color: id; }`
		engine := setupEngine(css)
		styles := engine.CalculateStyles(targetNode, engine.authorSheets)
		// Inline style="color: inline;"
		assert.Equal(t, "inline", string(styles["color"]))
	})

	t.Run("Author !important vs Inline", func(t *testing.T) {
		// Author !important beats inline (non-important)
		css := `#target { color: id !important; }`
		engine := setupEngine(css)
		styles := engine.CalculateStyles(targetNode, engine.authorSheets)
		// Based on calculateCascadePriority: Author !important (4) > Inline (3)
		assert.Equal(t, "id", string(styles["color"]))
	})
}

// --- Tests for Shorthand Expansion ---

func TestShorthandExpansion(t *testing.T) {
	htmlInput := `<div id="target"></div>`
	targetNode := parseHTMLAndFind(htmlInput, "target")

	t.Run("Margin/Padding (1-4 values)", func(t *testing.T) {
		css := `div {
			margin: 10px;               /* 10 10 10 10 */
			padding: 5px 20px;          /* 5 20 5 20 */
			border-width: 1px 2px 3px;  /* 1 2 3 2 */
		}`
		engine := setupEngine(css)
		styles := engine.CalculateStyles(targetNode, engine.authorSheets)

		assert.Equal(t, "10px", string(styles["margin-top"]))
		assert.Equal(t, "10px", string(styles["margin-left"]))

		assert.Equal(t, "5px", string(styles["padding-top"]))
		assert.Equal(t, "20px", string(styles["padding-right"]))

		assert.Equal(t, "1px", string(styles["border-top-width"]))
		assert.Equal(t, "2px", string(styles["border-left-width"])) // Left mirrors Right (3 values)
	})

	t.Run("Border Shorthand", func(t *testing.T) {
		engine := setupEngine(`div { border: 2px dashed red; }`)
		styles := engine.CalculateStyles(targetNode, engine.authorSheets)
		assert.Equal(t, "2px", string(styles["border-top-width"]))
		assert.Equal(t, "dashed", string(styles["border-right-style"]))
	})

	t.Run("Flex Shorthand", func(t *testing.T) {
		engine := setupEngine(`div { flex: 1 0 200px; }`)
		styles := engine.CalculateStyles(targetNode, engine.authorSheets)
		assert.Equal(t, "1", string(styles["flex-grow"]))
		assert.Equal(t, "0", string(styles["flex-shrink"]))
		assert.Equal(t, "200px", string(styles["flex-basis"]))
	})
}

// --- Tests for Inheritance and Value Resolution (BuildTree) ---

func TestInheritanceAndResolution(t *testing.T) {
	htmlInput := `
		<div id="parent" style="font-size: 20px; color: blue; border: 1px solid black;">
			<p id="child" style="font-size: 1.5em; line-height: 1.2;"></p>
			<span id="inherit-child" style="color: inherit;"></span>
		</div>
	`
	doc, _ := html.Parse(strings.NewReader(htmlInput))
	engine := setupEngine("") // Inline styles only
	engine.SetViewport(1000, 800)

	styleTree := engine.BuildTree(doc, nil)

	parent := findStyledNodeByID(styleTree, "parent")
	child := findStyledNodeByID(styleTree, "child")
	inheritChild := findStyledNodeByID(styleTree, "inherit-child")

	require.NotNil(t, parent)
	require.NotNil(t, child)

	t.Run("Default Inheritance", func(t *testing.T) {
		// Color should inherit.
		assert.Equal(t, "blue", child.Lookup("color", ""))
		// Border should not inherit.
		assert.Equal(t, "", child.Lookup("border-top-width", ""))
	})

	t.Run("Explicit Inherit", func(t *testing.T) {
		assert.Equal(t, "blue", inheritChild.Lookup("color", ""))
	})

	t.Run("Relative Unit Resolution (em)", func(t *testing.T) {
		// Parent: 20px
		assert.Equal(t, "20.000000px", parent.Lookup("font-size", ""))
		// Child: 1.5em * 20px = 30px
		assert.Equal(t, "30.000000px", child.Lookup("font-size", ""))
	})

	t.Run("Line Height Resolution (unitless)", func(t *testing.T) {
		// Child font-size is 30px. Line-height is 1.2.
		// Resolved line-height: 1.2 * 30px = 36px.
		assert.Equal(t, "36.000000px", child.Lookup("line-height", ""))
	})
}