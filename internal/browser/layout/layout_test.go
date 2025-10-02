// internal/browser/layout/layout_test.go
package layout_test

import (
	"strings"
	"testing"

	"github.com/antchfx/htmlquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/style"
	"golang.org/x/net/html"
)

// -- Mock for Style Engine Dependency --

// mockShadowDOMProcessor is a dummy implementation of the style.ShadowDOMProcessor
// interface, required to instantiate a style.Engine for our tests. It does nothing.
type mockShadowDOMProcessor struct{}

func (m *mockShadowDOMProcessor) DetectShadowHost(node *html.Node) bool { return false }
func (m *mockShadowDOMProcessor) InstantiateShadowRoot(host *html.Node) (*html.Node, []parser.StyleSheet) {
	return nil, nil
}
func (m *mockShadowDOMProcessor) AssignSlots(host *style.StyledNode) {}

// -- Test Helpers --

// setupLayoutTest is a convenience function to parse HTML and CSS, and run the layout engine.
// It now correctly reflects the two-engine architecture (style and layout).
func setupLayoutTest(t *testing.T, htmlString, cssString string, viewportWidth, viewportHeight float64) (*Engine, *LayoutBox) {
	t.Helper()

	// 1. Parse the HTML document.
	doc, err := htmlquery.Parse(strings.NewReader(htmlString))
	require.NoError(t, err, "Failed to parse test HTML")

	// The style engine expects the root element (<html>), not the document node.
	var rootNode *html.Node
	for n := doc.FirstChild; n != nil; n = n.NextSibling {
		if n.Type == html.ElementNode {
			rootNode = n
			break
		}
	}
	require.NotNil(t, rootNode, "Could not find root HTML element in parsed document")

	// 2. Set up the Style Engine.
	styleEngine := style.NewEngine(&mockShadowDOMProcessor{})
	styleEngine.SetViewport(viewportWidth, viewportHeight)

	// 3. Parse and add the CSS stylesheet.
	if cssString != "" {
		p := parser.NewParser(cssString)
		stylesheet := p.Parse()
		styleEngine.AddAuthorSheet(stylesheet)
	}

	// 4. Build the Style Tree.
	styleRoot := styleEngine.BuildTree(rootNode, nil)
	require.NotNil(t, styleRoot, "Style root should not be nil")

	// 5. Set up the Layout Engine.
	layoutEngine := NewEngine(viewportWidth, viewportHeight)

	// 6. Build the Layout Tree from the Style Tree.
	layoutRoot := layoutEngine.BuildAndLayoutTree(styleRoot)
	require.NotNil(t, layoutRoot, "Layout root should not be nil")

	return layoutEngine, layoutRoot
}

// -- Test Cases --

// TestFlexboxLayout_JustifyAndAlign verifies the core alignment properties of Flexbox.
func TestFlexboxLayout_JustifyAndAlign(t *testing.T) {
	html := `
	<div id="container">
	  <div id="item1"></div>
	  <div id="item2"></div>
	  <div id="item3"></div>
	</div>
	`
	css := `
	#container {
		width: 500px;
		height: 100px;
		display: flex;
		box-sizing: border-box; /* FIX: Added to make padding inclusive of width/height. */
		padding: 10px; /* Affects content area */
		justify-content: space-between;
		align-items: center;
	}
	#item1 { width: 50px; height: 50px; }
	#item2 { width: 50px; height: 80px; }
	#item3 { width: 50px; height: 30px; }
	`
	engine, root := setupLayoutTest(t, html, css, 600, 400)

	// -- Assertions --
	// Grab the geometry for each flex item.
	geo1, err1 := engine.GetElementGeometry(root, "//*[@id='item1']")
	geo2, err2 := engine.GetElementGeometry(root, "//*[@id='item2']")
	geo3, err3 := engine.GetElementGeometry(root, "//*[@id='item3']")

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.NoError(t, err3)

	// -- Verify justify-content: space-between --
	// Calculations are based on the container's CONTENT BOX.
	// Container is offset by body's 8px margin, but we test relative positions.
	// Content Box Width: 500px (width) - 10px (p-left) - 10px (p-right) = 480px.
	// Content Box Starts at X=8(body)+10(padding)=18 relative to viewport.
	// Total item width is 150px. Free space is 480 - 150 = 330px.
	// With 2 gaps, each gap is 330 / 2 = 165px.

	// Item 1 should be at the start of the content box.
	assert.InDelta(t, 18.0, geo1.Vertices[0], 0.1, "Item 1 X position")
	// Item 2 should be after item 1 and one gap: 18 (start) + 50 (item1) + 165 (gap) = 233.
	assert.InDelta(t, 233.0, geo2.Vertices[0], 0.1, "Item 2 X position")
	// Item 3 should be at the very end of the content box.
	// Start pos: 18 (start) + 480 (content width) - 50 (item3) = 448.
	assert.InDelta(t, 448.0, geo3.Vertices[0], 0.1, "Item 3 X position")

	// -- Verify align-items: center --
	// Calculations are based on the container's CONTENT BOX.
	// Content Box Height: 100px (height) - 10px (p-top) - 10px (p-bottom) = 80px.
	// Content Box Starts at Y=8(body)+10(padding)=18 relative to viewport.

	// Item 1 (50px high): 18 (start) + (80 - 50)/2 = 33.
	assert.InDelta(t, 33.0, geo1.Vertices[1], 0.1, "Item 1 Y position")
	// Item 2 (80px high): 18 (start) + (80 - 80)/2 = 18.
	assert.InDelta(t, 18.0, geo2.Vertices[1], 0.1, "Item 2 Y position")
	// Item 3 (30px high): 18 (start) + (80 - 30)/2 = 43.
	assert.InDelta(t, 43.0, geo3.Vertices[1], 0.1, "Item 3 Y position")
}

// TestAbsolutePositioning verifies an element is positioned relative to its containing block.
func TestAbsolutePositioning(t *testing.T) {
	html := `
	<div id="container">
	  <div id="absolute-child"></div>
	</div>
	`
	css := `
	body { margin: 8px; } /* Explicitly state for clarity, though it's in the UA sheet. */
	#container {
		position: relative;
		width: 300px;
		height: 300px;
		margin: 50px;
		padding: 20px;
		border: 10px solid black;
	}
	#absolute-child {
		position: absolute;
		top: 15px;
		left: 25px;
		width: 40px;
		height: 40px;
	}
	`
	engine, root := setupLayoutTest(t, html, css, 600, 400)

	geo, err := engine.GetElementGeometry(root, "//*[@id='absolute-child']")
	require.NoError(t, err)

	// The containing block is the PADDING box of the nearest positioned ancestor.
	// Body starts at (0,0) and has 8px margin.
	// Container starts at X=8(body margin) + 50(container margin) = 58.
	// Its padding box starts at X=58 + 10(border) = 68.
	// The child should be at:
	// X = 68 (container padding-box start) + 25 (left property) = 93
	// Y = 68 (container padding-box start) + 15 (top property) = 83
	assert.InDelta(t, 93.0, geo.Vertices[0], 0.1, "Absolute X position")
	assert.InDelta(t, 83.0, geo.Vertices[1], 0.1, "Absolute Y position")
	assert.Equal(t, int64(40), geo.Width, "Absolute width")
	assert.Equal(t, int64(40), geo.Height, "Absolute height")
}

// TestGridLayout_ExplicitPlacement verifies a simple grid with explicitly placed items.
func TestGridLayout_ExplicitPlacement(t *testing.T) {
	html := `
	<div id="grid">
	  <div id="itemA">A</div>
	  <div id="itemB">B</div>
	</div>
	`
	css := `
	body { margin: 8px; }
	#grid {
		display: grid;
		width: 400px;
		height: 300px;
		grid-template-columns: 100px 1fr;
		grid-template-rows: 50px 1fr;
	}
	#itemA {
		grid-column-start: 1;
		grid-row-start: 1;
	}
	#itemB {
		grid-column-start: 2;
		grid-row-start: 2;
	}
	`
	engine, root := setupLayoutTest(t, html, css, 600, 400)

	geoA, errA := engine.GetElementGeometry(root, "//*[@id='itemA']")
	geoB, errB := engine.GetElementGeometry(root, "//*[@id='itemB']")
	require.NoError(t, errA)
	require.NoError(t, errB)

	// Grid container starts at (8,8) due to body margin.
	// Item A: first column (100px wide), first row (50px high). Starts at container's content-box origin.
	assert.InDelta(t, 8.0, geoA.Vertices[0], 0.1, "Item A X position")
	assert.InDelta(t, 8.0, geoA.Vertices[1], 0.1, "Item A Y position")
	assert.Equal(t, int64(100), geoA.Width, "Item A width")
	assert.Equal(t, int64(50), geoA.Height, "Item A height")

	// Item B: second column (1fr = 300px), second row (1fr = 250px).
	// Position is relative to container: X=8+100=108, Y=8+50=58.
	assert.InDelta(t, 108.0, geoB.Vertices[0], 0.1, "Item B X position")
	assert.InDelta(t, 58.0, geoB.Vertices[1], 0.1, "Item B Y position")
	assert.Equal(t, int64(300), geoB.Width, "Item B width")
	assert.Equal(t, int64(250), geoB.Height, "Item B height")
}

// TestTransforms verifies that CSS transforms are correctly applied to the final vertices.
func TestTransforms(t *testing.T) {
	html := `<div id="transformed"></div>`
	css := `
	body { margin: 8px; }
	#transformed {
		width: 100px;
		height: 100px;
		transform-origin: 0 0; /* Top-left corner for simple calculation */
		transform: translate(50px, 50px) rotate(90deg);
	}
	`
	engine, root := setupLayoutTest(t, html, css, 600, 400)

	geo, err := engine.GetElementGeometry(root, "//*[@id='transformed']")
	require.NoError(t, err)

	// Original box is at (8,8) due to body margin.
	// Original corners relative to viewport: (8,8), (108,8), (108,108), (8,108)
	// Transform origin is (0,0) relative to the BOX, which is (8,8) in viewport space.
	// Rotation of 90deg is around (8,8).
	// After rotate(90deg) around (8,8):
	// (8,8) -> (8,8)
	// (108,8) -> (8, 108)
	// (108,108) -> (-92, 108) ... this gets complicated.
	// It's easier to calculate locally and then translate the whole result.
	//
	// Local corners: (0,0), (100,0), (100,100), (0,100)
	// After rotate(90deg) around (0,0): (0,0), (0,100), (-100,100), (-100,0)
	// After translate(50, 50): (-50, 50), (50, 150), (-50, 150), (-50, 50)
	// After translate(50, 50): (50, 50), (50, 150), (-50, 150), (-50, 50)
	// Final translation due to body margin: add (8,8) to all points.
	// Top-left: (50+8, 50+8) = (58, 58)
	// Top-right: (50+8, 150+8) = (58, 158)
	// Bottom-right: (-50+8, 150+8) = (-42, 158)
	// Bottom-left: (-50+8, 50+8) = (-42, 58)

	// Vertices are clockwise from top-left.
	assert.InDelta(t, 58.0, geo.Vertices[0], 0.1, "Transformed vertex 1 (X)")
	assert.InDelta(t, 58.0, geo.Vertices[1], 0.1, "Transformed vertex 1 (Y)")

	assert.InDelta(t, 58.0, geo.Vertices[2], 0.1, "Transformed vertex 2 (X)")
	assert.InDelta(t, 158.0, geo.Vertices[3], 0.1, "Transformed vertex 2 (Y)")

	assert.InDelta(t, -42.0, geo.Vertices[4], 0.1, "Transformed vertex 3 (X)")
	assert.InDelta(t, 158.0, geo.Vertices[5], 0.1, "Transformed vertex 3 (Y)")

	assert.InDelta(t, -42.0, geo.Vertices[6], 0.1, "Transformed vertex 4 (X)")
	assert.InDelta(t, 58.0, geo.Vertices[7], 0.1, "Transformed vertex 4 (Y)")

	// The AABB width and height should still be 100x100 for a 90-degree rotation.
	assert.Equal(t, int64(100), geo.Width)
	assert.Equal(t, int64(100), geo.Height)
}