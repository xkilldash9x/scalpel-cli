// browser/parser/css_test.go
package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper functions to build expected structures concisely
func d(prop, val string, important bool) Declaration {
	return Declaration{Property: Property(prop), Value: Value(val), Important: important}
}

func s(tag, id string, classes []string, attrs []AttributeSelector) SimpleSelector {
	return SimpleSelector{TagName: tag, ID: id, Classes: classes, Attributes: attrs}
}

func cs(selectors ...SimpleSelectorWithCombinator) ComplexSelector {
	return ComplexSelector{Selectors: selectors}
}

func sc(c Combinator, sel SimpleSelector) SimpleSelectorWithCombinator {
	return SimpleSelectorWithCombinator{Combinator: c, SimpleSelector: sel}
}

func TestParseSimpleSelectorsAndAttributes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected SimpleSelector
	}{
		{"Tag", "div", s("div", "", nil, nil)},
		{"ID", "#main", s("", "main", nil, nil)},
		{"Class", ".button", s("", "", []string{"button"}, nil)},
		{"Multiple Classes", ".btn.primary", s("", "", []string{"btn", "primary"}, nil)},
		{"Combined", "input#username.required", s("input", "username", []string{"required"}, nil)},
		{"Universal", "*", s("*", "", nil, nil)},
		// Attribute Selectors
		{"Attr Presence", "[disabled]", s("", "", nil, []AttributeSelector{{Name: "disabled"}})},
		{"Attr Exact", `[type="text"]`, s("", "", nil, []AttributeSelector{{Name: "type", Operator: "=", Value: "text"}})},
		{"Attr Contains Word (~=)", `[class~="alert"]`, s("", "", nil, []AttributeSelector{{Name: "class", Operator: "~=", Value: "alert"}})},
		{"Attr Prefix Hyphen (|=)", `[lang|="en"]`, s("", "", nil, []AttributeSelector{{Name: "lang", Operator: "|=", Value: "en"}})},
		{"Attr Starts With (^=)", `[href^="https"]`, s("", "", nil, []AttributeSelector{{Name: "href", Operator: "^=", Value: "https"}})},
		{"Attr Ends With ($=)", `[src$=".png"]`, s("", "", nil, []AttributeSelector{{Name: "src", Operator: "$=", Value: ".png"}})},
		{"Attr Contains Substring (*=)", `[title*="ex"]`, s("", "", nil, []AttributeSelector{{Name: "title", Operator: "*=", Value: "ex"}})},
		{"Mixed", `a.external[target="_blank"]`, s("a", "", []string{"external"}, []AttributeSelector{{Name: "target", Operator: "=", Value: "_blank"}})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser(tt.input + " { }")
			// Use the internal parseSelectorGroups for direct testing
			selectorGroups := p.parseSelectorGroups()
			if len(selectorGroups) == 0 || len(selectorGroups[0]) == 0 || len(selectorGroups[0][0].Selectors) == 0 {
				t.Fatalf("Failed to parse selector group for input: %s", tt.input)
			}
			got := selectorGroups[0][0].Selectors[0].SimpleSelector
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestParseCombinators(t *testing.T) {
	input := `
		div p,
		article > section,
		h1 + h2,
		h2 ~ p,
		.container .item > span
		{}
	`
	p := NewParser(input)
	selectorGroups := p.parseSelectorGroups()

	if len(selectorGroups) == 0 || len(selectorGroups[0]) != 5 {
		t.Fatalf("Expected 5 complex selectors, got %d", len(selectorGroups[0]))
	}

	expected := []ComplexSelector{
		// div p (Descendant)
		cs(sc(CombinatorNone, s("div", "", nil, nil)), sc(CombinatorDescendant, s("p", "", nil, nil))),
		// article > section (Child)
		cs(sc(CombinatorNone, s("article", "", nil, nil)), sc(CombinatorChild, s("section", "", nil, nil))),
		// h1 + h2 (Adjacent Sibling)
		cs(sc(CombinatorNone, s("h1", "", nil, nil)), sc(CombinatorAdjacentSibling, s("h2", "", nil, nil))),
		// h2 ~ p (General Sibling)
		cs(sc(CombinatorNone, s("h2", "", nil, nil)), sc(CombinatorGeneralSibling, s("p", "", nil, nil))),
		// .container .item > span (Complex)
		cs(
			sc(CombinatorNone, s("", "", []string{"container"}, nil)),
			sc(CombinatorDescendant, s("", "", []string{"item"}, nil)),
			sc(CombinatorChild, s("span", "", nil, nil)),
		),
	}

	for i, exp := range expected {
		got := selectorGroups[0][i]
		assert.Equal(t, exp, got, "Mismatch for ComplexSelector %d", i)
	}
}

func TestParseDeclarations(t *testing.T) {
	input := `
	{
		color: red;
		font-size: 16px !important;
		margin: 10px 20px;
		border: none;
        /* Comment between declarations */
        padding: 0;
	}
	`
	p := NewParser(input)
	p.consumeWhitespace() // Advance to start of block

	got, err := p.parseDeclarations()
	assert.NoError(t, err)

	expected := []Declaration{
		d("color", "red", false),
		d("font-size", "16px", true),
		d("margin", "10px 20px", false),
		d("border", "none", false),
		d("padding", "0", false),
	}

	assert.Equal(t, expected, got)
}

func TestCalculateSpecificity(t *testing.T) {
	tests := []struct {
		input   string
		a, b, c int
	}{
		{"*", 0, 0, 0},
		{"li", 0, 0, 1},
		{"ul li", 0, 0, 2},
		{".class", 0, 1, 0},
		{`[type="text"]`, 0, 1, 0}, // Attributes count as classes
		{".class[attr]", 0, 2, 0},
		{"#id", 1, 0, 0},
		{"div#id.class", 1, 1, 1},
		{"#header .nav li.active", 1, 2, 1},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			p := NewParser(tt.input + " {}")
			selectorGroups := p.parseSelectorGroups()
			complexSelector := selectorGroups[0][0]
			a, b, c := complexSelector.CalculateSpecificity()
			assert.Equal(t, tt.a, a)
			assert.Equal(t, tt.b, b)
			assert.Equal(t, tt.c, c)
		})
	}
}

func TestEdgeCasesAndSkipping(t *testing.T) {
	t.Run("Skip Comments", func(t *testing.T) {
		input := `/* Start */ body { margin: 0; } /* End */`
		p := NewParser(input)
		sheet := p.Parse()
		assert.Len(t, sheet.Rules, 1)
		assert.Equal(t, Property("margin"), sheet.Rules[0].Declarations[0].Property)
	})

	t.Run("Skip At-Rules", func(t *testing.T) {
		input := `@media screen and (min-width: 900px) { div { display: none; } } p { color: blue; } @import "style.css";`
		p := NewParser(input)
		sheet := p.Parse()
		// Should skip @media and @import, only parsing 'p'.
		if assert.Len(t, sheet.Rules, 1) {
			assert.Equal(t, "p", sheet.Rules[0].SelectorGroups[0][0].Selectors[0].SimpleSelector.TagName)
		}
	})

	t.Run("Malformed Declarations Recovery", func(t *testing.T) {
		input := `{ color: ; font-size: 12px; border }`
		p := NewParser(input)
		p.consumeWhitespace()
		decls, _ := p.parseDeclarations()
		// Should recover and parse the valid declaration (font-size)
		assert.Len(t, decls, 1)
		assert.Equal(t, Property("font-size"), decls[0].Property)
	})
}