// internal/browser/style/style.go
package style

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

// -- NEW INTERFACE TO BREAK IMPORT CYCLE --

// ShadowDOMProcessor defines the contract for a module that handles shadow DOM logic.
// This interface allows the style engine to remain decoupled from the concrete
// implementation of the shadow DOM engine, breaking the import cycle.
type ShadowDOMProcessor interface {
	DetectShadowHost(node *html.Node) bool
	InstantiateShadowRoot(host *html.Node) (*html.Node, []parser.StyleSheet)
	AssignSlots(host *StyledNode)
}

// -- Constants and Configuration --

const (
	BaseFontSize    = 16.0 // Default root font size.
	DefaultLineHeight = 1.2  // Default multiplier for 'line-height: normal'.
)

// DefaultUserAgentCSS is a minimal stylesheet compatible with the current parser capabilities.
// It provides basic rendering and intrinsic dimensions for form elements.
const DefaultUserAgentCSS = `
/* Basic Resets and Defaults */
div, p, h1, h2, h3, h4, h5, h6, body, html, ul, ol, li, form, header, footer, section, article, nav, main {
    display: block;
    margin: 0;
    padding: 0;
}

body {
    margin: 8px;
}

/* Typography (Simplified) */
h1 { font-size: 2em; margin: 0.67em 0; }
h2 { font-size: 1.5em; margin: 0.83em 0; }
p { margin: 1em 0; }

/* Lists */
ul, ol { padding-left: 40px; }
li { display: list-item; }

/* Form Elements - Crucial for layout stability */
input, button, textarea, select {
    display: inline-block;
    box-sizing: border-box;
    margin: 2px 0; /* Simplified margin */
    padding: 1px 2px; /* Simplified padding */
    border-width: 1px;
    border-style: solid;
    border-color: #767676; /* Simplified border */
    /* Use 'inherit' for font-size to respect parent styles, fallback handled by inheritance logic */
    font-size: inherit;
    line-height: normal;
}

/* Specific input types need default dimensions.
   We set a default for common text inputs and override specifics. */

/* Default width for text-like inputs */
input {
    width: 170px; /* Common default width (approx 20 chars) */
}

/* Apply width to specific types explicitly as well, as the parser might prioritize specific selectors */
input[type="text"], input[type="password"], input[type="email"], input[type="tel"], input[type="url"], input[type="number"] {
    width: 170px;
}

/* Checkboxes and Radios have specific intrinsic sizes */
input[type="checkbox"], input[type="radio"] {
    width: 13px;
    height: 13px;
    padding: 0; /* They usually don't use padding */
    margin: 3px;
}

/* Buttons use 'auto' width/height to allow layout engine to shrink-to-fit content */
button, input[type="submit"], input[type="button"], input[type="reset"] {
    width: auto;
    height: auto;
    padding: 1px 6px;
    text-align: center;
    cursor: default;
}

/* Links (using 'a' as pseudo-classes :link/:visited are unsupported) */
a {
    color: #0000EE;
    text-decoration: underline;
    cursor: pointer;
}
`

// -- Style Engine --

// Engine orchestrates the styling process, including the cascade,
// inheritance, and Shadow DOM style encapsulation.
type Engine struct {
	userAgentSheets []parser.StyleSheet
	authorSheets    []parser.StyleSheet
	shadowEngine    ShadowDOMProcessor
	viewportWidth   float64
	viewportHeight  float64
}

// NewEngine creates a new styling engine. It requires a ShadowDOMProcessor
// to handle shadow DOM instantiation and slotting.
func NewEngine(shadowEngine ShadowDOMProcessor) *Engine {
	// Parse the default User Agent stylesheet.
	p := parser.NewParser(DefaultUserAgentCSS)
	uaSheet := p.Parse()

	return &Engine{
		shadowEngine:    shadowEngine,
		userAgentSheets: []parser.StyleSheet{uaSheet}, // Initialize with the UA sheet
	}
}

// AddAuthorSheet adds a stylesheet provided by the webpage author.
func (se *Engine) AddAuthorSheet(sheet parser.StyleSheet) {
	se.authorSheets = append(se.authorSheets, sheet)
}

// SetViewport sets the dimensions used for viewport-relative units.
func (se *Engine) SetViewport(width, height float64) {
	se.viewportWidth = width
	se.viewportHeight = height
}

// -- Canonical Data Structures --

// StyledNode represents a DOM node combined with its computed styles.
type StyledNode struct {
	Node           *html.Node
	ComputedStyles map[parser.Property]parser.Value
	Children       []*StyledNode
	ShadowRoot     *StyledNode
	SlotAssignment []*StyledNode
}

// Color represents an RGBA color.
type Color struct {
	R, G, B, A uint8
}

var cssColors = map[string]Color{
	"black":       {0, 0, 0, 255},
	"white":       {255, 255, 255, 255},
	"red":         {255, 0, 0, 255},
	"green":       {0, 128, 0, 255},
	"blue":        {0, 0, 255, 255},
	"transparent": {0, 0, 0, 0},
}

type GridTrackDefinition struct {
	Size      string
	LineNames []string
}

type GridLine struct {
	IsAuto      bool
	IsNamedSpan bool
	Span        int
	Line        int
	Name        string
}

// -- Style Tree Construction (The Cascade and Inheritance) --

func (se *Engine) BuildTree(node *html.Node, parent *StyledNode) *StyledNode {
	return se.buildTreeRecursive(node, parent, se.authorSheets)
}

func (se *Engine) buildTreeRecursive(node *html.Node, parent *StyledNode, scopedSheets []parser.StyleSheet) *StyledNode {
	if node.Type == html.CommentNode {
		return nil
	}
	if parent != nil && parent.Node != nil && parent.Node.Type == html.ElementNode && strings.ToLower(parent.Node.Data) == "html" {
		if node.Type == html.ElementNode && strings.ToLower(node.Data) == "head" {
			return nil
		}
	}

	computedStyles := make(map[parser.Property]parser.Value)
	if node.Type == html.ElementNode {
		computedStyles = se.CalculateStyles(node, scopedSheets)
	}

	styledNode := &StyledNode{
		Node:           node,
		ComputedStyles: computedStyles,
	}

	if parent != nil {
		se.inheritStyles(styledNode, parent)
	} else {
		se.applyRootDefaults(styledNode)
	}

	se.resolveRelativeValues(styledNode, parent)

	if se.shadowEngine.DetectShadowHost(node) {
		shadowRootNode, shadowScopedSheets := se.shadowEngine.InstantiateShadowRoot(node)
		if shadowRootNode != nil {
			styledNode.ShadowRoot = se.buildTreeRecursive(shadowRootNode, styledNode, shadowScopedSheets)
		}
	}

	for c := node.FirstChild; c != nil; c = c.NextSibling {
		childStyled := se.buildTreeRecursive(c, styledNode, scopedSheets)
		if childStyled != nil {
			styledNode.Children = append(styledNode.Children, childStyled)
		}
	}

	return styledNode
}

func (se *Engine) applyRootDefaults(sn *StyledNode) {
	if _, exists := sn.ComputedStyles["font-size"]; !exists {
		sn.ComputedStyles["font-size"] = parser.Value(fmt.Sprintf("%fpx", BaseFontSize))
	}
}

func (se *Engine) inheritStyles(child, parent *StyledNode) {
	inheritableProperties := map[parser.Property]bool{
		"color": true, "font-family": true, "font-size": true, "font-weight": true,
		"line-height": true, "text-align": true, "visibility": true, "cursor": true,
	}

	for prop, val := range child.ComputedStyles {
		if val == "inherit" {
			if parentVal, parentHas := parent.ComputedStyles[prop]; parentHas {
				child.ComputedStyles[prop] = parentVal
			}
		}
	}

	for prop := range inheritableProperties {
		if _, exists := child.ComputedStyles[prop]; !exists {
			if val, parentHas := parent.ComputedStyles[prop]; parentHas {
				child.ComputedStyles[prop] = val
			}
		}
	}
}

func (se *Engine) resolveRelativeValues(sn *StyledNode, parent *StyledNode) {
	parentFontSize := BaseFontSize
	if parent != nil {
		parentFontSize = ParseAbsoluteLength(parent.Lookup("font-size", fmt.Sprintf("%fpx", BaseFontSize)))
	}

	if fontSizeStr, ok := sn.ComputedStyles["font-size"]; ok {
		resolvedFontSize := ParseLengthWithUnits(string(fontSizeStr), parentFontSize, BaseFontSize, parentFontSize, se.viewportWidth, se.viewportHeight)
		sn.ComputedStyles["font-size"] = parser.Value(fmt.Sprintf("%fpx", resolvedFontSize))
	}

	currentFontSize := ParseAbsoluteLength(sn.Lookup("font-size", fmt.Sprintf("%fpx", BaseFontSize)))

	if lineHeightStr, ok := sn.ComputedStyles["line-height"]; ok {
		resolvedLineHeight := se.resolveLineHeight(string(lineHeightStr), currentFontSize)
		sn.ComputedStyles["line-height"] = parser.Value(fmt.Sprintf("%fpx", resolvedLineHeight))
	}
}

func (se *Engine) resolveLineHeight(value string, fontSize float64) float64 {
	value = strings.TrimSpace(value)
	if value == "normal" {
		return fontSize * DefaultLineHeight
	}

	if val, err := parseFloat(value); err == nil && !strings.ContainsAny(value, "px%emremvwvhvminvmax") {
		return fontSize * val
	}

	return ParseLengthWithUnits(value, fontSize, BaseFontSize, 0, se.viewportWidth, se.viewportHeight)
}

type StyleOrigin int

const (
	OriginUserAgent StyleOrigin = iota
	OriginAuthor
	OriginInline
)

type DeclarationWithContext struct {
	Declaration parser.Declaration
	Specificity struct{ A, B, C int }
	Origin      StyleOrigin
	Order       int
}

func (se *Engine) CalculateStyles(node *html.Node, scopedSheets []parser.StyleSheet) map[parser.Property]parser.Value {
	var declarations []DeclarationWithContext
	order := 0

	processSheets := func(sheets []parser.StyleSheet, origin StyleOrigin) {
		for _, sheet := range sheets {
			for _, rule := range sheet.Rules {
				for _, selectorGroup := range rule.SelectorGroups {
					if matchingComplexSelector, ok := se.matches(node, selectorGroup); ok {
						a, b, c := matchingComplexSelector.CalculateSpecificity()
						for _, decl := range rule.Declarations {
							declarations = append(declarations, DeclarationWithContext{
								Declaration: decl,
								Specificity: struct{ A, B, C int }{a, b, c},
								Origin:      origin,
								Order:       order,
							})
							order++
						}
						break
					}
				}
			}
		}
	}

	processSheets(se.userAgentSheets, OriginUserAgent)
	processSheets(scopedSheets, OriginAuthor)

	for _, attr := range node.Attr {
		if attr.Key == "style" {
			inlineDecls := parseInlineStyles(attr.Val)
			for _, decl := range inlineDecls {
				declarations = append(declarations, DeclarationWithContext{
					Declaration: decl,
					Specificity: struct{ A, B, C int }{1, 0, 0},
					Origin:      OriginInline,
					Order:       order,
				})
				order++
			}
		}
	}

	sort.Slice(declarations, func(i, j int) bool {
		d1, d2 := declarations[i], declarations[j]
		p1, p2 := calculateCascadePriority(d1), calculateCascadePriority(d2)
		if p1 != p2 {
			return p1 < p2
		}
		s1, s2 := d1.Specificity, d2.Specificity
		if s1.A != s2.A {
			return s1.A < s2.A
		}
		if s1.B != s2.B {
			return s1.B < s2.B
		}
		if s1.C != s2.C {
			return s1.C < s2.C
		}
		return d1.Order < d2.Order
	})

	styles := make(map[parser.Property]parser.Value)
	for _, declCtx := range declarations {
		styles[declCtx.Declaration.Property] = declCtx.Declaration.Value
	}

	expandShorthands(styles)
	return styles
}

func expandShorthands(styles map[parser.Property]parser.Value) {
	expandFlexShorthand(styles)
	expand1To4Shorthand(styles, "margin", "margin-top", "margin-right", "margin-bottom", "margin-left")
	expand1To4Shorthand(styles, "padding", "padding-top", "padding-right", "padding-bottom", "padding-left")
	expand1To4Shorthand(styles, "border-width", "border-top-width", "border-right-width", "border-bottom-width", "border-left-width")

	if borderVal, ok := styles["border"]; ok {
		parts := strings.Fields(string(borderVal))
		width, styleVal := "medium", "none"
		foundWidth, foundStyle := false, false
		for _, part := range parts {
			if !foundWidth && (strings.ContainsAny(part, "px%emremvwvh") || (len(part) > 0 && (part[0] >= '0' && part[0] <= '9')) || part == "thin" || part == "medium" || part == "thick") {
				width = part
				foundWidth = true
			} else if !foundStyle && (part == "solid" || part == "dashed" || part == "dotted" || part == "double" || part == "none" || part == "hidden") {
				styleVal = part
				foundStyle = true
			}
		}
		for _, side := range []string{"top", "right", "bottom", "left"} {
			styles[parser.Property("border-"+side+"-width")] = parser.Value(width)
			styles[parser.Property("border-"+side+"-style")] = parser.Value(styleVal)
		}
	}
}

func expand1To4Shorthand(styles map[parser.Property]parser.Value, shorthand, top, right, bottom, left parser.Property) {
	val, ok := styles[shorthand]
	if !ok {
		return
	}
	parts := strings.Fields(string(val))
	switch len(parts) {
	case 1:
		v1 := parser.Value(parts[0])
		styles[top], styles[right], styles[bottom], styles[left] = v1, v1, v1, v1
	case 2:
		v1, v2 := parser.Value(parts[0]), parser.Value(parts[1])
		styles[top], styles[right], styles[bottom], styles[left] = v1, v2, v1, v2
	case 3:
		v1, v2, v3 := parser.Value(parts[0]), parser.Value(parts[1]), parser.Value(parts[2])
		styles[top], styles[right], styles[bottom], styles[left] = v1, v2, v3, v2
	case 4:
		v1, v2, v3, v4 := parser.Value(parts[0]), parser.Value(parts[1]), parser.Value(parts[2]), parser.Value(parts[3])
		styles[top], styles[right], styles[bottom], styles[left] = v1, v2, v3, v4
	}
}

func expandFlexShorthand(styles map[parser.Property]parser.Value) {
	flexVal, ok := styles["flex"]
	if !ok {
		return
	}
	grow, shrink, basis := "0", "1", "auto"
	parts := strings.Fields(string(flexVal))
	isLengthCheck := func(s string) bool {
		return strings.ContainsAny(s, "px%emremvwvhvminvmax") || (s == "0" && len(s) == 1)
	}

	if len(parts) == 1 {
		switch parts[0] {
		case "none":
			grow, shrink, basis = "0", "0", "auto"
		case "auto":
			grow, shrink, basis = "1", "1", "auto"
		default:
			isLength := isLengthCheck(parts[0])
			if _, err := parseFloat(parts[0]); err == nil && !isLength {
				grow = parts[0]
			} else {
				basis = parts[0]
				grow = "1"
				shrink = "1"
			}
		}
	} else if len(parts) == 2 {
		grow = parts[0]
		isLength := isLengthCheck(parts[1])
		if _, err := parseFloat(parts[1]); err == nil && !isLength {
			shrink = parts[1]
		} else {
			basis = parts[1]
		}
	} else if len(parts) >= 3 {
		grow = parts[0]
		shrink = parts[1]
		basis = parts[2]
	}

	styles["flex-grow"] = parser.Value(grow)
	styles["flex-shrink"] = parser.Value(shrink)
	styles["flex-basis"] = parser.Value(basis)
}

func calculateCascadePriority(d DeclarationWithContext) int {
	isImportant := d.Declaration.Important
	switch d.Origin {
	case OriginUserAgent:
		if isImportant {
			return 5
		}
		return 1
	case OriginAuthor:
		if isImportant {
			return 4
		}
		return 2
	case OriginInline:
		if isImportant {
			return 4
		}
		return 3
	}
	return 0
}

func parseInlineStyles(styleAttr string) []parser.Declaration {
	var decls []parser.Declaration
	parts := strings.Split(styleAttr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			prop, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
			important := false
			if strings.HasSuffix(strings.ToLower(val), "!important") {
				important = true
				val = strings.TrimSpace(val[:len(val)-len("!important")])
			}
			decls = append(decls, parser.Declaration{
				Property: parser.Property(prop), Value: parser.Value(val), Important: important,
			})
		}
	}
	return decls
}

func (se *Engine) matches(node *html.Node, group parser.SelectorGroup) (*parser.ComplexSelector, bool) {
	if node.Type != html.ElementNode {
		return nil, false
	}
	for _, complexSelector := range group {
		currentIndex := len(complexSelector.Selectors) - 1
		if currentIndex < 0 {
			continue
		}
		if se.recursiveMatch(node, complexSelector, currentIndex) {
			return &complexSelector, true
		}
	}
	return nil, false
}

func (se *Engine) recursiveMatch(node *html.Node, complexSelector parser.ComplexSelector, index int) bool {
	if node == nil || index < 0 {
		return false
	}
	if node.Type != html.ElementNode {
		return false
	}
	currentSelectorWithCombinator := complexSelector.Selectors[index]
	if !se.matchesSimple(node, currentSelectorWithCombinator.SimpleSelector) {
		return false
	}
	if index == 0 {
		return true
	}
	nextIndex := index - 1
	combinator := currentSelectorWithCombinator.Combinator
	switch combinator {
	case parser.CombinatorDescendant:
		for parent := node.Parent; parent != nil; parent = parent.Parent {
			if se.recursiveMatch(parent, complexSelector, nextIndex) {
				return true
			}
		}
		return false
	case parser.CombinatorChild:
		return se.recursiveMatch(node.Parent, complexSelector, nextIndex)
	case parser.CombinatorAdjacentSibling:
		prevSibling := getPreviousElementSibling(node)
		return se.recursiveMatch(prevSibling, complexSelector, nextIndex)
	case parser.CombinatorGeneralSibling:
		for sibling := getPreviousElementSibling(node); sibling != nil; sibling = getPreviousElementSibling(sibling) {
			if se.recursiveMatch(sibling, complexSelector, nextIndex) {
				return true
			}
		}
		return false
	case parser.CombinatorNone:
		return true
	}
	return false
}

func getPreviousElementSibling(node *html.Node) *html.Node {
	sibling := node.PrevSibling
	for sibling != nil {
		if sibling.Type == html.ElementNode {
			return sibling
		}
		sibling = sibling.PrevSibling
	}
	return nil
}

func (se *Engine) matchesSimple(node *html.Node, selector parser.SimpleSelector) bool {
	if selector.TagName != "" && selector.TagName != "*" && strings.ToLower(node.Data) != selector.TagName {
		return false
	}
	if selector.ID != "" {
		idFound := false
		for _, attr := range node.Attr {
			if attr.Key == "id" && attr.Val == selector.ID {
				idFound = true
				break
			}
		}
		if !idFound {
			return false
		}
	}
	if len(selector.Classes) > 0 {
		var nodeClasses []string
		for _, attr := range node.Attr {
			if attr.Key == "class" {
				nodeClasses = strings.Fields(attr.Val)
				break
			}
		}
		for _, requiredClass := range selector.Classes {
			found := false
			for _, nodeClass := range nodeClasses {
				if nodeClass == requiredClass {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	if len(selector.Attributes) > 0 {
		for _, attrSel := range selector.Attributes {
			if !matchesAttribute(node, attrSel) {
				return false
			}
		}
	}

	return true
}

func matchesAttribute(node *html.Node, sel parser.AttributeSelector) bool {
	var actualValue string
	found := false
	for _, attr := range node.Attr {
		if strings.EqualFold(attr.Key, sel.Name) {
			actualValue = attr.Val
			found = true
			break
		}
	}

	switch sel.Operator {
	case "":
		return found
	case "=":
		return found && actualValue == sel.Value
	case "~=":
		if !found {
			return false
		}
		words := strings.Fields(actualValue)
		for _, word := range words {
			if word == sel.Value {
				return true
			}
		}
		return false
	case "|=":
		return found && (actualValue == sel.Value || strings.HasPrefix(actualValue, sel.Value+"-"))
	case "^=":
		return found && strings.HasPrefix(actualValue, sel.Value)
	case "$=":
		return found && strings.HasSuffix(actualValue, sel.Value)
	case "*=":
		return found && strings.Contains(actualValue, sel.Value)
	default:
		return false
	}
}

func (sn *StyledNode) Lookup(property, fallback string) string {
	if val, ok := sn.ComputedStyles[parser.Property(property)]; ok {
		return string(val)
	}
	return fallback
}

func ParseColor(value string) (Color, bool) {
	value = strings.TrimSpace(strings.ToLower(value))

	if color, ok := cssColors[value]; ok {
		return color, true
	}

	if strings.HasPrefix(value, "#") {
		return parseHexColor(value)
	}

	if strings.HasPrefix(value, "rgb") {
		return parseRGBColor(value)
	}

	return Color{0, 0, 0, 255}, false
}

func parseHexColor(hex string) (Color, bool) {
	hex = strings.TrimPrefix(hex, "#")
	var r, g, b, a uint8 = 0, 0, 0, 255

	switch len(hex) {
	case 3:
		r = hexDigit(hex[0]) * 17
		g = hexDigit(hex[1]) * 17
		b = hexDigit(hex[2]) * 17
	case 4:
		r = hexDigit(hex[0]) * 17
		g = hexDigit(hex[1]) * 17
		b = hexDigit(hex[2]) * 17
		a = hexDigit(hex[3]) * 17
	case 6:
		r = hexDigit(hex[0])<<4 | hexDigit(hex[1])
		g = hexDigit(hex[2])<<4 | hexDigit(hex[3])
		b = hexDigit(hex[4])<<4 | hexDigit(hex[5])
	case 8:
		r = hexDigit(hex[0])<<4 | hexDigit(hex[1])
		g = hexDigit(hex[2])<<4 | hexDigit(hex[3])
		b = hexDigit(hex[4])<<4 | hexDigit(hex[5])
		a = hexDigit(hex[6])<<4 | hexDigit(hex[7])
	default:
		return Color{}, false
	}
	return Color{R: r, G: g, B: b, A: a}, true
}

func hexDigit(c byte) uint8 {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

var rgbRegex = regexp.MustCompile(`rgba?\((.*?)\)`)

func parseRGBColor(value string) (Color, bool) {
	matches := rgbRegex.FindStringSubmatch(value)
	if len(matches) != 2 {
		return Color{}, false
	}

	parts := strings.FieldsFunc(matches[1], func(r rune) bool {
		return r == ',' || r == ' ' || r == '/'
	})

	var values []string
	for _, p := range parts {
		if p != "" {
			if len(values) < 4 {
				values = append(values, p)
			}
		}
	}

	if len(values) < 3 || len(values) > 4 {
		return Color{}, false
	}

	r := parseColorComponent(values[0], false)
	g := parseColorComponent(values[1], false)
	b := parseColorComponent(values[2], false)
	a := uint8(255)

	if len(values) == 4 {
		a = parseColorComponent(values[3], true)
	}

	return Color{R: r, G: g, B: b, A: a}, true
}

func parseColorComponent(value string, isAlpha bool) uint8 {
	value = strings.TrimSpace(value)

	if strings.HasSuffix(value, "%") {
		percent, err := strconv.ParseFloat(strings.TrimSuffix(value, "%"), 64)
		if err != nil {
			return 0
		}
		return uint8(clamp(percent/100.0*255.0+0.5, 0, 255))
	}

	if isAlpha {
		val, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return 255
		}
		return uint8(clamp(val*255.0+0.5, 0, 255))
	}

	val, err := strconv.Atoi(value)
	if err != nil {
		if fval, err := strconv.ParseFloat(value, 64); err == nil {
			return uint8(clamp(fval+0.5, 0, 255))
		}
		return 0
	}
	return uint8(clamp(float64(val), 0, 255))
}

func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

type DisplayType int

const (
	DisplayInline DisplayType = iota
	DisplayBlock
	DisplayInlineBlock
	DisplayFlex
	DisplayGrid
	DisplayTable
	DisplayTableRow
	DisplayTableCell
	DisplayNone
)

func (sn *StyledNode) Display() DisplayType {
	if sn.Node.Type == html.TextNode {
		return DisplayInline
	}

	if display, ok := sn.ComputedStyles["display"]; ok {
		switch display {
		case "block":
			return DisplayBlock
		case "flex":
			return DisplayFlex
		case "grid":
			return DisplayGrid
		case "table":
			return DisplayTable
		case "table-row":
			return DisplayTableRow
		case "table-cell":
			return DisplayTableCell
		case "none":
			return DisplayNone
		case "inline-block":
			return DisplayInlineBlock
		case "inline":
			return DisplayInline
		}
	}
	return getDefaultDisplay(sn.Node)
}

type PositionType int

const (
	PositionStatic PositionType = iota
	PositionRelative
	PositionAbsolute
	PositionFixed
)

func (sn *StyledNode) Position() PositionType {
	switch sn.Lookup("position", "static") {
	case "relative":
		return PositionRelative
	case "absolute":
		return PositionAbsolute
	case "fixed":
		return PositionFixed
	default:
		return PositionStatic
	}
}

type FloatType int

const (
	FloatNone FloatType = iota
	FloatLeft
	FloatRight
)

func (sn *StyledNode) Float() FloatType {
	switch sn.Lookup("float", "none") {
	case "left":
		return FloatLeft
	case "right":
		return FloatRight
	default:
		return FloatNone
	}
}

type ClearType int

const (
	ClearNone ClearType = iota
	ClearLeft
	ClearRight
	ClearBoth
)

func (sn *StyledNode) Clear() ClearType {
	switch sn.Lookup("clear", "none") {
	case "left":
		return ClearLeft
	case "right":
		return ClearRight
	case "both":
		return ClearBoth
	default:
		return ClearNone
	}
}

type BoxSizingType int

const (
	ContentBox BoxSizingType = iota
	BorderBox
)

func (sn *StyledNode) BoxSizing() BoxSizingType {
	if sn.Lookup("box-sizing", "content-box") == "border-box" {
		return BorderBox
	}
	return ContentBox
}

type FlexDirection int

const (
	FlexDirectionRow FlexDirection = iota
	FlexDirectionRowReverse
	FlexDirectionColumn
	FlexDirectionColumnReverse
)

func (sn *StyledNode) GetFlexDirection() FlexDirection {
	switch sn.Lookup("flex-direction", "row") {
	case "column":
		return FlexDirectionColumn
	case "row-reverse":
		return FlexDirectionRowReverse
	case "column-reverse":
		return FlexDirectionColumnReverse
	default:
		return FlexDirectionRow
	}
}

type FlexWrap int

const (
	FlexNoWrap FlexWrap = iota
	FlexWrapValue
	FlexWrapReverse
)

func (sn *StyledNode) GetFlexWrap() FlexWrap {
	switch sn.Lookup("flex-wrap", "nowrap") {
	case "wrap":
		return FlexWrapValue
	case "wrap-reverse":
		return FlexWrapReverse
	default:
		return FlexNoWrap
	}
}

type JustifyContent int

const (
	JustifyFlexStart JustifyContent = iota
	JustifyFlexEnd
	JustifyCenter
	JustifySpaceBetween
	JustifySpaceAround
	JustifySpaceEvenly
)

func (sn *StyledNode) GetJustifyContent() JustifyContent {
	switch sn.Lookup("justify-content", "flex-start") {
	case "flex-end":
		return JustifyFlexEnd
	case "center":
		return JustifyCenter
	case "space-between":
		return JustifySpaceBetween
	case "space-around":
		return JustifySpaceAround
	case "space-evenly":
		return JustifySpaceEvenly
	default:
		return JustifyFlexStart
	}
}

type AlignItems int

const (
	AlignStretch AlignItems = iota
	AlignFlexStart
	AlignCenter
	AlignFlexEnd
	AlignBaseline
)

func (sn *StyledNode) GetAlignItems() AlignItems {
	switch sn.Lookup("align-items", "stretch") {
	case "flex-start":
		return AlignFlexStart
	case "center":
		return AlignCenter
	case "flex-end":
		return AlignFlexEnd
	case "baseline":
		return AlignBaseline
	default:
		return AlignStretch
	}
}

type AlignSelf int

const (
	AlignSelfAuto AlignSelf = iota
	AlignSelfStretch
	AlignSelfFlexStart
	AlignSelfCenter
	AlignSelfFlexEnd
	AlignSelfBaseline
)

func (sn *StyledNode) GetAlignSelf() AlignSelf {
	switch sn.Lookup("align-self", "auto") {
	case "stretch":
		return AlignSelfStretch
	case "flex-start":
		return AlignSelfFlexStart
	case "center":
		return AlignSelfCenter
	case "flex-end":
		return AlignSelfFlexEnd
	case "baseline":
		return AlignSelfBaseline
	default:
		return AlignSelfAuto
	}
}

type AlignContent int

const (
	AlignContentStretch AlignContent = iota
	AlignContentFlexStart
	AlignContentFlexEnd
	AlignContentCenter
	AlignContentSpaceBetween
	AlignContentSpaceAround
	AlignContentSpaceEvenly
)

func (sn *StyledNode) GetAlignContent() AlignContent {
	switch sn.Lookup("align-content", "stretch") {
	case "flex-start":
		return AlignContentFlexStart
	case "flex-end":
		return AlignContentFlexEnd
	case "center":
		return AlignContentCenter
	case "space-between":
		return AlignContentSpaceBetween
	case "space-around":
		return AlignContentSpaceAround
	case "space-evenly":
		return AlignContentSpaceEvenly
	default:
		return AlignContentStretch
	}
}

func (sn *StyledNode) IsVisible() bool {
	if sn.Display() == DisplayNone {
		return false
	}
	visibility := sn.Lookup("visibility", "visible")
	if visibility == "hidden" || visibility == "collapse" {
		return false
	}
	opacityStr := sn.Lookup("opacity", "1.0")
	if opacity, err := strconv.ParseFloat(opacityStr, 64); err == nil && opacity <= 0.0 {
		return false
	}
	return true
}

var repeatRegex = regexp.MustCompile(`repeat\(\s*(\d+)\s*,\s*([^)]+)\)`)

func isWhitespace(r byte) bool {
	return r == ' ' || r == '\t' || r == '\n'
}

func tokenizeGridTracks(value string) []string {
	var tokens []string
	for i := 0; i < len(value); {
		if isWhitespace(value[i]) {
			i++
			continue
		}
		if value[i] == '[' {
			start := i
			end := strings.IndexRune(value[start:], ']')
			if end == -1 {
				tokens = append(tokens, value[start:])
				break
			}
			tokens = append(tokens, value[start:start+end+1])
			i = start + end + 1
		} else {
			start := i
			parenDepth := 0
			inQuotes := false
			var quoteChar byte = ' '

			for ; i < len(value); i++ {
				char := value[i]
				if (char == '"' || char == '\'') && !inQuotes {
					inQuotes = true
					quoteChar = char
				} else if char == quoteChar && inQuotes {
					inQuotes = false
				}
				if char == '(' && !inQuotes {
					parenDepth++
				} else if char == ')' && !inQuotes {
					parenDepth--
				} else if isWhitespace(char) && parenDepth == 0 && !inQuotes {
					break
				}
			}
			tokens = append(tokens, value[start:i])
		}
	}
	return tokens
}

func (sn *StyledNode) GetGridTemplateTracks(property string) ([]GridTrackDefinition, []string) {
	value := sn.Lookup(property, "none")
	if value == "none" || value == "" {
		return nil, nil
	}
	expandedValue := repeatRegex.ReplaceAllStringFunc(value, func(match string) string {
		submatches := repeatRegex.FindStringSubmatch(match)
		if len(submatches) < 3 {
			observability.GetLogger().Warn("Malformed repeat() function", zap.String("match", match))
			return ""
		}
		count, err := strconv.Atoi(submatches[1])
		if err != nil {
			observability.GetLogger().Warn("Invalid count in repeat()", zap.String("count_val", submatches[1]), zap.Error(err))
			return ""
		}
		tracksToRepeat := submatches[2]
		return strings.TrimSpace(strings.Repeat(tracksToRepeat+" ", count))
	})

	var definitions []GridTrackDefinition
	var currentNames []string
	tokens := tokenizeGridTracks(expandedValue)

	for _, token := range tokens {
		if strings.HasPrefix(token, "[") {
			names := strings.Fields(strings.Trim(token, "[]"))
			currentNames = append(currentNames, names...)
		} else {
			definitions = append(definitions, GridTrackDefinition{
				Size:      token,
				LineNames: currentNames,
			})
			currentNames = nil
		}
	}
	return definitions, currentNames
}

func (sn *StyledNode) ParseGridLine(property, fallback string) GridLine {
	value := strings.TrimSpace(sn.Lookup(property, fallback))

	if value == "auto" {
		return GridLine{IsAuto: true}
	}
	if strings.HasPrefix(value, "span ") {
		spanValue := strings.TrimSpace(strings.TrimPrefix(value, "span "))
		if span, err := strconv.Atoi(spanValue); err == nil {
			return GridLine{Span: span}
		}
		return GridLine{Name: spanValue, IsNamedSpan: true}
	}
	if line, err := strconv.Atoi(value); err == nil {
		return GridLine{Line: line}
	}
	return GridLine{Name: value}
}

func getDefaultDisplay(node *html.Node) DisplayType {
	if node.Type != html.ElementNode {
		return DisplayInline
	}
	switch strings.ToLower(node.Data) {
	case "html", "body", "div", "p", "h1", "h2", "h3", "h4", "h5", "h6",
		"ul", "ol", "li", "form", "header", "footer", "section", "article", "nav", "main":
		return DisplayBlock
	case "table":
		return DisplayTable
	case "tr":
		return DisplayTableRow
	case "td", "th":
		return DisplayTableCell
	case "input", "button", "textarea", "select", "img":
		return DisplayInlineBlock
	default:
		return DisplayInline
	}
}

func GetFontSize(sn *StyledNode) float64 {
	if sn == nil {
		return BaseFontSize
	}
	return ParseAbsoluteLength(sn.Lookup("font-size", fmt.Sprintf("%fpx", BaseFontSize)))
}

func ParseLengthWithUnits(value string, parentFontSize, rootFontSize, referenceDimension, viewportWidth, viewportHeight float64) float64 {
	value = strings.TrimSpace(value)
	if value == "" || value == "auto" || value == "normal" {
		return 0.0
	}

	// Helper to parse the numeric part of the value.
	parseNumeric := func(s, suffix string) (float64, bool) {
		numStr := strings.TrimSuffix(s, suffix)
		if val, err := parseFloat(numStr); err == nil {
			return val, true
		}
		return 0.0, false
	}

	if strings.HasSuffix(value, "%") {
		if percent, ok := parseNumeric(value, "%"); ok {
			return referenceDimension * (percent / 100.0)
		}
	}
	if strings.HasSuffix(value, "px") {
		if px, ok := parseNumeric(value, "px"); ok {
			return px
		}
	}
	// -- FIX: Check for "rem" before "em" --
	if strings.HasSuffix(value, "rem") {
		if val, ok := parseNumeric(value, "rem"); ok {
			return val * rootFontSize
		}
	}
	if strings.HasSuffix(value, "em") {
		if val, ok := parseNumeric(value, "em"); ok {
			return val * parentFontSize
		}
	}
	if strings.HasSuffix(value, "vw") {
		if val, ok := parseNumeric(value, "vw"); ok {
			return viewportWidth * (val / 100.0)
		}
	}
	if strings.HasSuffix(value, "vh") {
		if val, ok := parseNumeric(value, "vh"); ok {
			return viewportHeight * (val / 100.0)
		}
	}
	if strings.HasSuffix(value, "vmin") {
		if val, ok := parseNumeric(value, "vmin"); ok {
			return min(viewportWidth, viewportHeight) * (val / 100.0)
		}
	}
	if strings.HasSuffix(value, "vmax") {
		if val, ok := parseNumeric(value, "vmax"); ok {
			return max(viewportWidth, viewportHeight) * (val / 100.0)
		}
	}
	// Fallback for unitless values (should be treated as px).
	if val, err := parseFloat(value); err == nil {
		return val
	}

	return 0.0
}

func GetFontAscent(sn *StyledNode) float64 {
	fontSize := GetFontSize(sn)
	return fontSize * 0.8
}

func MeasureText(sn *StyledNode) (width, height float64) {
	if sn == nil || sn.Node == nil || sn.Node.Type != html.TextNode {
		return 0, 0
	}
	text := sn.Node.Data
	fontSize := GetFontSize(sn)
	estimatedWidth := float64(len(text)) * fontSize * 0.6
	return estimatedWidth, fontSize
}

func ParseAbsoluteLength(value string) float64 {
	return ParseLengthWithUnits(value, 0, 0, 0, 0, 0)
}

func parseFloat(s string) (float64, error) {
	var result float64
	var sign float64 = 1
	var decimalPoint bool
	var decimalPlace float64 = 0.1
	if len(s) == 0 {
		return 0, fmt.Errorf("empty string")
	}
	i := 0
	if s[0] == '-' {
		sign = -1
		i++
	} else if s[0] == '+' {
		i++
	}
	parsedSomething := false
	for ; i < len(s); i++ {
		ch := s[i]
		if ch >= '0' && ch <= '9' {
			parsedSomething = true
			digit := float64(ch - '0')
			if decimalPoint {
				result += digit * decimalPlace
				decimalPlace *= 0.1
			} else {
				result = result*10 + digit
			}
		} else if ch == '.' && !decimalPoint {
			parsedSomething = true
			decimalPoint = true
		} else {
			break
		}
	}
	if !parsedSomething {
		return 0, fmt.Errorf("invalid float format: %s", s)
	}
	if result == 0 && sign == -1 {
		return 0, nil
	}
	return result * sign, nil
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}