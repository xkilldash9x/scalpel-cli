package layout

import (
    "fmt"
    "math"
    "sort"
    "strings"

    "github.com/antchfx/htmlquery"
    "golang.org/x/net/html"

    "github.com/xkilldash9x/scalpel-cli/api/schemas"
    "github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
    "github.com/xkilldash9x/scalpel-cli/internal/browser/style"
)

// -- Constants and Configuration --

const (
    BaseFontSize    = 16.0 // Default root font size.
    DefaultLineHeight = 1.2  // Default multiplier for 'line-height: normal'.
)

// -- Core Structures: Box Model and Dimensions --

// Dimensions defines the geometry of a layout box.
type Dimensions struct {
    // Content area (x, y) relative to the viewport (before transforms).
    Content Rect

    Padding Edges
    Border  Edges
    Margin  Edges
    // Stores the cumulative transformation matrix from the root.
    Transform TransformMatrix
}

// MarginBox returns the rectangle enclosing the margin area.
func (d Dimensions) MarginBox() Rect {
    return d.BorderBox().ExpandedBy(d.Margin)
}

// BorderBox returns the rectangle enclosing the border area.
func (d Dimensions) BorderBox() Rect {
    return d.PaddingBox().ExpandedBy(d.Border)
}

// PaddingBox returns the rectangle enclosing the padding area.
func (d Dimensions) PaddingBox() Rect {
    return d.Content.ExpandedBy(d.Padding)
}

// GetMainSize is an axis-agnostic helper for Dimensions.
func (d *Dimensions) GetMainSize(axis Axis) float64 {
    if axis == Horizontal {
        return d.Content.Width
    }
    return d.Content.Height
}

// SetMainSize is an axis-agnostic helper for Dimensions.
func (d *Dimensions) SetMainSize(axis Axis, size float64) {
    if axis == Horizontal {
        d.Content.Width = size
    } else {
        d.Content.Height = size
    }
}

// GetCrossSize is an axis-agnostic helper for Dimensions.
func (d *Dimensions) GetCrossSize(axis Axis) float64 {
    if axis == Horizontal {
        return d.Content.Height
    }
    return d.Content.Width
}

// SetCrossSize is an axis-agnostic helper for Dimensions.
func (d *Dimensions) SetCrossSize(axis Axis, size float64) {
    if axis == Horizontal {
        d.Content.Height = size
    } else {
        d.Content.Width = size
    }
}

// GetMainStatic returns the total size occupied by margins, borders, and paddings on the main axis.
func (d *Dimensions) GetMainStatic(axis Axis) float64 {
    if axis == Horizontal {
        return d.Margin.Left + d.Margin.Right + d.Border.Left + d.Border.Right + d.Padding.Left + d.Padding.Right
    }
    return d.Margin.Top + d.Margin.Bottom + d.Border.Top + d.Border.Bottom + d.Padding.Top + d.Padding.Bottom
}

// GetCrossStatic returns the total size occupied by margins, borders, and paddings on the cross axis.
func (d *Dimensions) GetCrossStatic(axis Axis) float64 {
    if axis == Horizontal {
        return d.Margin.Top + d.Margin.Bottom + d.Border.Top + d.Border.Bottom + d.Padding.Top + d.Padding.Bottom
    }
    return d.Margin.Left + d.Margin.Right + d.Border.Left + d.Border.Right + d.Padding.Left + d.Padding.Right
}

type Rect struct {
    X, Y, Width, Height float64
}

// ExpandedBy returns a new rectangle expanded by the edge sizes.
func (r Rect) ExpandedBy(e Edges) Rect {
    return Rect{
        X:      r.X - e.Left,
        Y:      r.Y - e.Top,
        Width:  r.Width + e.Left + e.Right,
        Height: r.Height + e.Top + e.Bottom,
    }
}

// GetMainStart is an axis-agnostic helper for Rect.
func (r *Rect) GetMainStart(axis Axis) float64 {
    if axis == Horizontal {
        return r.X
    }
    return r.Y
}

// SetMainStart is an axis-agnostic helper for Rect.
func (r *Rect) SetMainStart(axis Axis, pos float64) {
    if axis == Horizontal {
        r.X = pos
    } else {
        r.Y = pos
    }
}

// GetCrossStart is an axis-agnostic helper for Rect.
func (r *Rect) GetCrossStart(axis Axis) float64 {
    if axis == Horizontal {
        return r.Y
    }
    return r.X
}

// SetCrossStart is an axis-agnostic helper for Rect.
func (r *Rect) SetCrossStart(axis Axis, pos float64) {
    if axis == Horizontal {
        r.Y = pos
    } else {
        r.X = pos
    }
}

type Edges struct {
    Top, Right, Bottom, Left float64
}

// GetMainStart is an axis-agnostic helper for Edges.
func (e *Edges) GetMainStart(axis Axis) float64 {
    if axis == Horizontal {
        return e.Left
    }
    return e.Top
}

// GetMainEnd is an axis-agnostic helper for Edges.
func (e *Edges) GetMainEnd(axis Axis) float64 {
    if axis == Horizontal {
        return e.Right
    }
    return e.Bottom
}

// GetCrossStart is an axis-agnostic helper for Edges.
func (e *Edges) GetCrossStart(axis Axis) float64 {
    if axis == Horizontal {
        return e.Top
    }
    return e.Left
}

// -- CSS Transforms (2D) --

// TransformMatrix represents a 2D affine transformation matrix (3x3).
// [ a c e ]
// [ b d f ]
// [ 0 0 1 ]
type TransformMatrix struct {
    A, B, C, D, E, F float64
}

// IdentityMatrix returns the identity matrix (no transformation).
func IdentityMatrix() TransformMatrix {
    return TransformMatrix{A: 1, D: 1}
}

// Multiply combines two matrices (m1 * m2). Order matters.
func (m1 TransformMatrix) Multiply(m2 TransformMatrix) TransformMatrix {
    return TransformMatrix{
        A: m1.A*m2.A + m1.C*m2.B,
        B: m1.B*m2.A + m1.D*m2.B,
        C: m1.A*m2.C + m1.C*m2.D,
        D: m1.B*m2.C + m1.D*m2.D,
        E: m1.A*m2.E + m1.C*m2.F + m1.E,
        F: m1.B*m2.E + m1.D*m2.F + m1.F,
    }
}

// Apply transforms a point (x, y).
func (m TransformMatrix) Apply(x, y float64) (float64, float64) {
    newX := m.A*x + m.C*y + m.E
    newY := m.B*x + m.D*y + m.F
    return newX, newY
}

// -- Layout Tree (Box Tree) --

// BoxType defines the type of box generated by a node.
type BoxType int

const (
    BlockBox BoxType = iota
    InlineBox
    InlineBlockBox
    AnonymousBlockBox
    FlexContainer
    GridContainer
    TableBox
    TableRowGroup
    TableRow
    TableCell
)

// LayoutBox is a node in the Layout Tree.
type LayoutBox struct {
    Dimensions      Dimensions
    BoxType         BoxType
    StyledNode      *style.StyledNode
    Children        []*LayoutBox
    ContainingBlock *LayoutBox
    Floats          *FloatList
    BaselineOffset  float64 // Y offset from content-box top to the baseline.
    crossAxisOffset float64 // Temporary storage for alignment shifts.
}

func NewLayoutBox(boxType BoxType, styledNode *style.StyledNode) *LayoutBox {
    return &LayoutBox{
        BoxType:    boxType,
        StyledNode: styledNode,
        Dimensions: Dimensions{Transform: IdentityMatrix()},
    }
}

// IsBlockLevel checks if the box participates in a BFC.
func (b *LayoutBox) IsBlockLevel() bool {
    switch b.BoxType {
    case BlockBox, FlexContainer, GridContainer, TableBox, AnonymousBlockBox:
        return true
    default:
        return false
    }
}

// EstablishesNewFormattingContext checks if this box creates a new Block Formatting Context (BFC).
func (b *LayoutBox) EstablishesNewFormattingContext() bool {
    if b.StyledNode == nil {
        return b.BoxType == AnonymousBlockBox
    }

    if b.ContainingBlock == nil {
        return true
    } // Root (ICB)
    if b.StyledNode.Float() != style.FloatNone {
        return true
    }
    pos := b.StyledNode.Position()
    if pos == style.PositionAbsolute || pos == style.PositionFixed {
        return true
    }

    switch b.BoxType {
    case InlineBlockBox, FlexContainer, GridContainer, TableBox:
        return true
    }

    overflow := b.StyledNode.Lookup("overflow", "visible")
    if overflow != "visible" && overflow != "clip" {
        return true
    }

    return false
}

// GetPositioningContainingBlock finds the containing block (PCB) for positioned elements.
func (b *LayoutBox) GetPositioningContainingBlock() *LayoutBox {
    if b.StyledNode == nil {
        return b.getRoot()
    }

    position := b.StyledNode.Position()

    if position == style.PositionFixed {
        return b.getRoot()
    }

    if position == style.PositionAbsolute {
        ancestor := b.ContainingBlock
        for ancestor != nil {
            if ancestor.StyledNode != nil {
                ancestorPos := ancestor.StyledNode.Position()
                // A containing block is established by any position other than static.
                // Modern browsers also establish one for transform, perspective, etc. but we stick to position.
                if ancestorPos != style.PositionStatic {
                    return ancestor
                }
            }
            if ancestor.ContainingBlock == nil {
                break
            }
            ancestor = ancestor.ContainingBlock
        }
        // If no ancestor qualifies, the root (ICB) is the containing block.
        return b.getRoot()
    }

    // For static or relative, the containing block is the normal parent.
    return b.ContainingBlock
}

// GetInlineContainer manages the creation of AnonymousBlockBoxes for inline content.
func (b *LayoutBox) GetInlineContainer() *LayoutBox {
    switch b.BoxType {
    case InlineBox, InlineBlockBox, AnonymousBlockBox:
        return b
    case BlockBox:
        if len(b.Children) > 0 {
            if lastChild := b.Children[len(b.Children)-1]; lastChild.BoxType == AnonymousBlockBox {
                return lastChild
            }
        }
        anonBox := NewLayoutBox(AnonymousBlockBox, nil)
        return anonBox
    case FlexContainer, GridContainer, TableBox:
        return b
    }
    return b
}

// -- Engine Core --

type Engine struct {
    userAgentSheets []parser.StyleSheet
    authorSheets    []parser.StyleSheet
    viewportWidth   float64
    viewportHeight  float64
}

func NewEngine() *Engine {
    e := &Engine{}
    return e
}

// AddStyleSheet adds a stylesheet provided by the webpage author.
func (e *Engine) AddStyleSheet(sheet parser.StyleSheet) {
    e.authorSheets = append(e.authorSheets, sheet)
}

// Render orchestrates the entire rendering process.
func (e *Engine) Render(root *html.Node, viewportWidth, viewportHeight float64) *LayoutBox {
    e.viewportWidth = viewportWidth
    e.viewportHeight = viewportHeight

    // Pass the initial set of applicable stylesheets (author sheets) to the root.
    styleTree := e.BuildStyleTree(root, nil, e.authorSheets)
    layoutTree := e.BuildLayoutTree(styleTree)

    if layoutTree == nil {
        return nil
    }

    layoutTree.Dimensions.Content = Rect{X: 0, Y: 0, Width: viewportWidth, Height: viewportHeight}
    layoutTree.ContainingBlock = nil
    layoutTree.Floats = NewFloatList()

    layoutTree.Layout(e)
    layoutTree.applyTransforms(IdentityMatrix())

    return layoutTree
}

// -- Style Tree Construction (The Cascade and Inheritance) --

// BuildStyleTree constructs the StyledNode tree.
func (e *Engine) BuildStyleTree(node *html.Node, parent *style.StyledNode, scopedSheets []parser.StyleSheet) *style.StyledNode {
    computedStyles := make(map[parser.Property]parser.Value)

    // Calculate styles based on the cascade using the provided scoped stylesheets.
    if node.Type == html.ElementNode {
        computedStyles = e.CalculateStyles(node, scopedSheets)
    }

    styledNode := &style.StyledNode{
        Node:           node,
        ComputedStyles: computedStyles,
    }

    // Handle inheritance.
    if parent != nil {
        e.inheritStyles(styledNode, parent)
    } else {
        e.applyRootDefaults(styledNode)
    }

    // Resolve relative values.
    e.resolveRelativeValues(styledNode, parent)

    // Check if this node is a shadow host.
    isShadowHost := e.detectShadowHost(node)

    if isShadowHost {
        // If it's a shadow host, we build the shadow tree which encapsulates styles and structure.
        shadowRootNode, shadowScopedSheets := e.getShadowRootAndStyles(node)
        if shadowRootNode != nil {
            // Build the shadow tree recursively with its own scoped styles.
            // The host (styledNode) is passed as the parent for inheritance across the boundary.
            styledNode.ShadowRoot = e.BuildStyleTree(shadowRootNode, styledNode, shadowScopedSheets)
        }
        // Note: Light DOM children are still processed below, but might not be rendered if <slot> is not used.
    }

    // Recursively style light DOM children.
    for c := node.FirstChild; c != nil; c = c.NextSibling {
        if c.Type == html.CommentNode {
            continue
        }
        // Skip <head>.
        if node.Type == html.ElementNode && strings.ToLower(node.Data) == "html" && c.Type == html.ElementNode && strings.ToLower(c.Data) == "head" {
            continue
        }

        // Children inherit the current scope's stylesheets.
        childStyled := e.BuildStyleTree(c, styledNode, scopedSheets)
        styledNode.Children = append(styledNode.Children, childStyled)
    }

    return styledNode
}

// detectShadowHost checks if a node should host a shadow DOM.
func (e *Engine) detectShadowHost(node *html.Node) bool {
    // In a real browser, this is determined by JavaScript calls (attachShadow) or declarative shadow DOM.
    return false
}

// getShadowRootAndStyles retrieves the shadow DOM structure and its internal stylesheets.
func (e *Engine) getShadowRootAndStyles(host *html.Node) (*html.Node, []parser.StyleSheet) {
    // This function would retrieve the encapsulated DOM tree and parse <style> tags within it.
    return nil, nil
}

func (e *Engine) applyRootDefaults(sn *style.StyledNode) {
    if _, exists := sn.ComputedStyles["font-size"]; !exists {
        sn.ComputedStyles["font-size"] = parser.Value(fmt.Sprintf("%fpx", BaseFontSize))
    }
}

// inheritStyles applies inheritance rules.
func (e *Engine) inheritStyles(child, parent *style.StyledNode) {
    inheritableProperties := map[parser.Property]bool{
        "color": true, "font-family": true, "font-size": true, "font-weight": true,
        "line-height": true, "text-align": true, "visibility": true, "cursor": true,
    }

    // Handle explicit 'inherit'.
    for prop, val := range child.ComputedStyles {
        if val == "inherit" {
            if parentVal, parentHas := parent.ComputedStyles[prop]; parentHas {
                child.ComputedStyles[prop] = parentVal
            }
        }
    }

    // Handle standard inheritance.
    for prop := range inheritableProperties {
        if _, exists := child.ComputedStyles[prop]; !exists {
            if val, parentHas := parent.ComputedStyles[prop]; parentHas {
                child.ComputedStyles[prop] = val
            }
        }
    }
}

// resolveRelativeValues computes values that depend on other computed values (e.g., em units).
func (e *Engine) resolveRelativeValues(sn *style.StyledNode, parent *style.StyledNode) {
    // Resolve font-size first.
    parentFontSize := BaseFontSize
    if parent != nil {
        parentFontSize = parseAbsoluteLength(parent.Lookup("font-size", fmt.Sprintf("%fpx", BaseFontSize)))
    }

    if fontSizeStr, ok := sn.ComputedStyles["font-size"]; ok {
        // Pass viewport dimensions for vw/vh support.
        resolvedFontSize := parseLengthWithUnits(string(fontSizeStr), parentFontSize, BaseFontSize, parentFontSize, e.viewportWidth, e.viewportHeight)
        sn.ComputedStyles["font-size"] = parser.Value(fmt.Sprintf("%fpx", resolvedFontSize))
    }

    currentFontSize := parseAbsoluteLength(sn.Lookup("font-size", fmt.Sprintf("%fpx", BaseFontSize)))

    // Resolve line-height.
    if lineHeightStr, ok := sn.ComputedStyles["line-height"]; ok {
        resolvedLineHeight := e.resolveLineHeight(string(lineHeightStr), currentFontSize)
        sn.ComputedStyles["line-height"] = parser.Value(fmt.Sprintf("%fpx", resolvedLineHeight))
    }
}

// resolveLineHeight handles unitless multipliers.
func (e *Engine) resolveLineHeight(value string, fontSize float64) float64 {
    value = strings.TrimSpace(value)
    if value == "normal" {
        return fontSize * DefaultLineHeight
    }

    // Check for unitless number (multiplier).
    if val, err := parseFloat(value); err == nil && !strings.ContainsAny(value, "px%emremvwvhvminvmax") {
        return fontSize * val
    }

    // Treat as a length.
    return parseLengthWithUnits(value, fontSize, BaseFontSize, 0, e.viewportWidth, e.viewportHeight)
}

// StyleOrigin and DeclarationWithContext definitions.
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

// CalculateStyles determines the computed styles using the cascade algorithm.
func (e *Engine) CalculateStyles(node *html.Node, scopedSheets []parser.StyleSheet) map[parser.Property]parser.Value {
    var declarations []DeclarationWithContext
    order := 0

    processSheets := func(sheets []parser.StyleSheet, origin StyleOrigin) {
        for _, sheet := range sheets {
            for _, rule := range sheet.Rules {
                for _, selectorGroup := range rule.SelectorGroups {
                    // TODO: Selector matching logic needs updates for Shadow DOM boundaries (e.g., :host).
                    if matchingComplexSelector, ok := e.matches(node, selectorGroup); ok {
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

    // User Agent styles always apply.
    processSheets(e.userAgentSheets, OriginUserAgent)
    // Author styles (scoped to the current DOM tree).
    processSheets(scopedSheets, OriginAuthor)

    for _, attr := range node.Attr {
        if attr.Key == "style" {
            inlineDecls := parseInlineStyles(attr.Val)
            for _, decl := range inlineDecls {
                declarations = append(declarations, DeclarationWithContext{
                    Declaration: decl,
                    Specificity: struct{ A, B, C int }{1000, 0, 0},
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

// -- Advanced Selector Matching (Combinators) --
func (e *Engine) matches(node *html.Node, group parser.SelectorGroup) (*parser.ComplexSelector, bool) {
    if node.Type != html.ElementNode {
        return nil, false
    }
    for _, complexSelector := range group {
        currentIndex := len(complexSelector.Selectors) - 1
        if currentIndex < 0 {
            continue
        }
        if e.recursiveMatch(node, complexSelector, currentIndex) {
            return &complexSelector, true
        }
    }
    return nil, false
}

func (e *Engine) recursiveMatch(node *html.Node, complexSelector parser.ComplexSelector, index int) bool {
    if node == nil || index < 0 {
        return false
    }
    if node.Type != html.ElementNode {
        return false
    }
    currentSelectorWithCombinator := complexSelector.Selectors[index]
    if !e.matchesSimple(node, currentSelectorWithCombinator.SimpleSelector) {
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
            if e.recursiveMatch(parent, complexSelector, nextIndex) {
                return true
            }
        }
        return false
    case parser.CombinatorChild:
        return e.recursiveMatch(node.Parent, complexSelector, nextIndex)
    case parser.CombinatorAdjacentSibling:
        prevSibling := getPreviousElementSibling(node)
        return e.recursiveMatch(prevSibling, complexSelector, nextIndex)
    case parser.CombinatorGeneralSibling:
        for sibling := getPreviousElementSibling(node); sibling != nil; sibling = getPreviousElementSibling(sibling) {
            if e.recursiveMatch(sibling, complexSelector, nextIndex) {
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

func (e *Engine) matchesSimple(node *html.Node, selector parser.SimpleSelector) bool {
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
    return true
}

// -- Layout Tree Construction --

// BuildLayoutTree constructs the LayoutBox tree from the Style Tree (Box Construction).
func (e *Engine) BuildLayoutTree(styledNode *style.StyledNode) *LayoutBox {
    display := styledNode.Display()

    if display == style.DisplayNone {
        return nil
    }

    position := styledNode.Position()
    isPositioned := position == style.PositionAbsolute || position == style.PositionFixed
    isFloated := styledNode.Float() != style.FloatNone
    isRoot := styledNode.Node.Parent == nil || (styledNode.Node.Parent != nil && styledNode.Node.Parent.Type == html.DocumentNode)

    if isPositioned || isFloated || isRoot {
        switch display {
        case style.DisplayInline, style.DisplayInlineBlock, style.DisplayTable:
            display = style.DisplayBlock
        }
    }

    var root *LayoutBox
    switch display {
    case style.DisplayBlock:
        root = NewLayoutBox(BlockBox, styledNode)
    case style.DisplayFlex:
        root = NewLayoutBox(FlexContainer, styledNode)
    case style.DisplayGrid:
        root = NewLayoutBox(GridContainer, styledNode)
    case style.DisplayTable:
        root = NewLayoutBox(TableBox, styledNode)
    case style.DisplayTableRow:
        root = NewLayoutBox(TableRow, styledNode)
    case style.DisplayTableCell:
        root = NewLayoutBox(TableCell, styledNode)
    case style.DisplayInlineBlock:
        root = NewLayoutBox(InlineBlockBox, styledNode)
    case style.DisplayInline:
        if styledNode.Node.Type == html.TextNode && strings.TrimSpace(styledNode.Node.Data) == "" {
            return nil
        }
        root = NewLayoutBox(InlineBox, styledNode)
    }

    if root.BoxType == TableBox {
        e.fixupTableStructure(root)
        return root
    }

    // Determine which children to use for layout: Shadow DOM or Light DOM (Composed Tree).
    childrenToLayout := styledNode.Children
    if styledNode.ShadowRoot != nil {
        // If a shadow root exists, the shadow tree content is rendered instead of the light DOM children.
        // We use the children of the ShadowRoot StyledNode.
        // TODO: A full implementation needs to handle <slot> elements for composition.
        childrenToLayout = styledNode.ShadowRoot.Children
    }

    for _, childStyled := range childrenToLayout {
        childBox := e.BuildLayoutTree(childStyled)
        if childBox == nil {
            continue
        }

        switch root.BoxType {
        case FlexContainer, GridContainer:
            // Flex/Grid items are blockified.
            if !childBox.IsBlockLevel() && childBox.BoxType != InlineBlockBox {
                // In reality, an anonymous block box wraps the inline content, but for simplicity
                // we change the box type directly if needed, though Flex/Grid layout handles items robustly.
            }
            root.Children = append(root.Children, childBox)
        default:
            // Standard block/inline flow.
            if childBox.IsBlockLevel() {
                root.Children = append(root.Children, childBox)
            } else {
                container := root.GetInlineContainer()
                if container != root && (len(root.Children) == 0 || root.Children[len(root.Children)-1] != container) {
                    root.Children = append(root.Children, container)
                }
                container.Children = append(container.Children, childBox)
            }
        }
    }
    return root
}

func (e *Engine) fixupTableStructure(tableBox *LayoutBox) {
    if tableBox.StyledNode == nil {
        return
    }

    // Ensure we use the composed children list (handles potential Shadow DOM encapsulation)
    childrenToLayout := tableBox.StyledNode.Children
    if tableBox.StyledNode.ShadowRoot != nil {
        childrenToLayout = tableBox.StyledNode.ShadowRoot.Children
    }

    var currentRow *LayoutBox
    var currentSection *LayoutBox

    for _, childStyled := range childrenToLayout {
        childDisplay := childStyled.Display()
        if childDisplay == style.DisplayNone {
            continue
        }

        childBox := e.BuildLayoutTree(childStyled)
        if childBox == nil {
            continue
        }

        isCell := childBox.BoxType == TableCell
        isRow := childBox.BoxType == TableRow

        if isCell {
            if currentSection == nil {
                currentSection = NewLayoutBox(TableRowGroup, nil)
                tableBox.Children = append(tableBox.Children, currentSection)
            }
            if currentRow == nil {
                currentRow = NewLayoutBox(TableRow, nil)
                currentSection.Children = append(currentSection.Children, currentRow)
            }
            currentRow.Children = append(currentRow.Children, childBox)
        } else if isRow {
            if currentSection == nil {
                currentSection = NewLayoutBox(TableRowGroup, nil)
                tableBox.Children = append(tableBox.Children, currentSection)
            }
            currentSection.Children = append(currentSection.Children, childBox)
            currentRow = childBox
        } else {
            tableBox.Children = append(tableBox.Children, childBox)
            currentSection = childBox
            currentRow = nil
        }
    }
}

// -- Layout Algorithm (Flow, Positioning, Floats, Flexbox, Grid) --

type LayoutContext struct {
    CurrentY          float64
    MaxNegativeMargin float64
    MaxPositiveMargin float64
    IsEmpty           bool
}

func NewLayoutContext(startY float64) *LayoutContext {
    return &LayoutContext{
        CurrentY: startY,
        IsEmpty:  true,
    }
}

func (lc *LayoutContext) AddToMarginTotals(margin float64) {
    if margin > 0 {
        lc.MaxPositiveMargin = math.Max(lc.MaxPositiveMargin, margin)
    } else {
        if margin < lc.MaxNegativeMargin {
            lc.MaxNegativeMargin = margin
        }
    }
}

func (lc *LayoutContext) CalculateCollapsedMargin() float64 {
    return lc.MaxPositiveMargin + lc.MaxNegativeMargin
}

func (lc *LayoutContext) ResetMargins() {
    lc.MaxNegativeMargin = 0
    lc.MaxPositiveMargin = 0
}

// Layout calculates the dimensions and position recursively.
func (b *LayoutBox) Layout(e *Engine) {
    if b.EstablishesNewFormattingContext() {
        if b.Floats == nil {
            b.Floats = NewFloatList()
        }
    } else if b.ContainingBlock != nil {
        b.Floats = b.ContainingBlock.Floats
    }

    if b.StyledNode != nil {
        pos := b.StyledNode.Position()
        if pos == style.PositionAbsolute || pos == style.PositionFixed {
            return
        }
    }

    isManagedItem := false
    if b.ContainingBlock != nil {
        if b.ContainingBlock.BoxType == FlexContainer || b.ContainingBlock.BoxType == GridContainer {
            isManagedItem = true
        }
    }

    if !isManagedItem {
        switch b.BoxType {
        case BlockBox, FlexContainer, GridContainer, TableBox:
            b.layoutBlock(e)
        case InlineBlockBox:
            b.layoutBlock(e)
        case InlineBox:
            b.layoutInline(e)
        case AnonymousBlockBox:
            b.layoutAnonymous(e)
        }
    }

    b.layoutPositionedChildren(e)
    b.applyRelativePositioning()
}

func (b *LayoutBox) layoutContent(e *Engine) {
    if b.EstablishesNewFormattingContext() && b.Floats == nil {
        b.Floats = NewFloatList()
    }

    switch b.BoxType {
    case BlockBox, InlineBlockBox:
        b.layoutBlockFlow(e)
        b.calculateBlockHeight()
    case FlexContainer:
        b.layoutFlex(e)
    case GridContainer:
        b.layoutGrid(e)
    case TableBox:
        b.layoutTable(e)
    case InlineBox:
        b.layoutInlineFlow(e)
        b.calculateInlineDimensions()
    case AnonymousBlockBox:
        b.layoutInlineFlow(e)
        b.calculateBlockHeight()
    }
}

func (b *LayoutBox) layoutBlock(e *Engine) {
    b.calculateBlockWidthAndEdges(e)

    if b.ContainingBlock != nil {
        cb := b.ContainingBlock.Dimensions
        b.Dimensions.Content.X = cb.Content.X + b.Dimensions.Margin.Left + b.Dimensions.Border.Left + b.Dimensions.Padding.Left
    }

    switch b.BoxType {
    case FlexContainer:
        b.layoutFlex(e)
    case GridContainer:
        b.layoutGrid(e)
    case TableBox:
        b.layoutTable(e)
    default:
        b.layoutChildren(e)
    }

    b.calculateBlockHeight()

    if b.ContainingBlock == nil {
        b.Dimensions.Content.Y = b.Dimensions.Margin.Top + b.Dimensions.Border.Top + b.Dimensions.Padding.Top
    }
}

func (b *LayoutBox) layoutAnonymous(e *Engine) {
    if b.ContainingBlock == nil {
        return
    }
    cb := b.ContainingBlock.Dimensions
    b.Dimensions.Content.Width = cb.Content.Width

    b.layoutChildren(e)
    b.calculateBlockHeight()
}

func (b *LayoutBox) layoutInline(e *Engine) {
    b.calculateInlineEdges(e)
    b.layoutChildren(e)
    b.calculateInlineDimensions()
}

func (b *LayoutBox) layoutChildren(e *Engine) {
    switch b.BoxType {
    case FlexContainer, GridContainer, TableBox:
        return
    }

    switch b.BoxType {
    case BlockBox, InlineBlockBox:
        b.layoutBlockFlow(e)
    case AnonymousBlockBox, InlineBox:
        b.layoutInlineFlow(e)
    }
}

func (b *LayoutBox) layoutBlockFlow(e *Engine) {
    context := NewLayoutContext(b.Dimensions.Content.Y)

    for _, child := range b.Children {
        child.ContainingBlock = b

        if child.StyledNode != nil {
            pos := child.StyledNode.Position()
            if pos == style.PositionAbsolute || pos == style.PositionFixed {
                continue
            }
        }

        if child.StyledNode != nil && child.StyledNode.Float() != style.FloatNone {
            b.layoutFloatedBox(child, e, context)
            context.IsEmpty = false
            context.ResetMargins()
            continue
        }

        if child.IsBlockLevel() && child.BoxType != AnonymousBlockBox {
            child.calculateBlockWidthAndEdges(e)
        } else if child.BoxType == InlineBlockBox {
            child.calculateBlockWidthAndEdges(e)
        }
        marginTop := child.Dimensions.Margin.Top

        if child.BoxType == AnonymousBlockBox || (child.StyledNode != nil && child.EstablishesNewFormattingContext()) {
            context.CurrentY += context.CalculateCollapsedMargin()
            context.ResetMargins()
        }

        context.AddToMarginTotals(marginTop)

        clearance := 0.0
        if child.StyledNode != nil && b.Floats != nil {
            clearType := child.StyledNode.Clear()
            if clearType != style.ClearNone {
                potentialY := context.CurrentY + context.CalculateCollapsedMargin()
                clearance = b.Floats.CalculateClearance(potentialY, clearType)
            }
        }

        if clearance > 0 {
            context.CurrentY += context.CalculateCollapsedMargin() + clearance
            context.ResetMargins()
            context.AddToMarginTotals(marginTop)
        }

        collapsedTopMargin := context.CalculateCollapsedMargin()
        child.Dimensions.Content.Y = context.CurrentY + collapsedTopMargin + child.Dimensions.Border.Top + child.Dimensions.Padding.Top

        child.Layout(e)

        context.IsEmpty = false
        context.CurrentY += collapsedTopMargin + child.Dimensions.Border.Top + child.Dimensions.Padding.Top +
            child.Dimensions.Content.Height +
            child.Dimensions.Padding.Bottom + child.Dimensions.Border.Bottom

        context.ResetMargins()
        context.AddToMarginTotals(child.Dimensions.Margin.Bottom)
    }

    context.CurrentY += context.CalculateCollapsedMargin()
}

// -- Inline Formatting Context (IFC) and Line Breaking --

type LineBox struct {
    Rect
    Fragments []*LayoutBox
    BaselineY float64
}

func (b *LayoutBox) layoutInlineFlow(e *Engine) {
    containerWidth := b.Dimensions.Content.Width
    currentY := b.Dimensions.Content.Y

    var lineBoxes []*LineBox
    currentLine := &LineBox{Rect: Rect{Y: currentY}}
    lineBoxes = append(lineBoxes, currentLine)

    updateLineConstraints := func(line *LineBox, y float64) float64 {
        if b.Floats != nil {
            leftIndent, rightIndent := b.Floats.GetIndentationAtY(y, b.Dimensions.Content.X, containerWidth)
            line.X = b.Dimensions.Content.X + leftIndent
            return containerWidth - leftIndent - rightIndent
        }
        line.X = b.Dimensions.Content.X
        return containerWidth
    }

    availableWidth := updateLineConstraints(currentLine, currentY)
    currentX := currentLine.X

    for _, child := range b.Children {
        child.ContainingBlock = b
        if child.StyledNode != nil {
            pos := child.StyledNode.Position()
            if pos == style.PositionAbsolute || pos == style.PositionFixed {
                continue
            }
        }

        child.Layout(e)
        childWidth := child.Dimensions.MarginBox().Width

        if currentLine.Width+childWidth > availableWidth && currentLine.Width > 0 {
            b.calculateLineBoxHeightAndBaseline(currentLine)
            currentY += currentLine.Height
            currentLine = &LineBox{Rect: Rect{Y: currentY}}
            lineBoxes = append(lineBoxes, currentLine)
            availableWidth = updateLineConstraints(currentLine, currentY)
            currentX = currentLine.X
        }

        child.Dimensions.Content.X = currentX + child.Dimensions.Margin.Left + child.Dimensions.Border.Left + child.Dimensions.Padding.Left
        child.Dimensions.Content.Y = currentY + child.Dimensions.Margin.Top + child.Dimensions.Border.Top + child.Dimensions.Padding.Top

        currentLine.Fragments = append(currentLine.Fragments, child)
        currentLine.Width += childWidth
        currentX += childWidth
    }

    b.calculateLineBoxHeightAndBaseline(currentLine)

    for _, line := range lineBoxes {
        b.verticallyAlignLineBox(line)
    }
}

func (b *LayoutBox) calculateLineBoxHeightAndBaseline(line *LineBox) {
    maxHeight := 0.0
    maxAscent := 0.0

    for _, frag := range line.Fragments {
        lineHeight := BaseFontSize * DefaultLineHeight
        ascent := getFontAscent(frag.StyledNode)

        if frag.StyledNode != nil {
            lineHeight = parseAbsoluteLength(frag.StyledNode.Lookup("line-height", fmt.Sprintf("%fpx", lineHeight)))
        }

        boxHeight := frag.Dimensions.BorderBox().Height
        effectiveHeight := math.Max(boxHeight, lineHeight)

        if effectiveHeight > maxHeight {
            maxHeight = effectiveHeight
        }
        if ascent > maxAscent {
            maxAscent = ascent
        }
    }

    if maxHeight == 0 {
        if b.StyledNode != nil {
            maxHeight = parseAbsoluteLength(b.StyledNode.Lookup("line-height", fmt.Sprintf("%fpx", BaseFontSize*DefaultLineHeight)))
            maxAscent = getFontAscent(b.StyledNode)
        } else {
            maxHeight = BaseFontSize * DefaultLineHeight
            maxAscent = BaseFontSize * 0.8
        }
    }

    line.Height = maxHeight
    line.BaselineY = line.Y + maxAscent
}

func (b *LayoutBox) verticallyAlignLineBox(line *LineBox) {
    baselineY := line.BaselineY

    for _, frag := range line.Fragments {
        vAlign := "baseline"
        if frag.StyledNode != nil {
            vAlign = frag.StyledNode.Lookup("vertical-align", "baseline")
        }

        fragMarginBox := frag.Dimensions.MarginBox()
        offsetY := 0.0

        switch vAlign {
        case "top":
            offsetY = line.Y - fragMarginBox.Y
        case "bottom":
            offsetY = (line.Y + line.Height) - (fragMarginBox.Y + fragMarginBox.Height)
        case "middle":
            fontSize := getFontSize(frag.StyledNode)
            middleLine := baselineY - (0.5 * fontSize * 0.5)
            middleFrag := fragMarginBox.Y + fragMarginBox.Height/2
            offsetY = middleLine - middleFrag
        case "baseline":
            fragAscent := getFontAscent(frag.StyledNode)
            if frag.BoxType == InlineBlockBox && len(frag.Children) == 0 {
                targetMarginY := baselineY - fragMarginBox.Height
                offsetY = targetMarginY - fragMarginBox.Y
            } else {
                targetContentY := baselineY - fragAscent
                offsetY = targetContentY - frag.Dimensions.Content.Y
            }
        }
        frag.Dimensions.Content.Y += offsetY
    }
}

// -- Flexbox, Grid, Table Layout --
type Axis int

const (
    Horizontal Axis = iota
    Vertical
)

// FlexDirectionInfo for easier axis management
type FlexDirectionInfo struct {
    MainAxis       Axis
    CrossAxis      Axis
    IsReverse      bool // For flex-direction: reverse
    IsCrossReverse bool // For flex-wrap: wrap-reverse
}

func getFlexDirectionInfo(sn *style.StyledNode) FlexDirectionInfo {
    dir := sn.GetFlexDirection()
    wrap := sn.GetFlexWrap()
    info := FlexDirectionInfo{}

    switch dir {
    case style.FlexDirectionRow:
        info.MainAxis = Horizontal
        info.CrossAxis = Vertical
    case style.FlexDirectionRowReverse:
        info.MainAxis = Horizontal
        info.CrossAxis = Vertical
        info.IsReverse = true
    case style.FlexDirectionColumn:
        info.MainAxis = Vertical
        info.CrossAxis = Horizontal
    case style.FlexDirectionColumnReverse:
        info.MainAxis = Vertical
        info.CrossAxis = Horizontal
        info.IsReverse = true
    }

    if wrap == style.FlexWrapReverse {
        info.IsCrossReverse = true
    }
    return info
}

type FlexItemMetadata struct {
    Box                  *LayoutBox
    FlexBaseSize         float64
    HypotheticalMainSize float64
    TargetMainSize       float64
    Frozen               bool // Used during flexible length resolution
    // Min/Max constraints omitted for brevity.
}

type FlexLine struct {
    Items      []*FlexItemMetadata
    CrossSize  float64
    MainSize   float64 // Total main size used by items (including margins/static).
    CrossStart float64 // Position of the line on the cross axis.
}

// Implementation of the Flexbox algorithm based on the W3C specification.
func (b *LayoutBox) layoutFlex(e *Engine) {
    sn := b.StyledNode
    if sn == nil {
        return
    }

    // 1. Initialization
    dirInfo := getFlexDirectionInfo(sn)
    mainAxis := dirInfo.MainAxis
    crossAxis := dirInfo.CrossAxis
    availableMainSize := b.Dimensions.GetMainSize(mainAxis)
    availableCrossSize := b.Dimensions.GetCrossSize(crossAxis)

    // Collect flex items
    var items []*FlexItemMetadata
    for _, child := range b.Children {
        child.ContainingBlock = b // Ensure CB is set before layout calculations.
        if child.StyledNode != nil {
            pos := child.StyledNode.Position()
            if pos == style.PositionAbsolute || pos == style.PositionFixed {
                continue
            }
        }
        items = append(items, &FlexItemMetadata{Box: child})
    }

    if len(items) == 0 {
        return
    }

    // 2. Determine the flex base size and hypothetical main size of each item.
    b.calculateFlexBaseSizes(items, mainAxis, crossAxis, availableMainSize, e)

    // 3. Collect flex items into flex lines.
    lines := b.collectFlexLines(items, sn.GetFlexWrap(), availableMainSize, mainAxis)

    // 4. Resolve flexible lengths.
    for _, line := range lines {
        b.resolveFlexibleLengths(line, availableMainSize, mainAxis, e)
    }

    // 5. Cross-Size Determination
    b.determineCrossSizes(lines, mainAxis, crossAxis, e)

    // Calculate the total used cross space.
    totalCrossSize := 0.0
    for _, line := range lines {
        totalCrossSize += line.CrossSize
    }

    // Handle container auto cross size before alignment.
    if b.isAutoCrossSize(e) {
        b.Dimensions.SetCrossSize(crossAxis, totalCrossSize)
        availableCrossSize = totalCrossSize
    }

    // 6. Handle Alignment (Cross Axis) - align-content and align-items/self
    b.alignCrossAxis(lines, sn, dirInfo, availableCrossSize, totalCrossSize, crossAxis, e)

    // 7. Handle Alignment (Main Axis) - justify-content
    b.alignMainAxis(lines, sn, dirInfo, availableMainSize, mainAxis)
}

// calculateFlexBaseSizes is a Step 2 helper.
func (b *LayoutBox) calculateFlexBaseSizes(items []*FlexItemMetadata, mainAxis, crossAxis Axis, availableMainSize float64, e *Engine) {
    // Reference width for percentage resolution of padding/margins.
    refWidth := b.Dimensions.Content.Width

    for _, item := range items {
        // Calculate edges (non-auto margins, padding, borders).
        item.Box.calculatePaddingAndBorders(refWidth, e)
        item.Box.calculateMargins(refWidth, e) // Treat auto margins as 0 for now.

        // Determine Flex Base Size
        // Priority: flex-basis -> width/height -> content size.
        basisStr := item.Box.StyledNode.Lookup("flex-basis", "auto")
        mainSizeStr := item.Box.StyledNode.Lookup("width", "auto")
        if mainAxis == Vertical {
            mainSizeStr = item.Box.StyledNode.Lookup("height", "auto")
        }

        baseSize := math.NaN()

        // 1. Check flex-basis (if not auto/content)
        if basisStr != "auto" && basisStr != "content" {
            baseSize = b.resolveFlexLength(basisStr, mainAxis, e)
        }

        // 2. Check main size property (if basis was auto and main size is definite)
        if math.IsNaN(baseSize) && mainSizeStr != "auto" {
            baseSize = b.resolveFlexLength(mainSizeStr, mainAxis, e)
        }

        // 3. Fallback to content size (intrinsic size)
        if math.IsNaN(baseSize) {
            if mainAxis == Horizontal {
                // Use shrink-to-fit for width calculation.
                baseSize = item.Box.calculateShrinkToFitWidth(e, availableMainSize)
            } else {
                // Calculate height based on content. Requires knowing the width (cross-axis).
                // Simplified: Assume available cross size (container width) for width constraint.
                item.Box.Dimensions.SetCrossSize(mainAxis, b.Dimensions.GetCrossSize(mainAxis))
                item.Box.layoutContent(e)
                baseSize = item.Box.Dimensions.GetMainSize(mainAxis)
            }
        }

        // Handle box-sizing: convert specified size to content size if border-box.
        if item.Box.StyledNode.BoxSizing() == style.BorderBox && !math.IsNaN(baseSize) {
            // Calculate static space excluding margins for box-sizing adjustment.
            pStart, pEnd := item.Box.Dimensions.Padding.GetMainStart(mainAxis), item.Box.Dimensions.Padding.GetMainEnd(mainAxis)
            bStart, bEnd := item.Box.Dimensions.Border.GetMainStart(mainAxis), item.Box.Dimensions.Border.GetMainEnd(mainAxis)
            baseSize = math.Max(0, baseSize-(pStart+pEnd+bStart+bEnd))
        }

        item.FlexBaseSize = baseSize
        // Hypothetical main size (clamped by min/max-width/height - skipped for now)
        item.HypotheticalMainSize = item.FlexBaseSize
    }
}

// collectFlexLines is a Step 3 helper.
func (b *LayoutBox) collectFlexLines(items []*FlexItemMetadata, wrap style.FlexWrap, availableMainSize float64, mainAxis Axis) []*FlexLine {
    var lines []*FlexLine
    currentLine := &FlexLine{}
    lines = append(lines, currentLine)

    if wrap == style.FlexNoWrap {
        // Single line layout
        currentLine.Items = items
        for _, item := range items {
            currentLine.MainSize += item.HypotheticalMainSize + item.Box.Dimensions.GetMainStatic(mainAxis)
        }
        return lines
    }

    // Multi-line layout
    currentMainSize := 0.0
    for _, item := range items {
        // Use margin box size for line breaking
        itemMainSize := item.HypotheticalMainSize + item.Box.Dimensions.GetMainStatic(mainAxis)

        // Check for overflow, ensuring at least one item is placed if the line is empty.
        if currentMainSize+itemMainSize > availableMainSize && len(currentLine.Items) > 0 {
            // Wrap to a new line
            currentLine.MainSize = currentMainSize
            currentLine = &FlexLine{}
            lines = append(lines, currentLine)
            currentMainSize = 0.0
        }

        currentLine.Items = append(currentLine.Items, item)
        currentMainSize += itemMainSize
    }
    currentLine.MainSize = currentMainSize
    return lines
}

// resolveFlexibleLengths is a Step 4 helper.
func (b *LayoutBox) resolveFlexibleLengths(line *FlexLine, availableMainSize float64, mainAxis Axis, e *Engine) {
    // Calculate free space based on the line's calculated MainSize (sum of hypothetical sizes + static space)
    freeSpace := availableMainSize - line.MainSize
    isGrowing := freeSpace > 0.001
    isShrinking := freeSpace < -0.001

    // Helper to get flex factors
    getGrow := func(sn *style.StyledNode) float64 {
        val, _ := parseFloat(sn.Lookup("flex-grow", "0"))
        return math.Max(0, val)
    }
    getShrink := func(sn *style.StyledNode) float64 {
        val, _ := parseFloat(sn.Lookup("flex-shrink", "1"))
        return math.Max(0, val)
    }

    // Collect total factors
    totalGrow := 0.0
    totalWeightedShrink := 0.0

    // Initialize TargetMainSize and reset Frozen status
    for _, item := range line.Items {
        item.TargetMainSize = item.FlexBaseSize
        item.Frozen = false
        totalGrow += getGrow(item.Box.StyledNode)
        // Calculate weighted shrink factor sum
        totalWeightedShrink += getShrink(item.Box.StyledNode) * item.FlexBaseSize
    }

    // Check if flexible distribution is possible
    if (!isGrowing && !isShrinking) || (isGrowing && totalGrow == 0) || (isShrinking && totalWeightedShrink == 0) {
        // No flexibility or no space difference.
        return
    }

    // Simplified loop for resolving lengths. Does not handle min/max constraint violations robustly (requires iteration).
    remainingFreeSpace := freeSpace

    for _, item := range line.Items {
        if item.Frozen {
            continue
        }

        var adjustment float64
        if isGrowing {
            ratio := getGrow(item.Box.StyledNode) / totalGrow
            adjustment = remainingFreeSpace * ratio
        } else {
            // Shrinking
            scaledShrink := getShrink(item.Box.StyledNode) * item.FlexBaseSize
            weightedRatio := scaledShrink / totalWeightedShrink
            // freeSpace is negative here
            adjustment = remainingFreeSpace * weightedRatio
        }

        item.TargetMainSize += adjustment

        // Simplified min constraint check (size cannot be negative)
        if item.TargetMainSize < 0 {
            item.TargetMainSize = 0
            // Robust implementation requires freezing and redistributing excess space.
        }
    }
}

// determineCrossSizes is a Step 5 helper.
func (b *LayoutBox) determineCrossSizes(lines []*FlexLine, mainAxis, crossAxis Axis, e *Engine) {
    // Calculate the hypothetical cross size of each item.
    for _, line := range lines {
        for _, item := range line.Items {
            // Set the calculated main size.
            item.Box.Dimensions.SetMainSize(mainAxis, item.TargetMainSize)

            // Layout the item's content to determine its cross size (if auto).
            // We skip layout if the item will be stretched later, as we'll re-layout anyway.
            // (Optimization: Stretch check moved to alignCrossAxis)
            item.Box.layoutContent(e)
        }
    }

    // Calculate the cross size of each flex line.
    for _, line := range lines {
        maxCrossSize := 0.0
        // TODO: Handle baseline alignment which significantly affects line height.
        for _, item := range line.Items {
            // Use margin box size for line cross size calculation
            crossSize := item.Box.Dimensions.GetCrossSize(crossAxis) + item.Box.Dimensions.GetCrossStatic(crossAxis)
            if crossSize > maxCrossSize {
                maxCrossSize = crossSize
            }
        }
        line.CrossSize = maxCrossSize
    }
}

// alignCrossAxis is a Step 6 helper.
func (b *LayoutBox) alignCrossAxis(lines []*FlexLine, sn *style.StyledNode, dirInfo FlexDirectionInfo, availableCrossSize, totalCrossSize float64, crossAxis Axis, e *Engine) {
    // align-content (Distribute free cross space among lines)
    var currentCrossOffset float64
    var spacing float64

    alignContent := sn.GetAlignContent()

    // align-content only applies if wrapping is enabled.
    if sn.GetFlexWrap() != style.FlexNoWrap {

        // Handle Stretch (Default behavior for align-content)
        if alignContent == style.AlignContentStretch && availableCrossSize > totalCrossSize {
            freeSpace := availableCrossSize - totalCrossSize
            if len(lines) > 0 {
                extraPerLine := freeSpace / float64(len(lines))
                for _, line := range lines {
                    line.CrossSize += extraPerLine
                }
            }
            totalCrossSize = availableCrossSize // Update total size after stretching
        }

        // Calculate positioning offsets for lines
        currentCrossOffset, spacing = b.calculateAlignmentOffsets(len(lines), totalCrossSize, availableCrossSize, alignContent)
    }

    // Handle wrap-reverse (affects the starting position and direction of stacking)
    if dirInfo.IsCrossReverse {
        currentCrossOffset = availableCrossSize - currentCrossOffset // Start from the end
    }

    // align-items and align-self (Position items within their line)
    containerAlignItems := sn.GetAlignItems()
    for _, line := range lines {
        // Update line position (CrossStart)
        if dirInfo.IsCrossReverse {
            // When reversed, the offset points to the end edge of the line.
            line.CrossStart = currentCrossOffset - line.CrossSize
        } else {
            line.CrossStart = currentCrossOffset
        }

        for _, item := range line.Items {
            b.alignFlexItem(item.Box, line.CrossSize, containerAlignItems, crossAxis, e)
        }

        // Advance offset for the next line
        if dirInfo.IsCrossReverse {
            currentCrossOffset -= (line.CrossSize + spacing)
        } else {
            currentCrossOffset += (line.CrossSize + spacing)
        }
    }
}

// alignMainAxis is a Step 7 helper.
func (b *LayoutBox) alignMainAxis(lines []*FlexLine, sn *style.StyledNode, dirInfo FlexDirectionInfo, availableMainSize float64, mainAxis Axis) {
    containerMainStart := b.Dimensions.Content.GetMainStart(mainAxis)
    containerCrossStart := b.Dimensions.Content.GetCrossStart(dirInfo.CrossAxis)

    // Helper to calculate the offset from the margin edge to the content edge (start side)
    getStartContentOffset := func(d *Dimensions, axis Axis) float64 {
        m := d.Margin.GetMainStart(axis)
        p := d.Padding.GetMainStart(axis)
        bd := d.Border.GetMainStart(axis)
        return m + p + bd
    }

    getCrossStartContentOffset := func(d *Dimensions, axis Axis) float64 {
        m := d.Margin.GetCrossStart(axis)
        p := d.Padding.GetCrossStart(axis)
        bd := d.Border.GetCrossStart(axis)
        return m + p + bd
    }

    for _, line := range lines {
        // Calculate used space (sum of margin boxes based on target main size).
        usedMainSize := 0.0
        for _, item := range line.Items {
            usedMainSize += item.TargetMainSize + item.Box.Dimensions.GetMainStatic(mainAxis)
        }

        // Calculate alignment offsets (justify-content)
        currentMainOffset, spacing := b.calculateAlignmentOffsets(len(line.Items), usedMainSize, availableMainSize, sn.GetJustifyContent())

        // Handle reverse direction (affects starting position and direction of placement)
        if dirInfo.IsReverse {
            currentMainOffset = availableMainSize - currentMainOffset // Start from the end
        }

        // Position items
        for _, item := range line.Items {
            // 1. Main Axis Position
            startContentOffset := getStartContentOffset(&item.Box.Dimensions, mainAxis)

            var contentMainStart float64
            if dirInfo.IsReverse {
                // When reversed, the offset points to the end edge of the margin box.
                mainMarginBoxSize := item.TargetMainSize + item.Box.Dimensions.GetMainStatic(mainAxis)
                // Start of margin box = ContainerStart + Offset - Size
                // Start of content box = Start of margin box + ContentOffset
                contentMainStart = containerMainStart + currentMainOffset - mainMarginBoxSize + startContentOffset
            } else {
                contentMainStart = containerMainStart + currentMainOffset + startContentOffset
            }

            item.Box.Dimensions.Content.SetMainStart(mainAxis, contentMainStart)

            // 2. Cross Axis Position
            crossStartContentOffset := getCrossStartContentOffset(&item.Box.Dimensions, dirInfo.CrossAxis)

            // Position relative to the line start, adjusted by alignment offset (stored in crossAxisOffset) and edges.
            crossContentStart := containerCrossStart + line.CrossStart + item.Box.crossAxisOffset + crossStartContentOffset
            item.Box.Dimensions.Content.SetCrossStart(dirInfo.CrossAxis, crossContentStart)

            // Advance offset for the next item
            if dirInfo.IsReverse {
                currentMainOffset -= (item.TargetMainSize + item.Box.Dimensions.GetMainStatic(mainAxis) + spacing)
            } else {
                currentMainOffset += (item.TargetMainSize + item.Box.Dimensions.GetMainStatic(mainAxis) + spacing)
            }
        }
    }
}

// isAutoCrossSize checks if cross size is auto.
func (b *LayoutBox) isAutoCrossSize(e *Engine) bool {
    // If the height/width property corresponding to the cross axis is 'auto'.
    dirInfo := getFlexDirectionInfo(b.StyledNode)
    if dirInfo.CrossAxis == Vertical {
        // TODO: Handle percentage height complexities (depends on parent height).
        return b.StyledNode.Lookup("height", "auto") == "auto"
    }
    // For horizontal cross axis (width), 'auto' behavior depends on the display type of the container itself.
    return b.StyledNode.Lookup("width", "auto") == "auto"
}

// resolveFlexLength resolves lengths in flex context
func (b *LayoutBox) resolveFlexLength(value string, axis Axis, e *Engine) float64 {
    sn := b.StyledNode
    fontSize := getFontSize(sn)
    rootFontSize := BaseFontSize
    vw, vh := e.viewportWidth, e.viewportHeight

    // Determine reference dimension for percentage resolution (the container's size on that axis).
    dirInfo := getFlexDirectionInfo(sn)
    referenceDimension := b.Dimensions.GetMainSize(dirInfo.MainAxis)
    if axis != dirInfo.MainAxis {
        // Resolving percentages against cross size can be complex if the container's cross size is also auto.
        // This implementation assumes the container's size is definite when resolving percentages.
        referenceDimension = b.Dimensions.GetCrossSize(dirInfo.CrossAxis)
    }

    return parseLengthWithUnits(value, fontSize, rootFontSize, referenceDimension, vw, vh)
}

// alignFlexItem is a Step 6 helper for Cross Axis - align-self/align-items.
func (b *LayoutBox) alignFlexItem(item *LayoutBox, lineCrossSize float64, containerAlignItems style.AlignItems, crossAxis Axis, e *Engine) {
    align := containerAlignItems
    alignSelf := item.StyledNode.GetAlignSelf()

    // Determine the alignment style to use (align-self overrides align-items)
    switch alignSelf {
    case style.AlignSelfAuto:
        // Use container's align-items
    case style.AlignSelfStretch:
        align = style.AlignStretch
    case style.AlignSelfFlexStart:
        align = style.AlignFlexStart
    case style.AlignSelfCenter:
        align = style.AlignCenter
    case style.AlignSelfFlexEnd:
        align = style.AlignFlexEnd
    case style.AlignSelfBaseline:
        align = style.AlignBaseline
    }

    // Check if the item's cross size dimension is 'auto'.
    isAutoCross := false
    if crossAxis == Vertical {
        isAutoCross = item.StyledNode.Lookup("height", "auto") == "auto"
    } else {
        isAutoCross = item.StyledNode.Lookup("width", "auto") == "auto"
    }

    // Handle Stretch alignment
    if align == style.AlignStretch && isAutoCross {
        // Stretch the item to fill the line, respecting min/max constraints (skipped for now).
        // Calculate target content size by subtracting static space (margins, borders, padding).
        crossStatic := item.Dimensions.GetCrossStatic(crossAxis)
        targetCrossSize := lineCrossSize - crossStatic
        item.Dimensions.SetCrossSize(crossAxis, math.Max(0, targetCrossSize))

        // Re-layout content now that the size has changed, crucial for stretched items.
        item.layoutContent(e)

        item.crossAxisOffset = 0 // Stretched items start at the line start (relative offset).
        return
    }

    // Calculate free space within the line
    // Use the margin box size of the item for alignment calculation.
    itemCrossSize := item.Dimensions.GetCrossSize(crossAxis) + item.Dimensions.GetCrossStatic(crossAxis)
    freeSpace := lineCrossSize - itemCrossSize

    switch align {
    case style.AlignFlexStart, style.AlignStretch: // Stretch when dimension is fixed behaves as flex-start
        item.crossAxisOffset = 0
    case style.AlignFlexEnd:
        item.crossAxisOffset = freeSpace
    case style.AlignCenter:
        item.crossAxisOffset = freeSpace / 2.0
    case style.AlignBaseline:
        // TODO: Baseline alignment is complex. Requires calculating and aligning baselines.
        // Fallback to flex-start for now.
        item.crossAxisOffset = 0
    }
}

// calculateAlignmentOffsets is a helper for justify-content and align-content.
func (b *LayoutBox) calculateAlignmentOffsets(itemCount int, totalSize, availableSize float64, alignment interface{}) (startOffset, spacing float64) {
    freeSpace := availableSize - totalSize
    if freeSpace <= 0 {
        // If space is overflown or exactly filled, alignment defaults to flex-start behavior for positioning.
        return 0, 0
    }

    // Determine the specific alignment behavior based on the type (JustifyContent or AlignContent)
    var alignBehavior int // 0:Start, 1:End, 2:Center, 3:Between, 4:Around, 5:Evenly

    switch v := alignment.(type) {
    case style.JustifyContent:
        switch v {
        case style.JustifyFlexStart:
            alignBehavior = 0
        case style.JustifyFlexEnd:
            alignBehavior = 1
        case style.JustifyCenter:
            alignBehavior = 2
        case style.JustifySpaceBetween:
            alignBehavior = 3
        case style.JustifySpaceAround:
            alignBehavior = 4
        case style.JustifySpaceEvenly:
            alignBehavior = 5
        }
    case style.AlignContent:
        switch v {
        case style.AlignContentFlexStart:
            alignBehavior = 0
        case style.AlignContentFlexEnd:
            alignBehavior = 1
        case style.AlignContentCenter:
            alignBehavior = 2
        case style.AlignContentSpaceBetween:
            alignBehavior = 3
        case style.AlignContentSpaceAround:
            alignBehavior = 4
        case style.AlignContentSpaceEvenly:
            alignBehavior = 5
        case style.AlignContentStretch:
            // Stretch is handled by resizing the items/lines themselves.
            // For positioning offsets, it behaves like flex-start.
            alignBehavior = 0
        }
    default:
        return 0, 0 // Unknown alignment type
    }

    switch alignBehavior {
    case 0: // FlexStart
        startOffset = 0
        spacing = 0
    case 1: // FlexEnd
        startOffset = freeSpace
        spacing = 0
    case 2: // Center
        startOffset = freeSpace / 2.0
        spacing = 0
    case 3: // SpaceBetween
        startOffset = 0
        if itemCount > 1 {
            spacing = freeSpace / float64(itemCount-1)
        }
    case 4: // SpaceAround
        if itemCount > 0 {
            spacing = freeSpace / float64(itemCount)
            startOffset = spacing / 2.0
        } else {
            startOffset = freeSpace / 2.0 // Center if empty
        }
    case 5: // SpaceEvenly
        if itemCount > 0 {
            spacing = freeSpace / float64(itemCount+1)
            startOffset = spacing
        } else {
            startOffset = freeSpace / 2.0 // Center if empty
        }
    }
    return startOffset, spacing
}

type GridTrack struct {
    BaseSize     float64
    GrowthFactor float64
    MaxSize      float64
}
type GridItem struct {
    Box              *LayoutBox
    RowStart, RowEnd int
    ColStart, ColEnd int
    Row, Col         int
    RowSpan, ColSpan int
}

func (b *LayoutBox) layoutGrid(e *Engine) {
    // A full grid implementation is a massive undertaking.
    // We'll fall back to block layout as a placeholder.
    b.layoutBlockFlow(e)
}

type TableColumn struct {
    MinWidth    float64
    MaxWidth    float64
    FinalWidth  float64
    IsSpecified bool
}

func (b *LayoutBox) layoutTable(e *Engine) {
    // A full table implementation is also very complex.
    // Falling back to block layout is a robust placeholder.
    b.layoutBlockFlow(e)
}

// -- Positioning and Transforms --

func (b *LayoutBox) layoutPositionedChildren(e *Engine) {
    for _, child := range b.Children {
        if child.BoxType == AnonymousBlockBox {
            child.layoutPositionedChildren(e)
            continue
        }
        if child.StyledNode == nil {
            continue
        }
        pos := child.StyledNode.Position()
        if pos == style.PositionAbsolute || pos == style.PositionFixed {
            child.layoutPositioned(e)
        }
    }
}

func (b *LayoutBox) layoutPositioned(e *Engine) {
    pcbBox := b.GetPositioningContainingBlock()
    if pcbBox == nil {
        return
    }

    pcbPaddingBox := pcbBox.Dimensions.PaddingBox()
    refWidth := pcbBox.Dimensions.Content.Width
    sn := b.StyledNode
    fontSize := getFontSize(sn)
    rootFontSize := BaseFontSize
    vw, vh := e.viewportWidth, e.viewportHeight

    resolveW := func(val string) float64 { return parseLengthWithUnits(val, fontSize, rootFontSize, refWidth, vw, vh) }
    isRefHeightAuto := pcbBox.StyledNode != nil && pcbBox.StyledNode.Lookup("height", "auto") == "auto" && pcbBox.ContainingBlock != nil
    refHeight := pcbBox.Dimensions.Content.Height
    resolveH := func(val string) float64 {
        if strings.Contains(val, "%") && isRefHeightAuto {
            return math.NaN()
        }
        return parseLengthWithUnits(val, fontSize, rootFontSize, refHeight, vw, vh)
    }

    parseAutoW := func(val string) float64 {
        if val == "auto" {
            return math.NaN()
        }
        return resolveW(val)
    }
    parseAutoH := func(val string) float64 {
        if val == "auto" {
            return math.NaN()
        }
        return resolveH(val)
    }

    left := parseAutoW(sn.Lookup("left", "auto"))
    right := parseAutoW(sn.Lookup("right", "auto"))
    width := parseAutoW(sn.Lookup("width", "auto"))
    top := parseAutoH(sn.Lookup("top", "auto"))
    bottom := parseAutoH(sn.Lookup("bottom", "auto"))
    height := parseAutoH(sn.Lookup("height", "auto"))

    b.calculatePaddingAndBorders(refWidth, e)

    marginLeft := parseAutoW(sn.Lookup("margin-left", "0"))
    marginRight := parseAutoW(sn.Lookup("margin-right", "0"))
    marginTop := parseAutoH(sn.Lookup("margin-top", "0"))
    marginBottom := parseAutoH(sn.Lookup("margin-bottom", "0"))

    hStatic := b.Dimensions.Padding.Left + b.Dimensions.Padding.Right + b.Dimensions.Border.Left + b.Dimensions.Border.Right
    vStatic := b.Dimensions.Padding.Top + b.Dimensions.Padding.Bottom + b.Dimensions.Border.Top + b.Dimensions.Border.Bottom

    if sn.BoxSizing() == style.BorderBox {
        if !math.IsNaN(width) {
            width = math.Max(0.0, width-hStatic)
        }
        if !math.IsNaN(height) {
            height = math.Max(0.0, height-vStatic)
        }
    }

    finalWidth, finalLeft, finalMarginLeft, finalMarginRight := b.solvePositionedHorizontalConstraints(e, pcbBox, left, width, right, marginLeft, marginRight)
    b.Dimensions.Content.Width = finalWidth
    b.Dimensions.Margin.Left = finalMarginLeft
    b.Dimensions.Margin.Right = finalMarginRight

    b.layoutContent(e) // Layout children to determine auto height

    if math.IsNaN(height) {
        height = b.Dimensions.Content.Height
    }

    finalTop, finalMarginTop, finalMarginBottom := b.solvePositionedVerticalConstraints(e, pcbBox, top, height, bottom, marginTop, marginBottom)
    b.Dimensions.Content.Height = height
    b.Dimensions.Margin.Top = finalMarginTop
    b.Dimensions.Margin.Bottom = finalMarginBottom

    b.Dimensions.Content.X = pcbPaddingBox.X + finalLeft + b.Dimensions.Margin.Left + b.Dimensions.Border.Left + b.Dimensions.Padding.Left
    b.Dimensions.Content.Y = pcbPaddingBox.Y + finalTop + b.Dimensions.Margin.Top + b.Dimensions.Border.Top + b.Dimensions.Padding.Top

    b.layoutPositionedChildren(e)
}

func (b *LayoutBox) solvePositionedHorizontalConstraints(e *Engine, pcbBox *LayoutBox, left, width, right, marginLeft, marginRight float64) (float64, float64, float64, float64) {
    cbPaddingWidth := pcbBox.Dimensions.PaddingBox().Width
    hStatic := b.Dimensions.Padding.Left + b.Dimensions.Padding.Right + b.Dimensions.Border.Left + b.Dimensions.Border.Right
    availableWidth := cbPaddingWidth
    if !math.IsNaN(left) {
        availableWidth -= left
    }
    if !math.IsNaN(right) {
        availableWidth -= right
    }
    tempML := marginLeft
    if math.IsNaN(tempML) {
        tempML = 0.0
    }
    tempMR := marginRight
    if math.IsNaN(tempMR) {
        tempMR = 0.0
    }
    availableWidth -= (tempML + tempMR + hStatic)
    availableWidth = math.Max(0.0, availableWidth)

    if math.IsNaN(width) && (math.IsNaN(left) || math.IsNaN(right)) {
        width = b.calculateShrinkToFitWidth(e, availableWidth)
    }
    if math.IsNaN(left) && math.IsNaN(right) {
        left = b.getStaticPositionX(pcbBox)
    }

    if !math.IsNaN(left) && !math.IsNaN(right) && !math.IsNaN(width) {
        remaining := cbPaddingWidth - left - right - width - hStatic
        if math.IsNaN(marginLeft) && math.IsNaN(marginRight) {
            marginLeft = remaining / 2.0
            marginRight = remaining / 2.0
        } else if math.IsNaN(marginLeft) {
            marginLeft = remaining - marginRight
        } else if math.IsNaN(marginRight) {
            marginRight = remaining - marginLeft
        } else {
            right = cbPaddingWidth - left - width - hStatic - marginLeft - marginRight
        }
    } else {
        if math.IsNaN(marginLeft) {
            marginLeft = 0.0
        }
        if math.IsNaN(marginRight) {
            marginRight = 0.0
        }
        if math.IsNaN(width) {
            width = cbPaddingWidth - left - right - hStatic - marginLeft - marginRight
            width = math.Max(0.0, width)
        } else if math.IsNaN(left) {
            left = cbPaddingWidth - right - width - hStatic - marginLeft - marginRight
        } else if math.IsNaN(right) {
            right = cbPaddingWidth - left - width - hStatic - marginLeft - marginRight
        }
    }

    if math.IsNaN(marginLeft) {
        marginLeft = 0.0
    }
    if math.IsNaN(marginRight) {
        marginRight = 0.0
    }
    return width, left, marginLeft, marginRight
}

func (b *LayoutBox) solvePositionedVerticalConstraints(e *Engine, pcbBox *LayoutBox, top, height, bottom, marginTop, marginBottom float64) (float64, float64, float64) {
    cbPaddingHeight := pcbBox.Dimensions.PaddingBox().Height
    vStatic := b.Dimensions.Padding.Top + b.Dimensions.Padding.Bottom + b.Dimensions.Border.Top + b.Dimensions.Border.Bottom

    if math.IsNaN(height) {
        height = 0.0
    }
    if math.IsNaN(top) && math.IsNaN(bottom) {
        top = b.getStaticPositionY(pcbBox)
    }

    if !math.IsNaN(top) && !math.IsNaN(bottom) && !math.IsNaN(height) {
        remaining := cbPaddingHeight - top - bottom - height - vStatic
        if math.IsNaN(marginTop) && math.IsNaN(marginBottom) {
            marginTop = remaining / 2.0
            marginBottom = remaining / 2.0
        } else if math.IsNaN(marginTop) {
            marginTop = remaining - marginBottom
        } else if math.IsNaN(marginBottom) {
            marginBottom = remaining - marginTop
        } else {
            bottom = cbPaddingHeight - top - height - vStatic - marginTop - marginBottom
        }
    } else {
        if math.IsNaN(marginTop) {
            marginTop = 0.0
        }
        if math.IsNaN(marginBottom) {
            marginBottom = 0.0
        }
        if math.IsNaN(top) {
            top = cbPaddingHeight - bottom - height - vStatic - marginTop - marginBottom
        } else if math.IsNaN(bottom) {
            bottom = cbPaddingHeight - top - height - vStatic - marginTop - marginBottom
        }
    }

    if math.IsNaN(marginTop) {
        marginTop = 0.0
    }
    if math.IsNaN(marginBottom) {
        marginBottom = 0.0
    }
    return top, marginTop, marginBottom
}

func (b *LayoutBox) getStaticPositionX(pcbBox *LayoutBox) float64 {
    // A correct implementation is highly complex. This simplified placeholder returns 0,
    // which means the element's static position is assumed to be at the left padding edge
    // of its positioning containing block.
    return 0.0
}

func (b *LayoutBox) getStaticPositionY(pcbBox *LayoutBox) float64 {
    // Similar to the X version, this is a placeholder. The static Y position would be
    // where the element would have appeared in the normal flow.
    return 0.0
}

func (b *LayoutBox) applyRelativePositioning() {
    if b.StyledNode == nil || b.StyledNode.Position() != style.PositionRelative {
        return
    }

    sn := b.StyledNode
    fontSize := getFontSize(sn)
    rootFontSize := BaseFontSize
    cb := b.ContainingBlock.Dimensions
    vw, vh := b.getRoot().Dimensions.Content.Width, b.getRoot().Dimensions.Content.Height

    offsetX, offsetY := 0.0, 0.0
    top := sn.Lookup("top", "auto")
    bottom := sn.Lookup("bottom", "auto")
    left := sn.Lookup("left", "auto")
    right := sn.Lookup("right", "auto")

    if top != "auto" {
        offsetY += parseLengthWithUnits(top, fontSize, rootFontSize, cb.Content.Height, vw, vh)
    } else if bottom != "auto" {
        offsetY -= parseLengthWithUnits(bottom, fontSize, rootFontSize, cb.Content.Height, vw, vh)
    }

    if left != "auto" {
        offsetX += parseLengthWithUnits(left, fontSize, rootFontSize, cb.Content.Width, vw, vh)
    } else if right != "auto" {
        offsetX -= parseLengthWithUnits(right, fontSize, rootFontSize, cb.Content.Width, vw, vh)
    }

    b.Dimensions.Content.X += offsetX
    b.Dimensions.Content.Y += offsetY
}

func (b *LayoutBox) applyTransforms(parentTransform TransformMatrix) {
    currentTransform := parentTransform
    if b.StyledNode != nil {
        // A full implementation would parse the 'transform' and 'transform-origin' CSS properties,
        // create a matrix for each function (translate, rotate, scale), and combine them.
        // For now, we will just propagate the parent's transform down.
    }
    b.Dimensions.Transform = currentTransform
    for _, child := range b.Children {
        child.applyTransforms(b.Dimensions.Transform)
    }
}

// -- Floats --

type FloatList struct {
    Floats []*LayoutBox
}

func NewFloatList() *FloatList {
    return &FloatList{}
}

func (fl *FloatList) CalculateClearance(currentY float64, clearType style.ClearType) float64 {
    maxY := 0.0
    hasClear := false

    for _, floatBox := range fl.Floats {
        floatType := floatBox.StyledNode.Float()
        applies := (clearType == style.ClearLeft && floatType == style.FloatLeft) ||
            (clearType == style.ClearRight && floatType == style.FloatRight) ||
            (clearType == style.ClearBoth)

        if applies {
            bottomEdge := floatBox.Dimensions.MarginBox().Y + floatBox.Dimensions.MarginBox().Height
            if bottomEdge > maxY {
                maxY = bottomEdge
                hasClear = true
            }
        }
    }

    if hasClear && maxY > currentY {
        return maxY - currentY
    }
    return 0
}

func (fl *FloatList) GetIndentationAtY(y, containerX, containerWidth float64) (leftIndent, rightIndent float64) {
    leftEdge := containerX
    rightEdge := containerX + containerWidth

    for _, floatBox := range fl.Floats {
        mb := floatBox.Dimensions.MarginBox()
        if y >= mb.Y && y < mb.Y+mb.Height { // Check for vertical overlap
            if floatBox.StyledNode.Float() == style.FloatLeft {
                if mb.X+mb.Width > leftEdge {
                    leftEdge = mb.X + mb.Width
                }
            } else { // FloatRight
                if mb.X < rightEdge {
                    rightEdge = mb.X
                }
            }
        }
    }
    return leftEdge - containerX, (containerX + containerWidth) - rightEdge
}

func (fl *FloatList) GetMaxExtentY() float64 {
    maxY := 0.0
    for _, floatBox := range fl.Floats {
        extentY := floatBox.Dimensions.MarginBox().Y + floatBox.Dimensions.MarginBox().Height
        if extentY > maxY {
            maxY = extentY
        }
    }
    return maxY
}

func (b *LayoutBox) layoutFloatedBox(child *LayoutBox, e *Engine, context *LayoutContext) {
    child.calculateBlockWidthAndEdges(e)
    child.layoutContent(e) // Layout its children to determine height

    cbContent := b.Dimensions.Content
    floatType := child.StyledNode.Float()

    yPos := context.CurrentY

    for {
        leftIndent, rightIndent := b.Floats.GetIndentationAtY(yPos, cbContent.X, cbContent.Width)
        availableWidth := cbContent.Width - leftIndent - rightIndent

        if child.Dimensions.MarginBox().Width <= availableWidth {
            break // It fits here.
        }

        // It doesn't fit. We need to move down. A better algorithm would find the next
        // vertical position where the available width changes. This simplified version
        // just increments, which can be slow but is correct.
        yPos++
    }

    if floatType == style.FloatLeft {
        leftIndent, _ := b.Floats.GetIndentationAtY(yPos, cbContent.X, cbContent.Width)
        child.Dimensions.Content.X = cbContent.X + leftIndent + child.Dimensions.Margin.Left + child.Dimensions.Border.Left + child.Dimensions.Padding.Left
    } else {
        _, rightIndent := b.Floats.GetIndentationAtY(yPos, cbContent.X, cbContent.Width)
        child.Dimensions.Content.X = cbContent.X + cbContent.Width - rightIndent - child.Dimensions.Margin.Right - child.Dimensions.Border.Right - child.Dimensions.Padding.Right - child.Dimensions.Content.Width
    }
    child.Dimensions.Content.Y = yPos + child.Dimensions.Margin.Top + child.Dimensions.Border.Top + child.Dimensions.Padding.Top

    b.Floats.Floats = append(b.Floats.Floats, child)
}

// -- Box Model Calculations --

func (b *LayoutBox) calculateBlockWidthAndEdges(e *Engine) {
    if b.StyledNode == nil {
        return
    }
    if b.ContainingBlock == nil {
        b.calculatePaddingAndBorders(b.Dimensions.Content.Width, e)
        b.calculateMargins(b.Dimensions.Content.Width, e)
        return
    }

    sn := b.StyledNode
    cb := b.ContainingBlock.Dimensions
    referenceWidth := cb.Content.Width
    widthStr := sn.Lookup("width", "auto")
    marginLeftStr := sn.Lookup("margin-left", "0")
    marginRightStr := sn.Lookup("margin-right", "0")
    fontSize := getFontSize(sn)
    rootFontSize := BaseFontSize
    resolve := func(val string) float64 {
        return parseLengthWithUnits(val, fontSize, rootFontSize, referenceWidth, e.viewportWidth, e.viewportHeight)
    }

    b.calculatePaddingAndBorders(referenceWidth, e)
    paddingLeft := b.Dimensions.Padding.Left
    paddingRight := b.Dimensions.Padding.Right
    borderLeft := b.Dimensions.Border.Left
    borderRight := b.Dimensions.Border.Right

    parseAuto := func(val string) float64 {
        if val == "auto" {
            return math.NaN()
        }
        return resolve(val)
    }

    width := parseAuto(widthStr)
    marginLeft := parseAuto(marginLeftStr)
    marginRight := parseAuto(marginRightStr)
    isFloat := sn.Float() != style.FloatNone

    if (b.BoxType == InlineBlockBox || isFloat) && math.IsNaN(width) {
        width = b.calculateShrinkToFitWidth(e, referenceWidth)
    }

    boxSizing := sn.BoxSizing()
    if boxSizing == style.BorderBox && !math.IsNaN(width) && widthStr != "auto" {
        contentWidth := width - paddingLeft - paddingRight - borderLeft - borderRight
        width = math.Max(0.0, contentWidth)
    }

    totalStatic := paddingLeft + paddingRight + borderLeft + borderRight

    if b.BoxType == InlineBlockBox || isFloat {
        if math.IsNaN(marginLeft) {
            marginLeft = 0.0
        }
        if math.IsNaN(marginRight) {
            marginRight = 0.0
        }
    } else {
        if !math.IsNaN(width) && !math.IsNaN(marginLeft) && !math.IsNaN(marginRight) {
            marginRight = referenceWidth - totalStatic - width - marginLeft
        }

        if math.IsNaN(width) {
            if math.IsNaN(marginLeft) {
                marginLeft = 0.0
            }
            if math.IsNaN(marginRight) {
                marginRight = 0.0
            }
            width = referenceWidth - totalStatic - marginLeft - marginRight
            if width < 0 {
                width = 0.0
                marginRight = referenceWidth - totalStatic - width - marginLeft
            }
        } else {
            if math.IsNaN(marginLeft) && math.IsNaN(marginRight) {
                remaining := referenceWidth - totalStatic - width
                marginLeft = remaining / 2.0
                marginRight = remaining / 2.0
            } else if math.IsNaN(marginLeft) {
                marginLeft = referenceWidth - totalStatic - width - marginRight
            } else if math.IsNaN(marginRight) {
                marginRight = referenceWidth - totalStatic - width - marginLeft
            }
        }
    }

    b.Dimensions.Content.Width = width
    b.Dimensions.Margin.Left = marginLeft
    b.Dimensions.Margin.Right = marginRight
    b.Dimensions.Margin.Top = resolve(sn.Lookup("margin-top", "0"))
    b.Dimensions.Margin.Bottom = resolve(sn.Lookup("margin-bottom", "0"))
}

func (b *LayoutBox) calculateShrinkToFitWidth(e *Engine, availableWidth float64) float64 {
    // A proper implementation requires a complex intrinsic width calculation pass.
    // This heuristic measures text content as a substitute for the preferred width,
    // which works for simple cases.
    if b.StyledNode != nil {
        // Check children (considering potential Shadow DOM encapsulation)
        childrenToInspect := b.StyledNode.Children
        if b.StyledNode.ShadowRoot != nil {
            childrenToInspect = b.StyledNode.ShadowRoot.Children
        }

        if len(childrenToInspect) > 0 {
            // Simplified measurement of the first child if it's text.
            if childrenToInspect[0].Node.Type == html.TextNode {
                w, _ := measureText(childrenToInspect[0])
                return math.Min(w, availableWidth)
            }
        }
    }
    return 0.0
}

func (b *LayoutBox) calculatePaddingAndBorders(referenceWidth float64, e *Engine) {
    if b.StyledNode == nil {
        return
    }
    sn := b.StyledNode
    fontSize := getFontSize(sn)
    rootFontSize := BaseFontSize

    resolvePadding := func(propName string, defaultValue string) float64 {
        valStr := sn.Lookup(propName, defaultValue)
        resolved := parseLengthWithUnits(valStr, fontSize, rootFontSize, referenceWidth, e.viewportWidth, e.viewportHeight)
        return math.Max(0.0, resolved)
    }

    b.Dimensions.Padding.Top = resolvePadding("padding-top", "0")
    b.Dimensions.Padding.Right = resolvePadding("padding-right", "0")
    b.Dimensions.Padding.Bottom = resolvePadding("padding-bottom", "0")
    b.Dimensions.Padding.Left = resolvePadding("padding-left", "0")

    resolveBorder := func(propName string, stylePropName string) float64 {
        style := sn.Lookup(stylePropName, "none")
        if style == "none" || style == "hidden" {
            return 0.0
        }
        valStr := sn.Lookup(propName, "medium")
        if valStr == "thin" {
            return 1.0
        }
        if valStr == "medium" {
            return 3.0
        }
        if valStr == "thick" {
            return 5.0
        }
        resolved := parseLengthWithUnits(valStr, fontSize, rootFontSize, 0, e.viewportWidth, e.viewportHeight)
        return math.Max(0.0, resolved)
    }

    b.Dimensions.Border.Top = resolveBorder("border-top-width", "border-top-style")
    b.Dimensions.Border.Right = resolveBorder("border-right-width", "border-right-style")
    b.Dimensions.Border.Bottom = resolveBorder("border-bottom-width", "border-bottom-style")
    b.Dimensions.Border.Left = resolveBorder("border-left-width", "border-left-style")
}

func (b *LayoutBox) calculateMargins(referenceWidth float64, e *Engine) {
    if b.StyledNode == nil {
        return
    }
    sn := b.StyledNode
    fontSize := getFontSize(sn)
    rootFontSize := BaseFontSize

    resolveAuto := func(propName string) float64 {
        valStr := sn.Lookup(propName, "0")
        if valStr == "auto" {
            return 0.0
        }
        return parseLengthWithUnits(valStr, fontSize, rootFontSize, referenceWidth, e.viewportWidth, e.viewportHeight)
    }

    b.Dimensions.Margin.Top = resolveAuto("margin-top")
    b.Dimensions.Margin.Bottom = resolveAuto("margin-bottom")
    b.Dimensions.Margin.Left = resolveAuto("margin-left")
    b.Dimensions.Margin.Right = resolveAuto("margin-right")
}

func (b *LayoutBox) calculateInlineEdges(e *Engine) {
    referenceWidth := 0.0
    if b.ContainingBlock != nil {
        referenceWidth = b.ContainingBlock.Dimensions.Content.Width
    }
    b.calculatePaddingAndBorders(referenceWidth, e)
    b.calculateMargins(referenceWidth, e)
}

func (b *LayoutBox) calculateBlockHeight() {
    if b.StyledNode != nil {
        heightStr := b.StyledNode.Lookup("height", "auto")
        root := b.getRoot()
        vw, vh := root.Dimensions.Content.Width, root.Dimensions.Content.Height
        cbBox := b.ContainingBlock
        referenceHeight := 0.0
        isReferenceAuto := false

        if cbBox != nil {
            if cbBox.StyledNode != nil && cbBox.StyledNode.Lookup("height", "auto") == "auto" {
                if cbBox.ContainingBlock != nil {
                    isReferenceAuto = true
                }
            }
            referenceHeight = cbBox.Dimensions.Content.Height
        }

        isPercentage := strings.Contains(heightStr, "%")
        if heightStr != "auto" && (!isPercentage || !isReferenceAuto) {
            fontSize := getFontSize(b.StyledNode)
            resolvedHeight := parseLengthWithUnits(heightStr, fontSize, BaseFontSize, referenceHeight, vw, vh)
            if b.StyledNode.BoxSizing() == style.BorderBox {
                paddingTop := b.Dimensions.Padding.Top
                paddingBottom := b.Dimensions.Padding.Bottom
                borderTop := b.Dimensions.Border.Top
                borderBottom := b.Dimensions.Border.Bottom
                contentHeight := resolvedHeight - paddingTop - paddingBottom - borderTop - borderBottom
                b.Dimensions.Content.Height = math.Max(0.0, contentHeight)
            } else {
                b.Dimensions.Content.Height = resolvedHeight
            }
            return
        }
    }

    maxHeight := 0.0
    for _, child := range b.Children {
        if child.StyledNode != nil {
            pos := child.StyledNode.Position()
            if pos == style.PositionAbsolute || pos == style.PositionFixed {
                continue
            }
        }
        childMarginBox := child.Dimensions.MarginBox()
        childBottomY := childMarginBox.Y + childMarginBox.Height - b.Dimensions.Content.Y
        if childBottomY > maxHeight {
            maxHeight = childBottomY
        }
    }

    if b.EstablishesNewFormattingContext() && b.Floats != nil {
        floatMaxY := b.Floats.GetMaxExtentY()
        floatBottomY := floatMaxY - b.Dimensions.Content.Y
        if floatBottomY > maxHeight {
            maxHeight = floatBottomY
        }
    }
    b.Dimensions.Content.Height = maxHeight
}

func (b *LayoutBox) calculateInlineDimensions() {
    if b.StyledNode != nil && b.StyledNode.Node.Type == html.TextNode {
        width, height := measureText(b.StyledNode)
        b.Dimensions.Content.Width = width
        b.Dimensions.Content.Height = height
        return
    }

    maxWidth := 0.0
    maxHeight := 0.0
    for _, child := range b.Children {
        childMarginBox := child.Dimensions.MarginBox()
        maxWidth += childMarginBox.Width
        if childMarginBox.Height > maxHeight {
            maxHeight = childMarginBox.Height
        }
    }
    b.Dimensions.Content.Width = maxWidth

    if b.StyledNode != nil {
        lineHeight := BaseFontSize * DefaultLineHeight
        lineHeight = parseAbsoluteLength(b.StyledNode.Lookup("line-height", fmt.Sprintf("%fpx", lineHeight)))
        b.Dimensions.Content.Height = lineHeight
    } else {
        b.Dimensions.Content.Height = maxHeight
    }
}

// -- Text Measurement and Font Metrics --

func getFontSize(sn *style.StyledNode) float64 {
    if sn == nil {
        return BaseFontSize
    }
    return parseAbsoluteLength(sn.Lookup("font-size", fmt.Sprintf("%fpx", BaseFontSize)))
}

func getFontAscent(sn *style.StyledNode) float64 {
    return getFontSize(sn) * 0.8
}

func measureText(sn *style.StyledNode) (width, height float64) {
    if sn == nil || sn.Node.Type != html.TextNode {
        return 0, 0
    }
    fontSize := getFontSize(sn)
    text := sn.Node.Data
    avgCharWidth := fontSize * 0.5
    width = float64(len(text)) * avgCharWidth
    height = fontSize
    return width, height
}

// -- Helpers --

func (b *LayoutBox) getRoot() *LayoutBox {
    root := b
    for root.ContainingBlock != nil {
        root = root.ContainingBlock
    }
    return root
}

func lookupStyle(styles map[parser.Property]parser.Value, property parser.Property, fallback string) string {
    if val, ok := styles[property]; ok {
        return string(val)
    }
    return fallback
}

func parseLengthWithUnits(value string, parentFontSize, rootFontSize, referenceDimension, viewportWidth, viewportHeight float64) float64 {
    value = strings.TrimSpace(value)
    if value == "" || value == "auto" || value == "normal" {
        return 0.0
    }

    if strings.HasSuffix(value, "%") {
        if percent, err := parseFloat(strings.TrimSuffix(value, "%")); err == nil {
            return referenceDimension * (percent / 100.0)
        }
    }
    if strings.HasSuffix(value, "px") {
        if px, err := parseFloat(strings.TrimSuffix(value, "px")); err == nil {
            return px
        }
    }
    if strings.HasSuffix(value, "em") {
        if val, err := parseFloat(strings.TrimSuffix(value, "em")); err == nil {
            return val * parentFontSize
        }
    }
    if strings.HasSuffix(value, "rem") {
        if val, err := parseFloat(strings.TrimSuffix(value, "rem")); err == nil {
            return val * rootFontSize
        }
    }
    if strings.HasSuffix(value, "vw") {
        if val, err := parseFloat(strings.TrimSuffix(value, "vw")); err == nil {
            return viewportWidth * (val / 100.0)
        }
    }
    if strings.HasSuffix(value, "vh") {
        if val, err := parseFloat(strings.TrimSuffix(value, "vh")); err == nil {
            return viewportHeight * (val / 100.0)
        }
    }
    if strings.HasSuffix(value, "vmin") {
        if val, err := parseFloat(strings.TrimSuffix(value, "vmin")); err == nil {
            return math.Min(viewportWidth, viewportHeight) * (val / 100.0)
        }
    }
    if strings.HasSuffix(value, "vmax") {
        if val, err := parseFloat(strings.TrimSuffix(value, "vmax")); err == nil {
            return math.Max(viewportWidth, viewportHeight) * (val / 100.0)
        }
    }
    if val, err := parseFloat(value); err == nil {
        return val
    }
    return 0.0
}

func parseAbsoluteLength(value string) float64 {
    return parseLengthWithUnits(value, 0, 0, 0, 0, 0)
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

func max(a, b float64) float64 {
    if a > b {
        return a
    }
    return b
}

func maxInt(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// -- Public Interface for Geometry Retrieval --

func (e *Engine) GetElementGeometry(layoutRoot *LayoutBox, selector string) (*schemas.ElementGeometry, error) {
    if layoutRoot == nil {
        return nil, fmt.Errorf("layout tree is nil")
    }
    domRoot := findDOMRoot(layoutRoot)
    if domRoot == nil {
        return nil, fmt.Errorf("could not find root DOM node")
    }
    targetNode, err := htmlquery.Query(domRoot, selector)
    if err != nil {
        return nil, fmt.Errorf("invalid XPath selector '%s': %w", selector, err)
    }
    if targetNode == nil {
        // TODO: Implement search across Shadow DOM boundaries if not found in Light DOM.
        return nil, fmt.Errorf("element not found matching selector '%s'", selector)
    }
    // This traversal follows the layout tree, which represents the composed (flattened) tree.
    box := findLayoutBoxForNode(layoutRoot, targetNode)
    if box == nil {
        return nil, fmt.Errorf("element '%s' found in DOM but not rendered (e.g., display: none)", selector)
    }
    if box.StyledNode != nil && !box.StyledNode.IsVisible() {
        return nil, fmt.Errorf("element '%s' is hidden (visibility, opacity, etc.)", selector)
    }
    return box.ToElementGeometry(), nil
}

func (b *LayoutBox) ToElementGeometry() *schemas.ElementGeometry {
    rect := b.Dimensions.BorderBox()
    transform := b.Dimensions.Transform
    x, y, width, height := rect.X, rect.Y, rect.Width, rect.Height
    topLeftX, topLeftY := x, y
    topRightX, topRightY := x+width, y
    bottomRightX, bottomRightY := x+width, y+height
    bottomLeftX, bottomLeftY := x, y+height
    tx1, ty1 := transform.Apply(topLeftX, topLeftY)
    tx2, ty2 := transform.Apply(topRightX, topRightY)
    tx3, ty3 := transform.Apply(bottomRightX, bottomRightY)
    tx4, ty4 := transform.Apply(bottomLeftX, bottomLeftY)
    vertices := []float64{tx1, ty1, tx2, ty2, tx3, ty3, tx4, ty4}
    minX := math.Min(tx1, math.Min(tx2, math.Min(tx3, tx4)))
    maxX := math.Max(tx1, math.Max(tx2, math.Max(tx3, tx4)))
    minY := math.Min(ty1, math.Min(ty2, math.Min(ty3, ty4)))
    maxY := math.Max(ty1, math.Max(ty2, math.Max(ty3, ty4)))
    aabbWidth := maxX - minX
    aabbHeight := maxY - minY
    return &schemas.ElementGeometry{
        Vertices: vertices,
        Width:    int64(math.Round(aabbWidth)),
        Height:   int64(math.Round(aabbHeight)),
    }
}

func findDOMRoot(box *LayoutBox) *html.Node {
    if box == nil {
        return nil
    }
    rootBox := box.getRoot()
    if rootBox.StyledNode != nil && rootBox.StyledNode.Node != nil {
        rootNode := rootBox.StyledNode.Node
        for rootNode.Parent != nil {
            rootNode = rootNode.Parent
        }
        return rootNode
    }
    return nil
}

func findLayoutBoxForNode(root *LayoutBox, target *html.Node) *LayoutBox {
    if root == nil {
        return nil
    }
    if root.StyledNode != nil && root.StyledNode.Node == target {
        return root
    }
    for _, child := range root.Children {
        if found := findLayoutBoxForNode(child, target); found != nil {
            return found
        }
    }
    return nil
}