// internal/browser/layout/layout.go
package layout

import (
    "fmt"
    "math"
    "strconv"
    "strings"

    "github.com/antchfx/htmlquery"
    "github.com/xkilldash9x/scalpel-cli/api/schemas"
    "github.com/xkilldash9x/scalpel-cli/internal/browser/shadowdom"
    "github.com/xkilldash9x/scalpel-cli/internal/browser/style"
    "golang.org/x/net/html"
)

// -- Constants and Configuration --

const (
    BaseFontSize      = 16.0 // Default root font size.
    DefaultLineHeight = 1.2  // Default multiplier for 'line-height: normal'.
)

// -- Core Structures: Box Model and Dimensions --

// Axis represents the primary layout direction.
type Axis int

const (
    // Horizontal axis for layout calculations.
    Horizontal Axis = iota
    // Vertical axis for layout calculations.
    Vertical
)

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

// Inverse calculates the inverse of the transformation matrix.
// If the matrix is not invertible (i.e., its determinant is zero),
// it returns an error.
func (m TransformMatrix) Inverse() (TransformMatrix, error) {
    a, b, c, d, e, f := m.A, m.B, m.C, m.D, m.E, m.F

    det := a*d - b*c
    if det == 0 {
        return TransformMatrix{}, fmt.Errorf("matrix is not invertible")
    }

    invDet := 1.0 / det

    invA := d * invDet
    invB := -b * invDet
    invC := -c * invDet
    invD := a * invDet
    invE := (c*f - d*e) * invDet
    invF := (b*e - a*f) * invDet

    return TransformMatrix{
        A: invA, B: invB, C: invC, D: invD, E: invE, F: invF,
    }, nil
}

// TranslateMatrix creates a translation matrix.
func TranslateMatrix(tx, ty float64) TransformMatrix {
    return TransformMatrix{A: 1, D: 1, E: tx, F: ty}
}

// ScaleMatrix creates a scaling matrix.
func ScaleMatrix(sx, sy float64) TransformMatrix {
    return TransformMatrix{A: sx, D: sy}
}

// RotateMatrix creates a rotation matrix. Angle is in radians.
func RotateMatrix(angle float64) TransformMatrix {
    cosA := math.Cos(angle)
    sinA := math.Sin(angle)
    return TransformMatrix{
        A: cosA,
        B: sinA,
        C: -sinA,
        D: cosA,
    }
}

// SkewMatrix creates a skewing matrix. Angles are in radians.
func SkewMatrix(ax, ay float64) TransformMatrix {
    return TransformMatrix{
        A: 1,
        C: math.Tan(ax),
        B: math.Tan(ay),
        D: 1,
    }
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

// getRoot finds the root of the layout tree.
func (b *LayoutBox) getRoot() *LayoutBox {
    current := b
    for current.ContainingBlock != nil {
        current = current.ContainingBlock
    }
    return current
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
                if ancestorPos != style.PositionStatic {
                    return ancestor
                }
            }
            if ancestor.ContainingBlock == nil {
                break
            }
            ancestor = ancestor.ContainingBlock
        }
        return b.getRoot()
    }

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
    shadowEngine   *shadowdom.Engine
    viewportWidth  float64
    viewportHeight float64
}

func NewEngine(viewportWidth, viewportHeight float64) *Engine {
    return &Engine{
        shadowEngine:   &shadowdom.Engine{},
        viewportWidth:  viewportWidth,
        viewportHeight: viewportHeight,
    }
}

// BuildAndLayoutTree orchestrates the entire rendering process.
func (e *Engine) BuildAndLayoutTree(styleRoot *style.StyledNode) *LayoutBox {
    if styleRoot == nil {
        return nil
    }

    e.assignSlotsRecursive(styleRoot)

    layoutTree := e.BuildLayoutTree(styleRoot)

    if layoutTree == nil {
        return nil
    }

    layoutTree.Dimensions.Content = Rect{X: 0, Y: 0, Width: e.viewportWidth, Height: e.viewportHeight}
    layoutTree.ContainingBlock = nil
    layoutTree.Floats = NewFloatList()

    layoutTree.Layout(e)
    layoutTree.applyTransforms(e, IdentityMatrix())

    return layoutTree
}

// assignSlotsRecursive traverses the style tree and performs slot assignments for shadow hosts.
func (e *Engine) assignSlotsRecursive(sn *style.StyledNode) {
    if sn == nil {
        return
    }
    if sn.ShadowRoot != nil {
        e.shadowEngine.AssignSlots(sn)
    }

    for _, child := range sn.Children {
        e.assignSlotsRecursive(child)
    }
    if sn.ShadowRoot != nil {
        for _, child := range sn.ShadowRoot.Children {
            e.assignSlotsRecursive(child)
        }
    }
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

    childrenToLayout := styledNode.Children
    if styledNode.ShadowRoot != nil {
        childrenToLayout = styledNode.ShadowRoot.Children
    }

    for _, childStyled := range childrenToLayout {
        if childStyled.Node.Type == html.ElementNode && strings.EqualFold(childStyled.Node.Data, "slot") {
            slottedNodes := childStyled.SlotAssignment
            if len(slottedNodes) == 0 {
                slottedNodes = childStyled.Children
            }

            for _, slottedNode := range slottedNodes {
                childBox := e.BuildLayoutTree(slottedNode)
                if childBox != nil {
                    e.addChildToBox(root, childBox)
                }
            }
        } else {
            childBox := e.BuildLayoutTree(childStyled)
            if childBox != nil {
                e.addChildToBox(root, childBox)
            }
        }
    }

    return root
}

// addChildToBox is a helper to encapsulate the block/inline child placement logic.
func (e *Engine) addChildToBox(root *LayoutBox, childBox *LayoutBox) {
    switch root.BoxType {
    case FlexContainer, GridContainer:
        root.Children = append(root.Children, childBox)
    default:
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

func (e *Engine) fixupTableStructure(tableBox *LayoutBox) {
    if tableBox.StyledNode == nil {
        return
    }

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
        ascent := style.GetFontAscent(frag.StyledNode)

        if frag.StyledNode != nil {
            lineHeight = style.ParseAbsoluteLength(frag.StyledNode.Lookup("line-height", fmt.Sprintf("%fpx", lineHeight)))
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
            maxHeight = style.ParseAbsoluteLength(b.StyledNode.Lookup("line-height", fmt.Sprintf("%fpx", BaseFontSize*DefaultLineHeight)))
            maxAscent = style.GetFontAscent(b.StyledNode)
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
            fontSize := style.GetFontSize(frag.StyledNode)
            middleLine := baselineY - (0.5 * fontSize * 0.5)
            middleFrag := fragMarginBox.Y + fragMarginBox.Height/2
            offsetY = middleLine - middleFrag
        case "baseline":
            fragAscent := style.GetFontAscent(frag.StyledNode)
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

    dirInfo := getFlexDirectionInfo(sn)
    mainAxis := dirInfo.MainAxis
    crossAxis := dirInfo.CrossAxis
    b.calculateBlockHeight()
    availableMainSize := b.Dimensions.GetMainSize(mainAxis)
    availableCrossSize := b.Dimensions.GetCrossSize(mainAxis)

    var items []*FlexItemMetadata
    for _, child := range b.Children {
        child.ContainingBlock = b
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

    b.calculateFlexBaseSizes(items, mainAxis, crossAxis, availableMainSize, e)

    lines := b.collectFlexLines(items, sn.GetFlexWrap(), availableMainSize, mainAxis)

    for _, line := range lines {
        b.resolveFlexibleLengths(line, availableMainSize, mainAxis, e)
    }

    b.determineCrossSizes(lines, mainAxis, crossAxis, e)

    totalCrossSize := 0.0
    for _, line := range lines {
        totalCrossSize += line.CrossSize
    }

    if b.isAutoCrossSize(e) {
        b.Dimensions.SetCrossSize(mainAxis, totalCrossSize)
        availableCrossSize = totalCrossSize
    }

    b.alignCrossAxis(lines, sn, dirInfo, availableCrossSize, totalCrossSize, mainAxis, crossAxis, e)

    b.alignMainAxis(lines, sn, dirInfo, availableMainSize, mainAxis)

    for _, itemMeta := range items {
        itemMeta.Box.Layout(e)
    }
}

// calculateFlexBaseSizes is a Step 2 helper.
func (b *LayoutBox) calculateFlexBaseSizes(items []*FlexItemMetadata, mainAxis, crossAxis Axis, availableMainSize float64, e *Engine) {
    refWidth := b.Dimensions.Content.Width

    for _, item := range items {
        item.Box.calculatePaddingAndBorders(refWidth, e)
        item.Box.calculateMargins(refWidth, e) // Treat auto margins as 0 for now.

        basisStr := item.Box.StyledNode.Lookup("flex-basis", "auto")
        mainSizeStr := item.Box.StyledNode.Lookup("width", "auto")
        if mainAxis == Vertical {
            mainSizeStr = item.Box.StyledNode.Lookup("height", "auto")
        }

        baseSize := math.NaN()

        if basisStr != "auto" && basisStr != "content" {
            baseSize = b.resolveFlexLength(basisStr, mainAxis, e)
        }

        if math.IsNaN(baseSize) && mainSizeStr != "auto" {
            baseSize = b.resolveFlexLength(mainSizeStr, mainAxis, e)
        }

        if math.IsNaN(baseSize) {
            if mainAxis == Horizontal {
                baseSize = item.Box.calculateShrinkToFitWidth(e, availableMainSize)
            } else {
                item.Box.Dimensions.SetCrossSize(mainAxis, b.Dimensions.GetCrossSize(mainAxis))
                item.Box.layoutContent(e)
                baseSize = item.Box.Dimensions.GetMainSize(mainAxis)
            }
        }

        if item.Box.StyledNode.BoxSizing() == style.BorderBox && !math.IsNaN(baseSize) {
            pStart, pEnd := item.Box.Dimensions.Padding.GetMainStart(mainAxis), item.Box.Dimensions.Padding.GetMainEnd(mainAxis)
            bStart, bEnd := item.Box.Dimensions.Border.GetMainStart(mainAxis), item.Box.Dimensions.Border.GetMainEnd(mainAxis)
            baseSize = math.Max(0, baseSize-(pStart+pEnd+bStart+bEnd))
        }

        item.FlexBaseSize = baseSize
        item.HypotheticalMainSize = item.FlexBaseSize
    }
}

// collectFlexLines is a Step 3 helper.
func (b *LayoutBox) collectFlexLines(items []*FlexItemMetadata, wrap style.FlexWrap, availableMainSize float64, mainAxis Axis) []*FlexLine {
    var lines []*FlexLine
    currentLine := &FlexLine{}
    lines = append(lines, currentLine)

    if wrap == style.FlexNoWrap {
        currentLine.Items = items
        for _, item := range items {
            currentLine.MainSize += item.HypotheticalMainSize + item.Box.Dimensions.GetMainStatic(mainAxis)
        }
        return lines
    }

    currentMainSize := 0.0
    for _, item := range items {
        itemMainSize := item.HypotheticalMainSize + item.Box.Dimensions.GetMainStatic(mainAxis)

        if currentMainSize+itemMainSize > availableMainSize && len(currentLine.Items) > 0 {
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
    freeSpace := availableMainSize - line.MainSize
    isGrowing := freeSpace > 0.001
    isShrinking := freeSpace < -0.001

    getGrow := func(sn *style.StyledNode) float64 {
        val, _ := parseFloat(sn.Lookup("flex-grow", "0"))
        return math.Max(0, val)
    }
    getShrink := func(sn *style.StyledNode) float64 {
        val, _ := parseFloat(sn.Lookup("flex-shrink", "1"))
        return math.Max(0, val)
    }

    totalGrow := 0.0
    totalWeightedShrink := 0.0

    for _, item := range line.Items {
        item.TargetMainSize = item.FlexBaseSize
        item.Frozen = false
        totalGrow += getGrow(item.Box.StyledNode)
        totalWeightedShrink += getShrink(item.Box.StyledNode) * item.FlexBaseSize
    }

    if (!isGrowing && !isShrinking) || (isGrowing && totalGrow == 0) || (isShrinking && totalWeightedShrink == 0) {
        return
    }

    remainingFreeSpace := freeSpace

    for _, item := range line.Items {
        if item.Frozen {
            continue
        }

        var adjustment float64
        if isGrowing {
            ratio := 0.0
            if totalGrow > 0 {
                ratio = getGrow(item.Box.StyledNode) / totalGrow
            }
            adjustment = remainingFreeSpace * ratio
        } else {
            weightedRatio := 0.0
            if totalWeightedShrink > 0 {
                scaledShrink := getShrink(item.Box.StyledNode) * item.FlexBaseSize
                weightedRatio = scaledShrink / totalWeightedShrink
            }
            adjustment = remainingFreeSpace * weightedRatio
        }

        item.TargetMainSize += adjustment

        if item.TargetMainSize < 0 {
            item.TargetMainSize = 0
        }
    }
}

// determineCrossSizes is a Step 5 helper.
func (b *LayoutBox) determineCrossSizes(lines []*FlexLine, mainAxis, crossAxis Axis, e *Engine) {
    for _, line := range lines {
        for _, item := range line.Items {
            item.Box.Dimensions.SetMainSize(mainAxis, item.TargetMainSize)
            item.Box.calculateBlockHeight()
        }
    }

    for _, line := range lines {
        maxCrossSize := 0.0
        for _, item := range line.Items {
            crossSize := item.Box.Dimensions.GetCrossSize(mainAxis) + item.Box.Dimensions.GetCrossStatic(mainAxis)
            if crossSize > maxCrossSize {
                maxCrossSize = crossSize
            }
        }
        line.CrossSize = maxCrossSize
    }
}

// alignCrossAxis is a Step 6 helper.
func (b *LayoutBox) alignCrossAxis(lines []*FlexLine, sn *style.StyledNode, dirInfo FlexDirectionInfo, availableCrossSize, totalCrossSize float64, mainAxis, crossAxis Axis, e *Engine) {
    var currentCrossOffset float64
    var spacing float64

    alignContent := sn.GetAlignContent()

    if sn.GetFlexWrap() != style.FlexNoWrap {
        if alignContent == style.AlignContentStretch && availableCrossSize > totalCrossSize {
            freeSpace := availableCrossSize - totalCrossSize
            if len(lines) > 0 {
                extraPerLine := freeSpace / float64(len(lines))
                for _, line := range lines {
                    line.CrossSize += extraPerLine
                }
            }
            totalCrossSize = availableCrossSize
        }

        currentCrossOffset, spacing = b.calculateAlignmentOffsets(len(lines), totalCrossSize, availableCrossSize, alignContent)
    }

    if dirInfo.IsCrossReverse {
        currentCrossOffset = availableCrossSize - currentCrossOffset
    }

    containerAlignItems := sn.GetAlignItems()
    for _, line := range lines {
        if dirInfo.IsCrossReverse {
            line.CrossStart = currentCrossOffset - line.CrossSize
        } else {
            line.CrossStart = currentCrossOffset
        }

        for _, item := range line.Items {
            b.alignFlexItem(item.Box, line.CrossSize, containerAlignItems, mainAxis, crossAxis, e)
        }

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
    containerCrossStart := b.Dimensions.Content.GetCrossStart(mainAxis)
    justifyContent := sn.GetJustifyContent()

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
        usedMainSize := 0.0
        for _, item := range line.Items {
            usedMainSize += item.TargetMainSize + item.Box.Dimensions.GetMainStatic(mainAxis)
        }

        currentMainOffset, spacing := b.calculateAlignmentOffsets(len(line.Items), usedMainSize, availableMainSize, justifyContent)

        if dirInfo.IsReverse {
            currentMainOffset = availableMainSize - currentMainOffset
        }

        for _, item := range line.Items {
            startContentOffset := getStartContentOffset(&item.Box.Dimensions, mainAxis)

            var contentMainStart float64
            if dirInfo.IsReverse {
                mainMarginBoxSize := item.TargetMainSize + item.Box.Dimensions.GetMainStatic(mainAxis)
                contentMainStart = containerMainStart + currentMainOffset - mainMarginBoxSize + startContentOffset
            } else {
                contentMainStart = containerMainStart + currentMainOffset + startContentOffset
            }

            item.Box.Dimensions.Content.SetMainStart(mainAxis, contentMainStart)

            crossStartContentOffset := getCrossStartContentOffset(&item.Box.Dimensions, mainAxis)
            crossContentStart := containerCrossStart + line.CrossStart + item.Box.crossAxisOffset + crossStartContentOffset
            item.Box.Dimensions.Content.SetCrossStart(mainAxis, crossContentStart)

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
    dirInfo := getFlexDirectionInfo(b.StyledNode)
    if dirInfo.CrossAxis == Vertical {
        return b.StyledNode.Lookup("height", "auto") == "auto"
    }
    return b.StyledNode.Lookup("width", "auto") == "auto"
}

// resolveFlexLength resolves lengths in flex context
func (b *LayoutBox) resolveFlexLength(value string, axis Axis, e *Engine) float64 {
    sn := b.StyledNode
    fontSize := style.GetFontSize(sn)
    vw, vh := e.viewportWidth, e.viewportHeight

    dirInfo := getFlexDirectionInfo(sn)
    referenceDimension := b.Dimensions.GetMainSize(dirInfo.MainAxis)
    if axis != dirInfo.MainAxis {
        referenceDimension = b.Dimensions.GetCrossSize(dirInfo.MainAxis)
    }

    return style.ParseLengthWithUnits(value, fontSize, BaseFontSize, referenceDimension, vw, vh)
}

// alignFlexItem is a Step 6 helper for Cross Axis - align-self/align-items.
func (b *LayoutBox) alignFlexItem(item *LayoutBox, lineCrossSize float64, containerAlignItems style.AlignItems, mainAxis, crossAxis Axis, e *Engine) {
    align := containerAlignItems
    alignSelf := item.StyledNode.GetAlignSelf()

    switch alignSelf {
    case style.AlignSelfAuto:
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

    isAutoCross := false
    if crossAxis == Vertical {
        isAutoCross = item.StyledNode.Lookup("height", "auto") == "auto"
    } else {
        isAutoCross = item.StyledNode.Lookup("width", "auto") == "auto"
    }

    if align == style.AlignStretch && isAutoCross {
        crossStatic := item.Dimensions.GetCrossStatic(mainAxis)
        targetCrossSize := lineCrossSize - crossStatic
        item.Dimensions.SetCrossSize(mainAxis, math.Max(0, targetCrossSize))
        item.layoutContent(e)
        item.crossAxisOffset = 0
        return
    }

    itemCrossSize := item.Dimensions.GetCrossSize(mainAxis) + item.Dimensions.GetCrossStatic(mainAxis)
    freeSpace := lineCrossSize - itemCrossSize

    switch align {
    case style.AlignFlexStart, style.AlignStretch:
        item.crossAxisOffset = 0
    case style.AlignFlexEnd:
        item.crossAxisOffset = freeSpace
    case style.AlignCenter:
        item.crossAxisOffset = freeSpace / 2.0
    case style.AlignBaseline:
        item.crossAxisOffset = 0
    }
}

// calculateAlignmentOffsets is a helper for justify-content and align-content.
func (b *LayoutBox) calculateAlignmentOffsets(itemCount int, totalSize, availableSize float64, alignment interface{}) (startOffset, spacing float64) {
    freeSpace := availableSize - totalSize
    if freeSpace <= 0.001 {
        return 0, 0
    }

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
            alignBehavior = 0
        }
    default:
        return 0, 0
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
            startOffset = freeSpace / 2.0
        }
    case 5: // SpaceEvenly
        if itemCount > 0 {
            spacing = freeSpace / float64(itemCount+1)
            startOffset = spacing
        } else {
            startOffset = freeSpace / 2.0
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

// resolveGridTracks parses grid-template-rows/columns and calculates their final sizes.
func (b *LayoutBox) resolveGridTracks(e *Engine, template string, availableSpace float64) []float64 {
    parts := strings.Fields(template)
    if len(parts) == 0 {
        return []float64{}
    }

    var tracks []GridTrack
    totalFr := 0.0
    fixedSpaceUsed := 0.0

    for _, part := range parts {
        if strings.HasSuffix(part, "fr") {
            factor, err := parseFloat(strings.TrimSuffix(part, "fr"))
            if err == nil {
                tracks = append(tracks, GridTrack{GrowthFactor: factor})
                totalFr += factor
            }
        } else {
            size := style.ParseLengthWithUnits(part, style.GetFontSize(b.StyledNode), BaseFontSize, availableSpace, e.viewportWidth, e.viewportHeight)
            tracks = append(tracks, GridTrack{BaseSize: size})
            fixedSpaceUsed += size
        }
    }

    remainingSpace := math.Max(0, availableSpace-fixedSpaceUsed)
    spacePerFr := 0.0
    if totalFr > 0 {
        spacePerFr = remainingSpace / totalFr
    }

    finalSizes := make([]float64, len(tracks))
    for i, track := range tracks {
        if track.GrowthFactor > 0 {
            finalSizes[i] = track.GrowthFactor * spacePerFr
        } else {
            finalSizes[i] = track.BaseSize
        }
    }
    return finalSizes
}

func (b *LayoutBox) layoutGrid(e *Engine) {
    if b.StyledNode == nil {
        return
    }

    b.calculateBlockHeight()

    colTemplate := b.StyledNode.Lookup("grid-template-columns", "")
    rowTemplate := b.StyledNode.Lookup("grid-template-rows", "")

    colSizes := b.resolveGridTracks(e, colTemplate, b.Dimensions.Content.Width)
    rowSizes := b.resolveGridTracks(e, rowTemplate, b.Dimensions.Content.Height)

    colStarts := make([]float64, len(colSizes)+1)
    rowStarts := make([]float64, len(rowSizes)+1)
    for i := 1; i <= len(colSizes); i++ {
        colStarts[i] = colStarts[i-1] + colSizes[i-1]
    }
    for i := 1; i <= len(rowSizes); i++ {
        rowStarts[i] = rowStarts[i-1] + rowSizes[i-1]
    }

    for _, child := range b.Children {
        if child.StyledNode == nil {
            continue
        }
        child.ContainingBlock = b

        colStartStr := child.StyledNode.Lookup("grid-column-start", "1")
        rowStartStr := child.StyledNode.Lookup("grid-row-start", "1")
        colStart, _ := strconv.Atoi(colStartStr)
        rowStart, _ := strconv.Atoi(rowStartStr)
        if colStart == 0 {
            colStart = 1
        }
        if rowStart == 0 {
            rowStart = 1
        }

        colEnd := colStart + 1
        rowEnd := rowStart + 1

        if colStart > 0 && colEnd <= len(colStarts) && rowStart > 0 && rowEnd <= len(rowStarts) {
            child.Dimensions.Content.X = b.Dimensions.Content.X + colStarts[colStart-1]
            child.Dimensions.Content.Y = b.Dimensions.Content.Y + rowStarts[rowStart-1]
            child.Dimensions.Content.Width = colStarts[colEnd-1] - colStarts[colStart-1]
            child.Dimensions.Content.Height = rowStarts[rowEnd-1] - rowStarts[rowStart-1]

            child.Layout(e)
        }
    }
}

func (b *LayoutBox) layoutTable(e *Engine) {
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
    fontSize := style.GetFontSize(sn)
    vw, vh := e.viewportWidth, e.viewportHeight

    resolveW := func(val string) float64 { return style.ParseLengthWithUnits(val, fontSize, BaseFontSize, refWidth, vw, vh) }
    isRefHeightAuto := pcbBox.StyledNode != nil && pcbBox.StyledNode.Lookup("height", "auto") == "auto" && pcbBox.ContainingBlock != nil
    refHeight := pcbBox.Dimensions.Content.Height
    resolveH := func(val string) float64 {
        if strings.Contains(val, "%") && isRefHeightAuto {
            return math.NaN()
        }
        return style.ParseLengthWithUnits(val, fontSize, BaseFontSize, refHeight, vw, vh)
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
    return 0.0
}

func (b *LayoutBox) getStaticPositionY(pcbBox *LayoutBox) float64 {
    return 0.0
}

func (b *LayoutBox) applyRelativePositioning() {
    if b.StyledNode == nil || b.StyledNode.Position() != style.PositionRelative {
        return
    }

    sn := b.StyledNode
    fontSize := style.GetFontSize(sn)
    cb := b.ContainingBlock.Dimensions
    vw, vh := b.getRoot().Dimensions.Content.Width, b.getRoot().Dimensions.Content.Height

    offsetX, offsetY := 0.0, 0.0
    top := sn.Lookup("top", "auto")
    bottom := sn.Lookup("bottom", "auto")
    left := sn.Lookup("left", "auto")
    right := sn.Lookup("right", "auto")

    if top != "auto" {
        offsetY += style.ParseLengthWithUnits(top, fontSize, BaseFontSize, cb.Content.Height, vw, vh)
    } else if bottom != "auto" {
        offsetY -= style.ParseLengthWithUnits(bottom, fontSize, BaseFontSize, cb.Content.Height, vw, vh)
    }

    if left != "auto" {
        offsetX += style.ParseLengthWithUnits(left, fontSize, BaseFontSize, cb.Content.Width, vw, vh)
    } else if right != "auto" {
        offsetX -= style.ParseLengthWithUnits(right, fontSize, BaseFontSize, cb.Content.Width, vw, vh)
    }

    b.Dimensions.Content.X += offsetX
    b.Dimensions.Content.Y += offsetY
}

// parseAngle is a helper for transform functions, converting angle strings to radians.
func parseAngle(s string) float64 {
    s = strings.TrimSpace(s)
    if strings.HasSuffix(s, "deg") {
        val, _ := parseFloat(strings.TrimSuffix(s, "deg"))
        return val * math.Pi / 180.0
    }
    if strings.HasSuffix(s, "rad") {
        val, _ := parseFloat(strings.TrimSuffix(s, "rad"))
        return val
    }
    if strings.HasSuffix(s, "turn") {
        val, _ := parseFloat(strings.TrimSuffix(s, "turn"))
        return val * 2 * math.Pi
    }
    val, _ := parseFloat(s)
    return val * math.Pi / 180.0
}

// parseTransformOrigin resolves the `transform-origin` property into pixel coordinates.
func (b *LayoutBox) parseTransformOrigin(e *Engine) (float64, float64) {
    defaultX, defaultY := "50%", "50%"
    originStr := "50% 50%"
    if b.StyledNode != nil {
        originStr = b.StyledNode.Lookup("transform-origin", "50% 50%")
    }

    parts := strings.Fields(originStr)
    xStr, yStr := defaultX, defaultY
    if len(parts) >= 1 {
        xStr = parts[0]
    }
    if len(parts) >= 2 {
        yStr = parts[1]
    } else {
        yStr = "50%"
    }

    keywordToPercent := map[string]string{
        "left": "0%", "center": "50%", "right": "100%",
        "top": "0%", "bottom": "100%",
    }
    if p, ok := keywordToPercent[xStr]; ok {
        xStr = p
    }
    if p, ok := keywordToPercent[yStr]; ok {
        yStr = p
    }

    borderBox := b.Dimensions.BorderBox()
    refWidth := borderBox.Width
    refHeight := borderBox.Height
    fontSize := style.GetFontSize(b.StyledNode)

    originX := style.ParseLengthWithUnits(xStr, fontSize, BaseFontSize, refWidth, e.viewportWidth, e.viewportHeight)
    originY := style.ParseLengthWithUnits(yStr, fontSize, BaseFontSize, refHeight, e.viewportWidth, e.viewportHeight)

    return originX, originY
}

// parseTransform parses the `transform` CSS property into a single transformation matrix.
func (b *LayoutBox) parseTransform(e *Engine) TransformMatrix {
    transformStr := "none"
    if b.StyledNode != nil {
        transformStr = b.StyledNode.Lookup("transform", "none")
    }

    if transformStr == "none" {
        return IdentityMatrix()
    }

    finalMatrix := IdentityMatrix()
    functions := strings.Split(transformStr, ")")

    for _, f := range functions {
        f = strings.TrimSpace(f)
        if f == "" {
            continue
        }

        parts := strings.SplitN(f, "(", 2)
        if len(parts) != 2 {
            continue
        }
        funcName := strings.TrimSpace(parts[0])
        argsStr := parts[1]
        argParts := strings.Fields(strings.ReplaceAll(argsStr, ",", " "))
        var currentMatrix TransformMatrix = IdentityMatrix()

        fontSize := style.GetFontSize(b.StyledNode)
        refWidth := b.Dimensions.BorderBox().Width
        refHeight := b.Dimensions.BorderBox().Height

        resolveLenX := func(val string) float64 {
            return style.ParseLengthWithUnits(val, fontSize, BaseFontSize, refWidth, e.viewportWidth, e.viewportHeight)
        }
        resolveLenY := func(val string) float64 {
            return style.ParseLengthWithUnits(val, fontSize, BaseFontSize, refHeight, e.viewportWidth, e.viewportHeight)
        }

        switch funcName {
        case "matrix":
            if len(argParts) == 6 {
                a, _ := parseFloat(argParts[0])
                b, _ := parseFloat(argParts[1])
                c, _ := parseFloat(argParts[2])
                d, _ := parseFloat(argParts[3])
                eVal, _ := parseFloat(argParts[4])
                fVal, _ := parseFloat(argParts[5])
                currentMatrix = TransformMatrix{A: a, B: b, C: c, D: d, E: eVal, F: fVal}
            }
        case "translate":
            if len(argParts) >= 1 {
                tx := resolveLenX(argParts[0])
                ty := 0.0
                if len(argParts) > 1 {
                    ty = resolveLenY(argParts[1])
                }
                currentMatrix = TranslateMatrix(tx, ty)
            }
        case "translateX":
            if len(argParts) == 1 {
                tx := resolveLenX(argParts[0])
                currentMatrix = TranslateMatrix(tx, 0)
            }
        case "translateY":
            if len(argParts) == 1 {
                ty := resolveLenY(argParts[0])
                currentMatrix = TranslateMatrix(0, ty)
            }
        case "scale":
            if len(argParts) >= 1 {
                sx, _ := parseFloat(argParts[0])
                sy := sx
                if len(argParts) > 1 {
                    sy, _ = parseFloat(argParts[1])
                }
                currentMatrix = ScaleMatrix(sx, sy)
            }
        case "scaleX":
            if len(argParts) == 1 {
                sx, _ := parseFloat(argParts[0])
                currentMatrix = ScaleMatrix(sx, 1)
            }
        case "scaleY":
            if len(argParts) == 1 {
                sy, _ := parseFloat(argParts[0])
                currentMatrix = ScaleMatrix(1, sy)
            }
        case "rotate":
            if len(argParts) == 1 {
                angle := parseAngle(argParts[0])
                currentMatrix = RotateMatrix(angle)
            }
        case "skew":
            if len(argParts) >= 1 {
                ax := parseAngle(argParts[0])
                ay := 0.0
                if len(argParts) > 1 {
                    ay = parseAngle(argParts[1])
                }
                currentMatrix = SkewMatrix(ax, ay)
            }
        case "skewX":
            if len(argParts) == 1 {
                angle := parseAngle(argParts[0])
                currentMatrix = SkewMatrix(angle, 0)
            }
        case "skewY":
            if len(argParts) == 1 {
                angle := parseAngle(argParts[0])
                currentMatrix = SkewMatrix(0, angle)
            }
        }
        finalMatrix = finalMatrix.Multiply(currentMatrix)
    }

    return finalMatrix
}

func (b *LayoutBox) applyTransforms(e *Engine, parentTransform TransformMatrix) {
    localTransform := IdentityMatrix()

    if b.StyledNode != nil {
        transformProp := b.StyledNode.Lookup("transform", "none")

        if transformProp != "none" {
            transformsMatrix := b.parseTransform(e)
            originX, originY := b.parseTransformOrigin(e)
            toOrigin := TranslateMatrix(-originX, -originY)
            fromOrigin := TranslateMatrix(originX, originY)
            localTransform = fromOrigin.Multiply(transformsMatrix.Multiply(toOrigin))
        }
    }

    finalTransform := parentTransform.Multiply(localTransform)
    b.Dimensions.Transform = finalTransform

    for _, child := range b.Children {
        child.applyTransforms(e, b.Dimensions.Transform)
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
        if y >= mb.Y && y < mb.Y+mb.Height {
            if floatBox.StyledNode.Float() == style.FloatLeft {
                if mb.X+mb.Width > leftEdge {
                    leftEdge = mb.X + mb.Width
                }
            } else {
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
    child.layoutContent(e)

    cbContent := b.Dimensions.Content
    floatType := child.StyledNode.Float()
    yPos := context.CurrentY

    for {
        leftIndent, rightIndent := b.Floats.GetIndentationAtY(yPos, cbContent.X, cbContent.Width)
        availableWidth := cbContent.Width - leftIndent - rightIndent

        if child.Dimensions.MarginBox().Width <= availableWidth {
            break
        }
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
    fontSize := style.GetFontSize(sn)
    resolve := func(val string) float64 {
        return style.ParseLengthWithUnits(val, fontSize, BaseFontSize, referenceWidth, e.viewportWidth, e.viewportHeight)
    }

    b.calculatePaddingAndBorders(referenceWidth, e)
    paddingLeft, paddingRight := b.Dimensions.Padding.Left, b.Dimensions.Padding.Right
    borderLeft, borderRight := b.Dimensions.Border.Left, b.Dimensions.Border.Right

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

    if sn.BoxSizing() == style.BorderBox && !math.IsNaN(width) && widthStr != "auto" {
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
    if b.StyledNode != nil {
        childrenToInspect := b.StyledNode.Children
        if b.StyledNode.ShadowRoot != nil {
            childrenToInspect = b.StyledNode.ShadowRoot.Children
        }

        if len(childrenToInspect) > 0 {
            if childrenToInspect[0].Node.Type == html.TextNode {
                w, _ := style.MeasureText(childrenToInspect[0])
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
    fontSize := style.GetFontSize(sn)

    resolvePadding := func(propName string, defaultValue string) float64 {
        valStr := sn.Lookup(propName, defaultValue)
        resolved := style.ParseLengthWithUnits(valStr, fontSize, BaseFontSize, referenceWidth, e.viewportWidth, e.viewportHeight)
        return math.Max(0.0, resolved)
    }

    b.Dimensions.Padding.Top = resolvePadding("padding-top", "0")
    b.Dimensions.Padding.Right = resolvePadding("padding-right", "0")
    b.Dimensions.Padding.Bottom = resolvePadding("padding-bottom", "0")
    b.Dimensions.Padding.Left = resolvePadding("padding-left", "0")

    resolveBorder := func(propName, stylePropName string) float64 {
        styleVal := sn.Lookup(stylePropName, "none")
        if styleVal == "none" || styleVal == "hidden" {
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
        resolved := style.ParseLengthWithUnits(valStr, fontSize, BaseFontSize, 0, e.viewportWidth, e.viewportHeight)
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
    fontSize := style.GetFontSize(sn)

    resolveAuto := func(propName string) float64 {
        valStr := sn.Lookup(propName, "0")
        if valStr == "auto" {
            return 0.0
        }
        return style.ParseLengthWithUnits(valStr, fontSize, BaseFontSize, referenceWidth, e.viewportWidth, e.viewportHeight)
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
            fontSize := style.GetFontSize(b.StyledNode)
            resolvedHeight := style.ParseLengthWithUnits(heightStr, fontSize, BaseFontSize, referenceHeight, vw, vh)
            if b.StyledNode.BoxSizing() == style.BorderBox {
                paddingTop, paddingBottom := b.Dimensions.Padding.Top, b.Dimensions.Padding.Bottom
                borderTop, borderBottom := b.Dimensions.Border.Top, b.Dimensions.Border.Bottom
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
        width, height := style.MeasureText(b.StyledNode)
        b.Dimensions.Content.Width = width
        b.Dimensions.Content.Height = height
        return
    }

    maxWidth, maxHeight := 0.0, 0.0
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
        lineHeight = style.ParseAbsoluteLength(b.StyledNode.Lookup("line-height", fmt.Sprintf("%fpx", lineHeight)))
        b.Dimensions.Content.Height = lineHeight
    } else {
        b.Dimensions.Content.Height = maxHeight
    }
}

// -- Helpers --

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
        return nil, fmt.Errorf("element not found matching selector '%s'", selector)
    }
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

    tx1, ty1 := transform.Apply(x, y)
    tx2, ty2 := transform.Apply(x+width, y)
    tx3, ty3 := transform.Apply(x+width, y+height)
    tx4, ty4 := transform.Apply(x, y+height)

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