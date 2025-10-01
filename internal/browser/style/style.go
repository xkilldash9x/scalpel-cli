package style

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
	"golang.org/x/net/html"
)

// -- Canonical Data Structures --

// StyledNode represents a DOM node combined with its computed styles. It is the
// bridge between the parser's output and the layout engine's input.
type StyledNode struct {
	Node           *html.Node
	ComputedStyles map[parser.Property]parser.Value
	Children       []*StyledNode
	// ShadowRoot holds the encapsulated style tree for this node, if it's a shadow host.
	ShadowRoot *StyledNode
}

// Color represents an RGBA color.
type Color struct {
	R, G, B, A uint8
}

// Predefined colors (simplified list).
var cssColors = map[string]Color{
	"black":       {0, 0, 0, 255},
	"white":       {255, 255, 255, 255},
	"red":         {255, 0, 0, 255},
	"green":       {0, 128, 0, 255}, // CSS 'green' is darker than (0, 255, 0).
	"blue":        {0, 0, 255, 255},
	"transparent": {0, 0, 0, 0},
}

// GridTrackDefinition represents a single track definition, like "1fr" or "100px".
type GridTrackDefinition struct {
	Size      string
	LineNames []string
}

// GridLine represents a parsed placement value (e.g., from grid-column-start).
type GridLine struct {
	IsAuto      bool
	IsNamedSpan bool
	Span        int
	Line        int
	Name        string
}

// -- Value Lookup and Property Parsers --

// Lookup retrieves a style, falling back if not present.
func (sn *StyledNode) Lookup(property, fallback string) string {
	if val, ok := sn.ComputedStyles[parser.Property(property)]; ok {
		return string(val)
	}
	return fallback
}

// ParseColor parses a CSS color string.
func ParseColor(value string) (Color, bool) {
	value = strings.TrimSpace(strings.ToLower(value))

	// 1. Keywords
	if color, ok := cssColors[value]; ok {
		return color, true
	}

	// 2. Hex codes
	if strings.HasPrefix(value, "#") {
		return parseHexColor(value)
	}

	// 3. rgb() / rgba()
	if strings.HasPrefix(value, "rgb") {
		return parseRGBColor(value)
	}

	// Default to black if parsing fails (common browser behavior).
	return Color{0, 0, 0, 255}, false
}

func parseHexColor(hex string) (Color, bool) {
	hex = strings.TrimPrefix(hex, "#")
	var r, g, b, a uint8 = 0, 0, 0, 255

	switch len(hex) {
	case 3:
		// #RGB -> #RRGGBB
		r = hexDigit(hex[0]) * 17
		g = hexDigit(hex[1]) * 17
		b = hexDigit(hex[2]) * 17
	case 4:
		// #RGBA -> #RRGGBBAA
		r = hexDigit(hex[0]) * 17
		g = hexDigit(hex[1]) * 17
		b = hexDigit(hex[2]) * 17
		a = hexDigit(hex[3]) * 17
	case 6:
		// #RRGGBB
		r = hexDigit(hex[0])<<4 | hexDigit(hex[1])
		g = hexDigit(hex[2])<<4 | hexDigit(hex[3])
		b = hexDigit(hex[4])<<4 | hexDigit(hex[5])
	case 8:
		// #RRGGBBAA
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

	// Split by comma or space (CSS Color Module Level 4 allows space separation).
	parts := strings.FieldsFunc(matches[1], func(r rune) bool {
		return r == ',' || r == ' '
	})

	// Filter out empty strings and handle slash separator for alpha.
	var values []string
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		if p == "" {
			continue
		}
		if p == "/" {
			// If slash is found, the next part must be the alpha channel.
			if i+1 < len(parts) && parts[i+1] != "" {
				values = append(values, parts[i+1])
				i++
			}
			continue
		}
		// If we already have 3 components and haven't found a slash, stop (invalid format).
		if len(values) < 3 {
			values = append(values, p)
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
		// Both RGB and Alpha percentages are scaled to 0-255.
		return uint8(clamp(percent/100.0*255.0, 0, 255))
	}

	if isAlpha {
		// Alpha is a float between 0.0 and 1.0.
		val, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return 255 // Default alpha to 1 if parsing fails
		}
		return uint8(clamp(val*255.0, 0, 255))
	}

	// RGB components are integers between 0 and 255.
	val, err := strconv.Atoi(value)
	if err != nil {
		// Allow floats as well, rounding.
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

// Definitions for various CSS properties.
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

// Display determines the layout mode.
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

// BoxSizingType determines how width/height are calculated.
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

// JustifyContent defines main-axis alignment in Flexbox/Grid.
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
		// "normal" often behaves as flex-start in flex layout.
		return JustifyFlexStart
	}
}

// AlignItems defines cross-axis alignment (default) in Flexbox/Grid.
type AlignItems int

const (
	AlignStretch AlignItems = iota
	AlignFlexStart
	AlignCenter
	AlignFlexEnd
	AlignBaseline
)

func (sn *StyledNode) GetAlignItems() AlignItems {
	// Default for flexbox is stretch.
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
		// "normal" behaves as stretch in flex layout.
		return AlignStretch
	}
}

// AlignSelf defines cross-axis alignment (override) in Flexbox/Grid.
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

// AlignContent defines cross-axis alignment for multi-line flex containers.
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
	// Default for align-content is 'normal' which behaves as 'stretch'.
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

// IsVisible checks if the element is visually rendered.
func (sn *StyledNode) IsVisible() bool {
	if sn.Display() == DisplayNone {
		return false
	}
	visibility := sn.Lookup("visibility", "visible")
	if visibility == "hidden" || visibility == "collapse" {
		return false
	}
	// Check opacity.
	opacityStr := sn.Lookup("opacity", "1.0")
	if opacity, err := strconv.ParseFloat(opacityStr, 64); err == nil && opacity <= 0.0 {
		return false
	}
	return true
}

// A regex to find and parse repeat() functions.
var repeatRegex = regexp.MustCompile(`repeat\(\s*(\d+)\s*,\s*([^)]+)\)`)

// isWhitespace checks if a character is CSS whitespace.
func isWhitespace(r byte) bool {
	return r == ' ' || r == '\t' || r == '\n'
}

// tokenizeGridTracks splits a grid track definition string into its core components.
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

// GetGridTemplateTracks parses properties like `grid-template-columns`.
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

// ParseGridLine parses a single grid placement value (like for grid-column-start).
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

// getDefaultDisplay provides a basic User Agent stylesheet equivalent.
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
