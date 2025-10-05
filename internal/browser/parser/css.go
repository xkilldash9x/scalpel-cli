// browser/parser/css.go
// internal/browser/parser/css.go
package parser

import (
	"fmt"
	"strings"
)

// Property represents a CSS property (e.g., "display").
type Property string

// Value represents a CSS value (e.g., "none").
type Value string

// Declaration is a key-value pair (e.g., display: none).
type Declaration struct {
	Property  Property
	Value     Value
	Important bool
}

// RuleSet represents a set of declarations applied by one or more selector groups.
type RuleSet struct {
	SelectorGroups []SelectorGroup
	Declarations   []Declaration
}

// StyleSheet is the top-level structure representing the parsed CSSOM.
type StyleSheet struct {
	Rules []RuleSet
}

// SelectorGroup represents a comma-separated list of selectors (e.g., "h1, h2 .title").
type SelectorGroup []ComplexSelector

// ComplexSelector represents a sequence of simple selectors joined by combinators (e.g., "div > p").
type ComplexSelector struct {
	Selectors []SimpleSelectorWithCombinator
}

// SimpleSelectorWithCombinator pairs a simple selector with its preceding combinator.
type SimpleSelectorWithCombinator struct {
	Combinator     Combinator
	SimpleSelector SimpleSelector
}

// SimpleSelector represents the core components of a selector (tag, ID, classes).
type SimpleSelector struct {
	TagName    string
	ID         string
	Classes    []string
	Attributes []AttributeSelector // Added for full attribute selector support.
}

// AttributeSelector represents a CSS attribute selector like `[href]` or `[target="_blank"]`.
type AttributeSelector struct {
	Name     string
	Operator string // e.g., "=", "~=", "|=", "^=", "$=", "*="
	Value    string
}

// Combinator defines the relationship between simple selectors.
type Combinator int

const (
	CombinatorNone            Combinator = iota // No combinator (first selector)
	CombinatorDescendant                        // Space
	CombinatorChild                             // >
	CombinatorAdjacentSibling                   // +
	CombinatorGeneralSibling                    // ~
)

// CalculateSpecificity calculates the specificity for an entire selector group.
// In CSS, the specificity of a comma-separated list is the specificity of the most specific selector in that list.
// However, for matching, we need the specificity of the individual complex selector that matched.
// This function calculates it for a ComplexSelector.
func (cs ComplexSelector) CalculateSpecificity() (int, int, int) {
	a, b, c := 0, 0, 0
	for _, s := range cs.Selectors {
		sa, sb, sc := s.SimpleSelector.CalculateSpecificity()
		a += sa
		b += sb
		c += sc
	}
	return a, b, c
}

// CalculateSpecificity calculates for a simple selector.
func (s SimpleSelector) CalculateSpecificity() (a, b, c int) {
	if s.ID != "" {
		a = 1
	}
	// Attribute selectors and classes have the same specificity.
	b = len(s.Classes) + len(s.Attributes)
	if s.TagName != "" && s.TagName != "*" {
		c = 1
	}
	return a, b, c
}

// IsValid checks if the selector has at least one component.
func (s SimpleSelector) IsValid() bool {
	return s.TagName != "" || s.ID != "" || len(s.Classes) > 0 || len(s.Attributes) > 0
}

// Parser holds the state of the CSS parser.
type Parser struct {
	input string
	pos   int
}

func NewParser(input string) *Parser {
	return &Parser{input: input, pos: 0}
}

// Parse analyzes the input CSS string and builds a StyleSheet.
func (p *Parser) Parse() StyleSheet {
	var rules []RuleSet
	for {
		p.consumeWhitespace()
		if p.eof() {
			break
		}
		if p.startsWith("/*") {
			p.skipComment()
			continue
		}

		// Look ahead to see if this is a rule set or an at-rule we should skip.
		if p.currentChar() == '@' {
			p.skipAtRule()
			continue
		}

		selectorGroups := p.parseSelectorGroups()
		if len(selectorGroups) == 0 {
			p.skipTo('{')
			if !p.eof() && p.currentChar() == '{' {
				p.skipBlock('{', '}')
			}
			continue
		}

		declarations, err := p.parseDeclarations()
		if err != nil {
			continue
		}

		if len(declarations) > 0 {
			rules = append(rules, RuleSet{SelectorGroups: selectorGroups, Declarations: declarations})
		}
	}
	return StyleSheet{Rules: rules}
}

// parseSelectorGroups parses a comma-separated list of complex selectors.
func (p *Parser) parseSelectorGroups() []SelectorGroup {
	var selectorGroup SelectorGroup // This is []ComplexSelector
	for {
		p.consumeWhitespace()
		if p.eof() || p.currentChar() == '{' {
			break
		}
		complex := p.parseComplexSelector()
		if len(complex.Selectors) > 0 {
			selectorGroup = append(selectorGroup, complex)
		}

		p.consumeWhitespace()
		if p.eof() || p.currentChar() == '{' {
			break
		}
		if p.currentChar() == ',' {
			p.consumeChar()
			continue
		}
		// If it's not a comma, this selector group ends.
		break
	}
	if len(selectorGroup) > 0 {
		return []SelectorGroup{selectorGroup}
	}
	return nil
}

// parseComplexSelector parses a sequence of simple selectors and combinators.
func (p *Parser) parseComplexSelector() ComplexSelector {
	var complexSelector ComplexSelector
	combinator := CombinatorNone

	for {
		p.consumeWhitespace()
		if p.eof() || p.currentChar() == '{' || p.currentChar() == ',' {
			break
		}

		simple, err := p.parseSimpleSelector()
		if err != nil {
			// Skip to the next potential start of a selector or block.
			p.skipTo(' ', '>', '+', '~', ',', '{')
			continue
		}
		if simple.IsValid() {
			complexSelector.Selectors = append(complexSelector.Selectors, SimpleSelectorWithCombinator{
				Combinator:     combinator,
				SimpleSelector: simple,
			})
		}

		p.consumeWhitespace()
		// After parsing a simple selector, look for the next combinator.
		if p.eof() || p.currentChar() == '{' || p.currentChar() == ',' {
			break
		}

		switch p.currentChar() {
		case '>':
			combinator = CombinatorChild
			p.consumeChar()
		case '+':
			combinator = CombinatorAdjacentSibling
			p.consumeChar()
		case '~':
			combinator = CombinatorGeneralSibling
			p.consumeChar()
		default:
			// Any other character (including whitespace if not consumed yet) implies a descendant combinator.
			combinator = CombinatorDescendant
		}
	}
	return complexSelector
}

// parseSimpleSelector parses a single selector component (e.g., div#id.class1.class2).
func (p *Parser) parseSimpleSelector() (SimpleSelector, error) {
	selector := SimpleSelector{}

	// Universal or Tag Name
	if !p.eof() {
		ch := p.currentChar()
		if ch == '*' {
			p.consumeChar()
			selector.TagName = "*"
		} else if isValidIdentifierStart(ch) {
			selector.TagName = strings.ToLower(p.parseIdentifier())
		}
	}

	// IDs, Classes, and Attributes
	for !p.eof() {
		switch p.currentChar() {
		case '#':
			p.consumeChar()
			selector.ID = p.parseIdentifier()
		case '.':
			p.consumeChar()
			selector.Classes = append(selector.Classes, p.parseIdentifier())
		case '[':
			// This is the new part for attribute selectors.
			p.consumeChar() // consume '['
			attr, err := p.parseAttributeSelector()
			if err == nil {
				selector.Attributes = append(selector.Attributes, attr)
			}
			// The parseAttributeSelector consumes the ']'
		default:
			goto done
		}
	}

done:
	// A simple selector must have at least one part.
	if !selector.IsValid() && selector.TagName != "*" {
		return selector, fmt.Errorf("invalid simple selector")
	}
	return selector, nil
}

// parseAttributeSelector parses the contents of `[...]` for an attribute selector.
func (p *Parser) parseAttributeSelector() (AttributeSelector, error) {
	p.consumeWhitespace()
	name := p.parseIdentifier()
	p.consumeWhitespace()

	if p.eof() {
		return AttributeSelector{}, fmt.Errorf("unexpected EOF in attribute selector")
	}

	// If we hit ']', it's a presence selector like `[disabled]`.
	if p.currentChar() == ']' {
		p.consumeChar()
		return AttributeSelector{Name: name}, nil
	}

	// Otherwise, we expect an operator.
	var operator strings.Builder
	operator.WriteByte(p.consumeChar())

	// Check for two-character operators like `~=`, `|=`, `^=`, `$=`, `*=`.
	if !p.eof() && p.currentChar() == '=' {
		operator.WriteByte(p.consumeChar())
	}

	p.consumeWhitespace()

	var value string
	if p.currentChar() == '"' || p.currentChar() == '\'' {
		quote := p.currentChar()
		p.consumeChar() // consume opening quote
		start := p.pos
		for !p.eof() && p.currentChar() != quote {
			p.pos++
		}
		value = p.input[start:p.pos]
		if !p.eof() {
			p.consumeChar() // consume closing quote
		}
	} else {
		value = p.parseIdentifier()
	}
	p.consumeWhitespace()

	if p.eof() || p.currentChar() != ']' {
		return AttributeSelector{}, fmt.Errorf("expected ']' to close attribute selector")
	}
	p.consumeChar() // consume ']'

	return AttributeSelector{
		Name:     name,
		Operator: operator.String(),
		Value:    value,
	}, nil
}

// parseDeclarations parses the content within { ... }.
func (p *Parser) parseDeclarations() ([]Declaration, error) {
	p.consumeWhitespace()
	if p.eof() || p.currentChar() != '{' {
		return nil, fmt.Errorf("expected '{' at start of declarations")
	}
	p.consumeChar() // Consume '{'

	var declarations []Declaration
	for {
		p.consumeWhitespace()
		if p.eof() || p.currentChar() == '}' {
			break
		}

		if p.startsWith("/*") {
			p.skipComment()
			continue
		}

		property, value, important := p.parseDeclaration()
		if property != "" && value != "" {
			declarations = append(declarations, Declaration{
				Property:  Property(strings.ToLower(property)),
				Value:     Value(value),
				Important: important,
			})
		}
	}

	if !p.eof() && p.currentChar() == '}' {
		p.consumeChar() // Consume '}'
	}
	return declarations, nil
}

// parseDeclaration parses a single 'property: value;' pair.
func (p *Parser) parseDeclaration() (prop, val string, important bool) {
	// 1. Parse Property.
	if !isValidIdentifierStart(p.currentChar()) {
		p.skipTo(';', '}')
		if !p.eof() && p.currentChar() == ';' {
			p.consumeChar()
		}
		return
	}
	prop = p.parseIdentifier()
	p.consumeWhitespace()

	// 2. Parse Colon.
	if p.eof() || p.currentChar() != ':' {
		p.skipTo(';', '}')
		if !p.eof() && p.currentChar() == ';' {
			p.consumeChar()
		}
		return
	}
	p.consumeChar()
	p.consumeWhitespace()

	// 3. Parse Value.
	val = p.parseValue()

	// 4. Handle !important.
	if strings.HasSuffix(strings.ToLower(val), "!important") {
		important = true
		// Trim !important and any preceding whitespace from the value.
		val = strings.TrimSpace(val[:len(val)-len("!important")])
	}

	// 5. Consume optional semicolon.
	p.consumeWhitespace()
	if !p.eof() && p.currentChar() == ';' {
		p.consumeChar()
	}
	return
}

// parseValue reads a CSS value until a delimiter.
func (p *Parser) parseValue() string {
	start := p.pos
	for !p.eof() {
		ch := p.currentChar()
		if ch == ';' || ch == '}' {
			break
		}
		if ch == '"' || ch == '\'' {
			p.skipQuotedString(ch)
			continue
		}
		if ch == '(' {
			p.skipBlock('(', ')')
			continue
		}
		p.pos++
	}
	return strings.TrimSpace(p.input[start:p.pos])
}

// --- Lexer-like Helpers ---

func (p *Parser) eof() bool {
	return p.pos >= len(p.input)
}

func (p *Parser) currentChar() byte {
	if p.eof() {
		return 0
	}
	return p.input[p.pos]
}

func (p *Parser) consumeChar() byte {
	ch := p.currentChar()
	if !p.eof() {
		p.pos++
	}
	return ch
}

func (p *Parser) consumeN(n int) {
	p.pos += n
	if p.pos > len(p.input) {
		p.pos = len(p.input)
	}
}

func (p *Parser) consumeWhitespace() {
	for !p.eof() && isWhitespace(p.currentChar()) {
		p.pos++
	}
}

func (p *Parser) startsWith(s string) bool {
	if p.pos+len(s) > len(p.input) {
		return false
	}
	return p.input[p.pos:p.pos+len(s)] == s
}

func (p *Parser) skipComment() {
	p.pos += 2
	endIndex := strings.Index(p.input[p.pos:], "*/")
	if endIndex == -1 {
		p.pos = len(p.input)
	} else {
		p.pos += endIndex + 2
	}
}

func (p *Parser) skipTo(targets ...byte) {
	for !p.eof() {
		ch := p.currentChar()
		for _, target := range targets {
			if ch == target {
				return
			}
		}
		p.pos++
	}
}

func (p *Parser) skipBlock(open, close byte) {
	depth := 1
	for !p.eof() {
		c := p.consumeChar()
		if c == open {
			depth++
		} else if c == close {
			depth--
			if depth == 0 {
				return
			}
		}
	}
}

func (p *Parser) skipQuotedString(quote byte) {
	p.consumeChar() // Consume opening quote
	for !p.eof() {
		ch := p.consumeChar()
		if ch == '\\' {
			p.consumeChar() // Skip escaped character
		} else if ch == quote {
			return
		}
	}
}

func (p *Parser) skipAtRule() {
	p.consumeChar() // Consume '@'
	// Skip the identifier (e.g., 'media', 'keyframes').
	_ = p.parseIdentifier()
	p.consumeWhitespace()
	// Skip until the next block or semicolon.
	for !p.eof() {
		ch := p.currentChar()
		if ch == '{' {
			p.consumeChar() // Consume '{'
			p.skipBlock('{', '}')
			return
		}
		if ch == ';' {
			p.consumeChar()
			return
		}
		p.pos++
	}
}

func (p *Parser) parseIdentifier() string {
	start := p.pos
	for !p.eof() && isValidIdentifierChar(p.currentChar()) {
		p.pos++
	}
	return p.input[start:p.pos]
}

func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

func isValidIdentifierStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '-'
}

func isValidIdentifierChar(ch byte) bool {
	return isValidIdentifierStart(ch) || (ch >= '0' && ch <= '9')
}