// internal/browser/parser/css.go
package parser

import (
	"fmt"
	"strings"
)

// Property represents a CSS property (e.g., "display").
type Property string

// Value represents a CSS value (e.g., "none").
// In the CSSOM, this is the raw string value.
type Value string

// Declaration is a key-value pair (e.g., display: none).
type Declaration struct {
	Property Property
	Value    Value
    // Future: Add !important flag
}

// RuleSet represents a set of declarations applied by a selector.
type RuleSet struct {
	Selectors    []Selector
	Declarations []Declaration
}

// StyleSheet is the top-level structure representing the parsed CSSOM.
type StyleSheet struct {
	Rules []RuleSet
}

// SelectorType defines the type of selector.
type SelectorType int

const (
	SimpleSelector SelectorType = iota // Tag, Class, ID, or Universal
)

// Selector represents a CSS selector (e.g., "div.container").
// This implementation focuses on simple selectors (no combinators or pseudo-elements).
type Selector struct {
	Type      SelectorType
	TagName   string
	ID        string
	Classes   []string
}

// CalculateSpecificity calculates the specificity of the selector (IDs, Classes, Elements).
// See: https://developer.mozilla.org/en-US/docs/Web/CSS/Specificity
func (s Selector) CalculateSpecificity() (int, int, int) {
	a := 0 // IDs
	b := 0 // Classes, attributes, pseudo-classes
	c := 0 // Elements (tags), pseudo-elements

	if s.ID != "" {
		a = 1
	}
	b = len(s.Classes)
	if s.TagName != "" && s.TagName != "*" {
		c = 1
	}
	return a, b, c
}

// IsValid checks if the selector has at least one component.
func (s Selector) IsValid() bool {
    return s.TagName != "" || s.ID != "" || len(s.Classes) > 0
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
		// Handle comments
		if p.startsWith("/*") {
			p.skipComment()
			continue
		}

		selectors, err := p.parseSelectors()
		if err != nil || len(selectors) == 0 {
			// If selector parsing fails or yields nothing, recover by skipping the associated block.
			p.skipTo('{')
            if !p.eof() && p.currentChar() == '{' {
			    p.skipBlock('{', '}')
            }
			continue
		}

		declarations, err := p.parseDeclarations()
		if err != nil {
			// If declaration parsing fails (e.g., missing '{'), we discard the attempt and continue.
			continue
		}

		if len(declarations) > 0 {
			rules = append(rules, RuleSet{Selectors: selectors, Declarations: declarations})
		}
	}
	return StyleSheet{Rules: rules}
}

// parseSelectors parses a comma-separated list of selectors until '{'.
func (p *Parser) parseSelectors() ([]Selector, error) {
	var selectors []Selector

	for {
		p.consumeWhitespace()
        if p.eof() || p.currentChar() == '{' {
            break
        }

		selector, err := p.parseSimpleSelector()
		if err != nil {
			// Attempt recovery: skip this specific selector until the next comma or opening brace.
            p.skipTo(',', '{')
		} else if selector.IsValid() {
		    selectors = append(selectors, selector)
        }

        p.consumeWhitespace()
        if p.eof() || p.currentChar() == '{' {
            break
        }

		if p.currentChar() == ',' {
			p.consumeChar()
			continue
		}

        // Handle unsupported features (like combinators ' ', '>', '+').
        // If we encounter them, we stop parsing selectors for this rule block.
        // This allows basic parsing of complex stylesheets by ignoring rules we don't understand.
        break
	}

	return selectors, nil
}

// parseSimpleSelector parses a single selector (e.g., div#id.class1.class2).
func (p *Parser) parseSimpleSelector() (Selector, error) {
	selector := Selector{}
	// Do not consume whitespace here, it might be a combinator handled by parseSelectors.

	// Parse Tag Name or Universal selector
    if !p.eof() {
	    ch := p.currentChar()
        if ch != '#' && ch != '.' {
		    if ch == '*' {
			    p.consumeChar()
			    selector.TagName = "*"
		    } else if isValidIdentifierStart(ch) {
			    selector.TagName = strings.ToLower(p.parseIdentifier())
		    }
        }
	}

	// Parse IDs and Classes
	for !p.eof() {
		switch p.currentChar() {
		case '#':
			p.consumeChar()
			// Multiple IDs are technically invalid but allowed for robustness.
			selector.ID = p.parseIdentifier()
		case '.':
			p.consumeChar()
			selector.Classes = append(selector.Classes, p.parseIdentifier())
		default:
			// Stop if we hit whitespace, a combinator, or the start of the declaration block.
			goto done
		}
	}

done:
	return selector, nil
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

		// Handle comments within blocks
		if p.startsWith("/*") {
			p.skipComment()
			continue
		}

        // Parse Property
        if !isValidIdentifierStart(p.currentChar()) {
            // Invalid property start, skip to next delimiter
            p.skipTo(';', '}')
            if !p.eof() && p.currentChar() == ';' {
                p.consumeChar()
            }
            continue
        }
		property := strings.ToLower(p.parseIdentifier())
		p.consumeWhitespace()

        // Parse Colon
		if p.eof() || p.currentChar() != ':' {
			// Handle recovery
			p.skipTo(';', '}')
			if !p.eof() && p.currentChar() == ';' {
				p.consumeChar()
			}
			continue
		}
		p.consumeChar() // Consume ':'
		p.consumeWhitespace()

        // Parse Value
		value := p.parseValue()
		p.consumeWhitespace()

		// Handle !important
		if p.startsWith("!important") {
			p.consumeN(10)
			p.consumeWhitespace()
            // Future: Set importance flag on declaration
		}

		if property != "" && value != "" {
			declarations = append(declarations, Declaration{Property: Property(property), Value: Value(value)})
		}

        // Parse Delimiter
        if p.eof() {
             break
        }
		if p.currentChar() == ';' {
			p.consumeChar()
		} else if p.currentChar() == '}' {
			break
		} else {
			// Handle recovery
			p.skipTo(';', '}')
			if !p.eof() && p.currentChar() == ';' {
				p.consumeChar()
			}
		}
	}

	if !p.eof() && p.currentChar() == '}' {
		p.consumeChar() // Consume '}'
	}
	return declarations, nil
}

func (p *Parser) parseIdentifier() string {
	start := p.pos
	for !p.eof() && isValidIdentifierChar(p.currentChar()) {
		p.pos++
	}
	return p.input[start:p.pos]
}

// parseValue parses a CSS value until a delimiter.
func (p *Parser) parseValue() string {
	start := p.pos
	// Simplified value parsing: reads until ;, }, or EOF.
	for !p.eof() {
		ch := p.currentChar()
		if ch == ';' || ch == '}' {
			break
		}
		// Basic handling for quotes.
		if ch == '"' || ch == ''' {
			p.consumeChar()
			p.skipTo(ch)
			if !p.eof() {
				p.consumeChar()
			}
			continue
		}
        // Handle function calls like url().
        if ch == '(' {
            p.consumeChar()
            p.skipTo(')')
            if !p.eof() {
                p.consumeChar()
            }
            continue
        }

		// Handle !important detection
        if p.startsWith("!important") {
            // Check if the remaining string starts with !important followed by a delimiter or whitespace
            remaining := p.input[p.pos+10:]
            if len(remaining) == 0 || strings.HasPrefix(remaining, ";") || strings.HasPrefix(remaining, "}") || (len(remaining) > 0 && isWhitespace(remaining[0])) {
			    break
            }
        }

		p.pos++
	}
	// Trim trailing whitespace from the value before returning
	return strings.TrimSpace(p.input[start:p.pos])
}

// --- Helpers ---

func (p *Parser) eof() bool {
	return p.pos >= len(p.input)
}

// Using byte assuming ASCII input for CSS syntax.
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
	// Assumes we are at the start of "/*"
	p.pos += 2
	for !p.eof() {
		if p.startsWith("*/") {
			p.pos += 2
			return
		}
		p.pos++
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

// skipBlock skips content between matching delimiters (e.g., { ... }).
func (p *Parser) skipBlock(open, close byte) {
    if p.eof() { return }

    // Assumes we are currently at the opening delimiter.
    if p.currentChar() != open {
        return
    }
    p.consumeChar()

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

func isWhitespace(ch byte) bool {
	return ch == ' ' || ch == '	' || ch == '
' || ch == '
'
}

func isValidIdentifierStart(ch byte) bool {
    // CSS identifiers can start with a letter, underscore, or hyphen.
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '-'
}

func isValidIdentifierChar(ch byte) bool {
	return isValidIdentifierStart(ch) || (ch >= '0' && ch <= '9')
}
