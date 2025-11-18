package javascript

import (
	"context"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
)

func parseNode(t *testing.T, code string) (*sitter.Node, []byte) {
	parser := sitter.NewParser()
	parser.SetLanguage(javascript.GetLanguage())
	src := []byte(code)
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	// Return the first statement's expression usually
	// Structure: program -> expression_statement -> expression
	root := tree.RootNode()
	stmt := root.Child(0)
	if stmt == nil {
		t.Fatal("No statement found")
	}
	// Unwrap expression_statement if present
	if stmt.Type() == "expression_statement" {
		return stmt.Child(0), src
	}
	return stmt, src
}

func TestFlattenPropertyAccess(t *testing.T) {
	tests := []struct {
		code     string
		expected []string // nil means we expect failure/nil
	}{
		{"window.location.hash", []string{"window", "location", "hash"}},
		{"obj['prop']", []string{"obj", "prop"}},
		{"this.data", []string{"this", "data"}},
		{"simple", []string{"simple"}},
		{"arr[0]", nil},        // Computed property (integer) not currently handled in simple flatten
		{"obj[variable]", nil}, // Computed property (variable)
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			node, src := parseNode(t, tt.code)
			result := flattenPropertyAccess(node, src)

			if tt.expected == nil {
				if result != nil {
					t.Errorf("Expected nil, got %v", result)
				}
			} else {
				if len(result) != len(tt.expected) {
					t.Errorf("Expected length %d, got %d (%v)", len(tt.expected), len(result), result)
					return
				}
				for i, val := range result {
					if val != tt.expected[i] {
						t.Errorf("Index %d: expected %s, got %s", i, tt.expected[i], val)
					}
				}
			}
		})
	}
}
