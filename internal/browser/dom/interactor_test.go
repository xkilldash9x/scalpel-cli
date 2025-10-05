// internal/browser/dom/interactor_test.go
package dom

// We place this test inside the 'dom' package (not 'dom_test') to access unexported functions like generateNodeFingerprint and isTextInputElement.

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"sync"
	"testing"

	"github.com/antchfx/htmlquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/parser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/layout"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/style"
	"golang.org/x/net/html"
)

// MockCorePagePrimitives implements the CorePagePrimitives interface for testing.
type MockCorePagePrimitives struct {
	mu             sync.Mutex
	CurrentURL     string
	DOMSnapshot    string
	Interactions   []string
	StabilizeCount int
}

func (m *MockCorePagePrimitives) ExecuteClick(ctx context.Context, selector string, minMs, maxMs int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Interactions = append(m.Interactions, fmt.Sprintf("Click(%s)", selector))
	// Simulate state change on specific interaction
	if strings.Contains(selector, "id='change-state-btn'") {
		m.DOMSnapshot = `<html><body><p>Changed!</p><a href="/new">New Link</a></body></html>`
	}
	return nil
}

func (m *MockCorePagePrimitives) ExecuteType(ctx context.Context, selector string, text string, holdMeanMs float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Interactions = append(m.Interactions, fmt.Sprintf("Type(%s, '%s')", selector, text))
	return nil
}

func (m *MockCorePagePrimitives) ExecuteSelect(ctx context.Context, selector string, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Interactions = append(m.Interactions, fmt.Sprintf("Select(%s, '%s')", selector, value))
	return nil
}

func (m *MockCorePagePrimitives) GetCurrentURL() string {
	return m.CurrentURL
}

func (m *MockCorePagePrimitives) GetDOMSnapshot(ctx context.Context) (io.Reader, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return strings.NewReader(m.DOMSnapshot), nil
}

// IsVisible implements the missing method to satisfy the CorePagePrimitives interface.
// For the mock, we default to returning true, assuming elements are visible unless a test specifies otherwise.
func (m *MockCorePagePrimitives) IsVisible(ctx context.Context, selector string) bool {
	return true
}

func mockStabilizeFn(mock *MockCorePagePrimitives) StabilizationFunc {
	return func(ctx context.Context) error {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		mock.StabilizeCount++
		return nil
	}
}

// buildMockLayoutTree is a helper to build a mock layout tree for testing.
// It assumes all nodes are visible for simplicity.
func buildMockLayoutTree(node *html.Node) *layout.LayoutBox {
	if node == nil {
		return nil
	}

	// For our tests, we can treat all nodes as block-level elements
	// to ensure they are considered "visible" by the mock logic.
	box := &layout.LayoutBox{
		StyledNode: &style.StyledNode{
			Node: node,
			ComputedStyles: map[parser.Property]parser.Value{
				"display": "block",
			},
		},
	}

	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if child.Type == html.ElementNode {
			childBox := buildMockLayoutTree(child)
			if childBox != nil {
				box.Children = append(box.Children, childBox)
			}
		}
	}
	return box
}

func TestGenerateNodeFingerprintStability(t *testing.T) {
	// Test stability against attribute order and class order
	data1 := ElementData{
		NodeName:    "BUTTON",
		TextContent: "Login",
		Attributes:  map[string]string{"id": "btn1", "class": "btn primary", "type": "submit"},
	}
	data2 := ElementData{
		NodeName:    "BUTTON",
		TextContent: "Login",
		// Different class order, added extra attribute not used in fingerprinting
		Attributes: map[string]string{"id": "btn1", "class": "primary btn", "type": "submit", "data-testid-ignore": "xyz"},
	}

	fp1, desc1 := generateNodeFingerprint(data1)
	fp2, desc2 := generateNodeFingerprint(data2)

	assert.NotEmpty(t, fp1)
	assert.Equal(t, fp1, fp2, "Fingerprints should match")
	assert.Equal(t, desc1, desc2, "Descriptions should match")
	// Check sorted classes in description (stableClasses logic)
	assert.Contains(t, desc1, ".btn.primary")
}

func TestIsTextInputElement(t *testing.T) {
	tests := []struct {
		name     string
		data     ElementData
		expected bool
	}{
		{"Input Text", ElementData{NodeName: "INPUT", Attributes: map[string]string{"type": "text"}}, true},
		{"Input Email", ElementData{NodeName: "INPUT", Attributes: map[string]string{"type": "email"}}, true},
		{"Input Submit", ElementData{NodeName: "INPUT", Attributes: map[string]string{"type": "submit"}}, false},
		{"Input Checkbox", ElementData{NodeName: "INPUT", Attributes: map[string]string{"type": "checkbox"}}, false},
		{"Textarea", ElementData{NodeName: "TEXTAREA"}, true},
		{"ContentEditable True", ElementData{NodeName: "DIV", Attributes: map[string]string{"contenteditable": "true"}}, true},
		{"ContentEditable Empty", ElementData{NodeName: "P", Attributes: map[string]string{"contenteditable": ""}}, true},
		{"Button", ElementData{NodeName: "BUTTON"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isTextInputElement(tt.data))
		})
	}
}

func TestInteractor_DiscoveryAndFiltering(t *testing.T) {
	htmlContent := `
		<html><body>
			<a href="/home">Visible Link</a>
			<button disabled>Disabled Button</button>
			<button id="active-btn">Active Button</button>
			<input type="text" name="username">
			<input type="hidden" name="csrf">
			<input type="email" readonly value="admin@example.com">
			<div role="button" aria-disabled="true">Disabled ARIA</div>
		</body></html>
		`
	mockPage := &MockCorePagePrimitives{DOMSnapshot: htmlContent}
	logger := &NopLogger{}
	interactor := NewInteractor(logger, NewDefaultHumanoidConfig(), nil, mockPage)

	// Since discoverElements now requires a layout tree, we parse the HTML
	// and build a mock tree to pass into the function.
	doc, err := htmlquery.Parse(strings.NewReader(htmlContent))
	require.NoError(t, err)
	layoutRoot := buildMockLayoutTree(doc)

	interacted := make(map[string]bool)
	// Use the internal discovery method for this unit test
	elements, err := interactor.discoverElements(context.Background(), layoutRoot, interacted)
	require.NoError(t, err)

	// Expected: Visible Link, Active Button, username input
	expectedCount := 3
	assert.Equal(t, expectedCount, len(elements))

	// Verify specific filtering (ensure readonly/disabled are gone)
	descriptions := make([]string, len(elements))
	for i, el := range elements {
		descriptions[i] = el.Description
	}

	fullDesc := strings.Join(descriptions, "|")
	assert.Contains(t, fullDesc, "#active-btn")
	assert.NotContains(t, fullDesc, "Disabled Button")
	assert.NotContains(t, fullDesc, "readonly")
	assert.NotContains(t, fullDesc, "Disabled ARIA")
}

func TestInteractor_ExploreStep_FlowAndStateChange(t *testing.T) {
	// Setup: A page where clicking a button changes the DOM state.
	initialHTML := `<html><body><input type="text" id="input1"><button id="change-state-btn">Change</button></body></html>`
	mockPage := &MockCorePagePrimitives{DOMSnapshot: initialHTML}
	logger := &NopLogger{}
	hConfig := HumanoidConfig{Enabled: false} // Disable delays
	interactor := NewInteractor(logger, hConfig, mockStabilizeFn(mockPage), mockPage)

	// Use a seeded RNG to make the test deterministic
	interactor.rng = rand.New(rand.NewSource(1))

	config := schemas.InteractionConfig{} // Use defaults, delays are off anyway
	interactedElements := make(map[string]bool)
	ctx := context.Background()

	// -- First interaction step --
	doc1, err := htmlquery.Parse(strings.NewReader(mockPage.DOMSnapshot))
	require.NoError(t, err)
	layoutRoot1 := buildMockLayoutTree(doc1)

	step1Interacted, err := interactor.ExploreStep(ctx, config, layoutRoot1, interactedElements)
	require.NoError(t, err)
	assert.True(t, step1Interacted, "Expected an interaction in the first step")
	assert.Equal(t, 1, mockPage.StabilizeCount)
	assert.Len(t, mockPage.Interactions, 1)

	// -- Second interaction step --
	// The DOM state might have changed inside the mock after the first interaction.
	mockPage.mu.Lock()
	stateAfterStep1 := mockPage.DOMSnapshot
	mockPage.mu.Unlock()

	doc2, err := htmlquery.Parse(strings.NewReader(stateAfterStep1))
	require.NoError(t, err)
	layoutRoot2 := buildMockLayoutTree(doc2)

	step2Interacted, err := interactor.ExploreStep(ctx, config, layoutRoot2, interactedElements)
	require.NoError(t, err)
	assert.True(t, step2Interacted, "Expected an interaction in the second step")
	assert.Equal(t, 2, mockPage.StabilizeCount)
	assert.Len(t, mockPage.Interactions, 2)

	// -- Verification --
	// The button that changes state must have been clicked at some point.
	var buttonClicked bool
	for _, interaction := range mockPage.Interactions {
		if strings.Contains(interaction, "id='change-state-btn'") {
			buttonClicked = true
		}
	}
	assert.True(t, buttonClicked, "The button to change state should have been clicked")

	// Verify the final DOM state reflects the change.
	mockPage.mu.Lock()
	finalDOM := mockPage.DOMSnapshot
	mockPage.mu.Unlock()
	assert.Contains(t, finalDOM, "Changed!")
}

