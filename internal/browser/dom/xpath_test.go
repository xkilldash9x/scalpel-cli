package dom_test

import (
	"strings"
	"testing"

	"github.com/antchfx/htmlquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/dom"
)

const testHTML = `
	<html>
	<body>
		<div id="header">
			<h1>Welcome</h1>
		</div>
		<div class="content">
			<p>P1</p><p>P2</p>
			<ul>
				<li>Item 1</li>
				<li>Item 2</li>
				<li id="special">Item 3</li>
			</ul>
		</div>
		<div class="content"><p>P3</p></div>
	</body>
	</html>
	`

func TestGenerateUniqueXPath(t *testing.T) {
	doc, err := htmlquery.Parse(strings.NewReader(testHTML))
	require.NoError(t, err)

	tests := []struct {
		name          string
		targetXPath   string
		expectedXPath string
	}{
		{"Body", "//body", "/html[1]/body[1]"},
		{"Element with ID", "//div[@id='header']", `//*[@id='header']`},
		{"Child of ID element", "//h1", `//*[@id='header']/h1[1]`},
		// Use (//p)[index] for selecting the nth paragraph globally for the targetXPath
		{"Specific index", "(//p)[2]", "/html[1]/body[1]/div[2]/p[2]"},
		{"Ambiguous classes", "(//div[@class='content'])[2]/p", "/html[1]/body[1]/div[3]/p[1]"},
		{"List item skipping comments", "//ul/li[2]", "/html[1]/body[1]/div[2]/ul[1]/li[2]"},
		{"List item with ID (Optimization)", "//li[@id='special']", `//*[@id='special']`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetNode := htmlquery.FindOne(doc, tt.targetXPath)
			require.NotNil(t, targetNode, "Test setup error: target node not found with %s", tt.targetXPath)

			generatedXPath := dom.GenerateUniqueXPath(targetNode)
			assert.Equal(t, tt.expectedXPath, generatedXPath)

			// Verify that the generated XPath uniquely selects the original node
			verificationNode := htmlquery.FindOne(doc, generatedXPath)
			assert.Equal(t, targetNode, verificationNode, "Generated XPath did not select the original node")
		})
	}
}
