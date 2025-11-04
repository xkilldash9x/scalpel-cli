// internal/worker/adapters/header_adapter_test.go
package adapters_test

import ( // This is a comment to force a change
	"context"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

func TestNewHeadersAdapter(t *testing.T) {
	adapter := adapters.NewHeadersAdapter()
	assert.Equal(t, "Headers Adapter", adapter.Name())
	assert.Equal(t, core.TypePassive, adapter.Type())
}

func TestHeadersAdapter_Analyze_Delegation(t *testing.T) {
	adapter := adapters.NewHeadersAdapter()
	targetURL := "http://example.com/page" // FIX: Use the same URL as the HAR entry.

	harData := []byte(`{
		"log": {
			"entries": [
				{
					"request": {"url": "http://example.com/page"},
					"response": {
						"status": 200,
						"headers": [
							{"name": "Content-Type", "value": "text/html"},
							{"name": "X-Powered-By", "value": "PHP/7.4.3"}
						]
					}
				}
			]
		}
	}`)

	parsedURL, err := url.Parse(targetURL)
	require.NoError(t, err)

	analysisCtx := &core.AnalysisContext{
		Task:      schemas.Task{Type: schemas.TaskAnalyzeHeaders, TargetURL: targetURL},
		TargetURL: parsedURL,
		Logger:    zap.NewNop(),
		Artifacts: &schemas.Artifacts{
			HAR: (*json.RawMessage)(&harData),
		},
		Findings: []schemas.Finding{},
	}

	err = adapter.Analyze(context.Background(), analysisCtx)
	assert.NoError(t, err)

	assert.NotEmpty(t, analysisCtx.Findings)

	foundCSP := false
	foundXPB := false
	containsCWE := func(cwes []string, cwe string) bool {
		for _, item := range cwes {
			if item == cwe {
				return true
			}
		}
		return false
	}

	for _, f := range analysisCtx.Findings {
		// Check for the CWE related to missing CSP
		if containsCWE(f.CWE, "CWE-693") {
			foundCSP = true
		}
		// Check for the CWE related to information disclosure
		if containsCWE(f.CWE, "CWE-200") {
			foundXPB = true
		}
	}

	assert.True(t, foundCSP, "Expected finding for missing CSP was not generated")
	assert.True(t, foundXPB, "Expected finding for X-Powered-By was not generated")
}
