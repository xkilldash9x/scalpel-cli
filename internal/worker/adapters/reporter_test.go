// File: internal/worker/adapters/reporter_test.go
package adapters_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/active/taint"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/internal/worker/adapters"
)

func setupReporterTest() (*adapters.ContextReporter, *core.AnalysisContext) {
	// Setup context with a Nop logger and initialized Findings slice.
	ctx := &core.AnalysisContext{
		Logger:   zap.NewNop(),
		Findings: []schemas.Finding{},
	}
	reporter := adapters.NewContextReporter(ctx)
	return reporter, ctx
}

// TestContextReporter_Classification_Potential verifies the classification logic for unconfirmed findings.
func TestContextReporter_Classification_Potential(t *testing.T) {
	tests := []struct {
		name      string
		sink      schemas.TaintSink
		probeType schemas.ProbeType
		wantVuln  string
		wantSev   schemas.Severity
		wantCWE   string
	}{
		{"DOM XSS (innerHTML)", schemas.SinkInnerHTML, schemas.ProbeTypeXSS, "DOM-Based Cross-Site Scripting (Potential)", schemas.SeverityHigh, "CWE-79"},
		{"Code Injection (eval)", schemas.SinkEval, schemas.ProbeTypeXSS, "Client-Side Code Injection (Potential)", schemas.SeverityHigh, "CWE-94"},
		{"Tainted Resource (script src)", schemas.SinkScriptSrc, schemas.ProbeTypeXSS, "Tainted Resource Loading (Potential XSS/Injection)", schemas.SeverityHigh, "CWE-829"},
		{"Navigation XSS", schemas.SinkNavigation, schemas.ProbeTypeXSS, "DOM-Based Cross-Site Scripting (Navigation) (Potential)", schemas.SeverityHigh, "CWE-79"},
		{"Open Redirect (Navigation)", schemas.SinkNavigation, schemas.ProbeTypeGeneric, "Open Redirect / Data Leakage (Potential)", schemas.SeverityMedium, "CWE-601"},
		{"Data Exfiltration (Fetch)", schemas.SinkFetch, schemas.ProbeTypeGeneric, "Data Exfiltration / Information Disclosure (Potential)", schemas.SeverityMedium, "CWE-200"},
		{"Unclassified", schemas.TaintSink("unknownSink"), schemas.ProbeTypeGeneric, "Unclassified Taint Flow", schemas.SeverityInformational, "CWE-20"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := taint.CorrelatedFinding{
				Sink:        tt.sink,
				IsConfirmed: false,
				Probe:       taint.ActiveProbe{Type: tt.probeType},
			}

			// Create a fresh context/reporter for each test run to isolate findings.
			reporter, ctx := setupReporterTest()
			reporter.ReportTaintFinding(finding)

			require.Len(t, ctx.Findings, 1)
			result := ctx.Findings[0]

			assert.Equal(t, tt.wantVuln, result.Vulnerability.Name)
			assert.Equal(t, tt.wantSev, result.Severity)
			assert.Equal(t, []string{tt.wantCWE}, result.CWE)
			assert.NotContains(t, result.Description, "[CONFIRMED EXECUTION]")
		})
	}
}

// TestContextReporter_Classification_Confirmed verifies the classification logic for confirmed executions.
func TestContextReporter_Classification_Confirmed(t *testing.T) {
	tests := []struct {
		name      string
		probeType schemas.ProbeType
		wantVuln  string
		wantSev   schemas.Severity
		wantCWE   string
	}{
		{"Confirmed XSS", schemas.ProbeTypeXSS, "Confirmed Cross-Site Scripting", schemas.SeverityCritical, "CWE-79"},
		{"Confirmed SSTI", schemas.ProbeTypeSSTI, "Confirmed SSTI leading to XSS", schemas.SeverityCritical, "CWE-1336"},
		{"Confirmed SQLi (Reflected)", schemas.ProbeTypeSQLi, "Confirmed Reflected SQLi leading to XSS", schemas.SeverityCritical, "CWE-89"},
		{"Confirmed Cmd Injection (Reflected)", schemas.ProbeTypeCmdInjection, "Confirmed Reflected Command Injection leading to XSS", schemas.SeverityCritical, "CWE-78"},
		{"Confirmed Generic Execution", schemas.ProbeTypeGeneric, "Confirmed Code Execution", schemas.SeverityCritical, "CWE-94"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := taint.CorrelatedFinding{
				// Confirmed findings always use the SinkExecution sink.
				Sink:        schemas.SinkExecution,
				IsConfirmed: true,
				Probe:       taint.ActiveProbe{Type: tt.probeType},
			}

			// Create a fresh context/reporter for isolation.
			reporter, ctx := setupReporterTest()
			reporter.ReportTaintFinding(finding)

			require.Len(t, ctx.Findings, 1)
			result := ctx.Findings[0]

			assert.Equal(t, tt.wantVuln, result.Vulnerability.Name)
			assert.Equal(t, tt.wantSev, result.Severity)
			assert.Equal(t, []string{tt.wantCWE}, result.CWE)
			assert.Contains(t, result.Description, "[CONFIRMED EXECUTION]")
		})
	}
}

func TestContextReporter_EvidenceGeneration(t *testing.T) {
	reporter, ctx := setupReporterTest()

	// Create a detailed finding
	finding := taint.CorrelatedFinding{
		TaskID:     "task-123",
		TargetURL:  "http://example.com",
		Sink:       schemas.SinkInnerHTML,
		Origin:     "location.hash",
		Value:      "<svg onload=alert(1)>",
		Canary:     "canary_abc",
		Detail:     "Injected into div#main",
		StackTrace: "app.js:50\ninit.js:1",
		Probe: taint.ActiveProbe{
			Type: schemas.ProbeTypeXSS,
			Key:  "onload",
		},
	}

	reporter.ReportTaintFinding(finding)

	require.Len(t, ctx.Findings, 1)
	result := ctx.Findings[0]

	// Verify the evidence JSON structure and content.
	var evidenceMap map[string]interface{}
	err := json.Unmarshal([]byte(result.Evidence), &evidenceMap)
	require.NoError(t, err, "Evidence should be valid JSON")

	assert.Equal(t, string(schemas.SinkInnerHTML), evidenceMap["sink"])
	assert.Equal(t, "location.hash", evidenceMap["source_origin"])
	assert.Equal(t, "<svg onload=alert(1)>", evidenceMap["tainted_value"])
	assert.Equal(t, "canary_abc", evidenceMap["canary"])
	assert.Equal(t, string(schemas.ProbeTypeXSS), evidenceMap["probe_type"])

	// Verify stack trace is a string
	stackTrace, ok := evidenceMap["stack_trace"].(string)
	require.True(t, ok, "Stack trace should be a string")
	assert.Contains(t, stackTrace, "app.js:50")
	assert.Contains(t, stackTrace, "init.js:1")
}

func TestContextReporter_Recommendations(t *testing.T) {
	// Test recommendations indirectly by triggering classifications and checking the resulting recommendation string.

	tests := []struct {
		name                 string
		finding              taint.CorrelatedFinding
		expectedRecSubstring string
	}{
		{"XSS Rec", taint.CorrelatedFinding{Sink: schemas.SinkInnerHTML}, "DOMPurify"},
		{"Code Injection Rec", taint.CorrelatedFinding{Sink: schemas.SinkEval}, "Avoid using functions like 'eval()"},
		{"Open Redirect Rec", taint.CorrelatedFinding{Sink: schemas.SinkNavigation, Probe: taint.ActiveProbe{Type: schemas.ProbeTypeGeneric}}, "Validate all redirection URLs"},
		{"SSTI Rec", taint.CorrelatedFinding{Sink: schemas.SinkExecution, Probe: taint.ActiveProbe{Type: schemas.ProbeTypeSSTI}}, "templating engine is configured securely"},
		{"Exfiltration Rec", taint.CorrelatedFinding{Sink: schemas.SinkFetch}, "Review data flows to outbound communication channels"},
		{"Generic Rec", taint.CorrelatedFinding{Sink: schemas.TaintSink("unknown")}, "Validate and sanitize all user input"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh context/reporter for isolation.
			reporter, ctx := setupReporterTest()
			reporter.ReportTaintFinding(tt.finding)

			require.Len(t, ctx.Findings, 1)
			result := ctx.Findings[0]

			assert.Contains(t, result.Recommendation, tt.expectedRecSubstring)
		})
	}
}
