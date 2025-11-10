// internal/worker/adapters/reporter.go
package adapters

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/active/taint"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

type ContextReporter struct {
	Ctx    *core.AnalysisContext
	logger *zap.Logger
}

func NewContextReporter(ctx *core.AnalysisContext) *ContextReporter {
	logger := ctx.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ContextReporter{
		Ctx:    ctx,
		logger: logger.With(zap.String("component", "context_reporter")),
	}
}

func (r *ContextReporter) Report(finding taint.CorrelatedFinding) {
	evidenceMap := map[string]interface{}{
		"sink":          finding.Sink,
		"source_origin": finding.Origin,
		"tainted_value": finding.Value,
		"canary":        finding.Canary,
		"probe_type":    finding.Probe.Type,
		"probe_key":     finding.Probe.Key,
		"detail":        finding.Detail,
		"is_confirmed":  finding.IsConfirmed,
		"stack_trace":   finding.StackTrace,
	}
	evidence, err := json.Marshal(evidenceMap)
	if err != nil {
		r.logger.Error("failed to marshal taint evidence", zap.Error(err))
		evidence = []byte(fmt.Sprintf(`{"error": "failed to marshal evidence: %s"}`, err.Error()))
	}

	vulnType, severity, cwe := r.classifyTaintFinding(finding)

	description := fmt.Sprintf("Tainted value from '%s' reached sink '%s'. Detail: %s", finding.Origin, finding.Sink, finding.Detail)
	if finding.IsConfirmed {
		description = "[CONFIRMED EXECUTION] " + description
	}

	genericFinding := schemas.Finding{
		ID:     uuid.New().String(),
		TaskID: finding.TaskID,
		// Refactored: Renamed Timestamp to ObservedAt
		ObservedAt: time.Now().UTC(),
		Target:     finding.TargetURL,
		Module:     "TaintAnalyzer (IAST)",
		// Refactored: Flattened Vulnerability struct to VulnerabilityName
		VulnerabilityName: vulnType,
		Severity:          severity,
		Description:       description,
		// Refactored: Assign []byte directly to json.RawMessage
		Evidence:       evidence,
		Recommendation: r.getRecommendation(vulnType),
		CWE:            []string{cwe},
	}

	r.Ctx.AddFinding(genericFinding)
	r.logger.Info("Taint finding recorded", zap.String("vulnerability", vulnType), zap.String("severity", string(severity)), zap.Bool("confirmed", finding.IsConfirmed))
}

func (r *ContextReporter) Write(envelope *schemas.ResultEnvelope) error {
	if envelope == nil {
		return nil
	}
	for _, finding := range envelope.Findings {
		r.Ctx.AddFinding(finding)
	}
	return nil
}

func (r *ContextReporter) classifyTaintFinding(finding taint.CorrelatedFinding) (string, schemas.Severity, string) {
	// Refactored: Use schemas.SinkExecution constant
	if finding.Sink == schemas.SinkExecution {
		return r.classifyConfirmedExecution(finding)
	}
	switch finding.Sink {
	// Refactored: Use schemas constants for all sinks
	case schemas.SinkInnerHTML, schemas.SinkOuterHTML, schemas.SinkDocumentWrite, schemas.SinkIframeSrcDoc:
		return "DOM-Based Cross-Site Scripting (Potential)", schemas.SeverityHigh, "CWE-79"
	case schemas.SinkEval, schemas.SinkFunctionConstructor:
		return "Client-Side Code Injection (Potential)", schemas.SeverityHigh, "CWE-94"
	case schemas.SinkScriptSrc, schemas.SinkIframeSrc:
		return "Tainted Resource Loading (Potential XSS/Injection)", schemas.SeverityHigh, "CWE-829"
	case schemas.SinkNavigation:
		// Refactored: Use schemas constants for probe types
		if finding.Probe.Type == schemas.ProbeTypeXSS || finding.Probe.Type == schemas.ProbeTypeSSTI {
			return "DOM-Based Cross-Site Scripting (Navigation) (Potential)", schemas.SeverityHigh, "CWE-79"
		}
		return "Open Redirect / Data Leakage (Potential)", schemas.SeverityMedium, "CWE-601"
	case schemas.SinkFetch, schemas.SinkFetchURL, schemas.SinkWebSocketSend, schemas.SinkXMLHTTPRequest, schemas.SinkXMLHTTPRequestURL, schemas.SinkSendBeacon:
		return "Data Exfiltration / Information Disclosure (Potential)", schemas.SeverityMedium, "CWE-200"
	default:
		// Refactored: Use schemas.SeverityInfo
		return "Unclassified Taint Flow", schemas.SeverityInfo, "CWE-20"
	}
}

func (r *ContextReporter) classifyConfirmedExecution(finding taint.CorrelatedFinding) (string, schemas.Severity, string) {
	switch finding.Probe.Type {
	// Refactored: Use schemas constants for all probe types
	case schemas.ProbeTypeXSS, schemas.ProbeTypeDOMClobbering:
		return "Confirmed Cross-Site Scripting", schemas.SeverityCritical, "CWE-79"
	case schemas.ProbeTypeSSTI:
		return "Confirmed SSTI leading to XSS", schemas.SeverityCritical, "CWE-1336"
	case schemas.ProbeTypeSQLi:
		return "Confirmed Reflected SQLi leading to XSS", schemas.SeverityCritical, "CWE-89"
	case schemas.ProbeTypeCmdInjection:
		return "Confirmed Reflected Command Injection leading to XSS", schemas.SeverityCritical, "CWE-78"
	default:
		return "Confirmed Code Execution", schemas.SeverityCritical, "CWE-94"
	}
}

func (r *ContextReporter) getRecommendation(vulnType string) string {
	if strings.Contains(vulnType, "Cross-Site Scripting") {
		return "Implement context-aware output encoding (e.g., using DOMPurify). Avoid using dangerous sinks like innerHTML; prefer textContent. Implement a strong Content Security Policy (CSP)."
	}
	// ... other recommendations
	return "Validate and sanitize all user input at the source and before use in sensitive sinks."
}
