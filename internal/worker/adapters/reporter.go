// internal/worker/adapters/reporter.go --
package adapters

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/active/taint"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
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
		ID:             uuid.New().String(),
		TaskID:         finding.TaskID,
		Timestamp:      time.Now().UTC(), // CORRECTED: Use time.Time object directly.
		Target:         finding.TargetURL,
		Module:         "TaintAnalyzer (IAST)",
		Vulnerability:  vulnType,
		Severity:       severity, // CORRECTED: classifyTaintFinding now returns the correct type.
		Description:    description,
		Evidence:       evidence,
		Recommendation: r.getRecommendation(vulnType),
		CWE:            cwe,
	}

	r.Ctx.AddFinding(genericFinding)
	r.logger.Info("Taint finding recorded", zap.String("vulnerability", vulnType), zap.String("severity", string(severity)), zap.Bool("confirmed", finding.IsConfirmed))
}

func (r *ContextReporter) classifyTaintFinding(finding taint.CorrelatedFinding) (string, schemas.Severity, string) {
	if finding.Sink == taint.SinkExecution {
		return r.classifyConfirmedExecution(finding)
	}
	switch finding.Sink {
	case taint.SinkInnerHTML, taint.SinkOuterHTML, taint.SinkDocumentWrite, taint.SinkIframeSrcDoc:
		return "DOM-Based Cross-Site Scripting (Potential)", schemas.SeverityHigh, "CWE-79"
	case taint.SinkEval, taint.SinkFunctionConstructor:
		return "Client-Side Code Injection (Potential)", schemas.SeverityHigh, "CWE-94"
	case taint.SinkScriptSrc, taint.SinkIframeSrc:
		return "Tainted Resource Loading (Potential XSS/Injection)", schemas.SeverityHigh, "CWE-829"
	case taint.SinkNavigation:
		if finding.Probe.Type == taint.ProbeTypeXSS || finding.Probe.Type == taint.ProbeTypeSSTI {
			return "DOM-Based Cross-Site Scripting (Navigation) (Potential)", schemas.SeverityHigh, "CWE-79"
		}
		return "Open Redirect / Data Leakage (Potential)", schemas.SeverityMedium, "CWE-601"
	case taint.SinkFetch, taint.SinkFetch_URL, taint.SinkWebSocketSend, taint.SinkXMLHTTPRequest, taint.SinkXMLHTTPRequest_URL, taint.SinkSendBeacon:
		return "Data Exfiltration / Information Disclosure (Potential)", schemas.SeverityMedium, "CWE-200"
	default:
		return "Unclassified Taint Flow", schemas.SeverityInfo, "CWE-20"
	}
}

func (r *ContextReporter) classifyConfirmedExecution(finding taint.CorrelatedFinding) (string, schemas.Severity, string) {
	switch finding.Probe.Type {
	case taint.ProbeTypeXSS, taint.ProbeTypeDOMClobbering:
		return "Confirmed Cross-Site Scripting", schemas.SeverityCritical, "CWE-79"
	case taint.ProbeTypeSSTI:
		return "Confirmed SSTI leading to XSS", schemas.SeverityCritical, "CWE-1336"
	case taint.ProbeTypeSQLi:
		return "Confirmed Reflected SQLi leading to XSS", schemas.SeverityCritical, "CWE-89"
	case taint.ProbeTypeCmdInjection:
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
