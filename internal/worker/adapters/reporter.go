// File: internal/worker/adapters/reporter.go
package adapters

import (
	"context"
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

// ContextReporter is responsible for converting analyzer-specific findings
// (like taint results) into the generic schemas.Finding format and reporting
// them back into the AnalysisContext.
type ContextReporter struct {
	Ctx    *core.AnalysisContext
	logger *zap.Logger
}

// NewContextReporter creates a new reporter associated with a specific analysis context.
func NewContextReporter(ctx *core.AnalysisContext) *ContextReporter {
	logger := ctx.Logger
	// Ensure a logger is always available.
	if logger == nil {
		logger = zap.NewNop()
	}
	return &ContextReporter{
		Ctx:    ctx,
		logger: logger.With(zap.String("component", "context_reporter")),
	}
}

// ReportTaintFinding converts a taint.CorrelatedFinding into a schemas.Finding and adds it to the context.
// Renamed from Report for clarity as the reporter might handle other finding types in the future.
func (r *ContextReporter) ReportTaintFinding(ctx context.Context, finding taint.CorrelatedFinding) {
	// 1. Classify the finding
	vulnType, severity, cwe := r.classifyTaintFinding(finding)

	// 2. Generate Evidence
	evidence, err := r.generateTaintEvidence(finding)
	if err != nil {
		r.logger.Error("Failed to generate taint evidence", zap.Error(err))
		// Fallback evidence if generation fails.
		evidence = fmt.Sprintf(`{"error": "failed to generate evidence: %s"}`, err.Error())
	}

	// 3. Construct the Description
	description := fmt.Sprintf("Tainted value originating from '%s' reached sensitive sink '%s'. Detail: %s", finding.Origin, finding.Sink, finding.Detail)
	if finding.IsConfirmed {
		// Emphasize confirmed findings.
		description = "[CONFIRMED EXECUTION] " + description
	}

	// 4. Create the Generic Finding
	genericFinding := schemas.Finding{
		ID:        uuid.New().String(),
		TaskID:    finding.TaskID,
		Timestamp: time.Now().UTC(),
		Target:    finding.TargetURL,
		Module:    "TaintAnalyzer (IAST)", // Standardized module name for taint findings.
		Vulnerability: schemas.Vulnerability{
			Name: vulnType,
		},
		Severity:       severity,
		Description:    description,
		Evidence:       evidence,
		Recommendation: r.getRecommendation(vulnType),
		CWE:            []string{cwe},
	}

	// 5. Report to the context
	r.Ctx.AddFinding(genericFinding)
	r.logger.Info("Taint finding recorded",
		zap.String("vulnerability", vulnType),
		zap.String("severity", string(severity)),
		zap.Bool("confirmed", finding.IsConfirmed),
	)
}

// generateTaintEvidence marshals the details of the taint finding into a JSON string.
func (r *ContextReporter) generateTaintEvidence(finding taint.CorrelatedFinding) (string, error) {
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
	evidenceBytes, err := json.Marshal(evidenceMap)
	if err != nil {
		return "", err
	}
	return string(evidenceBytes), nil
}

// classifyTaintFinding determines the vulnerability type, severity, and CWE based on the sink and probe type.
func (r *ContextReporter) classifyTaintFinding(finding taint.CorrelatedFinding) (string, schemas.Severity, string) {
	// Confirmed execution findings take precedence.
	if finding.Sink == schemas.SinkExecution {
		return r.classifyConfirmedExecution(finding)
	}

	// Classify potential (unconfirmed) findings based on the sink reached.
	switch finding.Sink {
	case schemas.SinkInnerHTML, schemas.SinkOuterHTML, schemas.SinkDocumentWrite, schemas.SinkIframeSrcDoc:
		return "DOM-Based Cross-Site Scripting (Potential)", schemas.SeverityHigh, "CWE-79"

	case schemas.SinkEval, schemas.SinkFunctionConstructor:
		return "Client-Side Code Injection (Potential)", schemas.SeverityHigh, "CWE-94"

	case schemas.SinkScriptSrc, schemas.SinkIframeSrc:
		return "Tainted Resource Loading (Potential XSS/Injection)", schemas.SeverityHigh, "CWE-829"

	case schemas.SinkNavigation:
		// Navigation sinks can be XSS if the probe type suggests it (e.g., javascript: URLs).
		if finding.Probe.Type == schemas.ProbeTypeXSS || finding.Probe.Type == schemas.ProbeTypeSSTI {
			return "DOM-Based Cross-Site Scripting (Navigation) (Potential)", schemas.SeverityHigh, "CWE-79"
		}
		// Otherwise, it's likely an Open Redirect or data leakage via URL parameters.
		return "Open Redirect / Data Leakage (Potential)", schemas.SeverityMedium, "CWE-601"

	case schemas.SinkFetch, schemas.SinkFetchURL, schemas.SinkWebSocketSend, schemas.SinkXMLHTTPRequest, schemas.SinkXMLHTTPRequestURL, schemas.SinkSendBeacon:
		// Data reaching outbound communication sinks indicates potential exfiltration.
		return "Data Exfiltration / Information Disclosure (Potential)", schemas.SeverityMedium, "CWE-200"

	default:
		// Default classification for unknown or less severe taint flows.
		return "Unclassified Taint Flow", schemas.SeverityInformational, "CWE-20" // CWE-20: Improper Input Validation
	}
}

// classifyConfirmedExecution handles findings where code execution was confirmed (e.g., via OAST callback or alert()).
func (r *ContextReporter) classifyConfirmedExecution(finding taint.CorrelatedFinding) (string, schemas.Severity, string) {
	// Classification is primarily based on the type of probe that successfully executed.
	switch finding.Probe.Type {
	case schemas.ProbeTypeXSS, schemas.ProbeTypeDOMClobbering:
		return "Confirmed Cross-Site Scripting", schemas.SeverityCritical, "CWE-79"

	case schemas.ProbeTypeSSTI:
		// SSTI often leads to XSS in a browser context.
		return "Confirmed SSTI leading to XSS", schemas.SeverityCritical, "CWE-1336" // CWE-1336: Improper Neutralization of JavaScript in Templates

	case schemas.ProbeTypeSQLi:
		// Reflected SQLi manifesting as XSS.
		return "Confirmed Reflected SQLi leading to XSS", schemas.SeverityCritical, "CWE-89"

	case schemas.ProbeTypeCmdInjection:
		// Reflected Command Injection manifesting as XSS.
		return "Confirmed Reflected Command Injection leading to XSS", schemas.SeverityCritical, "CWE-78"

	default:
		return "Confirmed Code Execution", schemas.SeverityCritical, "CWE-94" // CWE-94: Code Injection
	}
}

// getRecommendation provides remediation advice based on the vulnerability type.
func (r *ContextReporter) getRecommendation(vulnType string) string {
	// Provide specific advice for common vulnerability classes.
	if strings.Contains(vulnType, "Cross-Site Scripting") || strings.Contains(vulnType, "XSS") {
		return "Implement context-aware output encoding (e.g., using DOMPurify) before inserting data into the DOM. Prefer safe sinks like 'textContent' over dangerous ones like 'innerHTML'. Implement a strong Content Security Policy (CSP) to mitigate the impact of XSS."
	}
	if strings.Contains(vulnType, "Code Injection") {
		return "Avoid using functions like 'eval()' or the 'Function' constructor with user-controlled input. If dynamic code execution is necessary, strictly validate and sanitize the input against a whitelist."
	}
	if strings.Contains(vulnType, "Open Redirect") {
		return "Validate all redirection URLs. Ensure they point to trusted domains or relative paths within the application. Avoid using user input directly in navigation APIs."
	}
	if strings.Contains(vulnType, "SSTI") {
		return "Ensure the client-side templating engine is configured securely. Sanitize template input or use sandboxing features if available. Avoid rendering user-provided strings as templates."
	}
	if strings.Contains(vulnType, "Information Disclosure") || strings.Contains(vulnType, "Exfiltration") {
		return "Review data flows to outbound communication channels (Fetch, XHR, WebSockets). Ensure that sensitive information is not leaked to unauthorized parties. Implement appropriate CORS policies."
	}

	// Generic recommendation
	return "Validate and sanitize all user input at the source and apply appropriate encoding/escaping before use in sensitive sinks."
}
