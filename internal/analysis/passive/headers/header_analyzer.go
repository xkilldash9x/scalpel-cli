// internal/analysis/passive/headers/analyzer.go
package headers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
	"go.uber.org/zap"
)

// -- Constants for HSTS Analysis --

// Defines the minimum acceptable HSTS max-age (6 months in seconds).
const MinHstsMaxAge = 15552000

// Pre-compiles the regex for extracting max-age from the HSTS header.
var regexMaxAge = regexp.MustCompile(`(?i)max-age=(\d+)`)

// HeadersAnalyzer is a passive analysis module that inspects HTTP response
// headers for security misconfigurations, missing protective headers, and
// information disclosure. It embeds `core.BaseAnalyzer` to satisfy the standard
// analyzer interface.
type HeadersAnalyzer struct {
	core.BaseAnalyzer
}

// NewHeadersAnalyzer creates a new instance of the HeadersAnalyzer. It sets up
// the base analyzer with its name, description, and type.
func NewHeadersAnalyzer() *HeadersAnalyzer {
	// The logger will be properly initialized when the adapter sets it up via the context.
	// A Nop logger is used as a placeholder during initial construction.
	logger := zap.NewNop()
	return &HeadersAnalyzer{
		BaseAnalyzer: *core.NewBaseAnalyzer("HeadersAnalyzer", "Analyzes security headers", core.TypePassive, logger),
	}
}

// Analyze is the main entry point for the header analysis. It extracts the HTTP
// response headers from the HAR artifact in the `AnalysisContext`, and then runs
// a series of checks for missing headers, weak configurations (like HSTS and
// CSP), and information disclosure.
func (a *HeadersAnalyzer) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	// Update the analyzer's logger to use the one from the context for rich, contextual logging.
	a.Logger = analysisCtx.Logger

	// This analyzer requires HAR artifacts to be present in the context.
	if analysisCtx.Artifacts == nil || analysisCtx.Artifacts.HAR == nil {
		a.Logger.Debug("No artifacts or HAR data available for header analysis.")
		return nil
	}

	// -- Start of Fix --
	// The HAR artifact is raw JSON, so we need to unmarshal it first.
	// We assume a `schemas.HAR` struct exists that mirrors the HAR JSON structure.
	var harData schemas.HAR
	if err := json.Unmarshal(*analysisCtx.Artifacts.HAR, &harData); err != nil {
		a.Logger.Error("Failed to unmarshal HAR data for header analysis", zap.Error(err))
		return fmt.Errorf("failed to unmarshal HAR data: %w", err)
	}
	// -- End of Fix --

	// Iterate through HAR entries to find the main document request for the target URL.
	var mainResponse *schemas.Response
	targetURL := analysisCtx.TargetURL.String()

	// -- Fix: Use the newly unmarshaled harData struct instead of analysisCtx.Artifacts.HAR --
	for i, entry := range harData.Log.Entries {
		// A simple check: if the request URL matches the target URL.
		// A more robust implementation might check for the main document frame type.
		if entry.Request.URL == targetURL {
			mainResponse = &harData.Log.Entries[i].Response
			break
		}
	}

	if mainResponse == nil {
		a.Logger.Debug("Could not find the main document response in HAR for header analysis.", zap.String("target_url", targetURL))
		return nil
	}

	// Convert HAR headers (which are a list of name-value pairs) into a map for easier lookup.
	headerMap := make(map[string]string)
	for _, h := range mainResponse.Headers {
		headerMap[strings.ToLower(h.Name)] = h.Value
	}

	// Run all specific header checks.
	a.checkMissingSecurityHeaders(analysisCtx, headerMap)
	a.checkHSTS(analysisCtx, headerMap) // HSTS gets its own detailed check.
	a.checkCSP(analysisCtx, headerMap)
	a.checkInformationDisclosure(analysisCtx, headerMap)

	return nil
}

// Defines required security headers (HSTS is handled separately) and their CWEs.
var requiredHeaders = map[string]string{
	"x-frame-options":        "CWE-1021", // Clickjacking
	"x-content-type-options": "CWE-116",  // MIME Sniffing
	"referrer-policy":        "CWE-200",  // Information Exposure
}

func (a *HeadersAnalyzer) checkMissingSecurityHeaders(analysisCtx *core.AnalysisContext, headers map[string]string) {
	for headerName, cwe := range requiredHeaders {
		if _, exists := headers[headerName]; !exists {
			a.reportMissingHeader(analysisCtx, headerName, cwe)
		}
	}
}

// performs a detailed analysis of the Strict-Transport-Security header.
func (a *HeadersAnalyzer) checkHSTS(analysisCtx *core.AnalysisContext, headers map[string]string) {
	headerName := "strict-transport-security"
	hstsValue, exists := headers[headerName]

	// Check 1: Is the header missing entirely?
	if !exists {
		a.reportMissingHeader(analysisCtx, headerName, "CWE-319")
		return
	}

	// Check 2: Does the header have a valid max-age directive?
	matches := regexMaxAge.FindStringSubmatch(hstsValue)
	if len(matches) < 2 {
		a.reportFinding(analysisCtx,
			"Weak HSTS Configuration: Missing max-age",
			schemas.SeverityLow,
			"CWE-319",
			"The Strict-Transport-Security (HSTS) header is present but is missing the required 'max-age' directive, making it ineffective.",
			fmt.Sprintf("HSTS Header Value: %s", hstsValue),
			"Ensure the HSTS header includes a 'max-age' directive with a non-zero value.",
		)
		return
	}

	// Check 3: Is the max-age value sufficiently long?
	maxAge, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		// If the number is too large to parse, that's good for HSTS. We can ignore the error.
		if errors.Is(err, strconv.ErrRange) {
			return
		}
		a.Logger.Error("Failed to parse HSTS max-age despite regex match", zap.Error(err), zap.String("value", matches[1]))
		return
	}

	if maxAge == 0 {
		a.reportFinding(analysisCtx,
			"Weak HSTS Configuration: max-age is Zero",
			schemas.SeverityMedium,
			"CWE-319",
			"The HSTS 'max-age' is set to 0, which explicitly tells browsers to disable this security mechanism.",
			fmt.Sprintf("HSTS Header Value: %s", hstsValue),
			"Set the HSTS 'max-age' to a large value, such as 31536000 (1 year).",
		)
	} else if maxAge < MinHstsMaxAge {
		desc := fmt.Sprintf("The HSTS 'max-age' is set to %d seconds, which is considered too short. It should be at least %d seconds (6 months) to be effective.", maxAge, MinHstsMaxAge)
		a.reportFinding(analysisCtx,
			"Weak HSTS Configuration: Short max-age",
			schemas.SeverityLow,
			"CWE-319",
			desc,
			fmt.Sprintf("HSTS Header Value: %s", hstsValue),
			fmt.Sprintf("Increase the HSTS 'max-age' to be at least %d.", MinHstsMaxAge),
		)
	}
}

func (a *HeadersAnalyzer) checkCSP(analysisCtx *core.AnalysisContext, headers map[string]string) {
	cspHeaderName := "content-security-policy"
	csp, exists := headers[cspHeaderName]
	if !exists {
		a.reportMissingHeader(analysisCtx, cspHeaderName, "CWE-693") // Protection Mechanism Failure
		return
	}

	// Basic CSP analysis for common weaknesses. A full CSP parser would be more robust.
	cspLower := strings.ToLower(csp)
	if strings.Contains(cspLower, "'unsafe-inline'") {
		// Rudimentary check: if 'unsafe-inline' is present without nonce/hash mitigation.
		if !strings.Contains(cspLower, "nonce-") && !strings.Contains(cspLower, "'sha") {
			a.reportFinding(analysisCtx,
				"Weak Content-Security-Policy (CSP)",
				schemas.SeverityMedium,
				"CWE-693",
				"The CSP header includes 'unsafe-inline' without a corresponding nonce or hash, which may allow execution of inline scripts and increases the risk of Cross-Site Scripting (XSS).",
				fmt.Sprintf("CSP Header Value: %s", csp),
				"Implement a strong CSP using nonces or hashes for inline scripts, or refactor inline scripts into external files.",
			)
		}
	}
}

func (a *HeadersAnalyzer) checkInformationDisclosure(analysisCtx *core.AnalysisContext, headers map[string]string) {
	disclosureHeaders := []string{"server", "x-powered-by", "x-aspnet-version"}

	for _, headerName := range disclosureHeaders {
		if value, exists := headers[headerName]; exists && value != "" {
			a.reportFinding(analysisCtx,
				"Information Disclosure in HTTP Headers",
				schemas.SeverityLow,
				"CWE-200",
				fmt.Sprintf("The '%s' header discloses technology stack or version information: '%s'. This can help attackers identify known vulnerabilities.", headerName, value),
				fmt.Sprintf("%s: %s", headerName, value),
				fmt.Sprintf("Configure the web server to suppress or obfuscate the '%s' header.", headerName),
			)
		}
	}
}

// reportMissingHeader is a helper to generate a finding specifically for a missing header.
func (a *HeadersAnalyzer) reportMissingHeader(analysisCtx *core.AnalysisContext, headerName string, cwe string) {
	// REFACTOR: Marshal string evidence to json.RawMessage
	evidenceString := fmt.Sprintf("Header not present in response: %s", headerName)
	evidencePayload := map[string]string{"details": evidenceString}
	evidenceBytes, err := json.Marshal(evidencePayload)
	if err != nil {
		a.Logger.Error("Failed to marshal evidence for missing header", zap.Error(err), zap.String("header", headerName))
		evidenceBytes = json.RawMessage(`{"error": "failed to marshal evidence"}`) // Fallback
	}

	finding := schemas.Finding{
		ID:     uuid.New().String(),
		TaskID: analysisCtx.Task.TaskID,
		// REFACTOR: Changed Timestamp to ObservedAt
		ObservedAt: time.Now().UTC(),
		Target:     analysisCtx.TargetURL.String(),
		Module:     a.Name(),
		// REFACTOR: Flattened Vulnerability struct
		VulnerabilityName: fmt.Sprintf("Missing Security Header: %s", headerName),
		Severity:          schemas.SeverityMedium,
		Description:       fmt.Sprintf("The response is missing the '%s' security header. This header is important for protecting against various web vulnerabilities.", headerName),
		// REFACTOR: Assign marshaled JSON
		Evidence:       evidenceBytes,
		Recommendation: fmt.Sprintf("Configure the web server or application framework to include the '%s' header in all relevant HTTP responses.", headerName),
		CWE:            []string{cwe},
	}
	analysisCtx.AddFinding(finding)
}

// reportFinding is a generic helper to generate a finding.
func (a *HeadersAnalyzer) reportFinding(analysisCtx *core.AnalysisContext, vulnName string, severity schemas.Severity, cwe string, description string, evidence string, recommendation string) {
	// REFACTOR: Marshal string evidence to json.RawMessage
	evidencePayload := map[string]string{"details": evidence}
	evidenceBytes, err := json.Marshal(evidencePayload)
	if err != nil {
		a.Logger.Error("Failed to marshal evidence for finding", zap.Error(err), zap.String("evidence", evidence))
		evidenceBytes = json.RawMessage(`{"error": "failed to marshal evidence"}`) // Fallback
	}

	finding := schemas.Finding{
		ID:     uuid.New().String(),
		TaskID: analysisCtx.Task.TaskID,
		// REFACTOR: Changed Timestamp to ObservedAt
		ObservedAt: time.Now().UTC(),
		Target:     analysisCtx.TargetURL.String(),
		Module:     a.Name(),
		// REFACTOR: Flattened Vulnerability struct
		VulnerabilityName: vulnName,
		Severity:          severity,
		Description:       description,
		// REFACTOR: Assign marshaled JSON
		Evidence:       evidenceBytes,
		Recommendation: recommendation,
		CWE:            []string{cwe},
	}
	analysisCtx.AddFinding(finding)
}
