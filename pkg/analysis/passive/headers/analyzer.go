// pkg/analysis/passive/headers/analyzer.go
package headers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// Define the minimum acceptable HSTS max-age (6 months in seconds)
const MinHstsMaxAge = 15552000

// Pre-compile regex for extracting max-age
var regexMaxAge = regexp.MustCompile(`(?i)max-age=(\d+)`)

type HeadersAnalyzer struct {
	core.BaseAnalyzer
	logger *zap.Logger
}

func NewHeadersAnalyzer(logger *zap.Logger) *HeadersAnalyzer {
	return &HeadersAnalyzer{
		BaseAnalyzer: core.NewBaseAnalyzer("Security Headers Analyzer", core.TypePassive),
		logger:       logger.Named("headers_analyzer"),
	}
}

// Analyze passively inspects HTTP response headers collected in the AnalysisContext artifacts.
func (a *HeadersAnalyzer) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	if analysisCtx.Artifacts == nil || len(analysisCtx.Artifacts.Responses) == 0 {
		return nil // No responses to analyze
	}

	for _, resp := range analysisCtx.Artifacts.Responses {
		// Ensure the request associated with the response is available.
		if resp.Request == nil {
			continue
		}

		// Security headers are most relevant for HTML content, but some apply universally.
		contentType := strings.ToLower(strings.Join(resp.Header["Content-Type"], ","))

		isHTML := strings.Contains(contentType, "text/html")
		isAPI := strings.Contains(contentType, "application/json") || strings.Contains(contentType, "application/xml")

		if isHTML || isAPI {
			parsedURL, err := url.Parse(resp.Request.URL.String())
			if err != nil {
				continue
			}
			a.checkHeaders(analysisCtx, parsedURL, resp.Header, isHTML)
		}
	}

	return nil
}

// checkHeaders evaluates the security posture based on the presence and configuration of headers.
func (a *HeadersAnalyzer) checkHeaders(analysisCtx *core.AnalysisContext, targetURL *url.URL, headers http.Header, isHTML bool) {
	urlString := targetURL.String()

	// 1. Content-Security-Policy (CSP) - Primarily relevant for HTML
	cspValues := headers.Values("Content-Security-Policy")
	cspOk := len(cspValues) > 0

	if isHTML {
		if !cspOk {
			a.createMissingHeaderFinding(analysisCtx, urlString, "Content-Security-Policy", string(core.SeverityMedium), "The CSP header is not set. This significantly increases the risk of Cross-Site Scripting (XSS) attacks.", "CWE-693")
		} else {
			a.analyzeCSP(analysisCtx, urlString, cspValues)
		}
	}

	// 2. Strict-Transport-Security (HSTS) - Relevant for all HTTPS traffic
	if strings.EqualFold(targetURL.Scheme, "https") {
		hstsValues := headers.Values("Strict-Transport-Security")
		if len(hstsValues) == 0 {
			a.createMissingHeaderFinding(analysisCtx, urlString, "Strict-Transport-Security", string(core.SeverityMedium), "The HSTS header is not set over HTTPS. This can expose users to man-in-the-middle attacks (e.g., SSL stripping).", "CWE-319")
		} else {
			a.analyzeHSTS(analysisCtx, urlString, hstsValues)
		}
	}

	// 3. X-Content-Type-Options - Relevant for all traffic
	val := headers.Get("X-Content-Type-Options")
	if strings.ToLower(val) != "nosniff" {
		a.createMissingHeaderFinding(analysisCtx, urlString, "X-Content-Type-Options", string(core.SeverityLow), "The header should be set to 'nosniff' to prevent the browser from MIME-sniffing a response away from the declared content-type.", "CWE-693")
	}

	// 4. X-Frame-Options - Primarily relevant for HTML
	if isHTML {
		if len(headers.Values("X-Frame-Options")) == 0 {
			// Check if CSP frame-ancestors is used instead.
			if !cspOk || !strings.Contains(strings.ToLower(strings.Join(cspValues, ",")), "frame-ancestors") {
				a.createMissingHeaderFinding(analysisCtx, urlString, "X-Frame-Options (or CSP frame-ancestors)", string(core.SeverityMedium), "Neither X-Frame-Options nor CSP frame-ancestors are set. This may allow the page to be rendered in a frame, leading to Clickjacking attacks.", "CWE-1021")
			}
		}
	}

	// 5. Referrer-Policy
	if len(headers.Values("Referrer-Policy")) == 0 {
		a.createMissingHeaderFinding(analysisCtx, urlString, "Referrer-Policy", string(core.SeverityLow), "The Referrer-Policy header is missing. This controls how much referrer information (URL) is included with requests.", "CWE-200")
	}

	// 6. Permissions-Policy / Feature-Policy
	if isHTML {
		if len(headers.Values("Permissions-Policy")) == 0 {
			if len(headers.Values("Feature-Policy")) == 0 {
				a.createMissingHeaderFinding(analysisCtx, urlString, "Permissions-Policy", string(core.SeverityInfo), "The Permissions-Policy (formerly Feature-Policy) header is missing. This header allows control over which browser features and APIs can be used.", "CWE-693")
			}
		}
	}

	// 7. Information leakage
	a.checkInformationLeakage(analysisCtx, urlString, headers, "Server")
	a.checkInformationLeakage(analysisCtx, urlString, headers, "X-Powered-By")
}

// analyzeHSTS parses the HSTS header to ensure max-age is sufficient.
func (a *HeadersAnalyzer) analyzeHSTS(analysisCtx *core.AnalysisContext, targetURL string, hstsValues []string) {
	hstsValue := strings.Join(hstsValues, "; ")
	matches := regexMaxAge.FindStringSubmatch(hstsValue)

	if len(matches) < 2 {
		a.createWeakHeaderFinding(analysisCtx, targetURL, "Strict-Transport-Security", string(core.SeverityLow), "The HSTS header is missing the required 'max-age' directive.", hstsValue, "CWE-319")
		return
	}

	// Use ParseInt for robustness against large numbers
	maxAge64, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil {
		// If the error is ErrRange, the number is very large, which is good for HSTS.
		if errors.Is(err, strconv.ErrRange) {
			return // Value is large; HSTS is strong.
		}
		// Handle other parsing errors
		a.logger.Debug("Failed to parse HSTS max-age despite regex match", zap.Error(err), zap.String("value", matches[1]))
		return
	}
	// Ensure MinHstsMaxAge is also defined as int64 if necessary for comparison.
	maxAge := maxAge64

	if maxAge == 0 {
		a.createWeakHeaderFinding(analysisCtx, targetURL, "Strict-Transport-Security", string(core.SeverityMedium), "The HSTS 'max-age' is set to 0, effectively disabling the security mechanism.", hstsValue, "CWE-319")
	} else if maxAge < MinHstsMaxAge {
		desc := fmt.Sprintf("The HSTS 'max-age' is too short (%d seconds). It should be at least %d seconds (6 months).", maxAge, MinHstsMaxAge)
		a.createWeakHeaderFinding(analysisCtx, targetURL, "Strict-Transport-Security", string(core.SeverityLow), desc, hstsValue, "CWE-319")
	}
}

// analyzeCSP performs a basic analysis of the CSP directives for weaknesses.
func (a *HeadersAnalyzer) analyzeCSP(analysisCtx *core.AnalysisContext, targetURL string, cspValues []string) {
	cspContent := strings.Join(cspValues, ",")
	cspLower := strings.ToLower(cspContent)

	// Check 1: 'unsafe-inline' without mitigation.
	if strings.Contains(cspLower, "'unsafe-inline'") {
		hasScriptDirective := strings.Contains(cspLower, "script-src") || strings.Contains(cspLower, "default-src")
		hasMitigation := strings.Contains(cspLower, "nonce-") || strings.Contains(cspLower, "sha256-") || strings.Contains(cspLower, "'strict-dynamic'")

		if hasScriptDirective && !hasMitigation {
			a.createWeakHeaderFinding(analysisCtx, targetURL, "Content-Security-Policy", string(core.SeverityHigh), "The CSP uses 'unsafe-inline' for scripts without a corresponding nonce, hash, or 'strict-dynamic', which largely negates XSS protection.", cspContent, "CWE-693")
		}
	}

	// Check 2: 'unsafe-eval'.
	if strings.Contains(cspLower, "'unsafe-eval'") {
		a.createWeakHeaderFinding(analysisCtx, targetURL, "Content-Security-Policy", string(core.SeverityMedium), "The CSP allows 'unsafe-eval', which permits the use of eval() and similar methods, increasing the attack surface for XSS.", cspContent, "CWE-693")
	}

	// Check 3: Overly permissive sources.
	if strings.Contains(cspContent, "*") || strings.Contains(cspLower, "data:") || strings.Contains(cspLower, "http:") {
		a.createWeakHeaderFinding(analysisCtx, targetURL, "Content-Security-Policy", string(core.SeverityMedium), "The CSP includes overly permissive sources (e.g., '*', 'data:', or 'http:'), which may allow loading untrusted content.", cspContent, "CWE-693")
	}
}

func (a *HeadersAnalyzer) checkInformationLeakage(analysisCtx *core.AnalysisContext, targetURL string, headers http.Header, headerName string) {
	values := headers.Values(headerName)
	if len(values) > 0 && values[0] != "" {
		value := strings.Join(values, ", ")
		// Simple heuristic: check if the value contains version numbers (dots or slashes)
		if len(value) > 5 && (strings.Contains(value, ".") || strings.Contains(value, "/")) {
			desc := fmt.Sprintf("The server is disclosing software/framework information via the '%s' header (%s).", headerName, value)
			a.createWeakHeaderFinding(analysisCtx, targetURL, headerName, string(core.SeverityInfo), desc, value, "CWE-200")
		}
	}
}

// Helper function for missing headers.
func (a *HeadersAnalyzer) createMissingHeaderFinding(analysisCtx *core.AnalysisContext, targetURL, headerName, severity, description, cwe string) {
	evidence, _ := json.Marshal(map[string]string{
		"header": headerName,
		"status": "Missing",
		"url":    targetURL,
	})

	finding := schemas.Finding{
		ID:             uuid.New().String(),
		Timestamp:      time.Now().UTC(),
		Target:         targetURL,
		Module:         a.Name(),
		Vulnerability:  fmt.Sprintf("Missing Security Header: %s", headerName),
		Severity:       severity,
		Description:    description,
		Evidence:       evidence,
		Recommendation: fmt.Sprintf("Ensure the '%s' header is configured and returned in the HTTP response.", headerName),
		CWE:            cwe,
	}
	analysisCtx.AddFinding(finding)

	// Log actionable findings
	if severity == string(core.SeverityHigh) || severity == string(core.SeverityMedium) {
		a.logger.Warn("Missing Security Header", zap.String("header", headerName), zap.String("url", targetURL))
	}
}

// Helper function for weak or misconfigured headers.
func (a *HeadersAnalyzer) createWeakHeaderFinding(analysisCtx *core.AnalysisContext, targetURL, headerName, severity, description, headerValue, cwe string) {
	evidence, _ := json.Marshal(map[string]string{
		"header": headerName,
		"status": "Weak or Misconfigured",
		"value":  headerValue,
		"url":    targetURL,
	})

	finding := schemas.Finding{
		ID:             uuid.New().String(),
		Timestamp:      time.Now().UTC(),
		Target:         targetURL,
		Module:         a.Name(),
		Vulnerability:  fmt.Sprintf("Weak Security Header Configuration: %s", headerName),
		Severity:       severity,
		Description:    description,
		Evidence:       evidence,
		Recommendation: "Review and strengthen the configuration of this security header.",
		CWE:            cwe,
	}
	analysisCtx.AddFinding(finding)

	// Log actionable findings
	if severity == string(core.SeverityHigh) || severity == string(core.SeverityMedium) {
		a.logger.Warn("Weak Security Header Configuration", zap.String("header", headerName), zap.String("url", targetURL))
	}
}
