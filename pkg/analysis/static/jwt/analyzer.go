// pkg/analysis/static/jwt/analyzer.go
package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
	"go.uber.org/zap"
)

// JWTAnalyzer implements the core.Analyzer interface for static analysis of JWTs.
type JWTAnalyzer struct {
	core.BaseAnalyzer
	logger *zap.Logger
	// Configuration options
	bruteForceEnabled bool
}

// Regex to identify potential JWTs: header.payload.signature
// Requires segments to be at least 10 chars long to reduce false positives.
var jwtRegex = regexp.MustCompile(`\b([A-Za-z0-9\-_]{10,})\.([A-Za-z0-9\-_]{10,})\.([A-Za-z0-9\-_]*)\b`)

func NewJWTAnalyzer(logger *zap.Logger, bruteForceEnabled bool) *JWTAnalyzer {
	return &JWTAnalyzer{
		BaseAnalyzer:      core.NewBaseAnalyzer("JWT Static Analyzer", core.TypeStatic),
		logger:            logger.Named("jwt_analyzer"),
		bruteForceEnabled: bruteForceEnabled,
	}
}

// Analyze scans the AnalysisContext artifacts for JWTs and analyzes them.
func (a *JWTAnalyzer) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	if analysisCtx.Artifacts == nil {
		return nil
	}

	// Use a map to track analyzed tokens to avoid redundancy.
	analyzedTokens := make(map[string]bool)

	// 1. Analyze HTTP Requests
	for _, req := range analysisCtx.Artifacts.Requests {
		a.extractAndAnalyze(analysisCtx, req, nil, analyzedTokens)
	}

	// 2. Analyze HTTP Responses
	for _, resp := range analysisCtx.Artifacts.Responses {
		// Ensure the request context is available for the response.
		if resp.Request != nil {
			a.extractAndAnalyze(analysisCtx, resp.Request, resp, analyzedTokens)
		}
	}

	return nil
}

// extractAndAnalyze finds tokens in the HTTP request/response pair and analyzes them.
func (a *JWTAnalyzer) extractAndAnalyze(analysisCtx *core.AnalysisContext, req *http.Request, resp *browser.Response, analyzedTokens map[string]bool) {
	targetURL := req.URL.String()

	// --- Extraction ---
	tokens := make(map[string]string) // Map of Token -> Location Found

	// A. Request Headers (includes Authorization Bearer and Cookies)
	extractFromHeaders(req.Header, tokens, "Request Header")

	// B. Request URL
	if match := jwtRegex.FindString(req.URL.String()); match != "" {
		tokens[match] = "Request URL"
	}

	// C. Request Body
	if req.Body != nil {
		// Handle JSON bodies specifically for robust extraction
		if strings.Contains(req.Header.Get("Content-Type"), "application/json") {
			extractFromJSONBody(req.Body, tokens, "Request Body")
		} else {
			// Fallback for other body types (e.g., form data)
			bodyBytes, _ := req.GetBody() // GetBody allows re-reading the body
			if bodyBytes != nil {
				matches := jwtRegex.FindAllString(string(bodyBytes), -1)
				for _, match := range matches {
					tokens[match] = "Request Body"
				}
			}
		}
	}

	// D. Response Headers and Body (if available)
	if resp != nil {
		extractFromHeaders(resp.Header, tokens, "Response Header") // Includes Set-Cookie
		if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
			extractFromJSONBody(resp.Body, tokens, "Response Body")
		} else {
			matches := jwtRegex.FindAllString(string(resp.Body), -1)
			for _, match := range matches {
				tokens[match] = "Response Body"
			}
		}
	}

	// -- Analysis --
	for tokenString, location := range tokens {
		if analyzedTokens[tokenString] {
			continue
		}

		// Perform the analysis using the logic from token_logic.go
		result, err := AnalyzeToken(tokenString, a.bruteForceEnabled)
		if err != nil {
			// Likely a false positive from the regex if parsing fails.
			continue
		}

		analyzedTokens[tokenString] = true

		// Report findings
		for _, finding := range result.Findings {
			a.reportFinding(analysisCtx, targetURL, location, tokenString, finding)
		}
	}
}

// extractFromHeaders searches HTTP headers for JWTs.
func extractFromHeaders(headers http.Header, tokens map[string]string, locationPrefix string) {
	for key, values := range headers {
		for _, value := range values {
			// Check for Bearer tokens specifically
			if strings.EqualFold(key, "Authorization") && strings.HasPrefix(strings.ToLower(value), "bearer ") {
				token := strings.TrimSpace(value[7:])
				if jwtRegex.MatchString(token) {
					tokens[token] = fmt.Sprintf("%s: Authorization Bearer", locationPrefix)
					continue
				}
			}

			// General regex search on header values (including Cookies/Set-Cookie)
			matches := jwtRegex.FindAllString(value, -1)
			for _, match := range matches {
				tokens[match] = fmt.Sprintf("%s: %s", locationPrefix, key)
			}
		}
	}
}

// extractFromJSONBody parses the body as JSON and recursively searches for JWTs.
func extractFromJSONBody(body []byte, tokens map[string]string, location string) {
	var data interface{}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&data); err != nil {
		return // Not valid JSON or error during decode
	}
	extractFromJSONRecursive(data, tokens, location)
}

func extractFromJSONRecursive(data interface{}, tokens map[string]string, location string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for _, value := range v {
			extractFromJSONRecursive(value, tokens, location)
		}
	case []interface{}:
		for _, value := range v {
			extractFromJSONRecursive(value, tokens, location)
		}
	case string:
		// Check if the string itself is a JWT
		if jwtRegex.MatchString(v) {
			tokens[v] = location
		}
	}
}

// reportFinding formats and adds the finding to the AnalysisContext.
func (a *JWTAnalyzer) reportFinding(analysisCtx *core.AnalysisContext, targetURL, location, tokenString string, finding Finding) {
	evidenceData := map[string]interface{}{
		"location":     location,
		"token_prefix": tokenString[:min(len(tokenString), 50)] + "...",
		"severity":     finding.Severity,
	}

	evidence, _ := json.Marshal(evidenceData)

	// Determine CWE based on the finding type
	cwe := "CWE-345" // Insufficient Verification of Data Authenticity
	if strings.Contains(finding.Description, "alg: none") {
		cwe = "CWE-347" // Improper Verification of Cryptographic Signature
	} else if strings.Contains(finding.Description, "Weak secret") {
		cwe = "CWE-326" // Inadequate Encryption Strength
	} else if strings.Contains(finding.Description, "sensitive information") {
		cwe = "CWE-200" // Exposure of Sensitive Information
	}

	schemaFinding := schemas.Finding{
		ID:             uuid.New().String(),
		Timestamp:      time.Now().UTC(),
		Target:         targetURL,
		Module:         a.Name(),
		Vulnerability:  "JWT Misconfiguration",
		Severity:       string(finding.Severity),
		Description:    finding.Description,
		Evidence:       evidence,
		Recommendation: "Review JWT implementation: enforce strong algorithms (e.g., RS256), use strong secrets, ensure expiration is set, and avoid including sensitive data in claims.",
		CWE:            cwe,
	}
	analysisCtx.AddFinding(schemaFinding)
}

// Helper function for min integer
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
