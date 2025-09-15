// internal/analysis/static/jwt/analyzer.go
package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// JWTAnalyzer implements the core.Analyzer interface for static analysis of JWTs.
type JWTAnalyzer struct {
	// The embedded core.BaseAnalyzer has been removed in favor of direct
	// implementation of the core.Analyzer interface.
	logger            *zap.Logger
	bruteForceEnabled bool
}

// Regex to identify potential JWTs: header.payload.signature.
// It requires segments to be at least 10 chars long to reduce false positives.
var jwtRegex = regexp.MustCompile(`\b([A-Za-z0-9\-_]{10,})\.([A-Za-z0-9\-_]{10,})\.([A-Za-z0-9\-_]*)\b`)

// NewJWTAnalyzer no longer needs to create a BaseAnalyzer.
func NewJWTAnalyzer(logger *zap.Logger, bruteForceEnabled bool) *JWTAnalyzer {
	return &JWTAnalyzer{
		logger:            logger.Named("jwt_analyzer"),
		bruteForceEnabled: bruteForceEnabled,
	}
}

// Name returns the static name of the analyzer.
func (a *JWTAnalyzer) Name() string {
	return "JWT Static Analyzer"
}

// Description provides a brief summary of the analyzer's purpose.
func (a *JWTAnalyzer) Description() string {
	return "Scans HTTP traffic for common JWT vulnerabilities."
}

// Type returns the category of the analyzer.
func (a *JWTAnalyzer) Type() core.AnalyzerType {
	return core.TypePassive
}

// Analyze scans the AnalysisContext artifacts for JWTs and analyzes them.
func (a *JWTAnalyzer) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	if analysisCtx.Artifacts == nil || analysisCtx.Artifacts.HAR == nil {
		return nil // Nothing to analyze
	}

	analyzedTokens := make(map[string]bool)

	// Iterate through the HAR log entries, which contain both request and response data.
	for _, entry := range analysisCtx.Artifacts.HAR.Log.Entries {
		a.extractAndAnalyze(analysisCtx, &entry.Request, &entry.Response, analyzedTokens)
	}

	return nil
}

// extractAndAnalyze finds tokens in the HTTP request/response pair and analyzes them.
func (a *JWTAnalyzer) extractAndAnalyze(analysisCtx *core.AnalysisContext, req *schemas.Request, resp *schemas.Response, analyzedTokens map[string]bool) {
	targetURL := req.URL

	// -- Extraction --
	tokens := make(map[string]string) // Map of Token -> Location Found

	// A. Request Headers & Cookies
	extractFromNVPairs(req.Headers, tokens, "Request Header")
	extractFromNVPairs(req.Cookies, tokens, "Request Cookie")

	// B. Request URL
	if match := jwtRegex.FindString(req.URL); match != "" {
		tokens[match] = "Request URL"
	}

	// C. Request Body
	if req.PostData != nil && req.PostData.Text != "" {
		bodyBytes := []byte(req.PostData.Text)
		if strings.Contains(req.PostData.MimeType, "application/json") {
			extractFromJSONBody(bodyBytes, tokens, "Request Body")
		} else {
			byteMatches := jwtRegex.FindAll(bodyBytes, -1)
			for _, match := range byteMatches {
				tokens[string(match)] = "Request Body"
			}
		}
	}

	// D. Response Headers & Body (if available)
	if resp != nil {
		extractFromNVPairs(resp.Headers, tokens, "Response Header")
		extractFromNVPairs(resp.Cookies, tokens, "Response Cookie")
		if strings.Contains(resp.Content.MimeType, "application/json") {
			extractFromJSONBody([]byte(resp.Content.Text), tokens, "Response Body")
		} else {
			byteMatches := jwtRegex.FindAll([]byte(resp.Content.Text), -1)
			for _, byteMatch := range byteMatches {
				tokens[string(byteMatch)] = "Response Body"
			}
		}
	}

	// -- Analysis --
	for tokenString, location := range tokens {
		// Skip tokens we've already processed to avoid duplicate findings.
		if analyzedTokens[tokenString] {
			continue
		}
		analyzedTokens[tokenString] = true

		result, err := AnalyzeToken(tokenString, a.bruteForceEnabled)
		if err != nil {
			// An error here likely means it wasn't a valid JWT, so we can ignore it.
			continue
		}

		for _, finding := range result.Findings {
			a.reportFinding(analysisCtx, targetURL, location, tokenString, finding)
		}
	}
}

// extractFromNVPairs is a helper that works with the Name-Value Pair
// structure found in the HAR schema for headers and cookies.
func extractFromNVPairs(pairs []schemas.NVPair, tokens map[string]string, locationPrefix string) {
	for _, pair := range pairs {
		// Check for Bearer tokens specifically.
		if strings.EqualFold(pair.Name, "Authorization") {
			if len(pair.Value) > 7 && strings.EqualFold(pair.Value[:7], "bearer ") {
				token := strings.TrimSpace(pair.Value[7:])
				if jwtRegex.MatchString(token) {
					tokens[token] = fmt.Sprintf("%s: Authorization Bearer", locationPrefix)
					continue // Skip generic check if we found a bearer token.
				}
			}
		}

		// General regex search on header/cookie values.
		matches := jwtRegex.FindAllString(pair.Value, -1)
		for _, match := range matches {
			tokens[match] = fmt.Sprintf("%s: %s", locationPrefix, pair.Name)
		}
	}
}

// extractFromJSONBody uses a streaming decoder to efficiently find JWTs in JSON.
func extractFromJSONBody(body []byte, tokens map[string]string, location string) {
	if len(body) == 0 {
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	for {
		t, err := decoder.Token()
		if err == io.EOF {
			break // End of JSON document.
		}
		if err != nil {
			return // Malformed JSON.
		}

		// Check if the JSON token is a string that looks like a JWT.
		if str, ok := t.(string); ok {
			if len(str) > 22 && jwtRegex.MatchString(str) {
				tokens[str] = location
			}
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

	// Safely marshal evidence, with a fallback for errors.
	evidenceBytes, err := json.Marshal(evidenceData)
	if err != nil {
		a.logger.Error("Failed to marshal JWT evidence", zap.Error(err))
		evidenceBytes = []byte(fmt.Sprintf(`{"error": "failed to marshal evidence: %v"}`, err))
	}

	var cwe string
	switch finding.Type {
	case AlgNoneVulnerability:
		cwe = "CWE-347" // Improper Verification of Cryptographic Signature
	case WeakSecretVulnerability:
		cwe = "CWE-326" // Inadequate Encryption Strength
	case SensitiveInfoExposure:
		cwe = "CWE-200" // Exposure of Sensitive Information to an Unauthorized Actor
	default:
		cwe = "CWE-345" // Insufficient Verification of Data Authenticity
	}

	schemaFinding := schemas.Finding{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Target:    targetURL,
		Module:    a.Name(),
		Vulnerability: schemas.Vulnerability{
			Name: "JWT Misconfiguration",
		},
		Severity:       schemas.Severity(finding.Severity),
		Description:    finding.Description,
		Evidence:       string(evidenceBytes),
		Recommendation: "Review JWT implementation: enforce strong algorithms (e.g., RS256), use strong, non-guessable secrets, ensure every token has an expiration claim ('exp'), and avoid including sensitive data in claims.",
		CWE:            []string{cwe},
	}
	analysisCtx.AddFinding(schemaFinding)
}

// min is a helper function to find the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
