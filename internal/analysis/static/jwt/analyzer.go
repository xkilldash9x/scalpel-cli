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

// JWTAnalyzer is a passive analyzer that scans HTTP traffic for JSON Web Tokens
// (JWTs) and checks them for common vulnerabilities, such as the use of weak
// secrets or the "none" algorithm.
type JWTAnalyzer struct {
	logger            *zap.Logger
	bruteForceEnabled bool
}

// A more robust regex for finding JWTs. It removes the restrictive word boundaries
// and length checks, which were causing issues with certain token formats.
var jwtRegex = regexp.MustCompile(`([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]+)\.([A-Za-z0-9\-_]*)`)

// NewJWTAnalyzer creates a new instance of the JWTAnalyzer.
func NewJWTAnalyzer(logger *zap.Logger, bruteForceEnabled bool) *JWTAnalyzer {
	return &JWTAnalyzer{
		logger:            logger.Named("jwt_analyzer"),
		bruteForceEnabled: bruteForceEnabled,
	}
}

// Name returns the unique name of the analyzer.
func (a *JWTAnalyzer) Name() string {
	return "JWT Static Analyzer"
}

// Description provides a brief explanation of what the analyzer does.
func (a *JWTAnalyzer) Description() string {
	return "Scans HTTP traffic for common JWT vulnerabilities."
}

// Type returns the type of the analyzer, which is `core.TypePassive` for JWT analysis.
func (a *JWTAnalyzer) Type() core.AnalyzerType {
	return core.TypePassive
}

// Analyze is the main entry point for the JWT analysis. It extracts JWTs from
// the HAR artifact and analyzes each unique token for potential vulnerabilities.
func (a *JWTAnalyzer) Analyze(ctx context.Context, analysisCtx *core.AnalysisContext) error {
	if analysisCtx.Artifacts == nil || analysisCtx.Artifacts.HAR == nil {
		return nil
	}
	var harData schemas.HAR
	if err := json.Unmarshal(*analysisCtx.Artifacts.HAR, &harData); err != nil {
		a.logger.Error("Failed to unmarshal HAR data for JWT analysis", zap.Error(err))
		return fmt.Errorf("failed to unmarshal HAR data: %w", err)
	}

	analyzedTokens := make(map[string]bool)
	for _, entry := range harData.Log.Entries {
		a.extractAndAnalyze(analysisCtx, &entry.Request, &entry.Response, analyzedTokens)
	}
	return nil
}

func (a *JWTAnalyzer) extractAndAnalyze(analysisCtx *core.AnalysisContext, req *schemas.Request, resp *schemas.Response, analyzedTokens map[string]bool) {
	targetURL := req.URL
	tokens := make(map[string]string)

	extractFromNVPairs(req.Headers, tokens, "Request Header")
	extractFromNVPairs(convertCookiesToNVPairs(req.Cookies), tokens, "Request Cookie")
	if match := jwtRegex.FindString(req.URL); match != "" {
		tokens[match] = "Request URL"
	}
	if req.PostData != nil && req.PostData.Text != "" {
		extractFromJSONBody([]byte(req.PostData.Text), tokens, "Request Body")
	}
	if resp != nil {
		extractFromNVPairs(resp.Headers, tokens, "Response Header")
		extractFromNVPairs(convertCookiesToNVPairs(resp.Cookies), tokens, "Response Cookie")
		extractFromJSONBody([]byte(resp.Content.Text), tokens, "Response Body")
	}

	for tokenString, location := range tokens {
		if analyzedTokens[tokenString] {
			continue
		}
		analyzedTokens[tokenString] = true
		result, err := AnalyzeToken(tokenString, a.bruteForceEnabled)
		if err != nil {
			a.logger.Debug("Could not analyze potential JWT", zap.Error(err), zap.String("location", location))
			continue
		}
		for _, finding := range result.Findings {
			a.reportFinding(analysisCtx, targetURL, location, tokenString, finding)
		}
	}
}

func convertCookiesToNVPairs(cookies []schemas.HARCookie) []schemas.NVPair {
	if cookies == nil {
		return nil
	}
	nvPairs := make([]schemas.NVPair, len(cookies))
	for i, cookie := range cookies {
		nvPairs[i] = schemas.NVPair{Name: cookie.Name, Value: cookie.Value}
	}
	return nvPairs
}

func extractFromNVPairs(pairs []schemas.NVPair, tokens map[string]string, locationPrefix string) {
	for _, pair := range pairs {
		if strings.EqualFold(pair.Name, "Authorization") && len(pair.Value) > 7 && strings.EqualFold(pair.Value[:7], "bearer ") {
			token := strings.TrimSpace(pair.Value[7:])
			if jwtRegex.MatchString(token) {
				tokens[token] = fmt.Sprintf("%s: Authorization Bearer", locationPrefix)
				continue
			}
		}
		for _, match := range jwtRegex.FindAllString(pair.Value, -1) {
			tokens[match] = fmt.Sprintf("%s: %s", locationPrefix, pair.Name)
		}
	}
}

func extractFromJSONBody(body []byte, tokens map[string]string, location string) {
	if len(body) == 0 {
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	for {
		t, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
		if str, ok := t.(string); ok {
			if len(str) > 22 && jwtRegex.MatchString(str) {
				tokens[str] = location
			}
		}
	}
}

func (a *JWTAnalyzer) reportFinding(analysisCtx *core.AnalysisContext, targetURL, location, tokenString string, finding Finding) {
	evidenceData := map[string]interface{}{
		"location":     location,
		"token_prefix": tokenString[:min(len(tokenString), 50)] + "...",
		"detail":       finding.Description,
	}

	if finding.Detail != nil {
		for k, v := range finding.Detail {
			evidenceData[k] = v
		}
	}

	// The marshal error is intentionally ignored here for brevity in this analyzer.
	// A production system might handle this more gracefully.
	evidenceBytes, _ := json.Marshal(evidenceData)

	var vulnName, cwe string
	switch finding.Type {
	case AlgNoneVulnerability:
		vulnName = "Unsecured JWT (None Algorithm)"
		cwe = "CWE-347"
	case WeakSecretVulnerability:
		vulnName = "Weak JWT Signing Key (Brute-Forced)"
		cwe = "CWE-326"
	case SensitiveInfoExposure:
		vulnName = "Sensitive Data in JWT Claims"
		cwe = "CWE-200"
	default:
		vulnName = "JWT Misconfiguration"
		cwe = "CWE-345"
	}

	schemaFinding := schemas.Finding{
		ID:     uuid.New().String(),
		// REFACTOR: Changed Timestamp to ObservedAt
		ObservedAt: time.Now().UTC(),
		Target:     targetURL,
		Module:     a.Name(),
		// REFACTOR: Flattened Vulnerability struct
		VulnerabilityName: vulnName,
		Severity:          schemas.Severity(finding.Severity),
		Description:       finding.Description,
		// REFACTOR: Assign raw bytes (json.RawMessage) instead of string
		Evidence:       evidenceBytes,
		Recommendation: "Review JWT implementation: enforce strong algorithms (e.g., RS256), use strong secrets, ensure tokens have an expiration ('exp'), and avoid placing sensitive data in claims.",
		CWE:            []string{cwe},
	}
	analysisCtx.AddFinding(schemaFinding)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
