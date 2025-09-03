// pkg/analysis/static/jwt/token_logic.go
package jwt

import (
	"fmt"
	"strings"

	// Using v5 of the jwt-go library
	"github.com/golang-jwt/jwt/v5"
	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
)

// TokenAnalysisResult holds the results of analyzing a single JWT.
type TokenAnalysisResult struct {
	TokenString string
	Header      map[string]interface{}
	Claims      jwt.MapClaims
	Findings    []Finding
}

// Finding describes a specific security issue found in a JWT.
type Finding struct {
	Description string
	Severity    core.SeverityLevel
}

// weakSecrets is a list of common weak secrets used for brute-forcing.
// Expanded list for better coverage.
var weakSecrets = []string{
	"secret", "password", "123456", "12345678", "admin", "test", "root", "qwerty", "changeme",
	"secretkey", "jwtsecret", "mysecret", "default", "key", "privatekey", "development",
	"production", "supersecret", "password123",
}

var (
	// parserUnverified is used to inspect token contents without checking the signature.
	parserUnverified = new(jwt.Parser)

	// parserSkipClaimsValidation is used for brute-forcing secrets.
	parserSkipClaimsValidation = jwt.NewParser(jwt.WithoutClaimsValidation())
)

// AnalyzeToken performs static analysis and optional weak secret attacks on a JWT string.
func AnalyzeToken(tokenString string, bruteForceEnabled bool) (TokenAnalysisResult, error) {
	result := TokenAnalysisResult{
		TokenString: tokenString,
		Findings:    []Finding{},
	}

	// 1. Parse the token without verification.
	// We use ParseUnverified to access the content even if the signature is invalid or expired.
	token, _, err := parserUnverified.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return result, fmt.Errorf("failed to parse token unverified: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		result.Claims = claims
	}
	result.Header = token.Header

	// 2. Check for 'alg: none' vulnerability (Critical).
	alg, algOk := result.Header["alg"].(string)
	if algOk && strings.EqualFold(alg, "none") {
		result.Findings = append(result.Findings, Finding{
			Description: "JWT uses 'alg: none'. This allows an attacker to forge valid tokens by bypassing signature verification.",
			Severity:    core.SeverityCritical,
		})
	}

	// 3. Check for sensitive information in claims (Heuristic).
	if containsSensitiveData(result.Claims) {
		result.Findings = append(result.Findings, Finding{
			Description: "JWT payload contains potentially sensitive information (based on claim keywords). JWTs are typically only encoded, not encrypted.",
			Severity:    core.SeverityMedium,
		})
	}

	// 4. Check for missing expiration (exp claim).
	if _, exists := result.Claims["exp"]; !exists {
		result.Findings = append(result.Findings, Finding{
			Description: "JWT does not have an expiration time ('exp' claim). Tokens should have a limited lifetime.",
			Severity:    core.SeverityLow,
		})
	}

	// 5. Attempt weak secret brute-force (if enabled and symmetric algorithm).
	if bruteForceEnabled && algOk {
		if strings.HasPrefix(alg, "HS") { // HS256, HS384, HS512
			if secret := bruteForceSecret(tokenString); secret != "" {
				result.Findings = append(result.Findings, Finding{
					Description: fmt.Sprintf("Weak secret found: '%s'. The token signature is valid using this common secret.", secret),
					Severity:    core.SeverityHigh,
				})
			}
		}
	}

	return result, nil
}

// bruteForceSecret attempts to verify the token signature using a list of weak secrets.
func bruteForceSecret(tokenString string) string {
	for _, secret := range weakSecrets {
		// Attempt to parse and verify the signature.
		token, err := parserSkipClaimsValidation.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Security Check: Ensure the signing method is HMAC.
			// This prevents "key confusion" attacks (using a public key as an HMAC secret).
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		})

		// If parsing is successful and the token is valid, the secret is correct.
		if err == nil && token.Valid {
			return secret
		}
	}
	return ""
}

// containsSensitiveData checks claims for patterns matching sensitive data using keywords.
func containsSensitiveData(claims jwt.MapClaims) bool {
	sensitiveKeywords := []string{
		"password", "pwd", "secret", "apikey", "api_key", "ssn", "creditcard",
		"privatekey", "credential", "auth_token", "access_key",
	}
	for key := range claims {
		lowerKey := strings.ToLower(key)
		for _, keyword := range sensitiveKeywords {
			if strings.Contains(lowerKey, keyword) {
				return true
			}
		}
	}
	return false
}