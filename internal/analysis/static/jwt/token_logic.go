// internal/analysis/static/jwt/token_logic.go
package jwt

import (
	"fmt"
	"strings"

	// Using v5 of the jwt-go library is the current standard.
	"github.com/golang-jwt/jwt/v5"
	// Import the schemas package which now contains the canonical Severity type.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// FindingType defines the specific kind of JWT vulnerability found.
type FindingType int

const (
	// UnknownFinding is a default or unknown finding type.
	UnknownFinding FindingType = iota
	// AlgNoneVulnerability indicates the token uses the 'none' algorithm.
	AlgNoneVulnerability
	// WeakSecretVulnerability indicates a weak, guessable secret was used for the signature.
	WeakSecretVulnerability
	// SensitiveInfoExposure indicates sensitive keywords were found in the claims.
	SensitiveInfoExposure
	// MissingExpiration indicates the 'exp' claim is not present.
	MissingExpiration
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
	Type        FindingType
	Description string
	// Changed from core.SeverityLevel to the canonical schemas.Severity.
	Severity    schemas.Severity
}

// weakSecrets is a list of common weak secrets used for brute-forcing.
var weakSecrets = []string{
	"secret", "password", "123456", "12345678", "admin", "test", "root", "qwerty", "changeme",
	"secretkey", "jwtsecret", "mysecret", "default", "key", "privatekey", "development",
	"production", "supersecret", "password123",
}

var (
	// parserUnverified is used to inspect token contents without checking the signature.
	parserUnverified = new(jwt.Parser)

	// parserSkipClaimsValidation is used for brute-forcing secrets, ignoring things like expiration.
	parserSkipClaimsValidation = jwt.NewParser(jwt.WithoutClaimsValidation())
)

// AnalyzeToken performs static analysis and optional weak secret attacks on a JWT string.
func AnalyzeToken(tokenString string, bruteForceEnabled bool) (TokenAnalysisResult, error) {
	result := TokenAnalysisResult{
		TokenString: tokenString,
		Findings:    []Finding{},
	}

	// 1. Parse the token without verification.
	// This lets us access the content even if the signature is invalid or the token is expired.
	token, _, err := parserUnverified.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return result, fmt.Errorf("failed to parse token unverified: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		result.Claims = claims
	}
	result.Header = token.Header

	// 2. Check for 'alg: none' vulnerability.
	alg, algOk := result.Header["alg"].(string)
	if algOk && strings.EqualFold(alg, "none") {
		result.Findings = append(result.Findings, Finding{
			Type:        AlgNoneVulnerability,
			Description: "JWT uses 'alg: none'. This allows an attacker to forge valid tokens by bypassing signature verification.",
			// Use the constant from the schemas package.
			Severity:    schemas.SeverityCritical,
		})
	}

	// 3. Check for sensitive information in claims (Heuristic).
	if containsSensitiveData(result.Claims) {
		result.Findings = append(result.Findings, Finding{
			Type:        SensitiveInfoExposure,
			Description: "JWT payload contains potentially sensitive information (based on claim keywords). JWTs are typically only encoded, not encrypted.",
			// Use the constant from the schemas package.
			Severity:    schemas.SeverityMedium,
		})
	}

	// 4. Check for missing expiration (exp claim).
	if _, exists := result.Claims["exp"]; !exists {
		result.Findings = append(result.Findings, Finding{
			Type:        MissingExpiration,
			Description: "JWT does not have an expiration time ('exp' claim). Tokens should have a limited lifetime.",
			// Use the constant from the schemas package.
			Severity:    schemas.SeverityLow,
		})
	}

	// 5. Attempt weak secret brute-force (if enabled and it's a symmetric algorithm).
	if bruteForceEnabled && algOk {
		if strings.HasPrefix(alg, "HS") { // HS256, HS384, HS512
			if secret := bruteForceSecret(tokenString); secret != "" {
				result.Findings = append(result.Findings, Finding{
					Type:        WeakSecretVulnerability,
					Description: fmt.Sprintf("Weak secret found: '%s'. The token signature is valid using this common secret.", secret),
					// Use the constant from the schemas package.
					Severity:    schemas.SeverityHigh,
				})
			}
		}
	}

	return result, nil
}

// bruteForceSecret attempts to verify the token signature using a list of weak secrets.
func bruteForceSecret(tokenString string) string {
	for _, secret := range weakSecrets {
		// Attempt to parse and verify the signature with the current secret.
		token, err := parserSkipClaimsValidation.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Security Check: Ensure the signing method is HMAC.
			// This prevents "key confusion" attacks where an attacker might try to use a public key as an HMAC secret.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		})

		// If there's no error and the token is valid, we found the secret.
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
