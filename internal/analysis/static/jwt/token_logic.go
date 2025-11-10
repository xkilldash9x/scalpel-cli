// internal/analysis/static/jwt/token_logic.go
package jwt

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// FindingType enumerates the specific types of JWT vulnerabilities that can be detected.
type FindingType int

const (
	UnknownFinding        FindingType = iota // An unknown or uncategorized finding.
	AlgNoneVulnerability                     // The token uses the insecure "none" algorithm.
	WeakSecretVulnerability                  // The token is signed with a weak, brute-forceable secret.
	SensitiveInfoExposure                    // The token's claims contain potentially sensitive information.
	MissingExpiration                        // The token lacks an expiration ('exp') claim.
)

// TokenAnalysisResult encapsulates the complete result of analyzing a single JWT,
// including its parsed components and a list of any findings.
type TokenAnalysisResult struct {
	TokenString string
	Header      map[string]interface{}
	Claims      jwt.MapClaims
	Findings    []Finding
}

// Finding represents a single vulnerability or misconfiguration identified within a JWT.
type Finding struct {
	Type        FindingType
	Description string
	Severity    schemas.Severity
	Detail      map[string]interface{}
}

// weakSecrets is a curated list of common, weak secrets used for signing JWTs.
var weakSecrets = []string{
	"secret", "password", "123456", "12345678", "admin", "test", "root", "qwerty", "changeme",
	"secretkey", "jwtsecret", "mysecret", "default", "key", "privatekey", "development",
	"production", "supersecret", "password123",
}

var (
	// parserUnverified is a JWT parser configured to decode tokens without
	// validating their signature. This is used for initial inspection of the
	// token's header and claims.
	parserUnverified = jwt.NewParser(
		jwt.WithoutClaimsValidation(),
		jwt.WithValidMethods([]string{"none", "HS256", "HS384", "HS512"}),
	)
)

// AnalyzeToken performs a series of security checks on a given JWT string.
// It checks for the "none" algorithm, sensitive data in claims, missing
// expiration, and, if enabled, attempts to brute-force the signature using a
// list of weak secrets.
func AnalyzeToken(tokenString string, bruteForceEnabled bool) (TokenAnalysisResult, error) {
	result := TokenAnalysisResult{
		TokenString: tokenString,
		Findings:    []Finding{},
	}

	token, _, err := parserUnverified.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return result, fmt.Errorf("failed to parse token unverified: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		result.Claims = claims
	}
	result.Header = token.Header

	alg, algOk := result.Header["alg"].(string)
	if algOk && strings.EqualFold(alg, "none") {
		result.Findings = append(result.Findings, Finding{
			Type:        AlgNoneVulnerability,
			Description: "JWT uses 'alg: none'. This allows an attacker to forge valid tokens by bypassing signature verification.",
			Severity:    schemas.SeverityCritical,
		})
	}

	if containsSensitiveData(result.Claims) {
		result.Findings = append(result.Findings, Finding{
			Type:        SensitiveInfoExposure,
			Description: "JWT payload contains potentially sensitive information (based on claim keywords). JWTs are typically only encoded, not encrypted.",
			Severity:    schemas.SeverityMedium,
		})
	}

	if _, exists := result.Claims["exp"]; !exists {
		result.Findings = append(result.Findings, Finding{
			Type:        MissingExpiration,
			Description: "JWT does not have an expiration time ('exp' claim). Tokens should have a limited lifetime.",
			Severity:    schemas.SeverityLow,
		})
	}

	if bruteForceEnabled && algOk {
		if strings.HasPrefix(alg, "HS") { // HS256, HS384, HS512
			if secret := bruteForceSecret(tokenString); secret != "" {
				result.Findings = append(result.Findings, Finding{
					Type:        WeakSecretVulnerability,
					Description: fmt.Sprintf("Weak secret found: '%s'. The token signature is valid using this common secret.", secret),
					Severity:    schemas.SeverityHigh,
					Detail:      map[string]interface{}{"key": secret},
				})
			}
		}
	}

	return result, nil
}

// bruteForceSecret creates a new parser instance locally to ensure
// it is always correctly configured and not subject to package-level state issues.
func bruteForceSecret(tokenString string) string {
	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
		jwt.WithValidMethods([]string{"HS256", "HS384", "HS512"}),
	)

	for _, secret := range weakSecrets {
		token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(secret), nil
		})

		if err == nil && token.Valid {
			return secret
		}
	}
	return ""
}

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
