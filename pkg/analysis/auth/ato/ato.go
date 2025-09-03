// -- pkg/analysis/auth/ato/ato.go --
package ato

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// A default list of weak passwords to check for if none are provided in config.
var defaultWeakPasswords = []string{"password", "123456", "admin", "qwerty", "12345678", "welcome", "12345"}

// ATOAnalyzer performs passive analysis for ATO risks on observed traffic.
// It is now architecturally aware and uses the main application configuration.
type ATOAnalyzer struct {
	config config.ATOConfig
}

// NewATOAnalyzer creates a new passive ATOAnalyzer.
// It accepts the active ATO configuration to reuse username/password field definitions.
func NewATOAnalyzer(cfg config.ATOConfig) *ATOAnalyzer {
	// If the user hasn't provided a password list for active spraying,
	// we'll use a basic default list for our passive check.
	if len(cfg.PasswordSprayWordlist) == 0 {
		cfg.PasswordSprayWordlist = defaultWeakPasswords
	}
	// Similarly, if field names aren't defined, use some sensible defaults.
	if len(cfg.UsernameFields) == 0 {
		cfg.UsernameFields = []string{"username", "email", "user", "login", "user_id"}
	}
	if len(cfg.PasswordFields) == 0 {
		cfg.PasswordFields = []string{"password", "pass", "pwd", "secret", "passwd", "user_pass"}
	}

	return &ATOAnalyzer{config: cfg}
}

// Analyze checks for potential Account Takeover vulnerabilities based on passive observation.
func (a *ATOAnalyzer) Analyze(req *http.Request, resp *http.Response) ([]schemas.Finding, error) {
	var vulnerabilities []schemas.Finding

	createFinding := func(vulnType, severity, description, cwe string) schemas.Finding {
		targetURL := "unknown"
		if req != nil && req.URL != nil {
			targetURL = req.URL.String()
		}
		return schemas.Finding{
			ID:            uuid.NewString(),
			Timestamp:     time.Now().UTC(),
			Target:        targetURL,
			Module:        "ATOAnalyzer (Passive)",
			Vulnerability: vulnType,
			Severity:      severity,
			Description:   description,
			CWE:           cwe,
		}
	}

	// Check for weak credentials in transit (Passive observation)
	if req != nil && req.Method == "POST" && isLoginEndpoint(req.URL.Path) {
		bodyBytes, _ := readRequestBody(req)

		// This logic intelligently parses the request body using the configured field names.
		if password, found := a.extractPasswordFromRequest(req, bodyBytes); found {
			for _, weakPass := range a.config.PasswordSprayWordlist {
				if password == weakPass {
					vulnerabilities = append(vulnerabilities, createFinding(
						"Weak Credentials Observed in Transit",
						"Low", // Severity is low because we don't know if they were accepted.
						fmt.Sprintf("The application transmitted a known weak password ('%s') during an authentication attempt.", weakPass),
						"CWE-521", // Weak Password Requirements
					))
					break // Found a weak password, no need to check others.
				}
			}
		}
	}

	// Check for predictable password recovery tokens
	if req != nil && isPasswordResetEndpoint(req.URL.Path) {
		token := req.URL.Query().Get("token")
		if token == "" {
			token = req.URL.Query().Get("reset_token")
		}

		if len(token) > 0 {
			if len(token) < 20 {
				vulnerabilities = append(vulnerabilities, createFinding(
					"Potentially Predictable Password Recovery Token (Short Length)",
					"Medium",
					"The password recovery token is short (less than 20 characters) and may be susceptible to brute-force attacks.",
					"CWE-330",
				))
			}

			entropy := calculateShannonEntropy(token)
			if entropy < 3.0 {
				vulnerabilities = append(vulnerabilities, createFinding(
					"Potentially Predictable Password Recovery Token (Low Entropy)",
					"Medium",
					fmt.Sprintf("The password recovery token has low entropy (%.2f bits/character), suggesting it may be predictable.", entropy),
					"CWE-330",
				))
			}
		}
	}

	return vulnerabilities, nil
}

// extractPasswordFromRequest parses the request body based on Content-Type
// and looks for common password field names from the analyzer's config.
func (a *ATOAnalyzer) extractPasswordFromRequest(req *http.Request, bodyBytes []byte) (string, bool) {
	if len(bodyBytes) == 0 {
		return "", false
	}

	contentType := req.Header.Get("Content-Type")
	passwordFields := a.config.PasswordFields

	// Use an if/else if structure to ensure content type handlers are mutually exclusive.
	if strings.Contains(contentType, "application/json") {
		var data map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &data); err != nil {
			return "", false // Not valid JSON
		}

		for key, value := range data {
			lowerKey := strings.ToLower(key)
			for _, fieldName := range passwordFields {
				if lowerKey == fieldName {
					if password, ok := value.(string); ok {
						return password, true
					}
				}
			}
		}
	} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		// Handle form-urlencoded bodies
		values, err := url.ParseQuery(string(bodyBytes))
		if err != nil {
			return "", false // Malformed query string
		}

		for _, fieldName := range passwordFields {
			if password := values.Get(fieldName); password != "" {
				return password, true
			}
		}
	}

	return "", false
}

func isLoginEndpoint(path string) bool {
	p := strings.ToLower(path)
	keywords := []string{"login", "auth", "signin", "session", "authenticate"}
	for _, keyword := range keywords {
		if strings.Contains(p, keyword) {
			return true
		}
	}
	return false
}

func isPasswordResetEndpoint(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "reset-password") || strings.Contains(p, "forgotpassword") || strings.Contains(p, "recover")
}

// readRequestBody safely reads the request body without consuming it permanently.
func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	originalBody := req.Body
	defer originalBody.Close()
	const maxBodySize = 1024 * 1024 // 1MB
	bodyBytes, err := io.ReadAll(io.LimitReader(originalBody, maxBodySize))
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, err
}

// calculateShannonEntropy calculates the Shannon entropy of a string.
func calculateShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	freqMap := make(map[rune]float64)
	for _, char := range s {
		freqMap[char]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freqMap {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}


