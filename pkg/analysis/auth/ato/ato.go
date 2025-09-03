// pkg/analysis/auth/ato/ato.go
package ato

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/pkg/schemas"
)

// ATOAnalyzer performs passive analysis for ATO risks on observed traffic.
type ATOAnalyzer struct {
	// Configuration can be added here if needed.
}

// NewATOAnalyzer creates a new ATOAnalyzer.
func NewATOAnalyzer() *ATOAnalyzer {
	return &ATOAnalyzer{}
}

// Analyze checks for potential Account Takeover vulnerabilities based on passive observation.
func (a *ATOAnalyzer) Analyze(req *http.Request, resp *http.Response) ([]schemas.Finding, error) {
	var vulnerabilities []schemas.Finding

	// A helper function to create findings consistently.
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

	// Check for weak credentials (Passive observation)
	if req != nil && req.Method == "POST" && isLoginEndpoint(req.URL.Path) {
		// Completed placeholder logic: Read the request body safely.
		bodyBytes, err := readRequestBody(req)
		if err == nil && len(bodyBytes) > 0 {
			body := string(bodyBytes)
			// Basic checks for common weak credentials.
			weakPasswords := []string{"password", "123456", "admin", "qwerty"}
			for _, weakPass := range weakPasswords {
				if strings.Contains(body, "password="+weakPass) || strings.Contains(body, `"`+weakPass+`"`) {
					vulnerabilities = append(vulnerabilities, createFinding(
						"Weak Credentials Observed in Transit",
						"Low", // Severity is low because we don't know if they were accepted.
						"The application transmitted common or weak credentials during an authentication attempt.",
						"CWE-521", // Weak Password Requirements
					))
					break
				}
			}
		}
	}

	/*
	 * REVISION: Removed Passive Rate Limiting Check.
	 * Observing a single failed login (4xx) without a 429 status is unreliable for detecting missing rate limiting 
	 * in a passive context and generates excessive noise. Active testing handles this better.
	 */

	// Check for predictable password recovery tokens
	if req != nil && isPasswordResetEndpoint(req.URL.Path) {
		token := req.URL.Query().Get("token")
		if token == "" {
			token = req.URL.Query().Get("reset_token")
		}

		if len(token) > 0 {
			// Check 1: Length
			if len(token) < 20 {
				vulnerabilities = append(vulnerabilities, createFinding(
					"Potentially Predictable Password Recovery Token (Short Length)",
					"Medium",
					"The password recovery token is short (less than 20 characters) and may be susceptible to brute-force attacks.",
					"CWE-330", // Insufficient Entropy
				))
			}

			// Check 2: Entropy (REVISION: Added entropy check)
			entropy := calculateShannonEntropy(token)
			// A threshold of 3.0 is often used as a minimum for secure tokens.
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

// Helper to safely read the request body without consuming it permanently.
func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	// Limit reading to prevent excessive memory usage
	const maxBodySize = 1024 * 1024 // 1MB
	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize))
	if err != nil {
		return nil, err
	}
	// Restore the body so it can be read again by other components.
	req.Body.Close() // Close the original body
	req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	return bodyBytes, nil
}

// calculateShannonEntropy calculates the Shannon entropy of a string.
func calculateShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	
	// Count frequency of each character
	freqMap := make(map[rune]float64)
	for _, char := range s {
		// Assuming case-sensitive tokens.
		freqMap[unicode.ToLower(char)]++
	}

	var entropy float64
	length := float64(len(s))

	// Calculate entropy: H = -sum(p_i * log2(p_i))
	for _, count := range freqMap {
		probability := count / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}
