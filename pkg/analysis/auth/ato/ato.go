// -- pkg/analysis/auth/ato/ato.go --
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
type ATOAnalyzer struct{}

// NewATOAnalyzer creates a new ATOAnalyzer.
func NewATOAnalyzer() *ATOAnalyzer {
	return &ATOAnalyzer{}
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
		bodyBytes, err := readRequestBody(req)
		// We proceed even if there was a partial read error.
		if err == nil && len(bodyBytes) > 0 {
			body := string(bodyBytes)
			// TODO: This is a fragile heuristic. For better accuracy, this should
			// parse the body based on Content-Type (JSON, form-urlencoded) and
			// inspect the values of specific known password fields.
			weakPasswords := []string{"password", "123456", "admin", "qwerty"}
			for _, weakPass := range weakPasswords {
				if strings.Contains(body, "password="+weakPass) || strings.Contains(body, `"`+weakPass+`"`) {
					vulnerabilities = append(vulnerabilities, createFinding(
						"Weak Credentials Observed in Transit",
						"Low",
						"The application transmitted common or weak credentials during an authentication attempt.",
						"CWE-521",
					))
					break
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
	// Defer closing the original body to ensure it's always cleaned up.
	defer originalBody.Close()

	const maxBodySize = 1024 * 1024 // 1MB
	bodyBytes, err := io.ReadAll(io.LimitReader(originalBody, maxBodySize))

	// Immediately restore the body with whatever we managed to read.
	// This ensures subsequent components in the chain can still read the request.
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Return the bytes read along with any error that occurred.
	return bodyBytes, err
}

// calculateShannonEntropy calculates the Shannon entropy of a string.
func calculateShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	freqMap := make(map[rune]float64)
	for _, char := range s {
		// Tokens must be treated as case-sensitive for accurate security analysis.
		// Removing unicode.ToLower for correct entropy calculation.
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
