// -- pkg/analysis/auth/ato/models.go --
package ato

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/xkilldash9x/scalpel-cli/pkg/analysis/core"
)

// LoginAttempt represents a single username/password combination.
type LoginAttempt struct {
	Username    string
	Password    string
	CSRFToken   string
}

// LoginResponse summarizes the result of a login attempt.
type LoginResponse struct {
	Attempt             LoginAttempt
	StatusCode          int
	ResponseBody        string
	ResponseTimeMs      int64
	Success             bool
	IsLockout           bool
	IsUserEnumeration   bool
	EnumerationDetail   string
	Evidence            *core.Evidence
}

// AnalyzeResponse interprets the HTTP response to determine the outcome of the login attempt.
func AnalyzeResponse(attempt LoginAttempt, statusCode int, responseBody string, responseTimeMs int64) LoginResponse {
	resp := LoginResponse{
		Attempt:        attempt,
		StatusCode:     statusCode,
		ResponseBody:   responseBody,
		ResponseTimeMs: responseTimeMs,
	}

	// Calculate the lowercase body once for all subsequent heuristics.
	// This prevents redundant allocations and processing.
	bodyLower := strings.ToLower(responseBody)

	// Heuristics for success:
	// 1. Redirect status codes (3xx) often indicate success.
	if statusCode == http.StatusFound || statusCode == http.StatusMovedPermanently || statusCode == http.StatusSeeOther {
		resp.Success = true
	} else if statusCode == http.StatusOK {
		// 2. Status code 200 with specific keywords (common in APIs).
		if strings.Contains(bodyLower, `"success": true`) ||
			strings.Contains(bodyLower, `"authenticated": true`) ||
			strings.Contains(bodyLower, `"token":`) ||
			strings.Contains(bodyLower, "welcome back") {
			resp.Success = true
		}
	}

	if resp.Success {
		return resp
	}

	// Heuristics for lockout:
	if statusCode == http.StatusTooManyRequests || statusCode == http.StatusLocked || statusCode == http.StatusForbidden {
		resp.IsLockout = true
	} else {
		if strings.Contains(bodyLower, "too many attempts") || strings.Contains(bodyLower, "locked out") || strings.Contains(bodyLower, "rate limit exceeded") {
			resp.IsLockout = true
		}
	}

	// Heuristics for user enumeration (verbose error messages):
	// Messages indicating invalid user
	if strings.Contains(bodyLower, "user not found") || strings.Contains(bodyLower, "invalid username") || strings.Contains(bodyLower, "email not recognized") {
		resp.IsUserEnumeration = true
		resp.EnumerationDetail = "The application disclosed that the username/email is invalid."
		// Messages indicating invalid password (implies valid user)
	} else if strings.Contains(bodyLower, "invalid password") || strings.Contains(bodyLower, "incorrect password") {
		resp.IsUserEnumeration = true
		resp.EnumerationDetail = "The application disclosed that the password was incorrect (implying the username is valid)."
	}

	return resp
}

// GenerateSprayingPayloads creates a list of login attempts for password spraying.
func GenerateSprayingPayloads(knownUsers []string) []LoginAttempt {
	// Common weak passwords for spraying.
	year := time.Now().Year()
	passwords := []string{
		"Password123!",
		"Password1!",
		"Welcome1",
		"admin",
		"password",
		"123456",
		"12345678",
		"changeme",
		// Seasonal passwords
		fmt.Sprintf("Spring%d", year),
		fmt.Sprintf("Summer%d", year),
		fmt.Sprintf("Fall%d", year),
		fmt.Sprintf("Winter%d", year),
		fmt.Sprintf("Spring%d!", year),
		fmt.Sprintf("Summer%d!", year),
		fmt.Sprintf("Fall%d!", year),
		fmt.Sprintf("Winter%d!", year),
	}

	var attempts []LoginAttempt
	// Strategy: Iterate through passwords first, then users. This helps evade user-specific lockout thresholds.
	for _, pass := range passwords {
		for _, user := range knownUsers {
			attempts = append(attempts, LoginAttempt{Username: user, Password: pass})
		}
	}
	return attempts
}
