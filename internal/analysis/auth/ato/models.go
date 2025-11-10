// internal/analysis/auth/ato/models.go
package ato

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// LoginAttempt represents a single attempt to authenticate with a username,
// password, and an optional CSRF token.
type LoginAttempt struct {
	Username  string
	Password  string
	CSRFToken string
}

// LoginResponse encapsulates the outcome of a single login attempt, providing a
// structured analysis of the HTTP response.
type LoginResponse struct {
	Attempt           LoginAttempt
	StatusCode        int
	ResponseBody      string
	ResponseTimeMs    int64
	Success           bool // Indicates if the login was successful.
	IsLockout         bool // Indicates if the attempt triggered an account lockout.
	IsUserEnumeration bool // Indicates if the response leaks information about the user's validity.
	EnumerationDetail string
}

// AnalyzeResponse applies a set of heuristics to an HTTP response to determine
// the semantic outcome of a login attempt. It checks for success, lockout, and
// user enumeration by analyzing status codes and keywords in the response body.
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
	switch statusCode {
	case http.StatusFound, http.StatusMovedPermanently, http.StatusSeeOther:
		resp.Success = true
	case http.StatusOK:
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

// GenerateSprayingPayloads creates a strategic list of login attempts designed
// for password spraying. It pairs a list of known usernames with a curated list
// of common and seasonal weak passwords. The list is structured to iterate
// through passwords first to help evade user-specific lockout policies.
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
