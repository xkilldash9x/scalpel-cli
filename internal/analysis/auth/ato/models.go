// internal/analysis/auth/ato/models.go
package ato

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// LoginAttempt represents a single attempt to authenticate with a username,
// password, and an optional CSRF token.
type LoginAttempt struct {
	Username     string
	Password     string
	CSRFToken    string
	IsEmailBased bool // Added to track if the username is likely an email
}

// LoginResponse encapsulates the outcome of a single login attempt, providing a
// structured analysis of the HTTP response.
type LoginResponse struct {
	Attempt           LoginAttempt
	StatusCode        int
	ResponseBody      string
	ResponseTimeMs    int64
	Success           bool // Indicates if the primary credentials were valid (even if MFA is required).
	IsMFAChallenge    bool // Indicates if the successful login triggered an MFA challenge.
	IsLockout         bool // Indicates if the attempt triggered an account lockout.
	IsUserEnumeration bool // Indicates if the response leaks information about the user's validity.
	EnumerationDetail string
}

// jwtRegex is a basic regex to identify potential JWT tokens, often indicating successful authentication.
var jwtRegex = regexp.MustCompile(`[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`)

// AnalyzeResponse applies a set of heuristics to an HTTP response to determine
// the semantic outcome of a login attempt. It checks for success, lockout, MFA,
// and user enumeration by analyzing status codes and keywords in the response body.
// This function is primarily used by the simpler ATOAdapter.
func AnalyzeResponse(attempt LoginAttempt, statusCode int, responseBody string, responseTimeMs int64) LoginResponse {
	resp := LoginResponse{
		Attempt:        attempt,
		StatusCode:     statusCode,
		ResponseBody:   responseBody,
		ResponseTimeMs: responseTimeMs,
	}

	// Calculate the lowercase body once for all subsequent heuristics.
	bodyLower := strings.ToLower(responseBody)

	// Heuristics for success:
	// 1. Redirect status codes (3xx) often indicate success or moving to the next step (like MFA).
	switch statusCode {
	case http.StatusFound, http.StatusMovedPermanently, http.StatusSeeOther:
		resp.Success = true
	case http.StatusOK:
		// 2. Status code 200 with specific keywords (common in APIs).
		if strings.Contains(bodyLower, `"success": true`) ||
			strings.Contains(bodyLower, `"authenticated": true`) ||
			strings.Contains(bodyLower, "welcome back") {
			resp.Success = true
		}
		// 3. Check for presence of a token. Use regex for JWT detection for higher fidelity than just `"token":`.
		if !resp.Success && (strings.Contains(bodyLower, `"token":`) || strings.Contains(bodyLower, `"jwt":`)) {
			if jwtRegex.MatchString(responseBody) {
				resp.Success = true
			}
		}
	}

	// Heuristics for MFA Challenge (Often overlap with success indicators)
	mfaKeywords := []string{
		"verification code",
		"otp required",
		"two-factor authentication",
		"mfa required",
		"enter the code",
	}
	for _, kw := range mfaKeywords {
		if strings.Contains(bodyLower, kw) {
			resp.IsMFAChallenge = true
			// Ensure success is marked if MFA is detected, as primary credentials were valid.
			resp.Success = true
			break
		}
	}

	// If it's success (which includes MFA), we stop analyzing for failures.
	if resp.Success {
		return resp
	}

	// Heuristics for lockout:
	// Refined status code checks. 403 (Forbidden) is ambiguous; rely more on body content if it's 403.
	if statusCode == http.StatusTooManyRequests || statusCode == http.StatusLocked {
		resp.IsLockout = true
	}

	lockoutKeywords := []string{"too many attempts", "locked out", "rate limit exceeded", "account temporarily suspended"}
	for _, kw := range lockoutKeywords {
		if strings.Contains(bodyLower, kw) {
			resp.IsLockout = true
			break
		}
	}

	if resp.IsLockout {
		// Ensure we only mark lockout if the status code isn't contradictory (e.g., 403, 500, or even 200 OK with error message).
		if statusCode >= 400 || statusCode == http.StatusOK {
			return resp
		}
	}

	// Heuristics for user enumeration (verbose error messages):
	// Messages indicating invalid user
	invalidUserKeywords := []string{"user not found", "invalid username", "email not recognized", "no account associated"}
	for _, kw := range invalidUserKeywords {
		if strings.Contains(bodyLower, kw) {
			resp.IsUserEnumeration = true
			resp.EnumerationDetail = "The application disclosed that the username/email is invalid."
			return resp
		}
	}

	// Messages indicating invalid password (implies valid user)
	invalidPassKeywords := []string{"invalid password", "incorrect password", "wrong password"}
	for _, kw := range invalidPassKeywords {
		if strings.Contains(bodyLower, kw) {
			resp.IsUserEnumeration = true
			resp.EnumerationDetail = "The application disclosed that the password was incorrect (implying the username is valid)."
			return resp
		}
	}

	return resp
}

// GenerateSprayingPayloads creates a strategic list of login attempts designed
// for password spraying. It pairs a list of known usernames with a curated list
// of common and seasonal weak passwords. The list is structured to iterate
// through passwords first to help evade user-specific lockout policies.
func GenerateSprayingPayloads(knownUsers []string) []LoginAttempt {
	// Common weak passwords for spraying.
	// Use UTC for consistency.
	year := time.Now().UTC().Year()
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
			// Determine if the username looks like an email for better context later.
			isEmail := strings.Contains(user, "@")
			attempts = append(attempts, LoginAttempt{Username: user, Password: pass, IsEmailBased: isEmail})
		}
	}
	return attempts
}
