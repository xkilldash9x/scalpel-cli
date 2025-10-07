// internal/analysis/auth/ato/models_test.go
package ato

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnalyzeResponse uses table-driven tests to cover the heuristics for login analysis comprehensively.
func TestAnalyzeResponse(t *testing.T) {
	t.Parallel()
	// Define a baseline attempt for the tests.
	attempt := LoginAttempt{Username: "testuser", Password: "password123"}
	responseTimeMs := int64(100)

	// Define expected detail messages
	invalidUserMsg := "The application disclosed that the username/email is invalid."
	invalidPassMsg := "The application disclosed that the password was incorrect (implying the username is valid)."

	testCases := []struct {
		name            string
		statusCode      int
		responseBody    string
		expectedSuccess bool
		expectedLockout bool
		expectedEnum    bool
		expectedDetail  string
	}{
		// Success Heuristics
		{"Success - 302 Redirect", http.StatusFound, "", true, false, false, ""},
		{"Success - 301 Redirect", http.StatusMovedPermanently, "", true, false, false, ""},
		{"Success - 200 JSON success true", http.StatusOK, `{"status": "ok", "success": true}`, true, false, false, ""},
		{"Success - 200 JSON authenticated", http.StatusOK, `{"authenticated": true}`, true, false, false, ""},
		{"Success - 200 JSON token", http.StatusOK, `{"token": "jwt.token.here"}`, true, false, false, ""},
		{"Success - 200 HTML Welcome Back", http.StatusOK, "<html><body>Welcome back!</body></html>", true, false, false, ""},

		// Lockout Heuristics
		{"Lockout - 429 Status Code", http.StatusTooManyRequests, "", false, true, false, ""},
		{"Lockout - 423 Status Code", http.StatusLocked, "", false, true, false, ""},
		{"Lockout - 403 Status Code", http.StatusForbidden, "", false, true, false, ""},
		{"Lockout - Body Too Many Attempts", http.StatusOK, `{"error": "Too many attempts"}`, false, true, false, ""},
		{"Lockout - Body Locked Out", http.StatusOK, "You are locked out.", false, true, false, ""},
		{"Lockout - Body Rate Limit Exceeded", http.StatusInternalServerError, "Rate limit exceeded", false, true, false, ""},

		// User Enumeration Heuristics (Invalid User)
		{"Enumeration - User Not Found", http.StatusUnauthorized, "Error: User not found.", false, false, true, invalidUserMsg},
		{"Enumeration - Invalid Username", http.StatusOK, `{"message": "Invalid username"}`, false, false, true, invalidUserMsg},
		{"Enumeration - Email Not Recognized", http.StatusBadRequest, "Email not recognized.", false, false, true, invalidUserMsg},

		// User Enumeration Heuristics (Invalid Password)
		{"Enumeration - Invalid Password", http.StatusUnauthorized, "Invalid password.", false, false, true, invalidPassMsg},
		{"Enumeration - Incorrect Password", http.StatusOK, `{"error": "Incorrect password"}`, false, false, true, invalidPassMsg},

		// Generic Failures
		{"Generic Failure - 401", http.StatusUnauthorized, "Invalid credentials.", false, false, false, ""},
		{"Generic Failure - 200 JSON", http.StatusOK, `{"success": false, "message": "Login failed."}`, false, false, false, ""},
		{"Server Error", http.StatusInternalServerError, "Database connection failed.", false, false, false, ""},
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable for parallel execution
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Execute the function under test.
			response := AnalyzeResponse(attempt, tc.statusCode, tc.responseBody, responseTimeMs)

			// Assertions
			assert.Equal(t, tc.expectedSuccess, response.Success, "Success status mismatch")
			assert.Equal(t, tc.expectedLockout, response.IsLockout, "Lockout status mismatch")
			assert.Equal(t, tc.expectedEnum, response.IsUserEnumeration, "Enumeration status mismatch")
			assert.Equal(t, tc.statusCode, response.StatusCode)
			assert.Equal(t, responseTimeMs, response.ResponseTimeMs)

			if tc.expectedEnum {
				assert.Equal(t, tc.expectedDetail, response.EnumerationDetail, "Enumeration detail mismatch")
			} else {
				assert.Empty(t, response.EnumerationDetail, "Enumeration detail should be empty when no enumeration detected")
			}
		})
	}
}

// TestAnalyzeResponse_CaseInsensitivity verifies that the analysis heuristics are case-insensitive.
func TestAnalyzeResponse_CaseInsensitivity(t *testing.T) {
	t.Parallel()
	attempt := LoginAttempt{Username: "admin", Password: "pwd"}

	// 1. Success check
	respSuccess := AnalyzeResponse(attempt, http.StatusOK, `{"SUCCESS": TRUE}`, 100)
	assert.True(t, respSuccess.Success)

	// 2. Lockout check
	respLockout := AnalyzeResponse(attempt, http.StatusOK, "Error: TOO MANY ATTEMPTS", 100)
	assert.True(t, respLockout.IsLockout)

	// 3. Enumeration check (Invalid User)
	respEnumUser := AnalyzeResponse(attempt, http.StatusUnauthorized, "Alert: USER NOT FOUND", 100)
	assert.True(t, respEnumUser.IsUserEnumeration)

	// 4. Enumeration check (Invalid Pass)
	respEnumPass := AnalyzeResponse(attempt, http.StatusUnauthorized, "Alert: INCORRECT PASSWORD", 100)
	assert.True(t, respEnumPass.IsUserEnumeration)
}

// TestGenerateSprayingPayloads verifies the generation logic, count, and iteration strategy.
func TestGenerateSprayingPayloads(t *testing.T) {
	t.Parallel()
	users := []string{"alice", "bob", "charlie"}
	year := time.Now().Year()

	// Define the expected passwords list based on the source code logic (8 static + 8 seasonal = 16 total)
	expectedPasswords := []string{
		"Password123!",
		"Password1!",
		"Welcome1",
		"admin",
		"password",
		"123456",
		"12345678",
		"changeme",
		fmt.Sprintf("Spring%d", year),
		fmt.Sprintf("Summer%d", year),
		fmt.Sprintf("Fall%d", year),
		fmt.Sprintf("Winter%d", year),
		fmt.Sprintf("Spring%d!", year),
		fmt.Sprintf("Summer%d!", year),
		fmt.Sprintf("Fall%d!", year),
		fmt.Sprintf("Winter%d!", year),
	}

	attempts := GenerateSprayingPayloads(users)

	// 1. Verify the total count
	expectedCount := len(users) * len(expectedPasswords)
	require.Len(t, attempts, expectedCount, "Incorrect number of generated attempts")

	// 2. Verify the generation strategy (Password iteration first)
	// Expected: Pass1/User1, Pass1/User2, Pass1/User3, Pass2/User1, Pass2/User2...

	// Check Pass1 sequence
	require.Equal(t, expectedPasswords[0], attempts[0].Password)
	require.Equal(t, users[0], attempts[0].Username)

	require.Equal(t, expectedPasswords[0], attempts[1].Password)
	require.Equal(t, users[1], attempts[1].Username)

	require.Equal(t, expectedPasswords[0], attempts[2].Password)
	require.Equal(t, users[2], attempts[2].Username)

	// Check Pass2 sequence start
	require.Equal(t, expectedPasswords[1], attempts[3].Password)
	require.Equal(t, users[0], attempts[3].Username)

	// 3. Verify all combinations exist
	foundCombinations := make(map[string]bool)
	for _, attempt := range attempts {
		combination := fmt.Sprintf("%s:%s", attempt.Username, attempt.Password)
		foundCombinations[combination] = true
	}

	for _, user := range users {
		for _, pass := range expectedPasswords {
			combination := fmt.Sprintf("%s:%s", user, pass)
			assert.True(t, foundCombinations[combination], "Missing combination: %s", combination)
		}
	}
}

// TestGenerateSprayingPayloads_EmptyUsers ensures it handles an empty user list gracefully.
func TestGenerateSprayingPayloads_EmptyUsers(t *testing.T) {
	t.Parallel()
	attempts := GenerateSprayingPayloads([]string{})
	assert.Empty(t, attempts, "Expected an empty list of attempts when no users are provided")

	// Also test nil input
	attemptsNil := GenerateSprayingPayloads(nil)
	assert.Empty(t, attemptsNil, "Expected an empty list when nil users are provided")
}
