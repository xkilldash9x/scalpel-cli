// Filename: internal/analysis/active/taint/scanner_test.go
package taint

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// --- Unit Tests for PANScanner Logic ---

func TestStripSeparators(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"No separators", "1234567890", "1234567890"},
		{"Spaces", "1234 5678 90", "1234567890"},
		{"Dashes", "1234-5678-90", "1234567890"},
		{"Mixed", "1234- 5678 - 90", "1234567890"},
		{"Non-digits", "12a34b", "1234"}, // Should remove letters
		{"Symbols", "12$34#", "1234"},    // Should remove symbols
		{"Empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripSeparators(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		name    string
		input   string // Input should be cleaned (digits only)
		isValid bool
	}{
		// Valid Numbers (Mathematically verified)
		{"Valid Visa", "453201511283034", true}, // Corrected: Ends in 34 (Sum 50)
		{"Valid MasterCard", "5555555555554444", true},
		{"Valid Amex", "371449635398431", true},

		// Invalid Numbers
		{"Invalid Checksum (Single Digit Off)", "453201511283035", false}, // Corrected: Ends in 35 (Sum 51)
		{"Invalid Checksum (Transposition)", "453201511283036", false},
		{"Too Short", "123456", false},
		{"Too Long", "123456789012345678901", false}, // > 19 digits
		{"Empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := luhnCheck(tt.input)
			assert.Equal(t, tt.isValid, result, "Input: %s", tt.input)
		})
	}
}

func TestPANScanner_HasValidPAN(t *testing.T) {
	scanner := NewPANScanner()

	tests := []struct {
		name        string
		input       string
		expectMatch bool
	}{
		// 1. Positive Matches (Valid Regex + Valid Luhn)
		{
			name:        "Simple Visa",
			input:       "Here is a card: 453201511283034 thanks", // Corrected Check Digit
			expectMatch: true,
		},
		{
			name:        "Formatted MasterCard",
			input:       "Payment: 5555-5555-5555-4444",
			expectMatch: true,
		},
		{
			name:        "Amex with spaces",
			input:       "AMEX 3714 496353 98431",
			expectMatch: true,
		},
		{
			name:        "Mixed text",
			input:       "user_id: 1234, cc: 4532-0151-1128-3034, exp: 12/25", // Corrected Check Digit
			expectMatch: true,
		},

		// 2. Negative Matches (Valid Regex + Invalid Luhn) -> False Positive Reduction
		{
			name:        "Regex Match but Invalid Luhn (Visa-like)",
			input:       "4111111111111112", // Ends in 2 (Sum 31) -> Invalid. (All 1s is Valid Sum 30)
			expectMatch: false,
		},
		{
			name:        "Regex Match but Invalid Luhn (MC-like)",
			input:       "5100000000000001", // Ends in 1 -> Sum ends in 1 -> Invalid
			expectMatch: false,
		},

		// 3. Negative Matches (No Regex Match)
		{
			name:        "Random Numbers",
			input:       "Call 18005550199 for help",
			expectMatch: false,
		},
		{
			name:        "Short Number",
			input:       "4123",
			expectMatch: false,
		},
		{
			name:        "IIN not in list",
			input:       "9000000000000000", // 9 is not a major card scheme start
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match := scanner.HasValidPAN(tt.input)
			assert.Equal(t, tt.expectMatch, match, "Input: %s", tt.input)
		})
	}
}

// --- Integration Tests (Analyzer + Scanner) ---

func TestProcessSensitiveDataEvent_ConfirmedLeak(t *testing.T) {
	// Setup Analyzer
	analyzer, reporter, _ := setupAnalyzer(t, nil, false)
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	// Valid Visa that passes Luhn
	validCC := "4532-0151-1128-3034" // Corrected Check Digit

	// Create a Sensitive Data Event
	event := SinkEvent{
		Type:      schemas.TaintSink("SENSITIVE_STORAGE_WRITE"),
		Value:     validCC,
		Detail:    "Sensitive pattern detected in storage value",
		PageURL:   "http://example.com/checkout",
		PageTitle: "Checkout",
	}

	// Expect a Report
	reporter.On("Report", mock.MatchedBy(func(f CorrelatedFinding) bool {
		return f.IsConfirmed == true &&
			f.Origin == schemas.TaintSource("HEURISTIC_CLIENT_DATA") &&
			f.Value == validCC &&
			f.Sink == schemas.TaintSink("SENSITIVE_STORAGE_WRITE")
	})).Return().Once()

	analyzer.eventsChan <- event
	finalizeCorrelationTest(t, analyzer)

	reporter.AssertExpectations(t)
}

func TestProcessSensitiveDataEvent_Suppressed_FalsePositive(t *testing.T) {
	analyzer, reporter, _ := setupAnalyzer(t, nil, false)
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	// Looks like a CC (Regex match) but INVALID Luhn
	invalidLuhnCC := "4111-1111-1111-1112" // Sum 31

	event := SinkEvent{
		Type:   schemas.TaintSink("SENSITIVE_STORAGE_WRITE"),
		Value:  invalidLuhnCC,
		Detail: "Sensitive pattern detected (shim guess)",
	}

	// We expect NO report because the backend verification (Luhn) should fail
	analyzer.eventsChan <- event
	finalizeCorrelationTest(t, analyzer)

	assert.Empty(t, reporter.GetFindings(), "Should suppress false positive CC numbers")
}

func TestProcessSensitiveDataEvent_OtherSecrets(t *testing.T) {
	analyzer, reporter, _ := setupAnalyzer(t, nil, false)
	analyzer.wg.Add(1)
	go analyzer.correlateWorker(0)

	// A value that does NOT look like a credit card, but was flagged by the shim
	apiKey := "AKIAIOSFODNN7EXAMPLE"

	event := SinkEvent{
		Type:   schemas.TaintSink("SENSITIVE_STORAGE_WRITE"),
		Value:  apiKey,
		Detail: "Sensitive pattern detected: AWS Key",
	}

	// Expect Report (Unconfirmed/Heuristic)
	reporter.On("Report", mock.MatchedBy(func(f CorrelatedFinding) bool {
		return f.IsConfirmed == false &&
			f.Value == apiKey &&
			f.Detail == "Potential Secret/Key Leak: Sensitive pattern detected: AWS Key"
	})).Return().Once()

	analyzer.eventsChan <- event
	finalizeCorrelationTest(t, analyzer)

	reporter.AssertExpectations(t)
}
