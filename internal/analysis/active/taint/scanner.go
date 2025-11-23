// Filename: internal/analysis/active/taint/scanner.go
package taint

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// PANScanner handles the verification of credit card numbers (Primary Account Numbers).
type PANScanner struct {
	// matcher uses a robust regex to identify potential PAN candidates.
	// It is unexported but accessible within the 'taint' package (e.g., by analyzer.go).
	matcher *regexp.Regexp
}

// The modernized and comprehensive regex pattern for PAN detection.
// Covers Visa, MasterCard (including 2-series), Amex, Discover, and Diners Club.
// It handles common separators (spaces, dashes).
// This must be kept in sync with the CC_REGEX in taint_shim.js.
const panPattern = `\b(?:4[0-9]{3}(?:[- ]?[0-9]{4}){2}(?:[- ]?[0-9]{1,4})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)(?:[- ]?[0-9]{4}){3}|3[47][0-9]{2}(?:[- ]?[0-9]{6})[- ]?[0-9]{5}|6(?:011|5[0-9]{2}|4[4-9][0-9])(?:[- ]?[0-9]{4}){3}|3(?:0[0-5]|[68][0-9])[0-9](?:[- ]?[0-9]{6})[- ]?[0-9]{4})\b`

// NewPANScanner initializes a PANScanner by compiling the detection regex once for efficient reuse.
func NewPANScanner() *PANScanner {
	return &PANScanner{
		matcher: regexp.MustCompile(panPattern),
	}
}

// HasValidPAN checks if an input string contains at least one sequence that matches
// the PAN pattern and subsequently passes the Luhn algorithm validation.
func (ps *PANScanner) HasValidPAN(input string) bool {
	// Find all sequences matching the regex pattern.
	matches := ps.matcher.FindAllString(input, -1)

	for _, match := range matches {
		// Clean the match (remove separators) before validation.
		clean := stripSeparators(match)
		if luhnCheck(clean) {
			// If any match is valid, return true immediately.
			return true
		}
	}
	// No valid PANs found in the input.
	return false
}

// stripSeparators removes non-digit characters (like dashes and spaces) from a potential PAN string.
func stripSeparators(pan string) string {
	// Use strings.Map to iterate over runes and keep only digits.
	return strings.Map(func(r rune) rune {
		if unicode.IsDigit(r) {
			return r
		}
		// Return -1 to drop the rune from the result.
		return -1
	}, pan)
}

// luhnCheck implements the Luhn algorithm (Mod 10 checksum) to validate a cleaned credit card number.
func luhnCheck(ccNumber string) bool {
	// Basic length validation (PANs are typically 13-19 digits).
	if len(ccNumber) < 13 || len(ccNumber) > 19 {
		return false
	}

	var sum int
	// 'alt' determines whether the current digit should be doubled (every second digit from the right).
	alt := false

	// Iterate backwards through the number string.
	for i := len(ccNumber) - 1; i >= 0; i-- {
		// Convert the character digit to an integer.
		digit, err := strconv.Atoi(string(ccNumber[i]))
		if err != nil {
			// Should not happen if stripSeparators and the regex are correct, but handle defensively.
			return false
		}

		if alt {
			// Double the digit.
			digit *= 2
			// If the result is greater than 9, subtract 9 (equivalent to summing the digits of the result).
			if digit > 9 {
				digit -= 9
			}
		}

		// Add the digit (or the processed doubled digit) to the total sum.
		sum += digit
		// Toggle the alternate flag for the next iteration.
		alt = !alt
	}

	// The number is valid if the total sum is divisible by 10.
	return sum%10 == 0
}
