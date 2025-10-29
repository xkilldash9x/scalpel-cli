package semanticfp

import (
	"regexp"
	"strings"
	"testing"
)

// findResult searches for a FingerprintResult by function name.
func findResult(results []FingerprintResult, name string) *FingerprintResult {
	for i := range results {
		if results[i].FunctionName == name {
			return &results[i]
		}
	}
	return nil
}

// getFunctionNames extracts function names from results for easier verification.
func getFunctionNames(results []FingerprintResult) []string {
	names := make([]string, len(results))
	for i, r := range results {
		names[i] = r.FunctionName
	}
	return names
}

// checkIRPattern checks IR against a pattern using regex, abstracting register names.
func checkIRPattern(t *testing.T, ir string, pattern string) {
	// 1. Escape the input pattern so regex meta-characters (like [, ], (, )) are treated literally.
	escapedPattern := regexp.QuoteMeta(pattern)

	// 2. Replace the placeholder <vN> with the regex pattern for registers.
	// Regex pattern: (?:[vp]\d+|fv\d+) matches vN, pN, or fvN
	// We must match the escaped version of the placeholder (e.g., \<vN\>).
	placeholder := regexp.QuoteMeta("<vN>")
	regexPattern := strings.ReplaceAll(escapedPattern, placeholder, `(?:[vp]\d+|fv\d+)`)

	match, err := regexp.MatchString(regexPattern, ir)
	if err != nil {
		t.Fatalf("Invalid regex pattern generated from: %s\nRegex: %s\nError: %v", pattern, regexPattern, err)
	}
	if !match {
		t.Errorf("Expected pattern not found in IR.\nPattern: %s\nRegex: %s\nActual IR:\n%s", pattern, regexPattern, ir)
	}
}
