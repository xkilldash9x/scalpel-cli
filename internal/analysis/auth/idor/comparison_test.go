// comparison_test.go
package idor

import (
	"bytes"
	"encoding/json"
	"fmt" // Added import
	"math"
	"regexp"
	"strings" // Added import
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestCalculateShannonEntropy verifies the entropy calculation against known values.
func TestCalculateShannonEntropy(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"", 0.0},
		{"aaaaa", 0.0},
		{"1234567890", 3.321928094887362},
		// FIX: Corrected the expected value for "hello world"
		{"hello world", 2.845350936622437},
		// FIX: Corrected the expected value for "BaSe64/+"
		{"BaSe64/+", 3.0},
		// FIX: Corrected the expected value for the UUID
		{"f3f2e850-b5d4-11ef-ac7e-96584d5248b2", 3.898412848364052},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := calculateShannonEntropy(tt.input)
			// FIX: Use a tolerance for float comparison instead of cmp.Diff
			const tolerance = 1e-9
			if math.Abs(tt.expected-got) > tolerance {
				t.Errorf("calculateShannonEntropy() got = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestNormalizer_IsValueDynamic tests the value-based heuristics.
func TestNormalizer_IsValueDynamic(t *testing.T) {
	rules := DefaultHeuristicRules()
	// Ensure entropy threshold is set for testing
	rules.EntropyThreshold = 4.5
	// Add specific values for testing the new feature
	rules.SpecificValuesToIgnore = map[string]struct{}{
		"IGNORE_ME": {},
		"12345":     {},
	}
	normalizer := NewNormalizer(rules)

	tests := []struct {
		name     string
		input    interface{}
		expected bool
	}{
		// Specific Values
		{"Specific String", "IGNORE_ME", true},
		{"Specific Integer (as string)", "12345", true},
		{"Specific Integer (as int)", 12345, true},
		{"Specific Integer (as json.Number)", json.Number("12345"), true},

		// UUIDs
		{"Valid UUIDv4", "f3f2e850-b5d4-11ef-ac7e-96584d5248b2", true},
		{"Valid UUIDv1", "123e4567-e89b-12d3-a456-426614174000", true},
		{"Invalid UUID format", "not-a-valid-uuid-format", false},
		{"Non-UUID string", "user-profile-123", false},
		// Timestamps
		{"RFC3339 Timestamp", "2025-10-10T11:00:00Z", true},
		{"RFC1123 Timestamp", "Fri, 10 Oct 2025 11:00:00 GMT", true},
		{"Non-Timestamp Date", "2025-10-10", false}, // Default rules don't include this simple format

		// High Entropy
		{"High Entropy (API Key)", "sk_live_51P5tqTRs9g5k8y3l0zYqXwVuTgFrEdCbAxBz", true},
		{"Medium Entropy (Password)", "P@ssw0rd123!", false}, // Below 4.5 threshold
		{"Low Entropy (Short)", "abc", false},

		// Non-Strings/Numbers (that aren't specifically ignored)
		{"Integer (not ignored)", 999, false},
		{"Boolean", true, false},
		{"Nil", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizer.isValueDynamic(tt.input)
			if got != tt.expected {
				t.Errorf("isValueDynamic(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestNormalizer_Normalize tests the full normalization process.
func TestNormalizer_Normalize(t *testing.T) {
	rules := DefaultHeuristicRules()
	// Add specific values to test the integration of SpecificValuesToIgnore
	rules.SpecificValuesToIgnore = map[string]struct{}{
		"101": {},
	}
	normalizer := NewNormalizer(rules)

	tests := []struct {
		name         string
		inputJSON    string
		expectedJSON string
	}{
		{
			name: "Basic normalization (UUID, Timestamp, Specific Value)",
			inputJSON: `{
				"id": "f3f2e850-b5d4-11ef-ac7e-96584d5248b2",
				"user_id": 101,
				"created_at": "2025-10-10T11:00:00Z"
			}`,
			expectedJSON: `{
				"id": "__DYNAMIC_VALUE__",
				"user_id": "__DYNAMIC_VALUE__",
				"created_at": "__DYNAMIC_VALUE__"
			}`,
		},
		{
			name: "Dynamic Key Collision Handling (Numbered Keys)",
			inputJSON: `{
				"session_a": "valueA",
				"session_b": "valueB",
				"session_c": "valueC"
			}`,
			// Order depends on map traversal. The test now expects the corrected key format.
			expectedJSON: `{
				"__DYNAMIC_KEY__": "valueA",
				"__DYNAMIC_KEY_1": "valueB",
				"__DYNAMIC_KEY_2": "valueC"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var inputData interface{}
			// Use Decoder with UseNumber for accurate representation of numbers
			decoder := json.NewDecoder(bytes.NewReader([]byte(tt.inputJSON)))
			decoder.UseNumber()
			if err := decoder.Decode(&inputData); err != nil {
				t.Fatalf("Failed to unmarshal input JSON: %v", err)
			}

			var expectedData interface{}
			decoderExp := json.NewDecoder(bytes.NewReader([]byte(tt.expectedJSON)))
			decoderExp.UseNumber()
			if err := decoderExp.Decode(&expectedData); err != nil {
				t.Fatalf("Failed to unmarshal expected JSON: %v", err)
			}

			gotData := normalizer.Normalize(inputData)

			// Use go-cmp for comparison. Handle non-determinism for dynamic keys.
			if diff := cmp.Diff(expectedData, gotData); diff != "" {
				// Lenient check for dynamic key collisions
				if tt.name == "Dynamic Key Collision Handling (Numbered Keys)" {
					if !lenientDynamicKeyCheck(t, expectedData, gotData) {
						t.Errorf("Normalize() mismatch (even with lenient check) (-want +got):\n%s", diff)
					}
				} else {
					t.Errorf("Normalize() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// lenientDynamicKeyCheck handles the non-deterministic ordering of dynamic key normalization.
func lenientDynamicKeyCheck(t *testing.T, expected, got interface{}) bool {
	t.Helper()
	expMap, okE := expected.(map[string]interface{})
	gotMap, okG := got.(map[string]interface{})

	if !okE || !okG || len(expMap) != len(gotMap) {
		return false
	}

	// Collect expected dynamic values
	expectedDynamicValues := make(map[interface{}]int)

	// MODIFICATION: Construct a regex that matches both the base placeholder and the numbered variants.
	// e.g., Matches "__DYNAMIC_KEY__" and "__DYNAMIC_KEY_1".
	// We derive the base name (e.g., "DYNAMIC_KEY") and construct the regex dynamically.
	baseName := strings.Trim(PlaceholderDynamicKey, "_")
	// Regex: ^__(BASENAME__|BASENAME_\d+)$
	dynamicKeyRegex := regexp.MustCompile(fmt.Sprintf(`^__(%s__|%s_\d+)$`, baseName, baseName))

	for key, val := range expMap {
		if dynamicKeyRegex.MatchString(key) {
			expectedDynamicValues[val]++
		}
	}

	// Verify got map against expected
	for key, val := range gotMap {
		if dynamicKeyRegex.MatchString(key) {
			if expectedDynamicValues[val] > 0 {
				expectedDynamicValues[val]--
			} else {
				return false // Found a dynamic value in got that wasn't expected
			}
		} else {
			// Static key, must match exactly
			if expVal, exists := expMap[key]; !exists || !cmp.Equal(val, expVal) {
				return false
			}
		}
	}
	return true
}

// TestCompareResponses verifies the high-level comparison logic.
func TestCompareResponses(t *testing.T) {
	rules := DefaultHeuristicRules()

	tests := []struct {
		name          string
		bodyA         string
		bodyB         string
		rules         HeuristicRules
		areEquivalent bool
	}{
		{
			name:  "Specific Value Ignore (Manipulation Test Simulation)",
			bodyA: `{"resource_id": 100, "data": "Resource A"}`,
			bodyB: `{"resource_id": 101, "data": "Resource B"}`,
			rules: func() HeuristicRules {
				r := DefaultHeuristicRules()
				// Simulate ignoring the specific data associated with the resources
				r.SpecificValuesToIgnore = map[string]struct{}{
					"100": {}, "101": {}, "Resource A": {}, "Resource B": {},
				}
				return r
			}(),
			areEquivalent: true,
		},
		{
			name:          "Array Order Different (Default Rules - Ignored)",
			bodyA:         `{"data": [1, 2, 3]}`,
			bodyB:         `{"data": [3, 2, 1]}`,
			rules:         rules,
			areEquivalent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := CompareResponses([]byte(tt.bodyA), []byte(tt.bodyB), tt.rules)
			if err != nil {
				t.Fatalf("CompareResponses() returned an unexpected error: %v", err)
			}

			if result.AreEquivalent != tt.areEquivalent {
				t.Errorf("CompareResponses() AreEquivalent = %v, want %v.\nDiff:\n%s", result.AreEquivalent, tt.areEquivalent, result.Diff)
			}
		})
	}
}
