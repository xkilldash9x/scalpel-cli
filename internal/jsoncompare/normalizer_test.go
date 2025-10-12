// internal/jsoncompare/normalizer_test.go
package jsoncompare

import (
	"math"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestNormalize_Unit tests the main normalization logic in isolation.
func TestNormalize_Unit(t *testing.T) {
	t.Parallel()
	normalizer := NewNormalizer(DefaultRules())

	testCases := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{"Key: Multiple dynamic keys",
			map[string]interface{}{"user": "bob", "session_id": "s1", "csrf_token": "c1"},
			map[string]interface{}{"user": "bob", PlaceholderDynamicKey: []interface{}{"s1", "c1"}},
		},
		{"Value: Is UUID",
			map[string]interface{}{"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
			map[string]interface{}{"id": PlaceholderDynamicValue},
		},
		{"Value: Is high entropy string",
			map[string]interface{}{"secret": "Xp2s5v8y/B?E(H+KbPeShVmYq3t6w9z$"},
			map[string]interface{}{"secret": PlaceholderDynamicValue},
		},
		{"Nested structure",
			map[string]interface{}{"user": map[string]interface{}{"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}, "session_id": "s1"},
			map[string]interface{}{"user": map[string]interface{}{"id": PlaceholderDynamicValue}, PlaceholderDynamicKey: []interface{}{"s1"}},
		},
		{"Dynamic key holding a dynamic value",
			map[string]interface{}{"session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
			map[string]interface{}{PlaceholderDynamicKey: []interface{}{PlaceholderDynamicValue}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizer.Normalize(tc.input)
			// Use cmp options to sort the dynamic key slice for a reliable comparison.
			cmpOpts := buildCmpOptions(DefaultOptions())
			if diff := cmp.Diff(tc.expected, got, cmpOpts...); diff != "" {
				t.Errorf("Normalize() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCalculateShannonEntropy tests the entropy calculation helper function.
func TestCalculateShannonEntropy(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		input    string
		expected float64
	}{
		{"Empty string", "", 0.0},
		{"Single character", "aaaaa", 0.0},
		{"Two chars, equal probability", "ababab", 1.0},
		{"Four chars, equal probability", "abcd", 2.0},
		{"Real GUID", "f47ac10b-58cc-4372-a567-0e02b2c3d479", 4.30},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := calculateShannonEntropy(tc.input)
			if math.Abs(got-tc.expected) > 0.01 { // Compare with tolerance
				t.Errorf("calculateShannonEntropy(%q) = %v, want approx %v", tc.input, got, tc.expected)
			}
		})
	}
}

// TestIsPlausibleUnixTimestamp tests the timestamp detection helper function.
func TestIsPlausibleUnixTimestamp(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		input    float64
		expected bool
	}{
		{"Seconds", 1665356400, true},            // In range
		{"Milliseconds", 1665356400000, true},    // In range
		{"Microseconds", 1665356400000000, true}, // In range
		{"Out of range (low)", 1410000000, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPlausibleUnixTimestamp(tc.input); got != tc.expected {
				t.Errorf("isPlausibleUnixTimestamp(%v) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}
