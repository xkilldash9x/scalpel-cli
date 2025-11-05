// internal/jsoncompare/service_internal_test.go
package jsoncompare

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

// NOTE: This file is named `service_internal_test.go` to be part of the `jsoncompare`
// package. This allows it to access unexported functions like `normalize` for
// targeted unit tests (e.g., idempotency) without making them public.

// FuzzCompare_Robustness tests the CompareWithOptions function against arbitrary inputs
// to ensure it never panics.
func FuzzCompare_Robustness(f *testing.F) {
	// Seed corpus with a mix of valid, invalid, and edge-case JSON.
	f.Add([]byte(`{"key": "value"}`), []byte(`{"key": "different"}`))
	f.Add([]byte(`{}`), []byte(`null`))
	f.Add([]byte(`invalid json`), []byte(`{`))
	f.Add([]byte(""), []byte(""))

	// Instantiate the service once for the fuzz target.
	s := NewService(newTestLogger()).(*service) // Assert to concrete type to access unexported methods if needed.
	opts := DefaultOptions()

	// The Fuzz Target.
	f.Fuzz(func(t *testing.T, dataA []byte, dataB []byte) {
		// The primary assertion is that the function must never panic.
		_, _ = s.CompareWithOptions(dataA, dataB, opts)
	})
}

// FuzzCompare_SemanticInvariants tests key properties (invariants) of the comparison.
func FuzzCompare_SemanticInvariants(f *testing.F) {
	// Seed with examples known to be semantically equivalent or different.
	f.Add([]byte(`{"session_id": "S1", "user": "A"}`), []byte(`{"session_id": "S2", "user": "A"}`))
	s := NewService(newTestLogger()).(*service)
	opts := DefaultOptions()
	cmpOptions := s.buildCmpOptions(opts)

	f.Fuzz(func(t *testing.T, dataA []byte, dataB []byte) {
		resAB, errA := s.CompareWithOptions(dataA, dataB, opts)
		resBA, errB := s.CompareWithOptions(dataB, dataA, opts)

		// If either comparison fails due to an error (which shouldn't happen), skip.
		require.NoError(t, errA)
		require.NoError(t, errB)

		// Invariant 1: Symmetry. Compare(A, B) == Compare(B, A)
		if resAB.AreEquivalent != resBA.AreEquivalent {
			t.Errorf("Symmetry violated: Compare(A, B) = %v, Compare(B, A) = %v", resAB.AreEquivalent, resBA.AreEquivalent)
		}

		// Invariant 2: Reflexivity. Compare(A, A) == true
		resAA, errAA := s.CompareWithOptions(dataA, dataA, opts)
		require.NoError(t, errAA, "Reflexivity check failed with an error")
		if !resAA.AreEquivalent {
			t.Errorf("Reflexivity violated: Compare(A, A) returned false for input A:\n%s", string(dataA))
		}

		// Invariant 3: Semantic Equivalence. If A == B, then Normalize(A) must be identical to Normalize(B).
		if resAB.AreEquivalent {
			// The Diff field in the result should be empty.
			if resAB.Diff != "" {
				t.Errorf("Semantic Equivalence violated: AreEquivalent=true, but Diff is not empty.\nDiff: %s", resAB.Diff)
			}

			// Directly compare the normalized structures.
			if diff := cmp.Diff(resAB.NormalizedA, resAB.NormalizedB, cmpOptions...); diff != "" {
				t.Errorf("Semantic Equivalence violated: AreEquivalent=true, but normalized structures differ.\nDiff: %s", diff)
			}
		}
	})
}

// FuzzNormalize_Idempotency tests that Normalize(Normalize(X)) == Normalize(X).
// This test lives in the internal test file to access the unexported `normalize` method.
func FuzzNormalize_Idempotency(f *testing.F) {
	f.Add([]byte(`{"key": "value", "session_id": "S1", "data": [1, "a"]}`))
	s := NewService(newTestLogger()).(*service)
	opts := DefaultOptions()
	cmpOpts := s.buildCmpOptions(opts)

	f.Fuzz(func(t *testing.T, data []byte) {
		var input interface{}
		// Fuzz only valid JSON structures to focus on normalization logic.
		if err := json.Unmarshal(data, &input); err != nil {
			return
		}

		// Calculate Normalize(X) using the unexported method.
		normalizedOnce := s.normalize(input, opts)

		// Calculate Normalize(Normalize(X)).
		normalizedTwice := s.normalize(normalizedOnce, opts)

		// Assert idempotency. The two should be identical.
		if diff := cmp.Diff(normalizedOnce, normalizedTwice, cmpOpts...); diff != "" {
			t.Errorf("Normalization is not idempotent.\nInput: %s\nDiff:\n%s", string(data), diff)
		}
	})
}

// TestCompare_Concurrent executes the comparison logic concurrently to detect data races.
// This test must be run with the race detector enabled (go test -race).
func TestCompare_Concurrent(t *testing.T) {
	// Define a complex input pair that exercises normalization, sorting, and recursion.
	jsonA := []byte(`{
        "session_id": "S1",
        "user": {"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
        "data": [1, 2, 3]
    }`)
	jsonB := []byte(`{
        "session_id": "S2",
        "user": {"id": "550e8400-e29b-4372-a567-0e02b2c3d479"},
        "data": [3, 1, 2]
    }`)

	s := NewService(newTestLogger())
	opts := DefaultOptions()
	const concurrencyLevel = 100
	var wg sync.WaitGroup

	// Use a channel to collect errors, which is safer than calling t.Error in goroutines.
	errChan := make(chan string, concurrencyLevel)

	for i := 0; i < concurrencyLevel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := s.CompareWithOptions(jsonA, jsonB, opts)

			if err != nil {
				errChan <- fmt.Sprintf("Concurrent CompareWithOptions() returned unexpected error: %v", err)
				return
			}
			// For these specific inputs, normalization should make them equal.
			if !result.AreEquivalent {
				errChan <- fmt.Sprintf("Concurrent CompareWithOptions() expected AreEquivalent=true, got false. Diff:\n%s", result.Diff)
			}
		}()
	}

	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		t.Fatalf("Detected %d errors during concurrent execution. First error: %s", len(errChan), <-errChan)
	}
}

// TestNormalize_Unit tests the main normalization logic in isolation.
func TestNormalize_Unit(t *testing.T) {
	t.Parallel()
	s := NewService(newTestLogger()).(*service)
	opts := DefaultOptions()

	testCases := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{"Key: Multiple dynamic keys",
			map[string]interface{}{"user": "bob", "session_id": "s1", "csrf_token": "c1"},
			map[string]interface{}{"user": "bob", PlaceholderDynamicKey: PlaceholderDynamicValue, "__DYNAMIC_KEY_1": PlaceholderDynamicValue},
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
			map[string]interface{}{"user": map[string]interface{}{"id": PlaceholderDynamicValue}, PlaceholderDynamicKey: PlaceholderDynamicValue},
		},
		{"Dynamic key holding a dynamic value",
			map[string]interface{}{"session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
			map[string]interface{}{PlaceholderDynamicKey: PlaceholderDynamicValue},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.normalize(tc.input, opts)
			// Use cmp options to sort map keys for a reliable comparison.
			cmpOpts := cmp.Options{
				cmpopts.SortMaps(func(x, y string) bool { return x < y }),
			}
			if diff := cmp.Diff(tc.expected, got, cmpOpts...); diff != "" {
				t.Errorf("Normalize() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCalculateShannonEntropy tests the entropy calculation helper function.
func TestCalculateShannonEntropy(t *testing.T) {
	t.Parallel()
	s := NewService(newTestLogger()).(*service)
	testCases := []struct {
		name     string
		input    string
		expected float64
	}{
		{"Empty string", "", 0.0},
		{"Single character", "aaaaa", 0.0},
		{"Two chars, equal probability", "ababab", 1.0},
		{"Four chars, equal probability", "abcd", 2.0},
		{"Real GUID", "f47ac10b-58cc-4372-a567-0e02b2c3d479", 3.88},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.calculateShannonEntropy(tc.input)
			if math.Abs(got-tc.expected) > 0.01 { // Compare with tolerance
				t.Errorf("calculateShannonEntropy(%q) = %v, want approx %v", tc.input, got, tc.expected)
			}
		})
	}
}

// TestIsPlausibleUnixTimestamp tests the timestamp detection helper function.
func TestIsPlausibleUnixTimestamp(t *testing.T) {
	t.Parallel()
	s := NewService(newTestLogger()).(*service)
	testCases := []struct {
		name     string
		input    float64
		expected bool
	}{
		{"Seconds", 1665356400, true},            // In range
		{"Milliseconds", 1665356400000, true},    // In range
		{"Microseconds", 1665356400000000, true}, // In range
		{"Out of range (low)", 1200000000, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.isPlausibleUnixTimestamp(tc.input); got != tc.expected {
				t.Errorf("isPlausibleUnixTimestamp(%v) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}
