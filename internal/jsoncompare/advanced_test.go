// internal/jsoncompare/advanced_test.go
package jsoncompare

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// FuzzCompare_Robustness tests the Compare function against arbitrary inputs
// to ensure it never panics (Document: "Mastering Native Go Fuzzing").
func FuzzCompare_Robustness(f *testing.F) {
	// Seed corpus initialization (Document: "The Seed Corpus as a Strategic Asset").
	f.Add([]byte(`{"key": "value"}`), []byte(`{"key": "different"}`))
	f.Add([]byte(`{}`), []byte(`null`))
	f.Add([]byte(`invalid json`), []byte(`{`))

	opts := DefaultOptions()

	// The Fuzz Target.
	f.Fuzz(func(t *testing.T, dataA []byte, dataB []byte) {
		// The primary assertion is that the function must never panic.
		Compare(dataA, dataB, opts)
	})
}

// FuzzCompare_SemanticInvariants tests key properties (invariants) of the comparison.
// (Document: "Fuzz Logic, Not Just Parsers").
func FuzzCompare_SemanticInvariants(f *testing.F) {
	// Seed with examples known to be semantically equivalent or different.
	f.Add([]byte(`{"session_id": "S1", "user": "A"}`), []byte(`{"session_id": "S2", "user": "A"}`))
	f.Add([]byte(`[1, 2]`), []byte(`[2, 1]`))

	opts := DefaultOptions()
	cmpOptions := buildCmpOptions(opts)

	f.Fuzz(func(t *testing.T, dataA []byte, dataB []byte) {
		resAB, errA := Compare(dataA, dataB, opts)
		resBA, errB := Compare(dataB, dataA, opts)

		// Handle parsing errors.
		if errA != nil || errB != nil {
			t.Skip("Skipping due to parsing error")
		}

		// Invariant 1: Symmetry. Compare(A, B) == Compare(B, A)
		if resAB.AreEqual != resBA.AreEqual {
			t.Errorf("Symmetry violated: Compare(A, B) = %v, Compare(B, A) = %v", resAB.AreEqual, resBA.AreEqual)
		}

		// Invariant 2: Reflexivity. Compare(A, A) == true
		resAA, errAA := Compare(dataA, dataA, opts)
		if errAA != nil || !resAA.AreEqual {
			t.Errorf("Reflexivity violated: Compare(A, A) failed or returned false. Error: %v", errAA)
		}

		// Invariant 3: Semantic Equivalence. If A == B, then Normalize(A) must be identical to Normalize(B).
		if resAB.AreEqual {
			// The Diff field in the result should be empty.
			if resAB.Diff != "" {
				t.Errorf("Semantic Equivalence violated: AreEqual=true, but Diff is not empty.\nDiff: %s", resAB.Diff)
			}

			// Directly compare the normalized structures.
			if diff := cmp.Diff(resAB.NormalizedA, resAB.NormalizedB, cmpOptions...); diff != "" {
				t.Errorf("Semantic Equivalence violated: AreEqual=true, but normalized structures differ.\nDiff: %s", diff)
			}
		}
	})
}

// FuzzNormalize_StructureAwareAndIdempotency implements structure-aware fuzzing (Ref: "Handling Complex Data Structures")
// and tests the idempotency invariant: Normalize(Normalize(X)) == Normalize(X).
func FuzzNormalize_StructureAwareAndIdempotency(f *testing.F) {
	f.Add([]byte(`{"key": "value", "session_id": "S1", "data": [1, "a"]}`))
	f.Add([]byte(`{}`))

	normalizer := NewNormalizer(DefaultRules())
	// We need the comparison options (for sorting) to reliably compare the results.
	cmpOpts := buildCmpOptions(DefaultOptions())

	f.Fuzz(func(t *testing.T, data []byte) {
		var input interface{}
		// Only test with valid JSON inputs. This focuses the fuzzer on the normalization logic.
		if err := json.Unmarshal(data, &input); err != nil {
			return
		}

		// Calculate Normalize(X)
		normalizedOnce := normalizer.Normalize(input)

		// Calculate Normalize(Normalize(X))
		normalizedTwice := normalizer.Normalize(normalizedOnce)

		// Assert idempotency
		if diff := cmp.Diff(normalizedOnce, normalizedTwice, cmpOpts...); diff != "" {
			t.Errorf("Normalization is not idempotent.\nInput: %s\nDiff: %s", data, diff)
		}
	})
}

// FuzzNormalize_Idempotency tests that Normalize(Normalize(X)) == Normalize(X).
func FuzzNormalize_Idempotency(f *testing.F) {
	f.Add([]byte(`{"key": "value", "session_id": "S1", "data": [1, "a"]}`))
	normalizer := NewNormalizer(DefaultRules())
	cmpOpts := buildCmpOptions(DefaultOptions())

	f.Fuzz(func(t *testing.T, data []byte) {
		var input interface{}
		if err := json.Unmarshal(data, &input); err != nil {
			return // Fuzz only valid JSON structures
		}

		normalizedOnce := normalizer.Normalize(input)
		normalizedTwice := normalizer.Normalize(normalizedOnce)

		if diff := cmp.Diff(normalizedOnce, normalizedTwice, cmpOpts...); diff != "" {
			t.Errorf("Normalization is not idempotent.\nInput: %s\nDiff: %s", data, diff)
		}
	})
}

// TestCompare_Concurrent executes the comparison logic concurrently to detect
// potential data races or concurrency issues (Ref: "Stress-Testing High-Throughput Systems").
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
        "user": {"id": "550e8400-e29b-41d4-a716-446655440000"},
        "data": [3, 1, 2]
    }`)

	// Use shared default options. The race detector ensures that access to shared
	// resources (like the compiled regexes in DefaultRules) is safe.
	opts := DefaultOptions()
	const concurrencyLevel = 100
	// Use sync.WaitGroup, an idiomatic Go synchronization primitive (Ref: Goja Deadlocks Doc).
	var wg sync.WaitGroup

	// Use a channel to collect errors, safer than calling t.Error directly in goroutines.
	errChan := make(chan string, concurrencyLevel)

	// Run the comparison concurrently.
	for i := 0; i < concurrencyLevel; i++ {
		wg.Add(1)
		go func() {
			// Ensure wg.Done() is called using defer (Ref: Context Best Practices, WaitGroup Mismanagement).
			defer wg.Done()
			result, err := Compare(jsonA, jsonB, opts)

			// Assert the expected outcome within the goroutine.
			if err != nil {
				errChan <- fmt.Sprintf("Concurrent Compare() returned unexpected error: %v", err)
				return
			}
			// For these specific inputs, normalization should make them equal.
			if !result.AreEqual {
				errChan <- fmt.Sprintf("Concurrent Compare() expected AreEqual=true, got false. Diff:\n%s", result.Diff)
			}
		}()
	}

	// Wait for all concurrent executions to finish.
	wg.Wait()
	close(errChan)

	if len(errChan) > 0 {
		t.Errorf("Detected %d errors during concurrent execution. First error: %s", len(errChan), <-errChan)
	}
}
