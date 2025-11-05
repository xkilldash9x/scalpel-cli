// internal/jsoncompare/comparison_test.go
package jsoncompare

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// TestMain sets up the global logger for all tests in this package.
func TestMain(m *testing.M) {
	// Reset to be able to initialize again (good for `go test -count=1 ...`)
	observability.ResetForTest()

	// Grab the default logger config
	cfg := config.NewDefaultConfig().Logger()
	// Tweak it for a better test experience
	cfg.Level = "debug"    // Show all logs during tests
	cfg.LogFile = ""       // Don't write to files
	cfg.Format = "console" // Ensure console-friendly output

	// Initialize the global logger
	observability.InitializeLogger(cfg)

	// Run all tests
	code := m.Run()

	// Flush the logger
	observability.Sync()

	// Exit with the correct status code
	os.Exit(code)
}

// TestCompare_Integration performs end-to-end testing of the Compare function.
func TestCompare_Integration(t *testing.T) {
	t.Parallel()
	opts := DefaultOptions()
	// Use the globally initialized logger
	service := NewService(observability.GetLogger())

	testCases := []struct {
		name        string
		jsonA       string
		jsonB       string
		expectEqual bool
	}{
		{"Identical", `{"a": 1}`, `{"a": 1}`, true},
		{"Different Key Order", `{"b": 2, "a": 1}`, `{"a": 1, "b": 2}`, true},
		{"Inequality (Value)", `{"a": 1}`, `{"a": 2}`, false},
		{"Arrays Different Order", `[1, 2, 3]`, `[3, 1, 2]`, true},
		{"Empty Map vs Null", `{"data": {}}`, `{"data": null}`, true},
		{"Empty Slice vs Null", `{"data": []}`, `{"data": null}`, true},
		{"Different Session IDs", `{"user": "A", "session_id": "S1"}`, `{"user": "A", "session_id": "S2"}`, true},
		{"Different UUIDs", `{"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}`, `{"id": "550e8400-e29b-41d4-a716-446655440000"}`, true},
		{"Complex Scenario", `{"req_id": "R1", "d": [{"id": 1}, {"id": 2}]}`, `{"req_id": "R2", "d": [{"id": 2}, {"id": 1}]}`, true},
	}

	for _, tc := range testCases {
		runCompareTest(t, service, tc.name, tc.jsonA, tc.jsonB, opts, tc.expectEqual)
	}
}

// TestCompare_Options verifies behavior when specific options are disabled.
func TestCompare_Options(t *testing.T) {
	t.Parallel()
	// Use the globally initialized logger
	service := NewService(observability.GetLogger())

	// IgnoreArrayOrder Disabled
	optsStrictOrder := DefaultOptions()
	optsStrictOrder.IgnoreArrayOrder = false
	runCompareTest(t, service, "IgnoreArrayOrder Disabled", `[1, 2]`, `[2, 1]`, optsStrictOrder, false)

	// EquateEmpty Disabled
	optsStrictEmpty := DefaultOptions()
	optsStrictEmpty.EquateEmpty = false
	runCompareTest(t, service, "EquateEmpty Disabled", `{"data": []}`, `{"data": null}`, optsStrictEmpty, false)
}

// TestCompare_ErrorHandling verifies that parsing errors are handled correctly.
func TestCompare_ErrorHandling(t *testing.T) {
	t.Parallel()
	opts := DefaultOptions()
	// Use the globally initialized logger
	service := NewService(observability.GetLogger())
	jsonA := `{"key": "value"` // missing closing brace
	jsonB := `{"key": "value"}`
	result, err := service.CompareWithOptions([]byte(jsonA), []byte(jsonB), opts)
	if err != nil {
		t.Fatalf("CompareWithOptions() returned unexpected error: %v", err)
	}
	// The service now handles non-JSON gracefully, so we check the result.
	if result.AreEquivalent {
		t.Error("Expected AreEquivalent to be false for invalid JSON, got true")
	}
	if !strings.Contains(result.Diff, "Content differs (Non-JSON or mixed types)") {
		t.Errorf("Expected diff to indicate non-JSON content, got: %s", result.Diff)
	}
}

// FuzzCompare tests for panics and key semantic invariants (Symmetry and Reflexivity).
func FuzzCompare(f *testing.F) {
	f.Add([]byte(`{"session_id": "S1", "user": "A"}`), []byte(`{"session_id": "S2", "user": "A"}`))
	f.Add([]byte(`[1, 2]`), []byte(`[2, 1]`))
	f.Add([]byte(`invalid json`), []byte(`{`))

	opts := DefaultOptions()
	// Use the globally initialized logger
	service := NewService(observability.GetLogger())

	f.Fuzz(func(t *testing.T, dataA, dataB []byte) {
		resAB, errA := service.CompareWithOptions(dataA, dataB, opts)
		resBA, errB := service.CompareWithOptions(dataB, dataA, opts)

		// The fuzzer automatically finds panics. Here, we add checks for logical invariants.
		if errA != nil || errB != nil {
			t.Fatalf("Symmetry broken: Compare(A, B) error state was %v, but Compare(B, A) was %v", errA, errB)
		}

		if resAB.AreEquivalent != resBA.AreEquivalent {
			t.Errorf("Symmetry violated: Compare(A, B) = %v, Compare(B, A) = %v", resAB.AreEquivalent, resBA.AreEquivalent)
		}

		// Check Reflexivity: Compare(A, A) must always be true.
		resAA, errAA := service.CompareWithOptions(dataA, dataA, opts)
		if errAA != nil {
			t.Fatalf("Reflexivity check failed with an error: %v", errAA)
		}
		if !resAA.AreEquivalent {
			t.Errorf("Reflexivity violated: Compare(A, A) returned false for input:\n%s", string(dataA))
		}
	})
}

// runCompareTest is a helper that runs a single comparison and verifies internal consistency.
func runCompareTest(t *testing.T, svc JSONComparison, name, jsonA, jsonB string, opts Options, expectEqual bool) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		t.Parallel()
		s := svc.(*service) // Assert to concrete type to access unexported methods.
		result, err := s.CompareWithOptions([]byte(jsonA), []byte(jsonB), opts)
		if err != nil {
			t.Fatalf("Compare() returned unexpected error: %v", err)
		}
		if result.AreEquivalent != expectEqual {
			t.Errorf("Compare() AreEquivalent = %v, want %v.\nDiff:\n%s", result.AreEquivalent, expectEqual, result.Diff)
		}
		// Self-verification: re-compare the normalized structures to ensure consistency.
		cmpOptions := s.buildCmpOptions(opts)
		normalizedDiff := cmp.Diff(result.NormalizedA, result.NormalizedB, cmpOptions...)
		if (normalizedDiff == "") != expectEqual {
			t.Errorf("Internal inconsistency: normalized diff does not match expectation.\nNormalized Diff:\n%s", normalizedDiff)
		}
	})
}
