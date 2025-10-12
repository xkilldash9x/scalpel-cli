// internal/jsoncompare/heuristics_test.go
package jsoncompare

import (
	"testing"
)

// TestDefaultRulesInitialization verifies that the default rules are initialized correctly
// and contain the expected baseline configurations.
func TestDefaultRulesInitialization(t *testing.T) {
	t.Parallel()
	rules := DefaultRules()

	// 1. Verify boolean flags are enabled by default.
	if !rules.CheckValueForUUID {
		t.Error("Expected CheckValueForUUID to be true by default")
	}
	if !rules.CheckValueForTimestamp {
		t.Error("Expected CheckValueForTimestamp to be true by default")
	}
	if !rules.CheckValueForHighEntropy {
		t.Error("Expected CheckValueForHighEntropy to be true by default")
	}

	// 2. Verify the default entropy threshold.
	expectedThreshold := 4.5
	if rules.EntropyThreshold != expectedThreshold {
		t.Errorf("Expected default EntropyThreshold %v, got %v", expectedThreshold, rules.EntropyThreshold)
	}

	// 3. Verify non-empty lists (ensures initialization occurred).
	if len(rules.KeyPatterns) == 0 {
		t.Error("Default KeyPatterns should not be empty")
	}
	if len(rules.TimestampFormats) == 0 {
		t.Error("Default TimestampFormats should not be empty")
	}

	// 4. Spot check a known pattern (e.g., session_id).
	foundSessionID := false
	for _, p := range rules.KeyPatterns {
		if p.MatchString("session_id") {
			foundSessionID = true
			break
		}
	}
	if !foundSessionID {
		t.Error("Expected default KeyPatterns to include a pattern matching 'session_id'")
	}
}
