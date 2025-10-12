// comparison.go
package idor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings" // Added import
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
)

// Placeholders for normalized data
const (
	PlaceholderDynamicKey   = "__DYNAMIC_KEY__"
	PlaceholderDynamicValue = "__DYNAMIC_VALUE__"
)

// DefaultHeuristicRules provides a sensible default configuration.
func DefaultHeuristicRules() HeuristicRules {
	return HeuristicRules{
		KeyPatterns: []*regexp.Regexp{
			// Common patterns: session IDs, tokens, CSRF, nonces, correlation IDs
			regexp.MustCompile(`(?i)sess(ion)?_?(id|key|token)?`),
			regexp.MustCompile(`(?i)(csrf|xsrf|api_?key|auth_?token|authorization)`),
			regexp.MustCompile(`(?i)(correlation|request|trace|tx)_?id`),
			regexp.MustCompile(`(?i)nonce`),
			// Dynamic session keys like "session_abc123"
			regexp.MustCompile(`(?i)session_[a-zA-Z0-9_-]+`),
		},
		CheckValueForUUID:              true,
		CheckValueForTimestamp:         true,
		CheckValueForHighEntropy:       true,
		EntropyThreshold:               4.5,  // Standard threshold for identifying secrets/tokens
		IgnoreArrayOrder:               true, // Often useful as API list orders can be non-deterministic
		SpecificValuesToIgnore:         make(map[string]struct{}),
		NormalizeAllValuesForStructure: false, // Default to false (semantic comparison)
	}
}

// Normalizer applies heuristic rules to a parsed JSON structure.
type Normalizer struct {
	Rules HeuristicRules
}

// NewNormalizer creates a new normalizer.
func NewNormalizer(rules HeuristicRules) *Normalizer {
	return &Normalizer{Rules: rules}
}

// Normalize recursively traverses the data structure (Explicit Pre-Comparison Normalization).
func (n *Normalizer) Normalize(data interface{}) interface{} {
	return n.normalizeRecursive(data)
}

func (n *Normalizer) normalizeRecursive(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		return n.normalizeMap(v)
	case []interface{}:
		return n.normalizeSlice(v)
	default:
		// Check primitives for dynamic values (e.g., a UUID string at the root)
		if n.isValueDynamic(v) {
			return PlaceholderDynamicValue
		}
		return data
	}
}

// normalizeMap handles normalization of JSON objects, including robust collision handling.
func (n *Normalizer) normalizeMap(m map[string]interface{}) map[string]interface{} {
	// Create a new map for the normalized output.
	// Optimization: In high-throughput systems, sync.Pool could be used here to reduce GC pressure.
	normalizedMap := make(map[string]interface{}, len(m))

	// MODIFICATION: Pre-calculate the base for numbered keys.
	// If PlaceholderDynamicKey is "__DYNAMIC_KEY__", baseKey becomes "__DYNAMIC_KEY_".
	baseKey := strings.TrimSuffix(PlaceholderDynamicKey, "__")
	if baseKey != PlaceholderDynamicKey {
		// Suffix was trimmed, add back a single underscore for formatting.
		baseKey += "_"
	} else {
		// Fallback if the placeholder doesn't end in "__"
		baseKey += "_"
	}

	for key, val := range m {
		newKey := key
		// 1. Check if the key itself is dynamic (e.g., "session_abc")
		if n.isKeyDynamic(key) {
			newKey = PlaceholderDynamicKey
		}

		// 2. Check if the value is dynamic or recurse
		newVal := val
		if n.isValueDynamic(val) {
			newVal = PlaceholderDynamicValue
		} else {
			// If the value is not dynamic, recurse into it
			newVal = n.normalizeRecursive(val)
		}

		// 3. Handle potential key collisions using the "numbered keys" strategy.
		// This ensures we don't lose structural information if multiple dynamic keys exist.
		if newKey == PlaceholderDynamicKey {
			i := 0
			collisionKey := PlaceholderDynamicKey
			for {
				if _, exists := normalizedMap[collisionKey]; !exists {
					newKey = collisionKey
					break
				}
				i++
				// e.g., __DYNAMIC_KEY_1, __DYNAMIC_KEY_2
				// MODIFICATION: Use the pre-calculated baseKey
				collisionKey = fmt.Sprintf("%s%d", baseKey, i)
			}
		}

		normalizedMap[newKey] = newVal
	}
	return normalizedMap
}

func (n *Normalizer) normalizeSlice(s []interface{}) []interface{} {
	normalizedSlice := make([]interface{}, len(s))
	for i, val := range s {
		normalizedSlice[i] = n.normalizeRecursive(val)
	}
	return normalizedSlice
}

// isKeyDynamic checks if a key matches configured patterns.
func (n *Normalizer) isKeyDynamic(key string) bool {
	for _, pattern := range n.Rules.KeyPatterns {
		if pattern.MatchString(key) {
			return true
		}
	}
	return false
}

// isValueDynamic applies value-based heuristics (Specific Values, UUID, Timestamp, Entropy).
func (n *Normalizer) isValueDynamic(val interface{}) bool {

	// Layer -1: Structural normalization override (for Manipulation tests)
	// This check is prioritized for efficiency.
	if n.Rules.NormalizeAllValuesForStructure {
		// Check if val is a primitive type (string, number, boolean, nil).
		switch val.(type) {
		case map[string]interface{}, []interface{}:
			// Do not normalize structures themselves; recursion handles their contents.
			return false
		default:
			// Normalize all primitives (string, float64, json.Number, bool, nil, native ints).
			return true
		}
	}

	// Layer 0: Specific Value Matching (Used for Manipulation tests)
	if len(n.Rules.SpecificValuesToIgnore) > 0 {
		// Convert value to string for comparison against the ignore list.
		// This handles numeric (including json.Number) and string types consistently.
		strVal := fmt.Sprintf("%v", val)
		if _, exists := n.Rules.SpecificValuesToIgnore[strVal]; exists {
			return true
		}
	}

	// Remaining heuristics primarily apply to string representations.
	s, ok := val.(string)
	if !ok {
		// Handle json.Number if it was used during unmarshal
		if num, ok := val.(json.Number); ok {
			s = num.String()
		} else {
			// If it's not a string or json.Number, and wasn't caught by SpecificValuesToIgnore, it's likely not dynamic.
			return false
		}
	}

	// Layer 1: UUID Detection (High reliability)
	if n.Rules.CheckValueForUUID {
		// Use uuid.Parse for strict validation.
		if _, err := uuid.Parse(s); err == nil {
			return true
		}
	}

	// Layer 2: Timestamp Detection (Medium reliability)
	if n.Rules.CheckValueForTimestamp {
		// Check against common formats.
		formats := []string{time.RFC3339, time.RFC3339Nano, time.RFC1123, time.RFC1123Z, time.RFC822}
		for _, format := range formats {
			if _, err := time.Parse(format, s); err == nil {
				return true
			}
		}
	}

	// Layer 3: High-Entropy String Detection (Medium reliability)
	if n.Rules.CheckValueForHighEntropy {
		// Entropy check is meaningful only for reasonably long strings.
		if len(s) > 8 && calculateShannonEntropy(s) > n.Rules.EntropyThreshold {
			return true
		}
	}

	return false
}

// calculateShannonEntropy computes the Shannon entropy of a string in bits per character.
func calculateShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}

	// Count the frequency of each rune (character) in the string.
	runeCounts := make(map[rune]int)
	for _, r := range s {
		runeCounts[r]++
	}

	var entropy float64
	// Use RuneCountInString for accurate length with multi-byte characters.
	strLen := float64(utf8.RuneCountInString(s))

	// H(X) = -sum(p(x) * log2(p(x)))
	for _, count := range runeCounts {
		probability := float64(count) / strLen
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// ResponseComparisonResult holds the result of the semantic comparison.
type ResponseComparisonResult struct {
	AreEquivalent bool
	Diff          string
	IsJSON        bool
}

// CompareResponses performs a comparison of two response bodies.
// It uses semantic comparison for JSON and falls back to byte comparison otherwise.
func CompareResponses(bodyA, bodyB []byte, rules HeuristicRules) (*ResponseComparisonResult, error) {
	// Optimization: If byte representations are identical, they are equivalent.
	if bytes.Equal(bodyA, bodyB) {
		return &ResponseComparisonResult{AreEquivalent: true}, nil
	}

	var dataA, dataB interface{}

	// Use json.Number to ensure numeric precision is maintained during unmarshaling
	// This is crucial for SpecificValuesToIgnore matching numeric IDs correctly.
	decoderA := json.NewDecoder(bytes.NewReader(bodyA))
	decoderA.UseNumber()
	errA := decoderA.Decode(&dataA)

	decoderB := json.NewDecoder(bytes.NewReader(bodyB))
	decoderB.UseNumber()
	errB := decoderB.Decode(&dataB)

	// Case 1: Both are valid JSON. Proceed with normalization and semantic comparison.
	if errA == nil && errB == nil {
		// The Normalizer uses the provided rules, which might include SpecificValuesToIgnore.
		normalizer := NewNormalizer(rules)
		normalizedA := normalizer.Normalize(dataA)
		normalizedB := normalizer.Normalize(dataB)

		opts := cmp.Options{
			// Treat nil and empty slices/maps as equal (common in API responses).
			cmpopts.EquateEmpty(),
		}

		if rules.IgnoreArrayOrder {
			// Add an option to sort slices before comparison using a robust helper.
			opts = append(opts, cmpopts.SortSlices(interfaceSliceLess))
		}

		// Use cmp.Diff to get a detailed, human-readable diff if they are not equal.
		diff := cmp.Diff(normalizedA, normalizedB, opts...)

		return &ResponseComparisonResult{
			AreEquivalent: diff == "",
			Diff:          diff,
			IsJSON:        true,
		}, nil
	}

	// Case 2: One or neither are JSON (e.g., HTML, XML, or error messages).
	// Since we already checked for byte equality, we know they differ.
	// We report the difference based on length and JSON validity.
	diff := fmt.Sprintf("Content differs (Non-JSON or mixed types). Length A: %d (JSON: %v), Length B: %d (JSON: %v)",
		len(bodyA), errA == nil, len(bodyB), errB == nil)

	return &ResponseComparisonResult{
		AreEquivalent: false,
		Diff:          diff,
		IsJSON:        errA == nil || errB == nil, // True if at least one was JSON
	}, nil
}

// interfaceSliceLess is a helper function for cmpopts.SortSlices to compare two interface{} values.
// It attempts to provide a stable ordering for common JSON types.
func interfaceSliceLess(x, y interface{}) bool {
	// Handle nil
	if x == nil && y != nil {
		return true
	}
	if x != nil && y == nil {
		return false
	}

	// Handle json.Number specifically
	if nx, ok := x.(json.Number); ok {
		if ny, ok := y.(json.Number); ok {
			// Simple string comparison of json.Number works for ordering
			return nx.String() < ny.String()
		}
	}

	// Handle different types by comparing type names
	typeX := fmt.Sprintf("%T", x)
	typeY := fmt.Sprintf("%T", y)

	if typeX != typeY {
		return typeX < typeY
	}

	// Handle same types
	switch vx := x.(type) {
	case string:
		return vx < y.(string)
	case float64: // Standard float64 (if UseNumber was not used)
		return vx < y.(float64)
	case bool:
		// Sort false before true
		return !vx && y.(bool)
	case map[string]interface{}:
		// Maps are difficult to sort stably. We sort by the number of keys as a heuristic.
		return len(vx) < len(y.(map[string]interface{}))
	case []interface{}:
		// Slices are sorted by length.
		return len(vx) < len(y.([]interface{}))
	default:
		// Fallback for unknown types
		return fmt.Sprintf("%v", x) < fmt.Sprintf("%v", y)
	}
}
