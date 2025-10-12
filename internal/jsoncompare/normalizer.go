// internal/jsoncompare/normalizer.go
package jsoncompare

import (
	"math"
	"time"

	"github.com/google/uuid"
)

// Normalizer applies heuristic rules to a parsed JSON structure.
type Normalizer struct {
	Rules HeuristicRules
}

// NewNormalizer creates a new normalizer with the given rules.
func NewNormalizer(rules HeuristicRules) *Normalizer {
	return &Normalizer{Rules: rules}
}

// Normalize recursively traverses a parsed JSON structure (interface{}) and replaces
// dynamic keys and values with static placeholders.
func (n *Normalizer) Normalize(data interface{}) interface{} {
	// Check if the value itself is dynamic before structural traversal (Layer 2 Heuristics).
	if n.isValueDynamic(data) {
		return PlaceholderDynamicValue
	}

	switch v := data.(type) {
	case map[string]interface{}:
		return n.normalizeMap(v)
	case []interface{}:
		return n.normalizeSlice(v)
	default:
		// Primitive types that weren't flagged by isValueDynamic are returned as is.
		return data
	}
}

// normalizeMap handles the normalization of JSON objects, including dynamic keys.
func (n *Normalizer) normalizeMap(m map[string]interface{}) map[string]interface{} {
	normalizedMap := make(map[string]interface{}, len(m))
	// Collect values associated with dynamic keys (e.g., "session_abc", "session_xyz").
	var dynamicKeyValues []interface{}

	for key, val := range m {
		// First, recurse on the value. This ensures that dynamic values are normalized
		// before we decide what to do with the key.
		newVal := n.Normalize(val)

		// Then, check if the key itself is dynamic (Layer 1 Heuristic).
		if n.isKeyDynamic(key) {
			// If the key is dynamic, collect its normalized value into a shared slice.
			dynamicKeyValues = append(dynamicKeyValues, newVal)
		} else {
			// If the key is static, assign the normalized value to it.
			normalizedMap[key] = newVal
		}
	}

	if len(dynamicKeyValues) > 0 {
		// Store all collected values under the single placeholder key.
		// The comparison function MUST sort this slice for a correct, order-agnostic comparison.
		normalizedMap[PlaceholderDynamicKey] = dynamicKeyValues
	}

	return normalizedMap
}

func (n *Normalizer) normalizeSlice(s []interface{}) []interface{} {
	normalizedSlice := make([]interface{}, len(s))
	for i, val := range s {
		normalizedSlice[i] = n.Normalize(val)
	}
	return normalizedSlice
}

// isKeyDynamic checks Layer 1 heuristics against a map key.
func (n *Normalizer) isKeyDynamic(key string) bool {
	for _, pattern := range n.Rules.KeyPatterns {
		if pattern.MatchString(key) {
			return true
		}
	}
	return false
}

// isValueDynamic applies Layer 2 heuristics to a value.
func (n *Normalizer) isValueDynamic(val interface{}) bool {
	if val == nil {
		return false
	}

	switch v := val.(type) {
	case string:
		return n.isStringValueDynamic(v)
	case float64:
		// Check if it's a plausible Unix timestamp (in seconds, ms, or µs).
		if n.Rules.CheckValueForTimestamp && isPlausibleUnixTimestamp(v) {
			return true
		}
	}
	return false
}

func (n *Normalizer) isStringValueDynamic(s string) bool {
	// Optimization: Short strings are less likely to be dynamic identifiers.
	if len(s) < 10 {
		return false
	}

	// 1. UUID Detection (High reliability)
	if n.Rules.CheckValueForUUID {
		if _, err := uuid.Parse(s); err == nil {
			return true
		}
	}

	// 2. Timestamp Detection (Medium reliability)
	if n.Rules.CheckValueForTimestamp {
		for _, format := range n.Rules.TimestampFormats {
			if _, err := time.Parse(format, s); err == nil {
				return true
			}
		}
	}

	// 3. High-Entropy String Detection (Medium reliability)
	if n.Rules.CheckValueForHighEntropy {
		// Entropy is more meaningful on longer strings.
		if len(s) < 16 {
			return false
		}
		if calculateShannonEntropy(s) > n.Rules.EntropyThreshold {
			return true
		}
	}

	return false
}

// calculateShannonEntropy calculates the Shannon entropy of a string in bits per character.
func calculateShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freqMap := make(map[rune]int)
	for _, r := range s {
		freqMap[r]++
	}

	var entropy float64
	length := float64(len([]rune(s)))
	for _, count := range freqMap {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// isPlausibleUnixTimestamp checks if a number falls within a reasonable range for a Unix timestamp.
func isPlausibleUnixTimestamp(ts float64) bool {
	// Range: 2015-01-01 00:00:00 UTC to 2030-10-09 00:00:00 UTC
	const minTimestamp = 1420070400
	const maxTimestamp = 1917792000

	// Check seconds, milliseconds, and microseconds
	return (ts >= minTimestamp && ts <= maxTimestamp) ||
		(ts >= minTimestamp*1000 && ts <= maxTimestamp*1000) ||
		(ts >= minTimestamp*1000000 && ts <= maxTimestamp*1000000)
}
