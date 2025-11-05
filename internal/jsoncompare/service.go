// File: internal/jsoncompare/service.go
package jsoncompare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// service is the concrete implementation of the JSONComparison interface.
type service struct {
	logger *zap.Logger
}

// NewService creates a new instance of the JSON comparison service.
func NewService(logger *zap.Logger) JSONComparison {
	return &service{
		logger: logger.Named("jsoncompare"),
	}
}

// Compare performs a comparison using default options.
func (s *service) Compare(bodyA, bodyB []byte) (*ComparisonResult, error) {
	return s.CompareWithOptions(bodyA, bodyB, DefaultOptions())
}

// CompareWithOptions performs a full semantic comparison using the specified options.
func (s *service) CompareWithOptions(bodyA, bodyB []byte, opts Options) (*ComparisonResult, error) {

	// Optimization: If byte representations are identical, they are equivalent.
	if bytes.Equal(bodyA, bodyB) {
		// Check if it's actually JSON for metadata purposes.
		isJSON := json.Valid(bodyA) && len(bodyA) > 0
		return &ComparisonResult{AreEquivalent: true, IsJSON: isJSON}, nil
	}

	var dataA, dataB interface{}
	var errA, errB error

	// 1. Parse JSON. UseNumber() maintains precision, crucial for SpecificValuesToIgnore.
	decoderA := json.NewDecoder(bytes.NewReader(bodyA))
	decoderA.UseNumber()
	errA = decoderA.Decode(&dataA)

	decoderB := json.NewDecoder(bytes.NewReader(bodyB))
	decoderB.UseNumber()
	errB = decoderB.Decode(&dataB)

	// Handle cases where one or both are not JSON.
	if errA != nil || errB != nil {
		return s.handleNonJSON(bodyA, bodyB, errA, errB), nil
	}

	// 2. Normalize the parsed data structures.
	normalizedA := s.normalize(dataA, opts)
	normalizedB := s.normalize(dataB, opts)

	// 3. Compare the normalized structures using google/go-cmp.
	cmpOptions := s.buildCmpOptions(opts)
	diff := cmp.Diff(normalizedA, normalizedB, cmpOptions...)
	areEqual := (diff == "")

	result := &ComparisonResult{
		AreEquivalent: areEqual,
		Diff:          diff,
		IsJSON:        true,
		NormalizedA:   normalizedA,
		NormalizedB:   normalizedB,
	}

	return result, nil
}

// handleNonJSON deals with cases where inputs are not valid JSON.
func (s *service) handleNonJSON(bodyA, bodyB []byte, errA, errB error) *ComparisonResult {
	// Since we already checked for byte equality, we know they differ.
	isJSON_A := (errA == nil)
	isJSON_B := (errB == nil)

	s.logger.Debug("Comparison involves non-JSON data",
		zap.Bool("isJSON_A", isJSON_A),
		zap.Bool("isJSON_B", isJSON_B),
	)

	diff := fmt.Sprintf("Content differs (Non-JSON or mixed types). Length A: %d (JSON: %v), Length B: %d (JSON: %v)",
		len(bodyA), isJSON_A, len(bodyB), isJSON_B)

	return &ComparisonResult{
		AreEquivalent: false,
		Diff:          diff,
		IsJSON:        isJSON_A || isJSON_B,
	}
}

// --- Normalization Logic (Consolidated) ---

// normalize is the entry point for the normalization process.
func (s *service) normalize(data interface{}, opts Options) interface{} {
	return s.normalizeRecursive(data, opts)
}

func (s *service) normalizeRecursive(data interface{}, opts Options) interface{} {
	// Check primitives first (Heuristics/Overrides).
	if s.isValueDynamic(data, opts) {
		return PlaceholderDynamicValue
	}

	switch v := data.(type) {
	case map[string]interface{}:
		return s.normalizeMap(v, opts)
	case []interface{}:
		return s.normalizeSlice(v, opts)
	default:
		return data
	}
}

// normalizeMap handles normalization of JSON objects, including robust collision handling for dynamic keys.
// Uses the "numbered keys" strategy migrated from idor/comparison.go.
func (s *service) normalizeMap(m map[string]interface{}, opts Options) map[string]interface{} {
	normalizedMap := make(map[string]interface{}, len(m))

	// Pre-calculate the base for numbered keys (e.g., "__DYNAMIC_KEY_").
	baseKey := strings.TrimSuffix(PlaceholderDynamicKey, "__") + "_"

	for key, val := range m {
		var newKey string
		var newVal interface{}

		// 1. Check if the key itself is dynamic (Heuristics).
		if s.isKeyDynamic(key, opts.Rules) {
			newKey = PlaceholderDynamicKey
			newVal = PlaceholderDynamicValue // If key is dynamic, value is also considered dynamic.
		} else {
			// 2. Normalize the value recursively only if the key is not dynamic.
			newKey = key
			newVal = s.normalizeRecursive(val, opts)
		}

		// 3. Handle potential key collisions.
		// This prevents overwriting data if multiple dynamic keys exist (e.g., "session_1" and "session_2").
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
				collisionKey = fmt.Sprintf("%s%d", baseKey, i)
			}
		}

		normalizedMap[newKey] = newVal
	}
	return normalizedMap
}

func (s *service) normalizeSlice(sl []interface{}, opts Options) []interface{} {
	normalizedSlice := make([]interface{}, len(sl))
	for i, val := range sl {
		normalizedSlice[i] = s.normalizeRecursive(val, opts)
	}
	return normalizedSlice
}

// --- Heuristic Checks ---

// isKeyDynamic checks key heuristics.
func (s *service) isKeyDynamic(key string, rules HeuristicRules) bool {
	for _, pattern := range rules.KeyPatterns {
		if pattern.MatchString(key) {
			return true
		}
	}
	return false
}

// isValueDynamic applies heuristics and overrides to a value.
func (s *service) isValueDynamic(val interface{}, opts Options) bool {

	// Override 1: Structural normalization.
	if opts.NormalizeAllValuesForStructure {
		// Check if val is a primitive type.
		switch val.(type) {
		case map[string]interface{}, []interface{}:
			return false // Structures are handled by recursion.
		default:
			return true // Normalize all primitives.
		}
	}

	// Override 2: Specific Value Matching.
	if len(opts.SpecificValuesToIgnore) > 0 {
		// Convert value to string for comparison. Handles numeric (including json.Number) and strings.
		strVal := fmt.Sprintf("%v", val)
		if _, exists := opts.SpecificValuesToIgnore[strVal]; exists {
			return true
		}
	}

	// Heuristics: Detection based on value type.
	if val == nil {
		return false
	}

	rules := opts.Rules
	switch v := val.(type) {
	case string:
		return s.isStringValueDynamic(v, rules)
	case json.Number:
		// Treat json.Number both as potential string and potential number.
		if s.isStringValueDynamic(v.String(), rules) {
			return true
		}
		if f, err := v.Float64(); err == nil {
			if rules.CheckValueForTimestamp && s.isPlausibleUnixTimestamp(f) {
				return true
			}
		}
	case float64:
		// Standard float64 (if UseNumber was not used during unmarshal).
		if rules.CheckValueForTimestamp && s.isPlausibleUnixTimestamp(v) {
			return true
		}
	}
	return false
}

func (s *service) isStringValueDynamic(str string, rules HeuristicRules) bool {
	// Optimization: Short strings are less likely to be dynamic identifiers.
	if len(str) < 8 {
		return false
	}

	// 1. UUID Detection
	if rules.CheckValueForUUID {
		if _, err := uuid.Parse(str); err == nil {
			return true
		}
	}

	// 2. Timestamp Detection
	if rules.CheckValueForTimestamp {
		for _, format := range rules.TimestampFormats {
			if _, err := time.Parse(format, str); err == nil {
				return true
			}
		}
	}

	// 3. High-Entropy String Detection
	if rules.CheckValueForHighEntropy {
		// Entropy is more meaningful on longer strings.
		if len(str) >= 12 {
			if s.calculateShannonEntropy(str) > rules.EntropyThreshold {
				return true
			}
		}
	}

	return false
}

// calculateShannonEntropy computes the Shannon entropy of a string.
func (s *service) calculateShannonEntropy(str string) float64 {
	if str == "" {
		return 0
	}

	runeCounts := make(map[rune]int)
	for _, r := range str {
		runeCounts[r]++
	}

	var entropy float64
	strLen := float64(utf8.RuneCountInString(str))

	// H(X) = -sum(p(x) * log2(p(x)))
	for _, count := range runeCounts {
		probability := float64(count) / strLen
		entropy -= probability * math.Log2(probability)
	}

	return entropy
}

// isPlausibleUnixTimestamp checks if a number falls within a reasonable range.
func (s *service) isPlausibleUnixTimestamp(ts float64) bool {
	// Range: 2010-01-01 to 2035-01-01 (Approximate)
	const minTimestamp = 1262304000
	const maxTimestamp = 2051222400

	// Check seconds, milliseconds, and microseconds.
	return (ts >= minTimestamp && ts <= maxTimestamp) ||
		(ts >= minTimestamp*1000 && ts <= maxTimestamp*1000) ||
		(ts >= minTimestamp*1000000 && ts <= maxTimestamp*1000000)
}

// --- Comparison Logic (go-cmp integration) ---

// buildCmpOptions assembles the necessary options for the go-cmp library.
func (s *service) buildCmpOptions(opts Options) cmp.Options {
	var cmpOpts cmp.Options

	if opts.EquateEmpty {
		// Use the custom equateEmptyOption to correctly handle interface{} types (JSON null vs {}).
		cmpOpts = append(cmpOpts, s.equateEmptyOption())
	}

	if opts.IgnoreArrayOrder {
		// Sort slices before comparison using a robust, generic helper.
		cmpOpts = append(cmpOpts, cmpopts.SortSlices(s.genericSliceLess))
	}

	return cmpOpts
}

// isEmpty checks if the value represents an empty state in JSON context.
func (s *service) isEmpty(v interface{}) bool {
	if v == nil {
		// Untyped nil interface (JSON null).
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map, reflect.Slice:
		return rv.Len() == 0
	}
	return false
}

// equateEmptyOption implements the logic for Options.EquateEmpty.
// Standard cmpopts.EquateEmpty() doesn't consider a nil interface{} (JSON null) as "empty".
func (s *service) equateEmptyOption() cmp.Option {
	return cmp.FilterValues(
		func(x, y interface{}) bool {
			// Apply this custom comparison only if both values are "empty".
			return s.isEmpty(x) && s.isEmpty(y)
		},
		cmp.Comparer(func(x, y interface{}) bool {
			// Both values are confirmed empty by the filter.

			// Check if either value is an untyped nil (representing JSON null).
			isXNull := (x == nil)
			isYNull := (y == nil)

			if isXNull || isYNull {
				// If either is Null, they are equal because the other is also empty.
				return true
			}

			// Both are non-null empty structures. They must be of the same kind (Ensures {} != []).
			return reflect.ValueOf(x).Kind() == reflect.ValueOf(y).Kind()
		}),
	)
}

// genericSliceLess provides a "less than" function for sorting slices of `interface{}`.
func (s *service) genericSliceLess(x, y interface{}) bool {
	// Handle json.Number specifically first.
	nx, okX := x.(json.Number)
	ny, okY := y.(json.Number)

	if okX && okY {
		// Attempt numeric comparison, fallback to string comparison for stability.
		fx, errX := nx.Float64()
		fy, errY := ny.Float64()
		if errX == nil && errY == nil {
			return fx < fy
		}
		return nx.String() < ny.String()
	}

	vx := reflect.ValueOf(x)
	vy := reflect.ValueOf(y)

	// Handle nil: A nil value is always considered "less than" a non-nil value.
	if !vx.IsValid() {
		return vy.IsValid()
	}
	if !vy.IsValid() {
		return false
	}

	// If types differ, sort by type name for a stable order.
	if vx.Type() != vy.Type() {
		return vx.Type().String() < vy.Type().String()
	}

	// Handle same types
	switch vx.Kind() {
	case reflect.String:
		return vx.String() < vy.String()
	case reflect.Float64: // Standard JSON numbers (if UseNumber was not used)
		return vx.Float() < vy.Float()
	case reflect.Bool:
		return !vx.Bool() && vy.Bool() // false < true
	default:
		// For complex types (maps, slices), use fmt.Sprint as a fallback for deterministic ordering.
		return fmt.Sprint(x) < fmt.Sprint(y)
	}
}
