// fuzz_test.go
// Contains Fuzz tests for the idor package.
package idor

import (
	"bytes"
	"context" // Added import
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
)

// FuzzExtractIdentifiers tests the robustness of the identifier extraction logic against
// various URL formats, headers, and JSON bodies.
func FuzzExtractIdentifiers(f *testing.F) {
	// Seed corpus: Provide diverse examples of valid inputs to guide the fuzzer.
	f.Add("GET", "https://example.com/users/123/posts/f3f2e850-b5d4-11ef-ac7e-96584d5248b2?q=test", "X-Trace-Id: abc", `{"id": 456, "uuid": "a1b2c3d4-e5f6-7890-1234-567890abcdef"}`)
	f.Add("POST", "https://api.test.com/v1/items", "Content-Type: application/json", `[{"id": 1}, {"id": 2}]`)
	f.Add("PUT", "http://localhost/resource/999999999999999", "", "")

	// Fuzz target
	f.Fuzz(func(t *testing.T, method, rawURL, headerLine, body string) {
		// 1. Input Validation/Sanitization (Necessary for creating valid http.Request)
		if method == "" || rawURL == "" {
			t.Skip()
		}

		// Attempt to parse the URL. If it fails, the input is not interesting for this target.
		parsedURL, err := url.Parse(rawURL)
		if err != nil || (parsedURL.Host == "" && !strings.HasPrefix(rawURL, "/")) {
			t.Skip()
		}

		req, err := http.NewRequest(method, rawURL, nil)
		if err != nil {
			// Invalid method or URL format
			t.Skip()
		}

		// Attempt to parse the fuzzed header line (simple Key: Value format)
		if parts := strings.SplitN(headerLine, ":", 2); len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}

		// If the body looks like JSON, set the content type header if not already set.
		trimmedBody := strings.TrimSpace(body)
		if strings.HasPrefix(trimmedBody, "{") || strings.HasPrefix(trimmedBody, "[") {
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/json")
			}
		}

		// 2. Execute the function under test
		// The primary goal here is to ensure it does not panic or hang.
		identifiers := ExtractIdentifiers(req, []byte(body))

		// 3. Assertions (Invariants)
		for _, id := range identifiers {
			if id.Value == "" {
				t.Errorf("Extracted identifier has empty Value: %+v", id)
			}
		}
	})
}

// FuzzApplyTestValue tests the robustness of the request modification logic,
// particularly the complex JSON path modification.
func FuzzApplyTestValue(f *testing.F) {
	// Seed corpus: Examples of valid identifiers and JSON structures.
	f.Add("user.id", "123", `{"user": {"id": 101, "name": "Alice"}}`)
	f.Add("items[0].id", "999", `{"items": [{"id": 1}, {"id": 2}]}`)
	f.Add("[0].name", "Bob", `[{"name": "Alice"}]`)

	f.Fuzz(func(t *testing.T, path, testValue, jsonBody string) {
		// 1. Input Validation
		if jsonBody == "" || path == "" || testValue == "" {
			t.Skip()
		}

		// We specifically target JSON body modification here.
		ident := ObservedIdentifier{
			Location: LocationJSONBody,
			Key:      path,
		}

		// Create a dummy request
		req, _ := http.NewRequest("POST", "https://example.com", nil)
		req.Header.Set("Content-Type", "application/json")

		// 2. Execute the function under test
		// MODIFICATION: Pass context.Background() for the fuzz environment.
		newReq, newBody, err := ApplyTestValue(context.Background(), req, []byte(jsonBody), ident, testValue)

		// 3. Assertions
		if err != nil {
			// It's acceptable for ApplyTestValue to return an error if the JSON is invalid
			// or the path does not exist in the structure. We skip these cases.
			t.Skip()
		}

		// If successful, the new request and body must be valid.
		if newReq == nil {
			t.Fatal("newReq should not be nil on success")
		}

		// The new body must be valid JSON if the operation succeeded.
		var data interface{}
		if err := json.Unmarshal(newBody, &data); err != nil {
			t.Fatalf("ApplyTestValue produced invalid JSON body: %s\nError: %v", string(newBody), err)
		}
	})
}

// FuzzNormalizer_Robustness tests the Normalizer against arbitrary, complex JSON inputs
// to ensure it handles deep nesting, unusual structures, and various data types without panicking.
// This aligns with the Fuzzing Strategy document (Part 3: Handling Complex Data Structures).
func FuzzNormalizer_Robustness(f *testing.F) {
	// Seed corpus with various valid JSON structures
	f.Add(`{"a": 1, "b": "string", "c": true}`)
	f.Add(`[1, 2, 3, "four"]`)
	f.Add(`{"nested": {"array": [{}, {"key": "value"}]}}`)
	f.Add(`null`)
	f.Add(fmt.Sprintf(`{"uuid": "%s"}`, uuid.NewString()))

	// Use default rules for normalization
	rules := DefaultHeuristicRules()
	normalizer := NewNormalizer(rules)

	f.Fuzz(func(t *testing.T, jsonData string) {
		// 1. Input Validation: Check if the input is valid JSON.
		var data interface{}

		// Use Decoder with UseNumber for consistency with the implementation
		decoder := json.NewDecoder(bytes.NewReader([]byte(jsonData)))
		decoder.UseNumber()
		if err := decoder.Decode(&data); err != nil {
			// If it's not valid JSON, the normalizer is not expected to process it.
			t.Skip()
		}

		// 2. Execute the function under test
		// The primary goal is to ensure Normalize completes without panicking.
		normalized := normalizer.Normalize(data)

		// 3. Assertions (Invariants)
		// The normalized output must be serializable back to JSON (i.e., contains only valid types).
		_, err := json.Marshal(normalized)
		if err != nil {
			t.Fatalf("Normalized data is not valid JSON serializable: %v\nData: %+v", err, normalized)
		}

		// If the input was a map, the output must also be a map (structure preservation).
		if _, ok := data.(map[string]interface{}); ok {
			if _, ok := normalized.(map[string]interface{}); !ok {
				t.Errorf("Input was a map, but normalized output was %T", normalized)
			}
		}

		// If the input was a slice, the output must also be a slice of the same length.
		if inputSlice, ok := data.([]interface{}); ok {
			if outputSlice, ok := normalized.([]interface{}); !ok {
				t.Errorf("Input was a slice, but normalized output was %T", normalized)
			} else if len(inputSlice) != len(outputSlice) {
				t.Errorf("Input slice length %d differs from output slice length %d", len(inputSlice), len(outputSlice))
			}
		}
	})
}

// FuzzCompareResponses_StructureAware utilizes a structure-aware approach to generate
// two related JSON documents and test the comparison logic.
func FuzzCompareResponses_StructureAware(f *testing.F) {
	// We fuzz a single JSON structure and a mutation strategy.
	f.Add(`{"a": 1, "b": [2, 3]}`, 1)
	f.Add(`{"session": "abc", "data": "xyz"}`, 2)

	rules := DefaultHeuristicRules()

	f.Fuzz(func(t *testing.T, jsonA string, mutationStrategy int) {
		// 1. Validate Input A
		var dataA interface{}
		if err := json.Unmarshal([]byte(jsonA), &dataA); err != nil {
			t.Skip()
		}

		// 2. Generate Input B by copying A and applying a mutation
		// This ensures B is structurally similar but potentially different in value.
		dataB := deepCopyJSON(dataA)

		// Apply a simple mutation based on the fuzzed strategy integer
		mutateJSON(dataB, mutationStrategy)

		jsonB, err := json.Marshal(dataB)
		if err != nil {
			t.Skip() // Should not happen if deepCopy and mutateJSON are correct
		}

		// 3. Execute Comparison
		result, err := CompareResponses([]byte(jsonA), jsonB, rules)
		if err != nil {
			t.Fatalf("CompareResponses failed unexpectedly: %v", err)
		}

		// 4. Assertions
		if !result.IsJSON {
			t.Error("Expected IsJSON to be true for valid JSON inputs.")
		}

		// Validate the result against a direct comparison without normalization (as a sanity check)
		// If they are different without normalization, the comparison engine must report a difference or equivalence correctly.
		directDiff := cmp.Diff(dataA, dataB)
		if directDiff != "" && !result.AreEquivalent && result.Diff == "" {
			// If they are different, and the engine says they are different, the diff must not be empty.
			t.Errorf("Comparison reported difference, but Diff string is empty. Direct Diff:\n%s", directDiff)
		}
	})
}

// Helper functions for structure-aware fuzzing (deep copy and mutation)

func deepCopyJSON(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		newMap := make(map[string]interface{}, len(v))
		for key, val := range v {
			newMap[key] = deepCopyJSON(val)
		}
		return newMap
	case []interface{}:
		newSlice := make([]interface{}, len(v))
		for i, val := range v {
			newSlice[i] = deepCopyJSON(val)
		}
		return newSlice
	default:
		return v
	}
}

// mutateJSON applies a simple modification to the structure based on the strategy integer.
// This is a simplistic mutation approach for demonstration.
func mutateJSON(data interface{}, strategy int) {
	switch v := data.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			return
		}
		// Iterate and mutate the first element found based on strategy
		for key, val := range v {
			switch strategy % 3 {
			case 0:
				// Change value
				if s, ok := val.(string); ok {
					v[key] = s + "_mutated"
					return
				}
			case 1:
				// Delete key
				delete(v, key)
				return
			case 2:
				// Recurse
				mutateJSON(val, strategy)
			}
		}
	case []interface{}:
		if len(v) == 0 {
			return
		}
		index := strategy % len(v)
		// Mutate element
		mutateJSON(v[index], strategy)
	}
}
