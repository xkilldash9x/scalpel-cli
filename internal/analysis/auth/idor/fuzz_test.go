// fuzz_test.go
// Contains Fuzz tests for the idor package.
package idor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
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
		// Pass context.Background() for the fuzz environment.
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
