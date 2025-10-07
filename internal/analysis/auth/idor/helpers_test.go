// Using idor_test package for black-box testing style.
package idor_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/auth/idor"
	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// TestExtractIdentifiers tests the extraction logic, including known limitations.
func TestExtractIdentifiers(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		url      string
		body     string
		headers  map[string]string
		expected []core.ObservedIdentifier
	}{
		{
			name:   "URL Path and Query Params",
			method: "GET",
			url:    "http://example.com/users/12345/accounts/f47ac10b-58cc-4372-a567-0e02b2c3d479?id=99",
			expected: []core.ObservedIdentifier{
				{Value: "12345", Type: core.TypeNumericID, Location: core.LocationURLPath, PathIndex: 2},
				{Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479", Type: core.TypeUUID, Location: core.LocationURLPath, PathIndex: 4},
				{Value: "99", Type: core.TypeNumericID, Location: core.LocationQueryParam, Key: "id"},
			},
		},
		{
			name:   "JSON Body with String IDs (Nested and Arrays)",
			method: "POST",
			url:    "http://example.com/update",
			// The implementation only detects string values in JSON.
			body:    `{"userId": "555", "details": {"uuid": "11111111-2222-3333-4444-555555555555"}, "items": ["101"]}`,
			headers: map[string]string{"Content-Type": "application/json"},
			expected: []core.ObservedIdentifier{
				{Value: "555", Type: core.TypeNumericID, Location: core.LocationJSONBody, Key: "userId"},
				{Value: "11111111-2222-3333-4444-555555555555", Type: core.TypeUUID, Location: core.LocationJSONBody, Key: "details.uuid"},
				{Value: "101", Type: core.TypeNumericID, Location: core.LocationJSONBody, Key: "items[0]"},
			},
		},
		{
			name:   "Limitation: JSON Body with Numeric IDs (Not Detected)",
			method: "POST",
			url:    "http://example.com/update",
			// The implementation ignores JSON numbers as it only checks the 'string' case in the type switch.
			body:     `{"userId": 555, "uuid": "11111111-2222-3333-4444-555555555555"}`,
			headers:  map[string]string{"Content-Type": "application/json"},
			expected: []core.ObservedIdentifier{
				// Only the UUID (string) is detected.
				{Value: "11111111-2222-3333-4444-555555555555", Type: core.TypeUUID, Location: core.LocationJSONBody, Key: "uuid"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			results := idor.ExtractIdentifiers(req, []byte(tt.body))

			// Sort for reliable comparison
			sortIdentifiers(results)
			sortIdentifiers(tt.expected)

			if !reflect.DeepEqual(results, tt.expected) {
				t.Errorf("ExtractIdentifiers() mismatch.\nGot: %v\nExpected: %v", results, tt.expected)
			}
		})
	}
}

// Helper function to sort slices of ObservedIdentifier
func sortIdentifiers(ids []core.ObservedIdentifier) {
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Location != ids[j].Location {
			return ids[i].Location < ids[j].Location
		}
		if ids[i].Location == core.LocationURLPath {
			return ids[i].PathIndex < ids[j].PathIndex
		}
		if ids[i].Key != ids[j].Key {
			return ids[i].Key < ids[j].Key
		}
		return ids[i].Value < ids[j].Value
	})
}

func TestGenerateTestValue(t *testing.T) {
	tests := []struct {
		name     string
		ident    core.ObservedIdentifier
		expected string
		wantErr  bool
	}{
		{
			name:     "Numeric Increment",
			ident:    core.ObservedIdentifier{Value: "100", Type: core.TypeNumericID},
			expected: "101",
		},
		{
			name:     "UUID Modification",
			ident:    core.ObservedIdentifier{Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479", Type: core.TypeUUID},
			// Last byte (79 hex) increments to 7a hex.
			expected: "f47ac10b-58cc-4372-a567-0e02b2c3d47a",
		},
		{
			name:    "Invalid Numeric",
			ident:   core.ObservedIdentifier{Value: "abc", Type: core.TypeNumericID},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := idor.GenerateTestValue(tt.ident)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateTestValue() error = %v, wantErr %v", err, tt.wantErr)
			}
			if result != tt.expected {
				t.Errorf("GenerateTestValue() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestApplyTestValue(t *testing.T) {
	baseURL := "http://example.com"
	testValue := "999"

	// Test URL Path Replacement
	t.Run("URL Path Replacement", func(t *testing.T) {
		req, _ := http.NewRequest("GET", baseURL+"/api/resource/123", nil)
		ident := core.ObservedIdentifier{Location: core.LocationURLPath, PathIndex: 3, Value: "123"}

		newReq, _, err := idor.ApplyTestValue(req, nil, ident, testValue)
		if err != nil {
			t.Fatal(err)
		}
		if newReq.URL.Path != "/api/resource/999" {
			t.Errorf("Expected path /api/resource/999, got %s", newReq.URL.Path)
		}
		// Immutability Check (Best Practice 1.2)
		if req.URL.Path == newReq.URL.Path {
			t.Error("Original request URL was modified.")
		}
	})

	// Test Query Param Replacement
	t.Run("Query Param Replacement", func(t *testing.T) {
		req, _ := http.NewRequest("GET", baseURL+"/?id=123&sort=asc", nil)
		ident := core.ObservedIdentifier{Location: core.LocationQueryParam, Key: "id", Value: "123"}

		newReq, _, err := idor.ApplyTestValue(req, nil, ident, testValue)
		if err != nil {
			t.Fatal(err)
		}
		// Note: Query param order might change.
		if newReq.URL.Query().Get("id") != testValue {
			t.Errorf("Expected query id=999, got %s", newReq.URL.Query().Get("id"))
		}
	})

	// Test JSON Body Replacement (Top Level)
	t.Run("JSON Body Top Level", func(t *testing.T) {
		reqBody := `{"id": "123", "data": "abc"}`
		req, _ := http.NewRequest("POST", baseURL, bytes.NewReader([]byte(reqBody)))
		ident := core.ObservedIdentifier{Location: core.LocationJSONBody, Key: "id", Value: "123"}

		newReq, newBody, err := idor.ApplyTestValue(req, []byte(reqBody), ident, testValue)
		if err != nil {
			t.Fatal(err)
		}

		// Compare JSON objects
		var gotData, wantData map[string]interface{}
		json.Unmarshal(newBody, &gotData)
		wantData = map[string]interface{}{"id": "999", "data": "abc"}

		if !reflect.DeepEqual(gotData, wantData) {
			t.Errorf("JSON body mismatch. Got %s", string(newBody))
		}
		if newReq.ContentLength != int64(len(newBody)) {
			t.Errorf("ContentLength not updated correctly.")
		}
	})

	// Test JSON Body Replacement (Limitation: Nested fails)
	t.Run("Limitation: JSON Body Nested", func(t *testing.T) {
		reqBody := `{"user": {"id": "123"}}`
		req, _ := http.NewRequest("POST", baseURL, bytes.NewReader([]byte(reqBody)))
		// The implementation explicitly checks len(keys) == 1 and does not recurse for nested keys.
		ident := core.ObservedIdentifier{Location: core.LocationJSONBody, Key: "user.id", Value: "123"}

		_, newBody, err := idor.ApplyTestValue(req, []byte(reqBody), ident, testValue)
		if err != nil {
			t.Fatal(err)
		}

		// **FIXED**: Compare the data structures, not the raw strings, as re-marshalling can change whitespace.
		var originalData, newData map[string]interface{}
		if err := json.Unmarshal([]byte(reqBody), &originalData); err != nil {
			t.Fatalf("Could not unmarshal original request body: %v", err)
		}
		if err := json.Unmarshal(newBody, &newData); err != nil {
			t.Fatalf("Could not unmarshal new body: %v", err)
		}

		if !reflect.DeepEqual(originalData, newData) {
			t.Errorf("Expected JSON body to remain unchanged for nested keys, but it changed. Got: %s, Want: %s", string(newBody), reqBody)
		}
	})
}