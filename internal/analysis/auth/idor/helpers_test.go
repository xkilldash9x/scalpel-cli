// helpers_test.go
package idor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestExtractIdentifiers verifies identifier extraction from various parts of the request.
func TestExtractIdentifiers(t *testing.T) {
	// Setup the request
	url := "https://api.example.com/v1/users/12345/projects/f3f2e850-b5d4-11ef-ac7e-96584d5248b2?filter=active&account_id=98765"
	body := `{
		"project_name": "Test Project",
		"owner_uuid": "123e4567-e89b-12d3-a456-426614174000",
		"details": {
			"id": 555,
			"nested_uuid": "123e4567-e89b-12d3-a456-426614174001"
		},
		"tags": [
			{"id": 1, "value": "tag1"},
			{"id": 2, "value": "tag2"}
		]
	}`

	req, err := http.NewRequest("POST", url, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "123e4567-e89b-12d3-a456-426614174002")
	// Should be ignored
	req.Header.Set("Authorization", "Bearer 123e4567-e89b-12d3-a456-426614174003")

	expected := []ObservedIdentifier{
		// URL Path
		{Value: "12345", Type: TypeNumericID, Location: LocationURLPath, PathIndex: 3},
		{Value: "f3f2e850-b5d4-11ef-ac7e-96584d5248b2", Type: TypeUUID, Location: LocationURLPath, PathIndex: 5},
		// Query Params
		{Value: "98765", Type: TypeNumericID, Location: LocationQueryParam, Key: "account_id"},
		// Headers
		{Value: "123e4567-e89b-12d3-a456-426614174002", Type: TypeUUID, Location: LocationHeader, Key: "X-Request-Id"}, // JSON Body
		{Value: "123e4567-e89b-12d3-a456-426614174000", Type: TypeUUID, Location: LocationJSONBody, Key: "owner_uuid"},
		{Value: "555", Type: TypeNumericID, Location: LocationJSONBody, Key: "details.id"},
		{Value: "123e4567-e89b-12d3-a456-426614174001", Type: TypeUUID, Location: LocationJSONBody, Key: "details.nested_uuid"},
		{Value: "1", Type: TypeNumericID, Location: LocationJSONBody, Key: "tags[0].id"},
		{Value: "2", Type: TypeNumericID, Location: LocationJSONBody, Key: "tags[1].id"},
	}

	got := ExtractIdentifiers(req, []byte(body))

	// Use go-cmp for comparison, sorting slices to ensure stability regardless of map traversal order during extraction.
	sortOpt := cmpopts.SortSlices(func(a, b ObservedIdentifier) bool {
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Value < b.Value
	})

	if diff := cmp.Diff(expected, got, sortOpt); diff != "" {
		t.Errorf("ExtractIdentifiers() mismatch (-want +got):\n%s", diff)
	}
}

// TestParseJSONPath verifies the robust parsing of JSON path strings into segments.
func TestParseJSONPath(t *testing.T) {
	tests := []struct {
		input    string
		expected []interface{}
	}{
		{"user.profile.id", []interface{}{"user", "profile", "id"}},
		{"items[0].id", []interface{}{"items", 0, "id"}},
		{"data[1][2]", []interface{}{"data", 1, 2}},
		{"[0].name", []interface{}{0, "name"}}, // Root array access
		{"[5]", []interface{}{5}},
		{"simple", []interface{}{"simple"}},
		{"", nil},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseJSONPath(tt.input)
			if diff := cmp.Diff(tt.expected, got); diff != "" {
				t.Errorf("parseJSONPath() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestModifyJSONByPath verifies the modification of nested JSON structures.
func TestModifyJSONByPath(t *testing.T) {
	// Define a helper to unmarshal JSON string into interface{}
	unmarshal := func(s string) interface{} {
		var data interface{}
		// Use json.Number to preserve numeric types accurately
		decoder := json.NewDecoder(bytes.NewReader([]byte(s)))
		decoder.UseNumber()
		if err := decoder.Decode(&data); err != nil {
			t.Fatalf("Failed to unmarshal JSON: %v", err)
		}
		return data
	}

	tests := []struct {
		name         string
		inputJSON    string
		path         string
		newValue     string
		expectedJSON string
		expectErr    bool
	}{
		{
			name:         "Simple object key",
			inputJSON:    `{"id": 1, "name": "test"}`,
			path:         "name",
			newValue:     "modified",
			expectedJSON: `{"id": 1, "name": "modified"}`,
		},
		{
			name:      "Nested object key (Numeric replacement)",
			inputJSON: `{"user": {"profile": {"id": 1}}}`,
			path:      "user.profile.id",
			newValue:  "999",
			// Expected JSON should have numeric 999, not string "999", because we use json.Number.
			expectedJSON: `{"user": {"profile": {"id": 999}}}`,
		},
		{
			name:         "Array index",
			inputJSON:    `[10, 20, 30]`,
			path:         "[1]",
			newValue:     "99",
			expectedJSON: `[10, 99, 30]`,
		},
		{
			name:         "Nested array access",
			inputJSON:    `{"items": [{"id": 1}, {"id": 2}]}`,
			path:         "items[0].id",
			newValue:     "555",
			expectedJSON: `{"items": [{"id": 555}, {"id": 2}]}`,
		},
		// Error cases
		{
			name:      "Type mismatch (expected object)",
			inputJSON: `{"a": 1}`,
			path:      "a.b",
			newValue:  "test",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := unmarshal(tt.inputJSON)

			err := modifyJSONByPath(data, tt.path, tt.newValue)

			if tt.expectErr {
				if err == nil {
					t.Error("Expected an error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("modifyJSONByPath() returned unexpected error: %v", err)
			}

			expectedData := unmarshal(tt.expectedJSON)
			// modifyJSONByPath uses json.Number internally when the newValue is numeric, so cmp.Diff should handle it correctly.
			if diff := cmp.Diff(expectedData, data); diff != "" {
				t.Errorf("Modified JSON mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
