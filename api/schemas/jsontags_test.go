package schemas_test

import (
	"reflect"
	"testing"

	// Third party libraries for expressive and robust assertions.
	"github.com/stretchr/testify/assert"

	// Import the package we are testing.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestStructJSONTags uses reflection to verify that the `json` tags on struct fields
// are correct. This is critical for ensuring API contract stability.
func TestStructJSONTags(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name         string
		structRef    interface{}
		expectedTags map[string]string
	}{
		{
			name:      "Finding",
			structRef: schemas.Finding{},
			// FIX: Updated this map to match the refactored schemas.Finding struct
			expectedTags: map[string]string{
				"ID":                "id",
				"ScanID":            "scan_id",
				"TaskID":            "task_id",
				"ObservedAt":        "observed_at", // Was Timestamp
				"Target":            "target",
				"Module":            "module",
				"VulnerabilityName": "vulnerability_name", // Was Vulnerability
				"Severity":          "severity",
				"Description":       "description",
				"Evidence":          "evidence,omitempty", // Was "evidence"
				"Recommendation":    "recommendation",
				"CWE":               "cwe,omitempty",
			},
		},
		{
			name:      "ResultEnvelope",
			structRef: schemas.ResultEnvelope{},
			expectedTags: map[string]string{
				"ScanID":    "scan_id",
				"TaskID":    "task_id",
				"Timestamp": "timestamp",
				"Findings":  "findings",
				"KGUpdates": "kg_updates,omitempty",
			},
		},
		{
			name:      "NodeInput",
			structRef: schemas.NodeInput{},
			expectedTags: map[string]string{
				"ID":         "id",
				"Type":       "type",
				"Label":      "label",
				"Status":     "status",
				"Properties": "properties",
			},
		},
		{
			name:      "EdgeInput",
			structRef: schemas.EdgeInput{},
			expectedTags: map[string]string{
				"ID":         "id",
				"From":       "from",
				"To":         "to",
				"Type":       "type",
				"Label":      "label",
				"Properties": "properties",
			},
		},
	}

	for _, tc := range testCases {
		// Capture the range variable to avoid issues in parallel tests.
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			structType := reflect.TypeOf(tt.structRef)
			actualTags := make(map[string]string)

			// Go through all the fields in the struct.
			for i := 0; i < structType.NumField(); i++ {
				field := structType.Field(i)
				jsonTag := field.Tag.Get("json")
				// Only add fields that actually have a json tag.
				if jsonTag != "" {
					actualTags[field.Name] = jsonTag
				}
			}

			// Verify that the collected tags match the expected ones.
			// This will also catch cases where a field is missing from expectedTags
			// or an unexpected field with a tag exists on the struct.
			assert.Equal(t, tt.expectedTags, actualTags, "JSON tags for struct %s do not match expectations", tt.name)
		})
	}
}
