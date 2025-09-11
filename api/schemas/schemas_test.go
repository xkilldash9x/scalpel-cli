package schemas_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	// Third party libraries for expressive and robust assertions.
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import the package we are testing.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// -- Test Helpers --

// getTestTime provides a fixed, reproducible timestamp for consistent test results.
func getTestTime(t *testing.T) time.Time {
	// Using RFC3339Nano ensures maximum precision, and UTC avoids timezone issues.
	ts, err := time.Parse(time.RFC3339Nano, "2025-10-26T10:00:00.123456789Z")
	require.NoError(t, err, "Test setup failed: unable to parse fixed timestamp")
	return ts
}

// -- Test Cases --

// TestConstants verifies that all defined constants hold their expected string values.
// This prevents accidental changes to values that might be used in APIs or databases.
func TestConstants(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name     string
		constant fmt.Stringer
		expected string
	}{
		// TaskTypes
		{"TaskAgentMission", schemas.TaskAgentMission, "AGENT_MISSION"},
		{"TaskAnalyzeWebPageTaint", schemas.TaskAnalyzeWebPageTaint, "ANALYZE_WEB_PAGE_TAINT"},
		{"TaskAnalyzeHeaders", schemas.TaskAnalyzeHeaders, "ANALYZE_HEADERS"},
		{"TaskAnalyzeJWT", schemas.TaskAnalyzeJWT, "ANALYZE_JWT"},

		// Severities
		{"SeverityCritical", schemas.SeverityCritical, "CRITICAL"},
		{"SeverityHigh", schemas.SeverityHigh, "HIGH"},
		{"SeverityInformational", schemas.SeverityInformational, "INFORMATIONAL"},
	}

	for _, tc := range testCases {
		// Capture range variable for parallel execution.
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.constant.String())
		})
	}
}

// TestStructJSONTags uses reflection to verify that the `json` tags on struct fields
// are correct. This is critical for ensuring API contract stability and correct
// serialization/deserialization.
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
			expectedTags: map[string]string{
				"ID":             "id",
				"TaskID":         "task_id",
				"Timestamp":      "timestamp",
				"Target":         "target",
				"Module":         "module",
				"Vulnerability":  "vulnerability",
				"Severity":       "severity",
				"Description":    "description",
				"Evidence":       "evidence",
				"Recommendation": "recommendation",
				"CWE":            "cwe",
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
				"KGUpdates": "kg_updates",
			},
		},
		{
			name:      "NodeInput",
			structRef: schemas.NodeInput{},
			expectedTags: map[string]string{
				"ID":         "id",
				"Type":       "type",
				"Properties": "properties",
			},
		},
		{
			name:      "EdgeInput",
			structRef: schemas.EdgeInput{},
			expectedTags: map[string]string{
				"SourceID":     "source_id",
				"TargetID":     "target_id",
				"Relationship": "relationship",
				"Properties":   "properties",
			},
		},
	}

	for _, tc := range testCases {
		tt := tc
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			structType := reflect.TypeOf(tt.structRef)
			for fieldName, expectedTag := range tt.expectedTags {
				field, found := structType.FieldByName(fieldName)
				require.True(t, found, "Field '%s' not found in struct '%s'", fieldName, tt.name)
				actualTag := field.Tag.Get("json")
				assert.Equal(t, expectedTag, actualTag, "JSON tag mismatch for field '%s.%s'", tt.name, fieldName)
			}
		})
	}
}

// TestSerializationCycle performs a round trip test (marshal to JSON -> unmarshal from JSON).
// It verifies that a struct's data integrity is maintained throughout serialization,
// which is essential for data transfer and persistence.
func TestSerializationCycle(t *testing.T) {
	t.Parallel()
	timestamp := getTestTime(t)

	// NOTE on map[string]interface{}: When Go's json library unmarshals into an
	// interface{}, it converts all JSON numbers to float64. To ensure a successful
	// reflect.DeepEqual comparison, the original structs must also use float64
	// for numeric types within these maps.
	finding := schemas.Finding{
		ID:          "finding-001",
		TaskID:      "task-abc",
		Timestamp:   timestamp,
		Target:      "https://example.com/login",
		Module:      "PassiveHeaderAnalysis",
		Description: "Missing Content-Security-Policy header.",
		Evidence:    "Response headers did not contain CSP.",
		Vulnerability: schemas.Vulnerability{
			Name:        "Missing Security Header",
			Description: "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.",
		},
		Severity:       schemas.SeverityMedium,
		Recommendation: "Implement a strict Content-Security-Policy header.",
		CWE:            []string{"CWE-693"},
	}

	nodeInput := schemas.NodeInput{
		ID:   "host-123",
		Type: schemas.NodeType("Host"),
		Properties: map[string]interface{}{
			"ip":     "192.168.1.100",
			"ports":  []interface{}{float64(80), float64(443)}, // Use float64 for numbers
			"active": true,
		},
	}

	edgeInput := schemas.EdgeInput{
		SourceID:     "host-123",
		TargetID:     "service-80",
		Relationship: schemas.RelationshipType("EXPOSES"),
		Properties: map[string]interface{}{
			"protocol": "tcp",
		},
	}

	envelope := schemas.ResultEnvelope{
		ScanID:    "scan-xyz",
		TaskID:    "task-abc",
		Timestamp: timestamp,
		Findings:  []schemas.Finding{finding},
		KGUpdates: &schemas.KnowledgeGraphUpdate{
			Nodes: []schemas.NodeInput{nodeInput},
			Edges: []schemas.EdgeInput{edgeInput},
		},
	}

	// Marshal the original object to JSON.
	data, err := json.Marshal(envelope)
	require.NoError(t, err, "Marshalling ResultEnvelope should not fail")

	// Unmarshal back into a new object.
	var unmarshaled schemas.ResultEnvelope
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err, "Unmarshalling ResultEnvelope should not fail")

	// Verify that the original and unmarshaled objects are identical.
	// reflect.DeepEqual provides a robust, recursive comparison.
	assert.True(t, reflect.DeepEqual(envelope, unmarshaled), "Original and unmarshaled objects should be identical")
}

// TestInterfaceHandlingBehavior explicitly verifies how the json library decodes
// different JSON types into the `map[string]interface{}` used in our schemas.
// This confirms our understanding of the library's behavior.
func TestInterfaceHandlingBehavior(t *testing.T) {
	t.Parallel()
	inputJSON := `{
        "id": "behavior-test-node",
        "type": "Test",
        "properties": {
            "intVal": 42,
            "floatVal": 3.14,
            "arrayVal": [100, "mixed", true],
            "objectVal": {"nested": "value"}
        }
    }`

	var node schemas.NodeInput
	err := json.Unmarshal([]byte(inputJSON), &node)
	require.NoError(t, err, "Unmarshalling for behavior test should succeed")

	props := node.Properties
	require.NotNil(t, props, "Properties map should not be nil")

	// JSON numbers (int or float) are decoded into float64.
	assert.Equal(t, float64(42), props["intVal"], "Integer value should be decoded as float64")
	assert.Equal(t, 3.14, props["floatVal"], "Float value should be decoded as float64")

	// JSON arrays are decoded into []interface{}.
	expectedArray := []interface{}{float64(100), "mixed", true}
	assert.Equal(t, expectedArray, props["arrayVal"], "Array should be decoded as []interface{} with correct types")

	// JSON objects are decoded into map[string]interface{}.
	expectedObject := map[string]interface{}{"nested": "value"}
	assert.Equal(t, expectedObject, props["objectVal"], "Object should be decoded as map[string]interface{}")
}