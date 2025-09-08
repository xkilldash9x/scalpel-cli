package schemas_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	// Assuming the module path is as provided in the prompt.
	// Adjust this import path if your actual project structure differs.
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// ============================================================================
// Test Helpers for Robust Logging
// ============================================================================

// fatalTestError logs a critical error that prevents the test from continuing (e.g., failed serialization/deserialization).
func fatalTestError(t *testing.T, context string, err error, inputData interface{}) {
	t.Helper()
	t.Logf("\n"+
		"==================================================================\n"+
		"CRITICAL ERROR - TEST STOPPED\n"+
		"==================================================================\n"+
		"Test:    %s\n"+
		"Context: %s\n"+
		"------------------------------------------------------------------\n"+
		"Error Details: %v\n"+
		"------------------------------------------------------------------\n"+
		"Input Data (if applicable):\n%#v\n"+
		"==================================================================\n",
		t.Name(), context, err, inputData)
	t.FailNow()
}

// assertionFailed logs a detailed message when an assertion fails (e.g., expected value does not match actual value).
// Uses %#v format specifier for Go-syntax representation, which is ideal for comparing structs.
func assertionFailed(t *testing.T, context string, expected interface{}, actual interface{}, details string) {
	t.Helper()
	t.Errorf("\n"+
		"==================================================================\n"+
		"ASSERTION FAILED\n"+
		"==================================================================\n"+
		"Test:    %s\n"+
		"Context: %s\n"+
		"Details: %s\n"+
		"------------------------------------------------------------------\n"+
		"Expected:\n%#v\n"+
		"------------------------------------------------------------------\n"+
		"Actual:\n%#v\n"+
		"==================================================================\n",
		t.Name(), context, details, expected, actual)
}

// ============================================================================
// Test Cases
// ============================================================================

// TestConstants verifies that all defined constants hold their expected values.
func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant interface{}
		expected string
	}{
		// TaskTypes
		{"TaskAgentMission", schemas.TaskAgentMission, "AGENT_MISSION"},
		{"TaskAnalyzeWebPageTaint", schemas.TaskAnalyzeWebPageTaint, "ANALYZE_WEB_PAGE_TAINT"},
		{"TaskAnalyzeWebPageProtoPP", schemas.TaskAnalyzeWebPageProtoPP, "ANALYZE_WEB_PAGE_PROTOPP"},
		{"TaskTestRaceCondition", schemas.TaskTestRaceCondition, "TEST_RACE_CONDITION"},
		{"TaskTestAuthATO", schemas.TaskTestAuthATO, "TEST_AUTH_ATO"},
		{"TaskTestAuthIDOR", schemas.TaskTestAuthIDOR, "TEST_AUTH_IDOR"},
		{"TaskAnalyzeHeaders", schemas.TaskAnalyzeHeaders, "ANALYZE_HEADERS"},
		{"TaskAnalyzeJWT", schemas.TaskAnalyzeJWT, "ANALYZE_JWT"},

		// Severities
		{"SeverityCritical", schemas.SeverityCritical, "CRITICAL"},
		{"SeverityHigh", schemas.SeverityHigh, "HIGH"},
		{"SeverityMedium", schemas.SeverityMedium, "MEDIUM"},
		{"SeverityLow", schemas.SeverityLow, "LOW"},
		{"SeverityInformational", schemas.SeverityInformational, "INFORMATIONAL"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := fmt.Sprintf("%v", tt.constant)
			if actual != tt.expected {
				assertionFailed(t, "Verifying constant value", tt.expected, actual, "Constant definition mismatch.")
			}
		})
	}
}

// Structure for Task Unmarshaling table-driven tests
type taskUnmarshalTest struct {
	name        string
	inputJSON   string
	expected    schemas.Task
	expectError bool
	errorMsg    string // Substring expected in the error message
}

// TestTaskUnmarshal_Success tests the custom UnmarshalJSON logic for every supported TaskType with valid parameters.
func TestTaskUnmarshal_Success(t *testing.T) {
	// Note: When unmarshaling JSON into a []byte field in Go, the JSON value must be a Base64 encoded string.
	// "cGF5bG9hZCBkYXRh" is "payload data"
	// "YW1vdW50PTEwMA==" is "amount=100"

	tests := []taskUnmarshalTest{
		{
			name: "AGENT_MISSION",
			inputJSON: `{
				"scan_id": "scan-1",
				"task_id": "task-1",
				"type": "AGENT_MISSION",
				"target_url": "http://example.com/mission",
				"parameters": {
					"mission_brief": "Infiltrate the mainframe"
				}
			}`,
			expected: schemas.Task{
				ScanID:    "scan-1",
				TaskID:    "task-1",
				Type:      schemas.TaskAgentMission,
				TargetURL: "http://example.com/mission",
				Parameters: &schemas.AgentMissionParams{
					MissionBrief: "Infiltrate the mainframe",
				},
			},
		},
		{
			name: "ANALYZE_WEB_PAGE_TAINT",
			inputJSON: `{
				"scan_id": "scan-2",
				"task_id": "task-2",
				"type": "ANALYZE_WEB_PAGE_TAINT",
				"target_url": "http://example.com/taint",
				"parameters": {
					"interaction_depth": 5,
					"focus_selector": "#main-form"
				}
			}`,
			expected: schemas.Task{
				ScanID:    "scan-2",
				TaskID:    "task-2",
				Type:      schemas.TaskAnalyzeWebPageTaint,
				TargetURL: "http://example.com/taint",
				Parameters: &schemas.TaintTaskParams{
					InteractionDepth: 5,
					FocusSelector:    "#main-form",
				},
			},
		},
		{
			name: "ANALYZE_WEB_PAGE_PROTOPP (Empty Struct)",
			inputJSON: `{
				"scan_id": "scan-3",
				"task_id": "task-3",
				"type": "ANALYZE_WEB_PAGE_PROTOPP",
				"target_url": "http://example.com/pp",
				"parameters": {}
			}`,
			expected: schemas.Task{
				ScanID:    "scan-3",
				TaskID:    "task-3",
				Type:      schemas.TaskAnalyzeWebPageProtoPP,
				TargetURL: "http://example.com/pp",
				Parameters: &schemas.ProtoPollutionTaskParams{},
			},
		},
		{
			name: "TEST_AUTH_ATO",
			inputJSON: `{
				"scan_id": "scan-4",
				"task_id": "task-4",
				"type": "TEST_AUTH_ATO",
				"target_url": "http://example.com/login",
				"parameters": {
					"usernames": ["admin", "user1"],
					"password_list": ["password123"]
				}
			}`,
			expected: schemas.Task{
				ScanID:    "scan-4",
				TaskID:    "task-4",
				Type:      schemas.TaskTestAuthATO,
				TargetURL: "http://example.com/login",
				Parameters: &schemas.ATOTaskParams{
					Usernames:    []string{"admin", "user1"},
					PasswordList: []string{"password123"},
				},
			},
		},
		{
			name: "TEST_AUTH_IDOR (Headers and Body)",
			inputJSON: `{
				"scan_id": "scan-5",
				"task_id": "task-5",
				"type": "TEST_AUTH_IDOR",
				"target_url": "http://example.com/api/user/1",
				"parameters": {
					"http_method": "GET",
					"http_body": "cGF5bG9hZCBkYXRh",
					"http_headers": {
						"Authorization": ["Bearer token123"],
						"X-Custom": ["Value1"]
					}
				}
			}`,
			expected: schemas.Task{
				ScanID:    "scan-5",
				TaskID:    "task-5",
				Type:      schemas.TaskTestAuthIDOR,
				TargetURL: "http://example.com/api/user/1",
				Parameters: &schemas.IDORTaskParams{
					HTTPMethod: "GET",
					HTTPBody:   []byte("payload data"),
					HTTPHeaders: http.Header{
						"Authorization": []string{"Bearer token123"},
						"X-Custom":      []string{"Value1"},
					},
				},
			},
		},
		{
			name: "ANALYZE_JWT",
			inputJSON: `{
				"scan_id": "scan-6",
				"task_id": "task-6",
				"type": "ANALYZE_JWT",
				"target_url": "http://example.com/api",
				"parameters": {
					"token": "eyJhbGci...",
					"brute_force_enabled": true
				}
			}`,
			expected: schemas.Task{
				ScanID:    "scan-6",
				TaskID:    "task-6",
				Type:      schemas.TaskAnalyzeJWT,
				TargetURL: "http://example.com/api",
				Parameters: &schemas.JWTTaskParams{
					Token:               "eyJhbGci...",
					BruteForceEnabled: true,
				},
			},
		},
		{
			name: "TEST_RACE_CONDITION",
			inputJSON: `{
				"scan_id": "scan-7",
				"task_id": "task-7",
				"type": "TEST_RACE_CONDITION",
				"target_url": "http://example.com/transfer",
				"parameters": {
					"http_method": "POST",
					"http_body": "YW1vdW50PTEwMA==",
					"concurrency": 20
				}
			}`,
			expected: schemas.Task{
				ScanID:    "scan-7",
				TaskID:    "task-7",
				Type:      schemas.TaskTestRaceCondition,
				TargetURL: "http://example.com/transfer",
				Parameters: &schemas.RaceConditionTaskParams{
					HTTPMethod:  "POST",
					HTTPBody:    []byte("amount=100"),
					Concurrency: 20,
				},
			},
		},
		{
			name: "ANALYZE_HEADERS (Empty Struct)",
			inputJSON: `{
				"scan_id": "scan-8",
				"task_id": "task-8",
				"type": "ANALYZE_HEADERS",
				"target_url": "http://example.com/",
				"parameters": {}
			}`,
			expected: schemas.Task{
				ScanID:    "scan-8",
				TaskID:    "task-8",
				Type:      schemas.TaskAnalyzeHeaders,
				TargetURL: "http://example.com/",
				Parameters: &schemas.HeadersTaskParams{},
			},
		},
	}

	runTaskUnmarshalTests(t, tests)
}

// TestTaskUnmarshal_EdgeCases tests scenarios like missing parameters, null parameters, and unknown task types.
func TestTaskUnmarshal_EdgeCases(t *testing.T) {
	tests := []taskUnmarshalTest{
		{
			name: "Parameters field missing",
			inputJSON: `{
				"scan_id": "scan-edge-1",
				"task_id": "task-edge-1",
				"type": "AGENT_MISSION",
				"target_url": "http://example.com"
			}`,
			expected: schemas.Task{
				ScanID:     "scan-edge-1",
				TaskID:     "task-edge-1",
				Type:       schemas.TaskAgentMission,
				TargetURL:  "http://example.com",
				Parameters: nil, // Should be nil if omitted
			},
		},
		{
			name: "Parameters field explicitly null",
			inputJSON: `{
				"scan_id": "scan-edge-2",
				"task_id": "task-edge-2",
				"type": "ANALYZE_WEB_PAGE_TAINT",
				"target_url": "http://example.com",
				"parameters": null
			}`,
			expected: schemas.Task{
				ScanID:     "scan-edge-2",
				TaskID:     "task-edge-2",
				Type:       schemas.TaskAnalyzeWebPageTaint,
				TargetURL:  "http://example.com",
				Parameters: nil, // Should be nil if null
			},
		},
		{
			// The implementation should gracefully handle unknown types by unmarshaling the base task
			// but ignoring the parameters (leaving Parameters as nil).
			name: "Unknown Task Type",
			inputJSON: `{
				"scan_id": "scan-edge-3",
				"task_id": "task-edge-3",
				"type": "FUTURE_TASK_TYPE",
				"target_url": "http://example.com/future",
				"parameters": {
					"some_field": "some_value"
				}
			}`,
			expected: schemas.Task{
				ScanID:     "scan-edge-3",
				TaskID:     "task-edge-3",
				Type:       schemas.TaskType("FUTURE_TASK_TYPE"),
				TargetURL:  "http://example.com/future",
				Parameters: nil,
			},
		},
	}

	runTaskUnmarshalTests(t, tests)
}

// TestTaskUnmarshal_FailureCases tests scenarios where the custom UnmarshalJSON should return an error.
func TestTaskUnmarshal_FailureCases(t *testing.T) {
	tests := []taskUnmarshalTest{
		{
			name: "Invalid Base JSON Structure",
			inputJSON: `{
				"scan_id": "scan-fail-1",
				"type": "AGENT_MISSION",
			`, // Missing closing brace
			expectError: true,
			errorMsg:    "failed to unmarshal base task structure",
		},
		{
			name: "Mismatched types in parameters (string instead of int)",
			inputJSON: `{
				"scan_id": "scan-fail-2",
				"type": "ANALYZE_WEB_PAGE_TAINT",
				"parameters": {
					"interaction_depth": "five"
				}
			}`,
			expectError: true,
			errorMsg:    "failed to unmarshal parameters for task type ANALYZE_WEB_PAGE_TAINT",
		},
		{
			name: "Mismatched types in parameters (int instead of string)",
			inputJSON: `{
				"scan_id": "scan-fail-3",
				"type": "AGENT_MISSION",
				"parameters": {
					"mission_brief": 12345
				}
			}`,
			expectError: true,
			errorMsg:    "failed to unmarshal parameters for task type AGENT_MISSION",
		},
		{
			name: "Corrupt JSON in parameters field",
			inputJSON: `{
				"scan_id": "scan-fail-4",
				"type": "AGENT_MISSION",
				"parameters": {"mission_brief": "test
			}`, // Missing closing brace in parameters
			expectError: true,
			errorMsg:    "failed to unmarshal parameters for task type AGENT_MISSION",
		},
		{
			name: "Parameters is an array instead of an object",
			inputJSON: `{
				"scan_id": "scan-fail-5",
				"type": "TEST_AUTH_ATO",
				"parameters": ["username", "password"]
			}`,
			expectError: true,
			errorMsg:    "failed to unmarshal parameters for task type TEST_AUTH_ATO",
		},
	}

	runTaskUnmarshalTests(t, tests)
}

// Runner function for the Task Unmarshal tests
func runTaskUnmarshalTests(t *testing.T, tests []taskUnmarshalTest) {
	t.Helper()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var actualTask schemas.Task
			err := json.Unmarshal([]byte(tc.inputJSON), &actualTask)

			// 1. Handle Error Expectations
			if tc.expectError {
				if err == nil {
					assertionFailed(t, "Error expectation check", fmt.Sprintf("An error containing '%s'", tc.errorMsg), "nil error", "Expected an error during unmarshaling but did not receive one.")
					return
				}
				if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					assertionFailed(t, "Error message verification", fmt.Sprintf("Error containing: '%s'", tc.errorMsg), err.Error(), "The error message did not contain the expected substring indicating the source of the failure.")
				}
				// Success: Expected an error and got the right one.
				return
			}

			// 2. Handle Unexpected Errors
			if err != nil {
				fatalTestError(t, fmt.Sprintf("Unmarshaling task: %s", tc.name), err, tc.inputJSON)
			}

			// 3. Verify the resulting structure
			// reflect.DeepEqual is sufficient to check both the content and the type of the dynamic Parameters interface.
			if !reflect.DeepEqual(actualTask, tc.expected) {
				assertionFailed(t, fmt.Sprintf("Verifying unmarshaled structure: %s", tc.name), tc.expected, actualTask, "The unmarshaled task structure does not match the expected structure.")

				// Provide extra details if the mismatch is in the parameters field
				if !reflect.DeepEqual(actualTask.Parameters, tc.expected.Parameters) {
					t.Logf("DETAILS: Mismatch specifically in Parameters field.")
					t.Logf("Expected Type: %T | Actual Type: %T", tc.expected.Parameters, actualTask.Parameters)
				}
			}
		})
	}
}

// TestResultEnvelope_SerializationCycle tests the integrity of the ResultEnvelope and its nested structures (Finding, KGUpdates) during Marshal/Unmarshal.
func TestResultEnvelope_SerializationCycle(t *testing.T) {
	// Use UTC and truncate precision to ensure reliable comparison after JSON serialization (which typically uses RFC3339 format).
	timestamp := time.Now().UTC().Truncate(time.Millisecond)
	evidenceJSON := json.RawMessage(`{"request": "GET /api/data", "response_code": 200}`)
	artifactsJSON := json.RawMessage(`{"dom_snapshot": "<html>...</html>", "logs": ["log1"]}`)

	// 1. Create a comprehensive ResultEnvelope instance
	envelope := schemas.ResultEnvelope{
		ScanID:    "scan-result-1",
		TaskID:    "task-result-a",
		Timestamp: timestamp,
		Findings: []schemas.Finding{
			{
				ID:             "finding-001",
				ScanID:         "scan-result-1", // Should be ignored in JSON (json:"-")
				TaskID:         "task-result-a",
				Timestamp:      timestamp,
				Target:         "http://example.com/vulnerable",
				Module:         "XSSScanner",
				Vulnerability:  "Reflected XSS",
				Severity:       schemas.SeverityHigh,
				Description:    "Vulnerable parameter 'q' reflects input.",
				Evidence:       evidenceJSON,
				Recommendation: "Sanitize input.",
				CWE:            "CWE-79",
			},
		},
		KGUpdates: &schemas.KGUpdates{
			Nodes: []schemas.Node{
				{
					ID:        "node-url-1",
					Type:      "URL",
					Label:     "http://example.com",
					Status:    "Scanned",
					CreatedAt: timestamp,
					LastSeen:  timestamp,
					// When unmarshaling into interface{}, JSON numbers become float64.
					Properties: map[string]interface{}{"port": float64(80), "secure": true},
				},
			},
			Edges: []schemas.Edge{
				{
					ID:        "edge-link-1",
					From:      "node-url-1",
					To:        "node-url-2",
					Type:      "LINK",
					Label:     "Hyperlink",
					CreatedAt: timestamp,
					LastSeen:  timestamp,
				},
			},
		},
		Artifacts: artifactsJSON,
	}

	// 2. Marshal to JSON
	data, err := json.Marshal(envelope)
	if err != nil {
		fatalTestError(t, "Marshalling ResultEnvelope", err, envelope)
	}

	// 3. Verify ScanID omission in Finding JSON output (Specific check for json:"-")
	var rawData map[string]interface{}
	if err := json.Unmarshal(data, &rawData); err != nil {
		fatalTestError(t, "Unmarshalling JSON to map for verification", err, string(data))
	}
	findingsList, ok := rawData["findings"].([]interface{})
	if !ok || len(findingsList) == 0 {
		fatalTestError(t, "Accessing findings array in raw JSON data", fmt.Errorf("findings array missing or empty"), string(data))
	}
	findingMap := findingsList[0].(map[string]interface{})
	if _, ok := findingMap["scan_id"]; ok {
		assertionFailed(t, "Checking Finding.ScanID JSON omission (json:\"-\")", "Field 'scan_id' should not be present", "Field 'scan_id' is present", "The ScanID field in Finding must be ignored during serialization.")
	}

	// 4. Unmarshal back from JSON
	var unmarshaledEnvelope schemas.ResultEnvelope
	err = json.Unmarshal(data, &unmarshaledEnvelope)
	if err != nil {
		fatalTestError(t, "Unmarshalling ResultEnvelope", err, string(data))
	}

	// 5. Verification

	// Time comparison using .Equal()
	if !unmarshaledEnvelope.Timestamp.Equal(envelope.Timestamp) {
		assertionFailed(t, "Verifying ResultEnvelope Timestamp", envelope.Timestamp, unmarshaledEnvelope.Timestamp, "Timestamps do not match after marshal/unmarshal cycle.")
	}

	// RawMessage checks (json.RawMessage)
	if string(unmarshaledEnvelope.Artifacts) != string(artifactsJSON) {
		assertionFailed(t, "Verifying Artifacts (RawMessage)", string(artifactsJSON), string(unmarshaledEnvelope.Artifacts), "Artifacts RawMessage content changed.")
	}
	if len(unmarshaledEnvelope.Findings) > 0 && string(unmarshaledEnvelope.Findings[0].Evidence) != string(evidenceJSON) {
		assertionFailed(t, "Verifying Evidence (RawMessage)", string(evidenceJSON), string(unmarshaledEnvelope.Findings[0].Evidence), "Evidence RawMessage content changed.")
	}

	// Deep Comparison
	// We must adjust the expected envelope slightly for comparison:
	// a. ScanID in the Finding should be empty in the unmarshaled version.
	expectedEnvelope := envelope
	expectedEnvelope.Findings[0].ScanID = ""

	// b. Timestamps might differ in internal representation (even if Equal() passes).
	// We align them before DeepEqual to ensure the comparison focuses strictly on other fields.
	alignTimestamps(&unmarshaledEnvelope, &expectedEnvelope)

	if !reflect.DeepEqual(unmarshaledEnvelope, expectedEnvelope) {
		assertionFailed(t, "Comparing original and deserialized ResultEnvelope", expectedEnvelope, unmarshaledEnvelope, "The overall structure or content differs after the serialization cycle.")
	}
}

// alignTimestamps ensures that time fields in the actual and expected ResultEnvelopes are identical if they are Equal,
// facilitating the use of reflect.DeepEqual.
func alignTimestamps(actual, expected *schemas.ResultEnvelope) {
	if actual.Timestamp.Equal(expected.Timestamp) {
		actual.Timestamp = expected.Timestamp
	}

	for i := range actual.Findings {
		if i < len(expected.Findings) {
			if actual.Findings[i].Timestamp.Equal(expected.Findings[i].Timestamp) {
				actual.Findings[i].Timestamp = expected.Findings[i].Timestamp
			}
		}
	}

	if actual.KGUpdates != nil && expected.KGUpdates != nil {
		for i := range actual.KGUpdates.Nodes {
			if i < len(expected.KGUpdates.Nodes) {
				if actual.KGUpdates.Nodes[i].CreatedAt.Equal(expected.KGUpdates.Nodes[i].CreatedAt) {
					actual.KGUpdates.Nodes[i].CreatedAt = expected.KGUpdates.Nodes[i].CreatedAt
				}
				if actual.KGUpdates.Nodes[i].LastSeen.Equal(expected.KGUpdates.Nodes[i].LastSeen) {
					actual.KGUpdates.Nodes[i].LastSeen = expected.KGUpdates.Nodes[i].LastSeen
				}
			}
		}
		for i := range actual.KGUpdates.Edges {
			if i < len(expected.KGUpdates.Edges) {
				if actual.KGUpdates.Edges[i].CreatedAt.Equal(expected.KGUpdates.Edges[i].CreatedAt) {
					actual.KGUpdates.Edges[i].CreatedAt = expected.KGUpdates.Edges[i].CreatedAt
				}
				if actual.KGUpdates.Edges[i].LastSeen.Equal(expected.KGUpdates.Edges[i].LastSeen) {
					actual.KGUpdates.Edges[i].LastSeen = expected.KGUpdates.Edges[i].LastSeen
				}
			}
		}
	}
}

// TestAuxiliaryStructs performs a basic initialization check on other simple structs.
func TestAuxiliaryStructs(t *testing.T) {
	t.Run("AgentState", func(t *testing.T) {
		state := schemas.AgentState{
			InternalMonologue: "Thinking...",
			Observation:       "Seeing...",
		}
		if state.InternalMonologue != "Thinking..." {
			assertionFailed(t, "AgentState Initialization", "Thinking...", state.InternalMonologue, "")
		}
	})

	t.Run("Action", func(t *testing.T) {
		action := schemas.Action{
			Name:      "Click",
			Arguments: `{"selector": "#button"}`,
		}
		if action.Name != "Click" {
			assertionFailed(t, "Action Initialization", "Click", action.Name, "")
		}
	})

	t.Run("InteractionConfig", func(t *testing.T) {
		config := schemas.InteractionConfig{
			MaxDepth: 5,
			InteractionDelayMs: 100,
		}
		if config.MaxDepth != 5 {
			assertionFailed(t, "InteractionConfig Initialization", 5, config.MaxDepth, "")
		}
	})

	t.Run("ConsoleLog", func(t *testing.T) {
		log := schemas.ConsoleLog{Type: "Error", Text: "Failed to load resource"}
		if log.Type != "Error" {
			assertionFailed(t, "ConsoleLog Initialization", "Error", log.Type, "")
		}
	})
}
