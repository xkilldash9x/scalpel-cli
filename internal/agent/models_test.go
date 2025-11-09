//go:build !integration

// internal/agent/models_test.go
package agent_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	json "github.com/json-iterator/go"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/agent"
)

// =============================================================================
//  HELPER FUNCTIONS
// =============================================================================

// mustParseTime is a helper that parses a timestamp and panics on error.
// It's used to create consistent time objects for testing.
func mustParseTime(ts string) time.Time {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic(err)
	}
	return t
}

// =============================================================================
//  UNIT TESTS
// =============================================================================

func TestMission_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	// Numbers in `map[string]interface{}` are deserialized as float64.
	// We define the expected struct with float64 to make the comparison pass.
	testTime := mustParseTime("2023-10-27T10:00:00Z")
	missionWithIntParam := agent.Mission{
		ID:          "mission-123",
		ScanID:      "scan-abc",
		Objective:   "Find all XSS vulnerabilities.",
		TargetURL:   "https://example.com",
		Constraints: []string{"Do not DDoS", "Stay within *.example.com"},
		Parameters: map[string]interface{}{
			"depth":         5,
			"user_agent":    "Scalpel-Agent/1.0",
			"include_forms": true,
		},
		StartTime: testTime,
	}
	missionWithFloatParam := agent.Mission{
		ID:          "mission-123",
		ScanID:      "scan-abc",
		Objective:   "Find all XSS vulnerabilities.",
		TargetURL:   "https://example.com",
		Constraints: []string{"Do not DDoS", "Stay within *.example.com"},
		Parameters: map[string]interface{}{
			"depth":         float64(5), // Explicitly float64 for comparison
			"user_agent":    "Scalpel-Agent/1.0",
			"include_forms": true,
		},
		StartTime: testTime,
	}

	// Marshal the struct
	jsonData, err := json.Marshal(missionWithIntParam)
	if err != nil {
		t.Fatalf("json.Marshal() failed: %v", err)
	}

	// Unmarshal back into a new struct
	var newMission agent.Mission
	if err := json.Unmarshal(jsonData, &newMission); err != nil {
		t.Fatalf("json.Unmarshal() failed: %v", err)
	}

	// Compare the new struct with the expected struct (with float64)
	if !reflect.DeepEqual(newMission, missionWithFloatParam) {
		t.Errorf("Round trip failed. Diff:\n%s", cmp.Diff(missionWithFloatParam, newMission))
	}
}

func TestAction_JSONMarshaling(t *testing.T) {
	t.Parallel()

	testTime := mustParseTime("2023-10-27T10:05:00Z")

	testCases := []struct {
		name         string
		action       agent.Action
		expectedJSON string
	}{
		{
			name: "full action with all fields",
			action: agent.Action{
				ID:        "action-001",
				MissionID: "mission-123",
				ScanID:    "scan-abc",
				Thought:   "The next logical step is to click the login button.",
				Type:      agent.ActionClick,
				Selector:  "#login-button",
				Value:     "", // Value is empty for a click action
				Metadata: map[string]interface{}{
					"wait_after_ms": float64(500), // JSON numbers become float64
					"is_critical":   true,
				},
				Rationale: "Attempting to access the authenticated area.",
				Timestamp: testTime,
			},
			expectedJSON: `{"id":"action-001","mission_id":"mission-123","scan_id":"scan-abc","thought":"The next logical step is to click the login button.","type":"CLICK","selector":"#login-button","metadata":{"is_critical":true,"wait_after_ms":500},"rationale":"Attempting to access the authenticated area.","timestamp":"2023-10-27T10:05:00Z"}`,
		},
		{
			name: "minimal action with omitempty fields zeroed",
			action: agent.Action{
				ID:        "action-002",
				MissionID: "mission-123",
				ScanID:    "scan-abc",
				Type:      agent.ActionAnalyzeTaint,
				Rationale: "Initial taint analysis on the landing page.",
				Timestamp: testTime, // Thought is empty and omitempty.
			},
			// `thought`, `selector`, `value`, `metadata` should be omitted.
			expectedJSON: `{"id":"action-002","mission_id":"mission-123","scan_id":"scan-abc","type":"ANALYZE_TAINT","rationale":"Initial taint analysis on the landing page.","timestamp":"2023-10-27T10:05:00Z"}`,
		},
		{
			name: "input text action",
			action: agent.Action{
				ID:        "action-003",
				MissionID: "mission-123",
				ScanID:    "scan-abc",
				Type:      agent.ActionInputText,
				Selector:  "input[name='username']",
				Value:     "admin' OR 1=1; --",
				Rationale: "Testing for SQL injection in the username field.",
				Timestamp: testTime, // Thought is empty and omitempty.
			},
			// 'thought' should be omitted.
			expectedJSON: `{"id":"action-003","mission_id":"mission-123","scan_id":"scan-abc","type":"INPUT_TEXT","selector":"input[name='username']","value":"admin' OR 1=1; --","rationale":"Testing for SQL injection in the username field.","timestamp":"2023-10-27T10:05:00Z"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test Marshaling
			jsonData, err := json.Marshal(tc.action)
			if err != nil {
				t.Fatalf("json.Marshal() failed: %v", err)
			}

			// Compare JSON strings by unmarshaling into maps to ignore key order
			var actualMap, expectedMap map[string]interface{}
			if err := json.Unmarshal(jsonData, &actualMap); err != nil {
				t.Fatalf("Failed to unmarshal actual JSON: %v", err)
			}
			if err := json.Unmarshal([]byte(tc.expectedJSON), &expectedMap); err != nil {
				t.Fatalf("Failed to unmarshal expected JSON: %v", err)
			}
			if !reflect.DeepEqual(actualMap, expectedMap) {
				t.Errorf("JSON mismatch. Diff:\n%s", cmp.Diff(expectedMap, actualMap))
			}

			// Test Unmarshaling (Round-trip)
			var newAction agent.Action
			if err := json.Unmarshal(jsonData, &newAction); err != nil {
				t.Fatalf("json.Unmarshal() failed: %v", err)
			}
			if !reflect.DeepEqual(newAction, tc.action) {
				t.Errorf("Round trip failed. Diff:\n%s", cmp.Diff(tc.action, newAction))
			}
		})
	}
}

func TestObservation_JSONRoundTrip(t *testing.T) {
	t.Parallel()

	testTime := mustParseTime("2023-10-27T11:00:00Z")

	testCases := []struct {
		name string
		obs  agent.Observation
	}{
		{
			name: "Observation with map data",
			obs: agent.Observation{
				ID:             "obs-001",
				MissionID:      "mission-123",
				SourceActionID: "action-001",
				Type:           agent.ObservedDOMChange,
				Data: map[string]interface{}{
					"url":         "https://example.com/login",
					"title":       "Login Page",
					"element_add": float64(5), // JSON numbers become float64
				},
				Result: agent.ExecutionResult{
					Status:          "success",
					ObservationType: agent.ObservedDOMChange,
				},
				Timestamp: testTime,
			},
		},
		{
			name: "Observation with string data",
			obs: agent.Observation{
				ID:             "obs-002",
				MissionID:      "mission-123",
				SourceActionID: "action-002",
				Type:           agent.ObservedConsoleMessage,
				Data:           "Error: Failed to load resource.",
				Result: agent.ExecutionResult{
					Status:          "success",
					ObservationType: agent.ObservedConsoleMessage,
				},
				Timestamp: testTime,
			},
		},
		{
			name: "Observation with nil data",
			obs: agent.Observation{
				ID:             "obs-003",
				MissionID:      "mission-123",
				SourceActionID: "action-003",
				Type:           agent.ObservedSystemState,
				Data:           nil,
				Result: agent.ExecutionResult{
					Status:          "failed",
					ObservationType: agent.ObservedSystemState,
					ErrorCode:       agent.ErrCodeTimeoutError,
				},
				Timestamp: testTime,
			},
		},
		{
			name: "Observation with vulnerability finding",
			obs: agent.Observation{
				ID:             "obs-004",
				MissionID:      "mission-123",
				SourceActionID: "action-004",
				Type:           agent.ObservedVulnerability,
				Data: map[string]interface{}{
					"summary": "Reflected XSS found",
				},
				Result: agent.ExecutionResult{
					Status:          "success",
					ObservationType: agent.ObservedVulnerability,
					Findings: []schemas.Finding{
						// FIX: Changed to use VulnerabilityName string
						{ID: "finding-xss-1", VulnerabilityName: "Reflected XSS"},
					},
					KGUpdates: &schemas.KnowledgeGraphUpdate{
						NodesToAdd: []schemas.NodeInput{{ID: "vuln-node-1", Type: schemas.NodeVulnerability}},
					},
				},
				Timestamp: testTime,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tc.obs)
			if err != nil {
				t.Fatalf("json.Marshal() failed: %v", err)
			}

			var newObs agent.Observation
			if err := json.Unmarshal(jsonData, &newObs); err != nil {
				t.Fatalf("json.Unmarshal() failed: %v", err)
			}

			// We need a custom comparison because `obs.Data` might contain `int`
			// which becomes `float64` after round-trip.
			expectedObs := tc.obs
			if dataMap, ok := expectedObs.Data.(map[string]interface{}); ok {
				for k, v := range dataMap {
					if _, isInt := v.(int); isInt {
						dataMap[k] = float64(v.(int))
					}
				}
			}

			// Handle json.RawMessage `null` vs nil slice normalization for comparison
			if expectedObs.Result.KGUpdates != nil && newObs.Result.KGUpdates != nil {
				if expectedObs.Result.KGUpdates.NodesToAdd != nil && newObs.Result.KGUpdates.NodesToAdd == nil {
					newObs.Result.KGUpdates.NodesToAdd = []schemas.NodeInput{}
				}
				if expectedObs.Result.KGUpdates.EdgesToAdd != nil && newObs.Result.KGUpdates.EdgesToAdd == nil {
					newObs.Result.KGUpdates.EdgesToAdd = []schemas.EdgeInput{}
				}
			}

			// This is a special case for the Finding struct in the round-trip test.
			// The `ObservedAt` field will be a zero-value time.Time, which is
			// fine and expected, so DeepEqual will pass.
			if !reflect.DeepEqual(newObs, expectedObs) {
				t.Errorf("Round trip failed. Diff:\n%s", cmp.Diff(expectedObs, newObs))
			}
		})
	}
}

func TestExecutionResult_JSONMarshaling(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		result       agent.ExecutionResult
		expectedJSON string
	}{
		{
			name: "success with findings and KG updates",
			result: agent.ExecutionResult{
				Status:          "success",
				ObservationType: agent.ObservedAnalysisResult,
				Data:            map[string]interface{}{"items_found": float64(3)},
				Findings: []schemas.Finding{
					// FIX: Changed to use VulnerabilityName string
					{ID: "finding-1", VulnerabilityName: "XSS"},
				},
				KGUpdates: &schemas.KnowledgeGraphUpdate{
					NodesToAdd: []schemas.NodeInput{
						{ID: "node-1", Label: "Vulnerable Page", Type: "", Status: "", Properties: nil},
					},
					EdgesToAdd: nil,
				},
			},
			// FIX: Corrected expectedJSON to match the real Finding struct
			// - Replaced "timestamp" with "observed_at"
			// - Replaced "vulnerability":{...} with "vulnerability_name":"XSS"
			// - Removed "evidence" (nil + omitempty)
			expectedJSON: `{"status":"success","observation_type":"ANALYSIS_RESULT","data":{"items_found":3},"findings":[{"id":"finding-1","scan_id":"","task_id":"","observed_at":"0001-01-01T00:00:00Z","target":"","module":"","vulnerability_name":"XSS","severity":"","description":"","recommendation":""}],"kg_updates":{"nodes_to_add":[{"id":"node-1","type":"","label":"Vulnerable Page","status":"","properties":null}],"edges_to_add":null}}`,
		},
		{
			name: "failed result with error details",
			result: agent.ExecutionResult{
				Status:          "failed",
				ObservationType: agent.ObservedDOMChange,
				ErrorCode:       agent.ErrCodeElementNotFound,
				ErrorDetails:    map[string]interface{}{"selector": "#non-existent"},
			},
			// `data`, `findings`, `kg_updates` should be omitted.
			expectedJSON: `{"status":"failed","observation_type":"DOM_CHANGE","error_code":"ELEMENT_NOT_FOUND","error_details":{"selector":"#non-existent"}}`,
		},
		{
			name: "minimal success",
			result: agent.ExecutionResult{
				Status:          "success",
				ObservationType: agent.ObservedSystemState,
			},
			// All optional fields should be omitted.
			expectedJSON: `{"status":"success","observation_type":"SYSTEM_STATE"}`,
		},
		{
			name:   "zero value result",
			result: agent.ExecutionResult{},
			// `status` and `observation_type` are not omitempty
			expectedJSON: `{"status":"","observation_type":""}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tc.result)
			if err != nil {
				t.Fatalf("json.Marshal() failed: %v", err)
			}

			var actualMap, expectedMap map[string]interface{}
			if err := json.Unmarshal(jsonData, &actualMap); err != nil {
				t.Fatalf("Failed to unmarshal actual JSON: %v\nRaw JSON: %s", err, string(jsonData))
			}
			if err := json.Unmarshal([]byte(tc.expectedJSON), &expectedMap); err != nil {
				t.Fatalf("Failed to unmarshal expected JSON: %v\nRaw JSON: %s", err, tc.expectedJSON)
			}
			if !reflect.DeepEqual(actualMap, expectedMap) {
				t.Errorf("JSON mismatch. Diff:\n%s", cmp.Diff(expectedMap, actualMap))
			}
		})
	}
}

// =============================================================================
//  FUZZ TESTS
// =============================================================================

// FuzzMission_UnmarshalJSON tests the robustness of Mission JSON unmarshaling.
func FuzzMission_UnmarshalJSON(f *testing.F) {
	// Seed corpus
	validJSON := `{"id":"mission-123","scan_id":"scan-abc","objective":"Find XSS.","target_url":"https://example.com","constraints":["Stay within scope"],"parameters":{"depth":5},"start_time":"2023-10-27T10:00:00Z"}`
	f.Add([]byte(validJSON))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"id":123, "objective":true}`)) // Invalid types

	f.Fuzz(func(t *testing.T, data []byte) {
		// The test passes as long as Unmarshal does not panic.
		var m agent.Mission
		_ = json.Unmarshal(data, &m)
	})
}

// FuzzAction_UnmarshalJSON tests the robustness of Action JSON unmarshaling.
func FuzzAction_UnmarshalJSON(f *testing.F) {
	// Seed corpus
	validJSON := `{"id":"action-001","mission_id":"mission-123","scan_id":"scan-abc","type":"CLICK","selector":"#btn","rationale":"Click button.","timestamp":"2023-10-27T10:05:00Z"}`
	f.Add([]byte(validJSON))
	f.Add([]byte(`{"type":"UNKNOWN_ACTION_TYPE"}`))
	f.Add([]byte(`{"metadata": "not-a-map"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var a agent.Action
		_ = json.Unmarshal(data, &a)
	})
}

// FuzzObservation_UnmarshalJSON tests the robustness of Observation JSON unmarshaling.
func FuzzObservation_UnmarshalJSON(f *testing.F) {
	// Seed corpus
	validJSON := `{"id":"obs-001","mission_id":"m-1","source_action_id":"a-1","type":"DOM_CHANGE","data":{"url":"/"},"result":{"status":"success"},"timestamp":"2023-10-27T11:00:00Z"}`
	f.Add([]byte(validJSON))
	f.Add([]byte(`{"data":123.45, "result": "not-an-object"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var o agent.Observation
		// Fuzzing the `data interface{}` field is important to catch type confusion issues.
		_ = json.Unmarshal(data, &o)
	})
}
