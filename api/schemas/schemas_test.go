package schemas_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	// Import the package containing the schemas using its full module path.
	schemas "github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/llmutil"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

// --- Helper Functions ---

// getTestTime provides a fixed, reproducible timestamp for consistent test results.
// This was moved from helpers_test.go for better consolidation.
func getTestTime(t *testing.T) time.Time {
	// Using RFC3339Nano ensures maximum precision, and UTC avoids timezone issues.
	ts, err := time.Parse(time.RFC3339Nano, "2025-10-26T10:00:00.123456789Z")
	require.NoError(t, err, "Test setup failed: unable to parse fixed timestamp")
	return ts
}

// testJSONRoundTrip performs a Struct -> JSON -> Struct serialization cycle
// and verifies that the data remains identical. It requires the input 'original'
// to be a pointer and an 'emptyTarget' factory function to create a new pointer instance.
func testJSONRoundTrip(t *testing.T, original interface{}, emptyTarget func() interface{}) {
	t.Helper()

	// 1. Marshal the original object to JSON
	// FIX: Use an Encoder with SetEscapeHTML(false) to prevent
	// "<script>" from becoming "\u003cscript\u003e" during the test.
	// This ensures the raw bytes of the Evidence field match after the round trip.
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(original); err != nil {
		t.Fatalf("Failed to marshal object (%T): %v", original, err)
	}
	data := buf.Bytes()

	// 2. Unmarshal the JSON back into a new object
	target := emptyTarget()
	if err := json.Unmarshal(data, target); err != nil {
		// Trim whitespace from data for cleaner error logging, as Encode adds a newline.
		t.Fatalf("Failed to unmarshal object (%T): %v\nJSON: %s", target, err, string(bytes.TrimSpace(data)))
	}

	// 3. Compare the original and the round-tripped object
	if diff := cmp.Diff(original, target); diff != "" {
		t.Errorf("Round-trip failed (%T). Mismatch (-want +got):\n%s", original, diff)
	}
}

// assertJSONEqual compares two JSON byte slices semantically, ignoring whitespace differences.
// This is used to verify the exact JSON structure (the contract).
func assertJSONEqual(t *testing.T, expectedJSON []byte, actualJSON []byte) {
	t.Helper()
	var expected, actual interface{}

	if err := json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatalf("Error unmarshaling expected JSON: %v\n%s", err, string(expectedJSON))
	}
	if err := json.Unmarshal(actualJSON, &actual); err != nil {
		t.Fatalf("Error unmarshaling actual JSON: %v\n%s", err, string(actualJSON))
	}

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("JSON mismatch (-want +got):\n%s\n\nExpected JSON:\n%s\n\nActual JSON:\n%s", diff, string(expectedJSON), string(actualJSON))
	}
}

// --- Test Cases ---

// TestTaskSerialization tests the Task struct, focusing on the dynamic interface{} Parameters field.
func TestTaskSerialization(t *testing.T) {
	t.Run("Task with ATOTaskParams - Contract and Interface Handling", func(t *testing.T) {
		task := schemas.Task{
			TaskID:    "T1",
			ScanID:    "S1",
			Type:      schemas.TaskTestAuthATO,
			TargetURL: "https://example.com/login",
			Parameters: schemas.ATOTaskParams{
				Usernames: []string{"admin", "guest"},
			},
		}

		// Marshal
		data, err := json.Marshal(task)
		if err != nil {
			t.Fatalf("Failed to marshal Task: %v", err)
		}

		// Verify the JSON structure (the contract)
		expectedJSON := `{
            "task_id": "T1",
            "scan_id": "S1",
            "type": "TEST_AUTH_ATO",
            "target_url": "https://example.com/login",
            "parameters": {
                "usernames": ["admin", "guest"]
            }
        }`
		assertJSONEqual(t, []byte(expectedJSON), data)

		// Unmarshal (Testing the behavior when the type inside interface{} is unknown)
		var newTask schemas.Task
		if err := json.Unmarshal(data, &newTask); err != nil {
			t.Fatalf("Failed to unmarshal Task: %v", err)
		}

		// CRITICAL: When unmarshaling JSON into an interface{}, Go uses map[string]interface{}.
		// We must verify this behavior.
		expectedParamsMap := map[string]interface{}{
			"usernames": []interface{}{"admin", "guest"},
		}

		if diff := cmp.Diff(expectedParamsMap, newTask.Parameters); diff != "" {
			t.Errorf("Unmarshalled Parameters mismatch (expected map[string]interface{}). (-want +got):\n%s", diff)
		}
	})

	t.Run("Task with IDORTaskParams - Contract Check", func(t *testing.T) {
		task := schemas.Task{
			TaskID: "T2",
			Type:   schemas.TaskTestAuthIDOR,
			Parameters: schemas.IDORTaskParams{
				HTTPMethod:  "POST",
				HTTPBody:    "id=123",
				HTTPHeaders: map[string]string{"X-Test": "true"},
			},
		}

		data, err := json.Marshal(task)
		if err != nil {
			t.Fatalf("Failed to marshal Task: %v", err)
		}

		expectedJSON := `{
            "task_id": "T2",
            "scan_id": "",
            "type": "TEST_AUTH_IDOR",
            "target_url": "",
            "parameters": {
                "http_method": "POST",
                "http_body": "id=123",
                "http_headers": {"X-Test": "true"}
            }
        }`
		assertJSONEqual(t, []byte(expectedJSON), data)
	})
}

// TestFindingSerialization tests the Finding struct round trip.
func TestFindingSerialization(t *testing.T) {
	now := getTestTime(t)
	finding := &schemas.Finding{
		ID:                "finding-1",
		ScanID:            "scan-1",
		TaskID:            "task-1",
		ObservedAt:        now,
		Target:            "https://example.com",
		Module:            "XSSAnalyzer",
		VulnerabilityName: "Reflected XSS",
		Severity:          schemas.SeverityHigh,
		Description:       "Found XSS in 'q' parameter.",
		// This is the field that was causing the failure
		Evidence:       json.RawMessage(`"<script>alert(1)</script>"`),
		Recommendation: "Encode user input.",
		CWE:            []string{"CWE-79"},
	}

	testJSONRoundTrip(t, finding, func() interface{} { return &schemas.Finding{} })

	t.Run("Test CWE omitempty", func(t *testing.T) {
		findingNoCWE := schemas.Finding{
			ID:  "F2",
			CWE: nil, // Should be omitted
		}

		data, err := json.Marshal(findingNoCWE)
		if err != nil {
			t.Fatalf("Failed to marshal Finding: %v", err)
		}

		// Check if the "cwe" key is present in the output
		if bytes.Contains(data, []byte(`"cwe":`)) {
			t.Errorf("Expected 'cwe' field to be omitted when nil/empty. JSON: %s", string(data))
		}
	})
}

// TestKnowledgeGraphSerialization tests Node and Edge serialization, focusing on json.RawMessage.
func TestKnowledgeGraphSerialization(t *testing.T) {
	now := getTestTime(t)
	propertiesJSON := json.RawMessage(`{"ip":"192.0.2.1","port":80}`)

	node := &schemas.Node{
		ID:         "node-host-1",
		Type:       schemas.NodeHost,
		Label:      "example.com",
		Status:     schemas.StatusNew,
		Properties: propertiesJSON,
		CreatedAt:  now,
		LastSeen:   now,
	}

	t.Run("Node Round Trip", func(t *testing.T) {
		testJSONRoundTrip(t, node, func() interface{} { return &schemas.Node{} })
	})

	edge := &schemas.Edge{
		ID:         "edge-1",
		From:       "node-host-1",
		To:         "node-ip-1",
		Type:       schemas.RelationshipResolvesTo,
		Label:      "A Record",
		Properties: json.RawMessage(`{}`),
		CreatedAt:  now,
		LastSeen:   now,
	}

	t.Run("Edge Round Trip", func(t *testing.T) {
		testJSONRoundTrip(t, edge, func() interface{} { return &schemas.Edge{} })
	})

	subgraph := &schemas.Subgraph{
		Nodes: []schemas.Node{*node},
		Edges: []schemas.Edge{*edge},
	}

	t.Run("Subgraph Round Trip", func(t *testing.T) {
		testJSONRoundTrip(t, subgraph, func() interface{} { return &schemas.Subgraph{} })
	})
}

// TestResultEnvelopeSerialization tests the comprehensive ResultEnvelope structure.
func TestResultEnvelopeSerialization(t *testing.T) {
	now := getTestTime(t)
	envelope := &schemas.ResultEnvelope{
		ScanID:    "scan-1",
		TaskID:    "task-1",
		Timestamp: now,
		Findings: []schemas.Finding{
			{ID: "f1", Severity: schemas.SeverityLow, ObservedAt: now},
		},
		KGUpdates: &schemas.KnowledgeGraphUpdate{
			NodesToAdd: []schemas.NodeInput{
				{ID: "n1", Type: schemas.NodeURL, Properties: json.RawMessage(`{"url":"https://example.com"}`)},
			},
			EdgesToAdd: []schemas.EdgeInput{
				// FIX #1: Explicitly set Properties to handle the nil -> "null" round trip issue.
				// This ensures the value before and after serialization is identical in Go's memory.
				{From: "n1", To: "n2", Type: schemas.RelationshipLinksTo, Properties: json.RawMessage("null")},
			},
		},
	}

	testJSONRoundTrip(t, envelope, func() interface{} { return &schemas.ResultEnvelope{} })

	t.Run("Test KGUpdates omitempty", func(t *testing.T) {
		envelopeNilKG := schemas.ResultEnvelope{
			ScanID:    "S2",
			KGUpdates: nil, // Should be omitted
		}

		data, err := json.Marshal(envelopeNilKG)
		if err != nil {
			t.Fatalf("Failed to marshal ResultEnvelope: %v", err)
		}

		// Check if the "kg_updates" key is present in the output
		if bytes.Contains(data, []byte(`"kg_updates":`)) {
			t.Errorf("Expected 'kg_updates' field to be omitted when nil. JSON: %s", string(data))
		}
	})
}

// TestDefaultPersona verifies the values of the exported DefaultPersona variable.
func TestDefaultPersona(t *testing.T) {
	p := schemas.DefaultPersona
	expectedUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/536.36"

	if p.UserAgent != expectedUA {
		t.Errorf("Unexpected DefaultPersona UserAgent: %s", p.UserAgent)
	}
	if p.Platform != "Win32" {
		t.Errorf("Unexpected DefaultPersona Platform: %s", p.Platform)
	}
	if p.Width != 1920 || p.Height != 1080 {
		t.Errorf("Unexpected DefaultPersona dimensions: %dx%d", p.Width, p.Height)
	}
	if p.Mobile {
		t.Errorf("DefaultPersona should not be mobile")
	}
	if p.Timezone != "America/Los_Angeles" {
		t.Errorf("Unexpected DefaultPersona Timezone: %s", p.Timezone)
	}
}

// TestBrowserArtifactsSerialization tests complex browser related schemas.
func TestBrowserArtifactsSerialization(t *testing.T) {
	t.Run("Persona Round Trip", func(t *testing.T) {
		persona := &schemas.Persona{
			UserAgent: "TestAgent/1.0",
			ClientHintsData: &schemas.ClientHints{
				Platform: "Linux",
				Brands:   []*schemas.UserAgentBrandVersion{{Brand: "Test", Version: "1"}},
			},
			NoiseSeed: 12345,
		}
		testJSONRoundTrip(t, persona, func() interface{} { return &schemas.Persona{} })
	})

	t.Run("InteractionConfig Round Trip", func(t *testing.T) {
		config := &schemas.InteractionConfig{
			MaxDepth:        5,
			CustomInputData: map[string]string{"email": "test@example.com"},
			Steps: []schemas.InteractionStep{
				{Action: schemas.ActionNavigate, Value: "https://example.com"},
				{Action: schemas.ActionClick, Selector: "#login"},
			},
		}
		testJSONRoundTrip(t, config, func() interface{} { return &schemas.InteractionConfig{} })
	})

	t.Run("Artifacts Round Trip", func(t *testing.T) {
		harRaw := json.RawMessage(`{"log":{"version":"1.2"}}`)
		// schemas.Cookie uses Unix timestamp (float seconds) for Expires.
		cookieExpires := 1700000000.123

		artifacts := &schemas.Artifacts{
			HAR: &harRaw,
			DOM: "<html><body>Hello</body></html>",
			ConsoleLogs: []schemas.ConsoleLog{
				{Type: "log", Text: "test"},
			},
			Storage: schemas.StorageState{
				Cookies: []*schemas.Cookie{
					{Name: "session", Value: "abc", Expires: cookieExpires, SameSite: schemas.CookieSameSiteLax},
				},
				LocalStorage: map[string]string{"theme": "dark"},
			},
		}
		testJSONRoundTrip(t, artifacts, func() interface{} { return &schemas.Artifacts{} })
	})
}

// TestHARInitialization verifies the NewHAR function.
func TestHARInitialization(t *testing.T) {
	har := schemas.NewHAR()

	if har.Log.Version != "1.2" {
		t.Errorf("Expected HAR version 1.2, got %s", har.Log.Version)
	}
	if har.Log.Creator.Name != "Scalpel-CLI" || har.Log.Creator.Version != "2.0" {
		t.Errorf("Expected Creator Scalpel-CLI v2.0, got %s v%s", har.Log.Creator.Name, har.Log.Creator.Version)
	}
	// Entries should be initialized as an empty slice, not nil, to ensure JSON output is [] not null.
	if har.Log.Entries == nil {
		t.Error("HAR Log Entries should be initialized (empty slice), not nil")
	}
	if len(har.Log.Entries) != 0 {
		t.Errorf("Expected 0 initial entries, got %d", len(har.Log.Entries))
	}
}

// TestHARSerialization tests the HAR structure round trip, ensuring compliance with the format,
// especially the distinct HARCookie time format.
func TestHARSerialization(t *testing.T) {
	now := getTestTime(t)
	// CRITICAL: HARCookie Expires must be ISO 8601 format string (RFC3339Nano is compatible).
	// This is different from schemas.Cookie which uses a float Unix timestamp.
	expiresISO := now.Add(24 * time.Hour).Format(time.RFC3339Nano)

	har := schemas.NewHAR()
	har.Log.Pages = append(har.Log.Pages, schemas.Page{
		StartedDateTime: now,
		ID:              "page_1",
		Title:           "Test Page",
	})

	entry := schemas.Entry{
		Pageref:         "page_1",
		StartedDateTime: now,
		Time:            150.5,
		Request: schemas.Request{
			Method: "POST",
			URL:    "https://example.com/api",
			// Uses HARCookie (string expires)
			Cookies: []schemas.HARCookie{
				{Name: "req_cookie", Value: "123"},
			},
			Headers: []schemas.NVPair{
				{Name: "Content-Type", Value: "application/json"},
			},
			PostData: &schemas.PostData{
				MimeType: "application/json",
				Text:     `{"key":"value"}`,
			},
		},
		Response: schemas.Response{
			Status: 200,
			// Uses HARCookie (string expires)
			Cookies: []schemas.HARCookie{
				{Name: "session", Value: "abc", Expires: expiresISO, HTTPOnly: true, Secure: true},
			},
			Content: schemas.Content{
				MimeType: "application/json",
				Text:     `{"status":"ok"}`,
				Encoding: "base64",
			},
		},
		Timings: schemas.Timings{
			Wait: 100.0,
		},
	}
	har.Log.Entries = append(har.Log.Entries, entry)

	testJSONRoundTrip(t, har, func() interface{} { return &schemas.HAR{} })

	// Specific check for HARCookie Expires format retention
	data, _ := json.Marshal(har)
	var decodedHAR schemas.HAR
	json.Unmarshal(data, &decodedHAR)

	if len(decodedHAR.Log.Entries) > 0 && len(decodedHAR.Log.Entries[0].Response.Cookies) > 0 {
		cookie := decodedHAR.Log.Entries[0].Response.Cookies[0]
		if cookie.Expires != expiresISO {
			t.Errorf("HARCookie Expires format mismatch. Expected ISO 8601 string.\nGot: %s\nWant: %s", cookie.Expires, expiresISO)
		}
	} else {
		t.Fatal("Failed to find response cookies for validation.")
	}
}

// TestHumanoidAndLLMSerialization tests the remaining specialized schemas.
func TestHumanoidAndLLMSerialization(t *testing.T) {
	t.Run("LLM GenerationRequest", func(t *testing.T) {
		req := &schemas.GenerationRequest{
			SystemPrompt: "You are a helpful assistant.",
			UserPrompt:   "What is the capital of France?",
			Tier:         schemas.TierPowerful,
			Options: schemas.GenerationOptions{
				Temperature:     llmutil.Float64Ptr(0.7),
				ForceJSONFormat: true,
				TopP:            0.9,
				TopK:            40,
			},
		}
		testJSONRoundTrip(t, req, func() interface{} { return &schemas.GenerationRequest{} })
	})

	t.Run("Humanoid ElementGeometry", func(t *testing.T) {
		geo := &schemas.ElementGeometry{
			Vertices: []float64{10.0, 20.0, 110.0, 20.0, 110.0, 70.0, 10.0, 70.0},
			Width:    100,
			Height:   50,
		}
		testJSONRoundTrip(t, geo, func() interface{} { return &schemas.ElementGeometry{} })
	})

	t.Run("Humanoid MouseEventData", func(t *testing.T) {
		event := &schemas.MouseEventData{
			Type:       schemas.MousePress,
			X:          55.5,
			Y:          45.5,
			Button:     schemas.ButtonLeft,
			ClickCount: 1,
		}
		testJSONRoundTrip(t, event, func() interface{} { return &schemas.MouseEventData{} })
	})
}

// TestJSONRawMessageHandling ensures that json.RawMessage fields are treated as valid JSON objects during marshalling.
func TestJSONRawMessageHandling(t *testing.T) {
	// 1. Valid JSON object as RawMessage
	validProps := json.RawMessage(`{"key": "value"}`)
	node := schemas.Node{
		ID:         "n1",
		Properties: validProps,
	}

	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("Failed to marshal node with valid RawMessage: %v", err)
	}

	// Ensure the properties field is embedded as an object, not a string.
	expectedJSON := `{
        "id":"n1",
        "type":"",
        "label":"",
        "status":"",
        "properties":{"key": "value"},
        "created_at":"0001-01-01T00:00:00Z",
        "last_seen":"0001-01-01T00:00:00Z"
    }`
	assertJSONEqual(t, []byte(expectedJSON), data)

	// 2. Empty RawMessage
	// FIX #2: Changed from json.RawMessage{} (invalid empty slice) to json.RawMessage(nil) (valid nil slice).
	// This correctly tests the desired behavior of marshaling a nil RawMessage to the JSON literal 'null'.
	emptyProps := json.RawMessage(nil)
	nodeEmpty := schemas.Node{
		ID:         "n2",
		Properties: emptyProps,
	}

	dataEmpty, err := json.Marshal(nodeEmpty)
	if err != nil {
		t.Fatalf("Failed to marshal node with empty RawMessage: %v", err)
	}

	// A nil json.RawMessage marshals to 'null'.
	expectedEmptyJSON := `{
        "id":"n2",
        "type":"",
        "label":"",
        "status":"",
        "properties":null,
        "created_at":"0001-01-01T00:00:00Z",
        "last_seen":"0001-01-01T00:00:00Z"
    }`
	assertJSONEqual(t, []byte(expectedEmptyJSON), dataEmpty)

	// 3. Test Unmarshalling into RawMessage
	inputJSON := `{"id":"n3", "properties": {"nested": [1, 2, 3]}}`
	var nodeInput schemas.Node
	if err := json.Unmarshal([]byte(inputJSON), &nodeInput); err != nil {
		t.Fatalf("Failed to unmarshal into Node: %v", err)
	}

	expectedRaw := `{"nested": [1, 2, 3]}`

	// Compare the resulting RawMessage semantically
	var expectedMap, actualMap map[string]interface{}
	if err := json.Unmarshal([]byte(expectedRaw), &expectedMap); err != nil {
		t.Fatalf("Failed to unmarshal expected RawMessage: %v", err)
	}
	if err := json.Unmarshal(nodeInput.Properties, &actualMap); err != nil {
		t.Fatalf("Failed to unmarshal actual RawMessage: %v", err)
	}

	if diff := cmp.Diff(expectedMap, actualMap); diff != "" {
		t.Errorf("RawMessage content mismatch after unmarshal (-want +got):\n%s", diff)
	}
}
