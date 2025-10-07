package idor

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// --- Mocks and Helpers ---

// MockSession implements the Session interface for testing.
type MockSession struct {
	AuthToken string
	IsAuth    bool
}

func (s *MockSession) IsAuthenticated() bool {
	return s.IsAuth
}

func (s *MockSession) ApplyToRequest(req *http.Request) {
	if s.IsAuth && s.AuthToken != "" {
        // Ensure the header map is initialized
        if req.Header == nil {
            req.Header = make(http.Header)
        }
		req.Header.Set("Authorization", "Bearer "+s.AuthToken)
	}
}

// Helper to create a RequestResponsePair
func createMockPair(method, url, reqBody, respBody string, statusCode int) RequestResponsePair {
	req := httptest.NewRequest(method, url, strings.NewReader(reqBody))
	resp := &http.Response{
		StatusCode:    statusCode,
		Body:          io.NopCloser(strings.NewReader(respBody)),
		ContentLength: int64(len(respBody)),
		Header:        make(http.Header),
	}
	return RequestResponsePair{Request: req, Response: resp}
}

// --- Tests for analyzer.go ---

func TestAnalyzeTraffic_Validations(t *testing.T) {
	analyzer := NewIDORAnalyzer(log.New(io.Discard, "", 0))
	traffic := []RequestResponsePair{createMockPair("GET", "/", "", "", 200)}
    authSession := &MockSession{IsAuth: true}
    unauthSession := &MockSession{IsAuth: false}

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{"Both Nil", Config{}, true},
		{"Session1 Nil", Config{SecondSession: authSession}, true},
        {"Session2 Nil", Config{Session: authSession}, true},
		{"Session1 Unauth", Config{Session: unauthSession, SecondSession: authSession}, true},
		{"Session2 Unauth", Config{Session: authSession, SecondSession: unauthSession}, true},
		{"Authenticated", Config{Session: authSession, SecondSession: authSession}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := analyzer.AnalyzeTraffic(traffic, tt.config)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected an error, but got nil")
				}
				if _, ok := err.(*ErrUnauthenticated); !ok {
					t.Errorf("Expected error type *ErrUnauthenticated, but got %T", err)
				}
			} else if err != nil {
				t.Errorf("Expected no error, but got %v", err)
			}
		})
	}
}

func TestAnalyzeTraffic_EmptyTraffic(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	analyzer := NewIDORAnalyzer(logger)
	config := Config{
		Session:       &MockSession{IsAuth: true},
		SecondSession: &MockSession{IsAuth: true},
	}

	findings, err := analyzer.AnalyzeTraffic(nil, config)
	if err != nil {
		t.Fatalf("AnalyzeTraffic failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(findings))
	}
    // Verify the specific log message for this condition
	if !strings.Contains(buf.String(), "No traffic provided to analyze.") {
		t.Errorf("Expected log message about empty traffic, got: %s", buf.String())
	}
}

// --- Tests for idor.go ---

func TestIdentifyPotentialIDParameters(t *testing.T) {
	traffic := []RequestResponsePair{
		createMockPair("GET", "/api?id=10&user_id=20&PROFILE_ID=30", "", "", 200),
		createMockPair("GET", "/api?id=40&other=50", "", "", 200),
	}
	explicitParams := []string{"other", "not_found"}

    // The implementation is case-sensitive and overwrites values (last one seen wins).
	expected := map[string]string{
		"id":        "40", // Last value seen
		"user_id":   "20",
        // PROFILE_ID is NOT included because the implementation check (key == common) is case-sensitive.
		"other":     "", // Explicitly added, initialized as empty by implementation
		"not_found": "",
	}

	params := identifyPotentialIDParameters(traffic, explicitParams)

	if !reflect.DeepEqual(params, expected) {
		t.Errorf("Identified parameters do not match expected behavior.\nGot: %v\nWant: %v", params, expected)
	}
}

func TestRequestContainsParam(t *testing.T) {
	req := httptest.NewRequest("GET", "/test?param1=value1&param2=", nil)

	if !requestContainsParam(req, "param1") {
		t.Error("Expected true for param1")
	}
	// The implementation checks req.URL.Query().Get(paramName) != ""
	if requestContainsParam(req, "param2") {
		t.Error("Expected false for param2 (empty value)")
	}
	if requestContainsParam(req, "param3") {
		t.Error("Expected false for param3 (not found)")
	}
}

// TestDetect_Integration uses httptest.Server to validate the detection logic.
func TestDetect_Integration(t *testing.T) {
	User1Token := "TokenA"
	User2Token := "TokenB"

	// 1. Setup Mock Server simulating application behavior
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken := r.Header.Get("Authorization")

        // This server simulates the replay requests made by the analyzer (using User2Token).
		if authToken != "Bearer "+User2Token {
            // Requests should only come from the second session during Detect
            w.WriteHeader(http.StatusUnauthorized)
            return
        }

		switch r.URL.Path {
		case "/vulnerable":
			// IDOR: User 2 can access. Returns same body as User 1 observed.
            w.WriteHeader(http.StatusOK)
            fmt.Fprint(w, "SensitiveData")
		case "/secure":
			// Secure: User 2 cannot access.
            w.WriteHeader(http.StatusForbidden)
		case "/different_length":
			// Secure (by current logic): User 2 gets 200 OK, but the response length differs.
            w.WriteHeader(http.StatusOK)
            fmt.Fprint(w, "Different")
		}
	}))
	defer server.Close()

	// 2. Define Config
	config := Config{
		Session:       &MockSession{AuthToken: User1Token, IsAuth: true},
		SecondSession: &MockSession{AuthToken: User2Token, IsAuth: true},
	}

	// 3. Define Traffic (Observed by User 1)
	traffic := []RequestResponsePair{
		createMockPair("GET", server.URL+"/vulnerable?id=1", "", "SensitiveData", 200),
		createMockPair("GET", server.URL+"/secure?user_id=2", "", "SecureData", 200),
		createMockPair("GET", server.URL+"/different_length?id=3", "", "SensitiveDataLong", 200),
	}

	// 4. Run Detection
    logger := log.New(io.Discard, "", 0)
	findings, err := Detect(traffic, config, logger)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}

	// 5. Assertions: Expect 1 finding for the /vulnerable endpoint.
	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d. Findings: %+v", len(findings), findings)
	}

	finding := findings[0]
	if finding.URL != server.URL+"/vulnerable?id=1" {
		t.Errorf("URL mismatch. Got %s, Want %s/vulnerable?id=1", finding.URL, server.URL)
	}
    // The implementation identifies 'id' because it's a common name and present in the vulnerable request.
	if finding.Parameter != "id" {
		t.Errorf("Parameter mismatch. Got %s, Want id", finding.Parameter)
	}
}
