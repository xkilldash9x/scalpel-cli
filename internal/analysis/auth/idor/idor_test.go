// internal/analysis/auth/idor/analyzer_test.go
package idor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// ====================================================================================
// Mock Definitions
// ====================================================================================

// MockReporter mocks the core.Reporter interface.
// It captures findings concurrently and provides safe access for verification.
type MockReporter struct {
	mock.Mock
	findings []core.AnalysisResult
	mu       sync.Mutex
}

func (m *MockReporter) Publish(finding core.AnalysisResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	args := m.Called(finding)
	// Capture the finding only if Publish succeeds (allows testing reporter errors)
	if args.Error(0) == nil {
		m.findings = append(m.findings, finding)
	}
	return args.Error(0)
}

// GetFindings safely retrieves the recorded findings.
func (m *MockReporter) GetFindings() []core.AnalysisResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy to prevent race conditions in tests accessing the slice concurrently
	findings := make([]core.AnalysisResult, len(m.findings))
	copy(findings, m.findings)
	return findings
}

// ====================================================================================
// Test Setup Helpers
// ====================================================================================

const (
	RolePrimary   = "UserA_Victim"
	RoleSecondary = "UserB_Attacker"
	RoleUnrelated = "UserC_Other"
)

// setupAnalyzer creates a standard Analyzer instance for testing, along with its mocks.
func setupAnalyzer(t *testing.T, concurrency int) (*Analyzer, *MockReporter, *zap.Logger) {
	t.Helper()
	logger := zaptest.NewLogger(t)
	scanID := uuid.New()
	reporter := new(MockReporter)

	// Set default concurrency optimized for testing if not specified or invalid
	if concurrency <= 0 {
		concurrency = 5
	}

	analyzer := NewAnalyzer(scanID, logger, reporter, concurrency)
	require.NotNil(t, analyzer, "NewAnalyzer should return a non-nil instance")

	return analyzer, reporter, logger
}

// setupInitializedAnalyzer initializes the analyzer and standard roles (Primary and Secondary).
func setupInitializedAnalyzer(t *testing.T) (*Analyzer, *MockReporter) {
	t.Helper()
	// Use default concurrency (5)
	analyzer, reporter, _ := setupAnalyzer(t, 5)

	require.NoError(t, analyzer.InitializeSession(RolePrimary), "Initializing Primary role failed")
	require.NoError(t, analyzer.InitializeSession(RoleSecondary), "Initializing Secondary role failed")

	return analyzer, reporter
}

// setupObservationServer creates a mock HTTP server for testing request execution and application behavior.
func setupObservationServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	// Use a robust handler that recovers from panics within the specific test handler,
	// preventing the entire test suite from crashing if one handler fails.
	robustHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				t.Errorf("HTTP server handler panicked: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		handler(w, r)
	})
	server := httptest.NewServer(robustHandler)
	t.Cleanup(server.Close)
	return server
}

// ====================================================================================
// Test Cases: Initialization and Configuration
// ====================================================================================

// TestNewAnalyzer_Defaults verifies constructor behavior and default settings.
func TestNewAnalyzer_Defaults(t *testing.T) {
	scanID := uuid.New()
	logger := zaptest.NewLogger(t)
	reporter := new(MockReporter)

	// Test 1: Default concurrency when provided 0 (as defined in NewAnalyzer implementation)
	analyzer1 := NewAnalyzer(scanID, logger, reporter, 0)
	// White-box access to the unexported 'concurrency' field.
	assert.Equal(t, 10, analyzer1.concurrency, "Concurrency should default to 10 if 0 is provided")

	// Test 2: Default concurrency when provided negative value
	analyzer2 := NewAnalyzer(scanID, logger, reporter, -5)
	assert.Equal(t, 10, analyzer2.concurrency, "Concurrency should default to 10 if negative is provided")

	// Test 3: Valid concurrency
	analyzer3 := NewAnalyzer(scanID, logger, reporter, 25)
	assert.Equal(t, 25, analyzer3.concurrency)

	// Verify common fields initialization
	assert.Equal(t, scanID, analyzer3.ScanID)
	assert.NotNil(t, analyzer3.sessions, "Sessions map should be initialized")
}

// TestInitializeSession_Success verifies session creation and HTTP client configuration.
func TestInitializeSession_Success(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, 5)
	role := "TestRole"

	err := analyzer.InitializeSession(role)
	require.NoError(t, err)

	// Verify session exists (Thread-safe access)
	analyzer.mu.RLock()
	session, exists := analyzer.sessions[role]
	analyzer.mu.RUnlock()

	require.True(t, exists)
	require.NotNil(t, session)

	// Verify Client configuration details
	assert.NotNil(t, session.Client)
	assert.NotNil(t, session.Client.Jar, "Cookie jar must be initialized for session isolation")
	assert.Equal(t, 15*time.Second, session.Client.Timeout)

	// Verify Redirect handling (Crucial for IDOR testing)
	// We check if the CheckRedirect function returns the specific error indicating "Use Last Response".
	// This ensures the analyzer can observe authorization responses (e.g., 302 vs 403) instead of following them.
	err = session.Client.CheckRedirect(nil, nil)
	assert.Equal(t, http.ErrUseLastResponse, err, "Client must be configured to not follow redirects")
}

// TestInitializeSession_DuplicateRole verifies that roles must be unique.
func TestInitializeSession_DuplicateRole(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, 5)
	role := "TestRole"

	err := analyzer.InitializeSession(role)
	require.NoError(t, err)

	// Attempt to initialize the same role again
	err = analyzer.InitializeSession(role)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already initialized")
}

// TestInitializeSession_ConcurrencySafety verifies thread-safe session initialization.
func TestInitializeSession_ConcurrencySafety(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, 5)
	count := 50
	wg := sync.WaitGroup{}

	// Concurrently initialize many unique sessions
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			role := fmt.Sprintf("Role_%d", i)
			err := analyzer.InitializeSession(role)
			// Use require fail-fast if initialization fails, as it indicates a potential data race or locking issue.
			require.NoError(t, err, "Concurrent initialization failed for %s", role)
		}(i)
	}
	wg.Wait()

	// Verify all sessions were created successfully
	analyzer.mu.RLock()
	defer analyzer.mu.RUnlock()
	assert.Len(t, analyzer.sessions, count)
}

// ====================================================================================
// Test Cases: Observation Phase (ObserveAndExecute)
// ====================================================================================

// TestObserveAndExecute_Success_WithIdentifiers verifies request execution and storage when IDs are found.
func TestObserveAndExecute_Success_WithIdentifiers(t *testing.T) {
	analyzer, _ := setupInitializedAnalyzer(t)
	ctx := context.Background()
	expectedBody := "Response for item 12345"
	expectedStatus := http.StatusOK

	// Setup mock server
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/items/12345", r.URL.Path)
		w.WriteHeader(expectedStatus)
		w.Write([]byte(expectedBody))
	})

	// Prepare request
	targetURL := server.URL + "/api/items/12345" // 12345 is the identifier
	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)

	// Execute
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	// Crucial: Ensure the response body is closed by the caller (the test in this case).
	defer resp.Body.Close()

	// Verify Response (Ensuring the analyzer correctly proxies the response and resets the body)
	assert.Equal(t, expectedStatus, resp.StatusCode)
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, expectedBody, string(respBody))

	// Verify Observation Storage (Thread-safe white-box access)
	session := analyzer.sessions[RolePrimary]
	session.mu.RLock()
	defer session.mu.RUnlock()

	requestKey := "GET /api/items/12345"
	observed, exists := session.ObservedRequests[requestKey]
	require.True(t, exists, "Request should be stored in ObservedRequests")

	// Verify stored baseline details
	assert.Equal(t, expectedStatus, observed.BaselineStatus)
	assert.Equal(t, int64(len(expectedBody)), observed.BaselineLength)
	assert.Empty(t, observed.Body, "GET request body should be empty")

	// Verify Identifier extraction results
	require.Len(t, observed.Identifiers, 1)
	assert.Equal(t, "12345", observed.Identifiers[0].Value)
	assert.Equal(t, TypeNumericID, observed.Identifiers[0].Type)
}

// TestObserveAndExecute_NoIdentifiers verifies that requests without interesting IDs are executed but not stored.
func TestObserveAndExecute_NoIdentifiers(t *testing.T) {
	analyzer, _ := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// Setup mock server
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Static content"))
	})

	// Prepare request (No IDs)
	req, _ := http.NewRequest(http.MethodGet, server.URL+"/static/page.html", nil)

	// Execute
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// Verify Observation Storage
	session := analyzer.sessions[RolePrimary]
	session.mu.RLock()
	defer session.mu.RUnlock()

	assert.Empty(t, session.ObservedRequests, "Requests without identifiers should not be stored")
}

// TestObserveAndExecute_PostRequest verifies handling of requests with bodies (e.g., JSON) and identifier extraction.
func TestObserveAndExecute_PostRequest(t *testing.T) {
	analyzer, _ := setupInitializedAnalyzer(t)
	ctx := context.Background()
	requestBody := `{"action": "view", "userId": 998877}` // 998877 is the identifier

	// Setup mock server to echo back the request body for verification of request handling
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		// Read the body to ensure the analyzer correctly set it up
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		w.WriteHeader(http.StatusAccepted)
		w.Write(body) // Echo back
	})

	// Prepare request
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/action", nil)
	req.Header.Set("Content-Type", "application/json")

	// Execute (passing the body separately as the crawler would)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, []byte(requestBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify response body matches request body (echoed)
	respBody, _ := io.ReadAll(resp.Body)
	assert.Equal(t, requestBody, string(respBody))

	// Verify Observation Storage
	session := analyzer.sessions[RolePrimary]
	session.mu.RLock()
	defer session.mu.RUnlock()

	requestKey := "POST /api/action"
	observed, exists := session.ObservedRequests[requestKey]
	require.True(t, exists)

	// Verify stored body matches original request body
	assert.Equal(t, requestBody, string(observed.Body))
	assert.Equal(t, http.StatusAccepted, observed.BaselineStatus)

	// Verify Identifier extraction from JSON
	require.Len(t, observed.Identifiers, 1)
	assert.Equal(t, "998877", observed.Identifiers[0].Value)
	assert.Equal(t, LocationJSONBody, observed.Identifiers[0].Location)
}

// TestObserveAndExecute_UninitializedRole verifies error handling for missing sessions.
func TestObserveAndExecute_UninitializedRole(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, 5) // Analyzer not initialized with roles
	ctx := context.Background()

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)

	resp, err := analyzer.ObserveAndExecute(ctx, "NonExistentRole", req, nil)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "not initialized")
}

// TestObserveAndExecute_NetworkError verifies handling of connection failures during observation.
func TestObserveAndExecute_NetworkError(t *testing.T) {
	analyzer, _ := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// Create and immediately close a server to simulate connection refused
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)

	// Execute
	_, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)

	// Verify error is returned
	assert.Error(t, err)

	// The request should not be recorded if it failed to execute completely.
	session := analyzer.sessions[RolePrimary]
	session.mu.RLock()
	defer session.mu.RUnlock()
	assert.Empty(t, session.ObservedRequests)
}

// TestObserveAndExecute_ConcurrencySafety verifies thread-safe observation recording for the same session.
func TestObserveAndExecute_ConcurrencySafety(t *testing.T) {
	analyzer, _ := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// Setup a simple responsive server
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Concurrently observe different requests for the same role
	wg := sync.WaitGroup{}
	count := 50
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Use a predictable identifier in the URL to ensure it's recorded
			targetURL := fmt.Sprintf("%s/api/resource/%d", server.URL, 10000+i)
			req, _ := http.NewRequest(http.MethodGet, targetURL, nil)

			resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
			// Fail fast if execution fails, indicating potential issues.
			require.NoError(t, err)
			resp.Body.Close()
		}(i)
	}
	wg.Wait()

	// Verify all requests were recorded without data races (protected by SessionContext.mu)
	session := analyzer.sessions[RolePrimary]
	session.mu.RLock()
	defer session.mu.RUnlock()
	assert.Len(t, session.ObservedRequests, count)
}

// ====================================================================================
// Test Cases: Identifier Handling (idor.go Unit Tests)
// Comprehensive tests for the critical helper functions: Classification, Extraction, Generation, and Application.
// ====================================================================================

// TestClassifyIdentifier comprehensively tests the classification logic and heuristics.
func TestClassifyIdentifier(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  IdentifierType
	}{
		// UUIDs (Case-insensitive)
		{"UUIDv4", "f47ac10b-58cc-4372-a567-0e02b2c3d479", TypeUUID},
		{"UUID uppercase", "F47AC10B-58CC-4372-A567-0E02B2C3D479", TypeUUID},

		// MongoDB ObjectIDs (Case-insensitive, 24 hex chars)
		{"ObjectID", "507f1f77bcf86cd799439011", TypeObjectID},
		{"ObjectID uppercase", "507F1F77BCF86CD799439011", TypeObjectID},

		// Numeric IDs (1-19 digits)
		{"Numeric Short", "12345", TypeNumericID},
		{"Numeric Long (Max Int64)", "9223372036854775807", TypeNumericID},
		{"Numeric 1 digit", "1", TypeNumericID},

		// Base64 (Length >= 8, matches regex, and passes decoding heuristic)
		{"Base64 Std (Padded)", "aGVsbG8gd29ybGQ=", TypeBase64}, // "hello world"
		{"Base64 URL-Safe", "aGVsbG8tMTIzNA==", TypeBase64},
		{"Base64 Raw (No padding)", "aGVsbG8xMjM0", TypeBase64},

		// False Positives and Heuristics
		{"Empty String", "", TypeUnknown},
		{"Non-ID String", "username", TypeUnknown},
		{"Numeric Too Long (>19 digits)", "12345678901234567890", TypeUnknown},
		{"Base64 too short (<8)", "YQ==", TypeUnknown}, // "a"
		{"Invalid Base64 characters", "invalid!@#", TypeUnknown},

		// Numeric Heuristics (Filtering common non-IDs)
		{"Year (1980-2100)", "2023", TypeUnknown},
		{"Year (Boundary)", "1980", TypeUnknown},
		{"Year (Outside boundary)", "1979", TypeNumericID},
		{"Common Port (80)", "80", TypeUnknown},
		{"Common Port (8080)", "8080", TypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyIdentifier(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestExtractIdentifiers_Comprehensive verifies extraction from all supported locations (URL, Query, JSON Body, Headers).
func TestExtractIdentifiers_Comprehensive(t *testing.T) {
	// 1. Setup Request
	// URL Path: /api/users/12345/posts/f47ac10b-58cc-4372-a567-0e02b2c3d479 (Numeric and UUID)
	// Query Param: session_id=507f1f77bcf86cd799439011 (ObjectID)
	targetURL := "http://example.com/api/users/12345/posts/f47ac10b-58cc-4372-a567-0e02b2c3d479?session_id=507f1f77bcf86cd799439011&filter=recent"

	// JSON Body (Nested structure, arrays, different types)
	// Includes Numeric, Base64. Uses UseNumber() internally for precision.
	body := `{
		"request_id": 67890,
		"metadata": {
			"auth_token": "aGVsbG8gd29ybGQ=",
			"details": [
				{"item_id": 1001},
				{"item_id": 1002}
			]
		},
		"filter": "none"
	}`

	req, _ := http.NewRequest(http.MethodPost, targetURL, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Correlation-ID", "99999")
	// Standard auth/cookie headers should be ignored by ExtractIdentifiers
	req.Header.Set("Authorization", "Bearer ignored_token")
	req.Header.Set("Cookie", "ignored_cookie")

	// 2. Execute
	identifiers := ExtractIdentifiers(req, []byte(body))

	// 3. Verify (Use ElementsMatch for order-independent comparison)
	expected := []ObservedIdentifier{
		// URL Path (Note the PathIndex which is crucial for correct replacement)
		{Value: "12345", Type: TypeNumericID, Location: LocationURLPath, PathIndex: 3},
		{Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479", Type: TypeUUID, Location: LocationURLPath, PathIndex: 5},
		// Query Param
		{Value: "507f1f77bcf86cd799439011", Type: TypeObjectID, Location: LocationQueryParam, Key: "session_id"},
		// JSON Body (Note the dot-separated keys for nested access)
		{Value: "67890", Type: TypeNumericID, Location: LocationJSONBody, Key: "request_id"},
		{Value: "aGVsbG8gd29ybGQ=", Type: TypeBase64, Location: LocationJSONBody, Key: "metadata.auth_token"},
		{Value: "1001", Type: TypeNumericID, Location: LocationJSONBody, Key: "metadata.details.0.item_id"},
		{Value: "1002", Type: TypeNumericID, Location: LocationJSONBody, Key: "metadata.details.1.item_id"},
		// Headers
		{Value: "99999", Type: TypeNumericID, Location: LocationHeader, Key: "X-Correlation-ID"},
	}

	assert.ElementsMatch(t, expected, identifiers)
}

// TestExtractIdentifiers_NonJSONBody verifies that non-JSON content types are skipped during body analysis.
func TestExtractIdentifiers_NonJSONBody(t *testing.T) {
	targetURL := "http://example.com/api/data"
	// Body contains identifiers, but Content-Type is XML
	body := `<data><id>12345</id></data>`
	req, _ := http.NewRequest(http.MethodPost, targetURL, nil)
	req.Header.Set("Content-Type", "application/xml")

	identifiers := ExtractIdentifiers(req, []byte(body))
	assert.Empty(t, identifiers, "Should not extract IDs from non-JSON bodies (e.g., XML)")
}

// TestGenerateTestValue verifies the logic for creating plausible, predictable alternative IDs for testing.
func TestGenerateTestValue(t *testing.T) {
	tests := []struct {
		name       string
		identifier ObservedIdentifier
		want       string
		wantErr    bool
	}{
		// Numeric (Simple increment)
		{"Numeric Increment", ObservedIdentifier{Type: TypeNumericID, Value: "100"}, "101", false},
		{"Numeric Large", ObservedIdentifier{Type: TypeNumericID, Value: "9223372036854775806"}, "9223372036854775807", false},

		// Base64 (Decode, flip last bit, re-encode)
		// "hello" (aGVsbG8=) -> flip last bit of 'o' -> "helln" (aGVsbG4=)
		{"Base64 Std", ObservedIdentifier{Type: TypeBase64, Value: "aGVsbG8="}, "aGVsbG4=", false},
		// "test-1" (dGVzdC0x) -> flip last bit of '1' -> "test-0" (dGVzdC0w)
		{"Base64 RawURL", ObservedIdentifier{Type: TypeBase64, Value: "dGVzdC0x"}, "dGVzdC0w", false},

		// ObjectID (Hex cycle modification of the last character)
		{"ObjectID Increment (0-9)", ObservedIdentifier{Type: TypeObjectID, Value: "507f1f77bcf86cd799439011"}, "507f1f77bcf86cd799439012", false},
		{"ObjectID Increment (a-f)", ObservedIdentifier{Type: TypeObjectID, Value: "507f1f77bcf86cd79943901a"}, "507f1f77bcf86cd79943901b", false},
		{"ObjectID Wrap (f->0)", ObservedIdentifier{Type: TypeObjectID, Value: "507f1f77bcf86cd79943901f"}, "507f1f77bcf86cd799439010", false},

		// Unsupported Types (Predictive testing must skip these)
		{"UUID (Unsupported)", ObservedIdentifier{Type: TypeUUID, Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479"}, "", true},
		{"Unknown (Unsupported)", ObservedIdentifier{Type: TypeUnknown, Value: "test"}, "", true},

		// Error cases
		{"Invalid Numeric (Parse error)", ObservedIdentifier{Type: TypeNumericID, Value: "abc"}, "", true},
		{"Undecodable Base64", ObservedIdentifier{Type: TypeBase64, Value: "invalid!"}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateTestValue(tt.identifier)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestApplyTestValue_Comprehensive verifies the modification of the request object in all locations.
func TestApplyTestValue_Comprehensive(t *testing.T) {
	// Setup baseline request
	originalURL := "http://example.com/api/resource/100?id=200"
	originalBody := `{"data": {"key": 300}}`
	req, _ := http.NewRequest(http.MethodPost, originalURL, bytes.NewReader([]byte(originalBody)))
	req.Header.Set("X-Test-ID", "400")

	testValue := "999"

	tests := []struct {
		name           string
		identifier     ObservedIdentifier
		expectedURL    string
		expectedHeader string
		expectedBody   string
	}{
		{
			"URL Path (Index based)",
			// PathIndex 3 corresponds to "100" in /api/resource/100
			ObservedIdentifier{Location: LocationURLPath, Value: "100", PathIndex: 3},
			"http://example.com/api/resource/999?id=200", "", originalBody,
		},
		{
			"Query Param (Key based)",
			ObservedIdentifier{Location: LocationQueryParam, Key: "id", Value: "200"},
			// Note: URL encoding might change the order, but Query().Get() handles this. We check the full URL string here for simplicity assuming standard encoding order.
			"http://example.com/api/resource/100?id=999", "", originalBody,
		},
		{
			"Header (Key based)",
			ObservedIdentifier{Location: LocationHeader, Key: "X-Test-ID", Value: "400"},
			originalURL, "999", originalBody,
		},
		{
			"JSON Body (Path based, Numeric)",
			// TypeNumericID ensures the replacement value is treated as a number in JSON.
			ObservedIdentifier{Location: LocationJSONBody, Key: "data.key", Value: "300", Type: TypeNumericID},
			originalURL, "", `{"data":{"key":999}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Execute
			modifiedReq, modifiedBody, err := ApplyTestValue(req, []byte(originalBody), tt.identifier, testValue)
			require.NoError(t, err)

			// Verify URL modification
			assert.Equal(t, tt.expectedURL, modifiedReq.URL.String())

			// Verify Header modification
			if tt.expectedHeader != "" {
				assert.Equal(t, tt.expectedHeader, modifiedReq.Header.Get("X-Test-ID"))
			}

			// Verify Body modification (Use JSONEq for structured comparison, ignoring formatting differences)
			assert.JSONEq(t, tt.expectedBody, string(modifiedBody))

			// Verify Content-Length update if body changed
			if string(modifiedBody) != originalBody {
				assert.Equal(t, int64(len(modifiedBody)), modifiedReq.ContentLength)
			}
		})
	}
}

// TestModifyJSONPayload_StructuredModification verifies the robustness of the internal JSON modification helper.
// This tests the logic of navigating and updating the JSON structure (maps/slices) securely.
func TestModifyJSONPayload_StructuredModification(t *testing.T) {
	// Complex payload including arrays and nested objects.
	original := `{
		"users": [
			{"id": 101, "name": "Alice"},
			{"id": 102, "name": "Bob"}
		],
		"config": {"setting": "value", "id": 201}
	}`

	tests := []struct {
		name       string
		path       string
		testValue  string
		idType     IdentifierType
		expected   string
		wantErr    bool
	}{
		// Modification in Array (Index based access)
		{
			"Array Element (Numeric)", "users.1.id", "999", TypeNumericID,
			`{"users": [{"id": 101, "name": "Alice"}, {"id": 999, "name": "Bob"}], "config": {"setting": "value", "id": 201}}`,
			false,
		},
		// Modification in Object (Key based access)
		{
			"Nested Object (String)", "config.setting", "new_value", TypeUnknown,
			`{"users": [{"id": 101, "name": "Alice"}, {"id": 102, "name": "Bob"}], "config": {"setting": "new_value", "id": 201}}`,
			false,
		},
		// Type Preservation (Crucial: Numeric ID should remain a JSON number, not converted to a string)
		{
			"Type Preservation (Numeric)", "config.id", "888", TypeNumericID,
			`{"users": [{"id": 101, "name": "Alice"}, {"id": 102, "name": "Bob"}], "config": {"setting": "value", "id": 888}}`,
			false,
		},
		// Type Change (If TypeNumericID is not specified, it defaults to string replacement)
		{
			"Type Change (Numeric to String)", "config.id", "888", TypeUnknown,
			`{"users": [{"id": 101, "name": "Alice"}, {"id": 102, "name": "Bob"}], "config": {"setting": "value", "id": "888"}}`,
			false,
		},
		// Error Cases (Robustness against invalid paths)
		{"Invalid Path (Key not found)", "config.nonexistent", "val", TypeUnknown, "", true},
		{"Invalid Path (Array index out of bounds)", "users.5.id", "val", TypeUnknown, "", true},
		{"Invalid Path (Non-integer array index)", "users.abc.id", "val", TypeUnknown, "", true},
		{"Invalid Path (Type mismatch)", "config.setting.id", "val", TypeUnknown, "", true}, // Trying to index a string value
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the unexported modifyJSONPayload function
			identifier := ObservedIdentifier{Key: tt.path, Location: LocationJSONBody, Type: tt.idType}
			modified, err := modifyJSONPayload([]byte(original), identifier, tt.testValue)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				// Use JSONEq for structured comparison
				assert.JSONEq(t, tt.expected, string(modified))
			}
		})
	}
}

// ====================================================================================
// Test Cases: Analysis - Horizontal IDOR (User A vs User B)
// Tests the strategy of replaying Victim's requests using the Attacker's session.
// ====================================================================================

// TestRunAnalysis_Horizontal_Vulnerable verifies detection when the attacker successfully accesses the victim's resource.
func TestRunAnalysis_Horizontal_Vulnerable(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// A vulnerable endpoint that checks for authentication (any valid session) but lacks authorization (object-level checks).
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		// Vulnerable logic: Success for any authenticated user (Primary or Secondary).
		if cookie.Value == RolePrimary || cookie.Value == RoleSecondary {
			w.WriteHeader(http.StatusOK)
			// Include dynamic content (e.g., the accessor's role) to verify the response corresponds to the attacker's session.
			w.Write([]byte(fmt.Sprintf("Details for resource 12345. Accessed by %s.", cookie.Value)))
		} else {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
		}
	})

	// --- Observation Phase (Victim) ---
	// Simulate login: Set session cookies for both users.
	targetURL := server.URL + "/api/resource/12345"
	u, _ := url.Parse(targetURL)
	// The InitializeSession ensures clients have unique cookie jars.
	analyzer.sessions[RolePrimary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RolePrimary}})
	analyzer.sessions[RoleSecondary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RoleSecondary}})

	// Observe the victim accessing their resource
	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// Verify observation occurred
	assert.Len(t, analyzer.sessions[RolePrimary].ObservedRequests, 1)

	// --- Analysis Phase (Attacker vs Victim) ---
	// Expect a finding to be reported as the attacker's replay should succeed.
	reporter.On("Publish", mock.Anything).Return(nil).Once()

	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// --- Verification ---
	reporter.AssertExpectations(t)
	findings := reporter.GetFindings()
	require.Len(t, findings, 1)

	finding := findings[0]
	assert.Equal(t, "Horizontal Insecure Direct Object Reference (IDOR)", finding.Title)
	assert.Equal(t, core.SeverityHigh, finding.Severity)
	assert.Equal(t, targetURL, finding.TargetURL)
	assert.Equal(t, "CWE-284", finding.CWE)

	// Verify Evidence details (Crucial for confirming the vulnerability)
	require.NotNil(t, finding.Evidence)
	assert.Equal(t, http.StatusOK, finding.Evidence.Response.StatusCode)
	// Check that the response body confirms access by the secondary user (attacker)
	assert.Contains(t, finding.Evidence.Response.Body, fmt.Sprintf("Accessed by %s", RoleSecondary))
}

// TestRunAnalysis_Horizontal_Secure verifies no findings when the attacker is correctly blocked (e.g., 403 Forbidden).
func TestRunAnalysis_Horizontal_Secure(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// A secure endpoint that correctly implements object-level authorization.
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Secure logic: Resource 12345 belongs exclusively to RolePrimary.
		resourceID := r.URL.Path[len("/api/resource/"):]
		if resourceID == "12345" && cookie.Value == RolePrimary {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success: Details for 12345"))
		} else {
			// Correctly block RoleSecondary
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Error: Access denied"))
		}
	})

	// --- Observation Phase (Victim) ---
	targetURL := server.URL + "/api/resource/12345"
	u, _ := url.Parse(targetURL)
	analyzer.sessions[RolePrimary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RolePrimary}})
	analyzer.sessions[RoleSecondary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RoleSecondary}})

	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// --- Analysis Phase ---
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// --- Verification ---
	// No findings should be reported because the status codes differ (200 vs 403).
	assert.Empty(t, reporter.GetFindings())
}

// TestRunAnalysis_Horizontal_RedirectBehavior verifies handling of authorization via redirects (e.g., 302 Found).
// This tests the configuration where the HTTP client does not follow redirects.
func TestRunAnalysis_Horizontal_RedirectBehavior(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// Endpoint that uses redirects (302) to handle unauthorized access attempts.
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("session_id")

		// Logic: RolePrimary gets the resource (200 OK), RoleSecondary (or unauthenticated) gets redirected (302 Found).
		if cookie != nil && cookie.Value == RolePrimary {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Success: Resource Details"))
		} else {
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound) // 302
		}
	})

	// --- Observation Phase (Victim) ---
	targetURL := server.URL + "/api/secure/resource"
	u, _ := url.Parse(targetURL)
	analyzer.sessions[RolePrimary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RolePrimary}})
	// Secondary user has no cookie in this scenario (simulating unauthenticated access attempt)

	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// Verify baseline status is 200
	observed := analyzer.sessions[RolePrimary].ObservedRequests["GET /api/secure/resource"]
	assert.Equal(t, http.StatusOK, observed.BaselineStatus)

	// --- Analysis Phase ---
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// --- Verification ---
	// No findings, because the status codes differ (Baseline 200 vs Replay 302).
	assert.Empty(t, reporter.GetFindings())
}

// TestRunAnalysis_Horizontal_LengthTolerance verifies the detection logic handles minor variations in content length (e.g., dynamic content).
func TestRunAnalysis_Horizontal_LengthTolerance(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// Base content used to establish a significant baseline length.
	baseContent := "Resource details content. This is a substantial block of text. "
	// The detection logic uses a 10% tolerance for variations.

	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("session_id")
		w.WriteHeader(http.StatusOK) // Vulnerable: Same status code for both users.

		if cookie.Value == RolePrimary {
			// Dynamic content for Primary user (Length: 10)
			w.Write([]byte(baseContent + "User:Alice"))
		} else if cookie.Value == RoleSecondary {
			// Dynamic content for Secondary user (Length: 16)
			// This variation (6 bytes) is within the 10% tolerance of the total length (~90 bytes).
			w.Write([]byte(baseContent + "User:Bob_Attacker"))
		}
	})

	// Setup cookies and observe
	targetURL := server.URL + "/api/resource/1"
	u, _ := url.Parse(targetURL)
	analyzer.sessions[RolePrimary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RolePrimary}})
	analyzer.sessions[RoleSecondary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RoleSecondary}})

	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// Analysis
	reporter.On("Publish", mock.Anything).Return(nil).Once()
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// Verification
	assert.Len(t, reporter.GetFindings(), 1, "Should detect IDOR when content length variation is within tolerance")
}

// TestRunAnalysis_Horizontal_LengthExceeded verifies no detection if content length varies significantly, even if status codes match.
func TestRunAnalysis_Horizontal_LengthExceeded(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	baseContent := "Short content." // Length 14

	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("session_id")
		w.WriteHeader(http.StatusOK) // Same status code (False positive scenario)

		if cookie.Value == RolePrimary {
			w.Write([]byte(baseContent))
		} else if cookie.Value == RoleSecondary {
			// Significantly different content (e.g., a detailed error message or a different page structure)
			// This exceeds the 10% tolerance.
			w.Write([]byte("Error: Although we returned 200 OK, this is actually an error page with much different content."))
		}
	})

	// Setup and observe
	targetURL := server.URL + "/api/resource/1"
	u, _ := url.Parse(targetURL)
	analyzer.sessions[RolePrimary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RolePrimary}})
	analyzer.sessions[RoleSecondary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RoleSecondary}})

	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// Analysis
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// Verification
	assert.Empty(t, reporter.GetFindings(), "Should not detect IDOR if content length differs significantly")
}

// ====================================================================================
// Test Cases: Analysis - Predictive IDOR (Resource Enumeration)
// Tests the strategy of modifying identifiers (e.g., incrementing IDs) and checking if the modified request succeeds.
// ====================================================================================

// TestRunAnalysis_Predictive_Vulnerable_Numeric verifies detection when an incremented numeric ID returns a valid resource.
func TestRunAnalysis_Predictive_Vulnerable_Numeric(t *testing.T) {
	// Predictive analysis uses the original user's session.
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// An endpoint where resources are sequentially numbered (100, 101) and authorization checks are missing.
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		resourceID := r.URL.Path[len("/api/items/"):]

		// Vulnerable logic: Allows access to specific sequential IDs.
		if resourceID == "100" || resourceID == "101" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf("Success: Details for item %s", resourceID)))
		} else {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Error: Item not found"))
		}
	})

	// --- Observation Phase ---
	// Observe access to item 100.
	targetURL := server.URL + "/api/items/100"
	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// Verify observation and identifier type
	observed := analyzer.sessions[RolePrimary].ObservedRequests["GET /api/items/100"]
	require.Len(t, observed.Identifiers, 1)
	assert.Equal(t, TypeNumericID, observed.Identifiers[0].Type)

	// --- Analysis Phase ---
	// The analyzer should generate a test value (101) and attempt to access it.
	reporter.On("Publish", mock.Anything).Return(nil).Once()

	// RunAnalysis requires both roles, even though Predictive only actively uses the primary session for requests.
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// --- Verification ---
	reporter.AssertExpectations(t)
	findings := reporter.GetFindings()
	require.Len(t, findings, 1)

	finding := findings[0]
	assert.Equal(t, "Predictive Insecure Direct Object Reference (IDOR)", finding.Title)
	assert.Equal(t, core.SeverityMedium, finding.Severity)
	assert.Equal(t, "CWE-639", finding.CWE)

	// Verify Evidence details
	require.NotNil(t, finding.Evidence)
	// The request URL in the evidence must be the modified URL (101).
	assert.Equal(t, server.URL+"/api/items/101", finding.Evidence.Request.URL)
	assert.Equal(t, http.StatusOK, finding.Evidence.Response.StatusCode)
	// Check the description details the modification
	assert.Contains(t, finding.Description, "original identifier '100'")
	assert.Contains(t, finding.Description, "modified to '101'")
}

// TestRunAnalysis_Predictive_Secure verifies no findings when the predicted ID returns 404 or 403.
func TestRunAnalysis_Predictive_Secure(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// Endpoint where the next sequential ID does not exist.
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		resourceID := r.URL.Path[len("/api/items/"):]

		if resourceID == "100" {
			w.WriteHeader(http.StatusOK)
		} else {
			// Predicted ID 101 returns Not Found (Secure behavior).
			w.WriteHeader(http.StatusNotFound)
		}
	})

	// --- Observation Phase ---
	targetURL := server.URL + "/api/items/100"
	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// --- Analysis Phase ---
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// --- Verification ---
	// No findings because the predicted request resulted in a non-successful status (404).
	assert.Empty(t, reporter.GetFindings())
}

// TestRunAnalysis_Predictive_SkipUUID verifies that UUIDs are correctly skipped for predictive testing as they are non-enumerable.
func TestRunAnalysis_Predictive_SkipUUID(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()
	uuidVal := "f47ac10b-58cc-4372-a567-0e02b2c3d479"

	// Track if the server receives any requests other than the initial observation request.
	var requestCount int
	var mu sync.Mutex
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	// --- Observation Phase ---
	targetURL := server.URL + "/api/resource/" + uuidVal
	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// Verify identifier type
	observed := analyzer.sessions[RolePrimary].ObservedRequests["GET /api/resource/"+uuidVal]
	assert.Equal(t, TypeUUID, observed.Identifiers[0].Type)

	// --- Analysis Phase ---
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// --- Verification ---
	assert.Empty(t, reporter.GetFindings())
	// The server should only have received the single observation request.
	// The predictive worker should see the UUID type, fail to GenerateTestValue, and skip sending a request.
	mu.Lock()
	assert.Equal(t, 1, requestCount, "No predictive requests should be sent for UUIDs")
	mu.Unlock()
}

// TestRunAnalysis_Predictive_JSONBody verifies predictive testing works correctly for identifiers within JSON payloads.
func TestRunAnalysis_Predictive_JSONBody(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// Endpoint expecting a JSON body with a numeric ID.
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		var data map[string]interface{}
		// Use Decoder to read the request body robustly.
		decoder := json.NewDecoder(r.Body)
		decoder.UseNumber() // Match the analyzer's internal handling
		if err := decoder.Decode(&data); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Extract ID (expecting json.Number)
		idNum, ok := data["itemId"].(json.Number)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id, _ := idNum.Int64()

		// Vulnerable logic: Accepts sequential IDs 500 and 501.
		if id == 500 || id == 501 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(fmt.Sprintf(`{"status":"success", "id": %d}`, id)))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})

	// --- Observation Phase ---
	targetURL := server.URL + "/api/process"
	requestBody := `{"action": "view", "itemId": 500}`
	req, _ := http.NewRequest(http.MethodPost, targetURL, nil)
	req.Header.Set("Content-Type", "application/json")

	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, []byte(requestBody))
	require.NoError(t, err)
	resp.Body.Close()

	// --- Analysis Phase ---
	reporter.On("Publish", mock.Anything).Return(nil).Once()
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// --- Verification ---
	findings := reporter.GetFindings()
	require.Len(t, findings, 1)

	// Verify the evidence details
	require.NotNil(t, findings[0].Evidence)
	// The request body in the evidence must contain the modified ID (501).
	// Use JSONEq to verify the structured payload, confirming 501 is correctly injected as a JSON number.
	assert.JSONEq(t, `{"action": "view", "itemId": 501}`, findings[0].Evidence.Request.Body)
	assert.Contains(t, findings[0].Description, "modified to '501'")
}

// ====================================================================================
// Test Cases: Concurrency, Robustness, and Edge Cases
// ====================================================================================

// TestRunAnalysis_Concurrency_HighLoad verifies the worker pool implementation handles many concurrent tests correctly and efficiently.
func TestRunAnalysis_Concurrency_HighLoad(t *testing.T) {
	// Setup analyzer with high concurrency level
	analyzer, reporter, _ := setupAnalyzer(t, 50)
	analyzer.InitializeSession(RolePrimary)
	analyzer.InitializeSession(RoleSecondary)
	ctx := context.Background()

	// --- Setup Scenario ---
	// A simple server that always returns 200 OK (simulating vulnerable endpoints)
	// Includes a slight delay to ensure workers are operating concurrently.
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// --- Observation Phase (Simulated) ---
	// Manually populate many observed requests to focus the test on the analysis phase concurrency, skipping observation HTTP calls.
	observationCount := 200
	for i := 0; i < observationCount; i++ {
		id := 10000 + i
		targetURL := fmt.Sprintf("%s/api/item/%d", server.URL, id)
		req, _ := http.NewRequest(http.MethodGet, targetURL, nil)

		analyzer.sessions[RolePrimary].ObservedRequests[fmt.Sprintf("GET /api/item/%d", id)] = ObservedRequest{
			Request:        req,
			Identifiers:    []ObservedIdentifier{{Type: TypeNumericID, Value: fmt.Sprintf("%d", id)}},
			BaselineStatus: http.StatusOK,
			BaselineLength: 2, // Length of "OK"
		}
	}

	// --- Analysis Phase ---
	// Expect findings for both strategies (Horizontal and Predictive) for every observation.
	// Horizontal: 200 findings. Predictive: 200 findings. Total: 400.
	expectedFindings := observationCount * 2
	reporter.On("Publish", mock.Anything).Return(nil).Times(expectedFindings)

	startTime := time.Now()
	err := analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	duration := time.Since(startTime)
	require.NoError(t, err)

	// --- Verification ---
	reporter.AssertExpectations(t)
	assert.Len(t, reporter.GetFindings(), expectedFindings)

	// Verify efficiency: The concurrent execution should be significantly faster than sequential execution.
	// Sequential time estimate: (200 requests * 10ms/request) * 2 strategies = 4 seconds.
	assert.Less(t, duration, 1*time.Second, "Analysis should complete efficiently using concurrent workers")
}

// TestRunAnalysis_ContextCancellation verifies that the analysis stops promptly when the context is cancelled, preventing deadlocks.
func TestRunAnalysis_ContextCancellation(t *testing.T) {
	analyzer, reporter, _ := setupAnalyzer(t, 10)
	analyzer.InitializeSession(RolePrimary)
	analyzer.InitializeSession(RoleSecondary)
	ctx, cancel := context.WithCancel(context.Background())

	// --- Setup Scenario ---
	// A server that hangs indefinitely (or until explicitly stopped).
	serverHang := make(chan struct{})
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-serverHang // Wait until the channel is closed
		w.WriteHeader(http.StatusOK)
	})
	// Ensure the server eventually stops when the test finishes
	t.Cleanup(func() { close(serverHang) })

	// Populate ObservedRequests pointing to the hanging server
	for i := 0; i < 50; i++ {
		targetURL := fmt.Sprintf("%s/api/item/%d", server.URL, i)
		req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
		analyzer.sessions[RolePrimary].ObservedRequests[fmt.Sprintf("GET %d", i)] = ObservedRequest{
			Request:        req,
			Identifiers:    []ObservedIdentifier{{Type: TypeNumericID}},
			BaselineStatus: http.StatusOK,
		}
	}

	// --- Analysis Phase ---
	go func() {
		// Cancel the context shortly after starting the analysis
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	startTime := time.Now()
	// RunAnalysis should return when workers detect the cancellation.
	// The returned error might be nil if cancellation occurs gracefully within the workers.
	analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	duration := time.Since(startTime)

	// --- Verification ---
	// Analysis must stop quickly, not wait for the hanging requests.
	assert.Less(t, duration, 500*time.Millisecond, "Analysis did not stop promptly after context cancellation")

	// It's expected that few or no findings are reported as requests were hanging.
	assert.Less(t, len(reporter.GetFindings()), 100) // Max potential findings: 50 horizontal + 50 predictive
}

// TestRunAnalysis_EmptyObservationSet verifies behavior when no interesting requests were observed.
func TestRunAnalysis_EmptyObservationSet(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// No observation calls made.

	err := analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err, "RunAnalysis should handle empty observation sets gracefully")

	assert.Empty(t, reporter.GetFindings())
}

// TestRunAnalysis_InitializationChecks verifies that analysis requires both roles to be initialized before starting.
func TestRunAnalysis_InitializationChecks(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, 5)
	ctx := context.Background()

	// Case 1: Neither initialized
	err := analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be initialized")

	// Case 2: Only primary initialized
	analyzer.InitializeSession(RolePrimary)
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	assert.Error(t, err)

	// Case 3: Only secondary initialized (Swap roles)
	analyzer, _, _ = setupAnalyzer(t, 5) // Reset analyzer
	analyzer.InitializeSession(RoleSecondary)
	err = analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	assert.Error(t, err)
}

// TestHorizontalWorker_NetworkErrorRobustness verifies that network errors during the analysis replay do not crash the analyzer.
func TestHorizontalWorker_NetworkErrorRobustness(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// Create and immediately close a server to simulate connection refused during the analysis phase.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close()

	// Manually register an observation pointing to the dead server.
	targetURL := server.URL + "/api/fail"
	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	analyzer.sessions[RolePrimary].ObservedRequests["GET /api/fail"] = ObservedRequest{
		Request:        req,
		BaselineStatus: http.StatusOK,
		Identifiers:    []ObservedIdentifier{{Type: TypeNumericID, Value: "1"}}, // Add identifier for predictive test robustness too
	}

	// Run Analysis (Should not panic, deadlock, or return an error)
	// The errors are handled within the workers.
	err := analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// No findings expected, but the process must complete successfully.
	assert.Empty(t, reporter.GetFindings())
}