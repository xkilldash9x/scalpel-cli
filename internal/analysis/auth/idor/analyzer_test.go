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

	"github.com.com/google/uuid"
	"github.com.com/stretchr/testify/assert"
	"github.com.com/stretchr/testify/mock"
	"github.com.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com.com/xkilldash9x/scalpel-cli/internal/analysis/core"
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
	assert.Equal(t, core.TypeNumericID, observed.Identifiers[0].Type)
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
	assert.Equal(t, core.LocationJSONBody, observed.Identifiers[0].Location)
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
		want  core.IdentifierType
	}{
		// UUIDs (Case-insensitive)
		{"UUIDv4", "f47ac10b-58cc-4372-a567-0e02b2c3d479", core.TypeUUID},
		{"UUID uppercase", "F47AC10B-58CC-4372-A567-0E02B2C3D479", core.TypeUUID},

		// MongoDB ObjectIDs (Case-insensitive, 24 hex chars)
		{"ObjectID", "507f1f77bcf86cd799439011", core.TypeObjectID},
		{"ObjectID uppercase", "507F1F77BCF86CD799439011", core.TypeObjectID},

		// Numeric IDs (1-19 digits)
		{"Numeric Short", "12345", core.TypeNumericID},
		{"Numeric Long (Max Int64)", "9223372036854775807", core.TypeNumericID},
		{"Numeric 1 digit", "1", core.TypeNumericID},

		// Base64 (Length >= 8, matches regex, and passes decoding heuristic)
		{"Base64 Std (Padded)", "aGVsbG8gd29ybGQ=", core.TypeBase64}, // "hello world"
		{"Base64 URL-Safe", "aGVsbG8tMTIzNA==", core.TypeBase64},
		{"Base64 Raw (No padding)", "aGVsbG8xMjM0", core.TypeBase64},

		// False Positives and Heuristics
		{"Empty String", "", core.TypeUnknown},
		{"Non-ID String", "username", core.TypeUnknown},
		{"Numeric Too Long (>19 digits)", "12345678901234567890", core.TypeUnknown},
		{"Base64 too short (<8)", "YQ==", core.TypeUnknown}, // "a"
		{"Invalid Base64 characters", "invalid!@#", core.TypeUnknown},

		// Numeric Heuristics (Filtering common non-IDs)
		{"Year (1980-2100)", "2023", core.TypeUnknown},
		{"Year (Boundary)", "1980", core.TypeUnknown},
		{"Year (Outside boundary)", "1979", core.TypeNumericID},
		{"Common Port (80)", "80", core.TypeUnknown},
		{"Common Port (8080)", "8080", core.TypeUnknown},
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
	expected := []core.ObservedIdentifier{
		// URL Path (Note the PathIndex which is crucial for correct replacement)
		{Value: "12345", Type: core.TypeNumericID, Location: core.LocationURLPath, PathIndex: 3},
		{Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479", Type: core.TypeUUID, Location: core.LocationURLPath, PathIndex: 5},
		// Query Param
		{Value: "507f1f77bcf86cd799439011", Type: core.TypeObjectID, Location: core.LocationQueryParam, Key: "session_id"},
		// JSON Body (Note the dot-separated keys for nested access)
		{Value: "67890", Type: core.TypeNumericID, Location: core.LocationJSONBody, Key: "request_id"},
		{Value: "aGVsbG8gd29ybGQ=", Type: core.TypeBase64, Location: core.LocationJSONBody, Key: "metadata.auth_token"},
		{Value: "1001", Type: core.TypeNumericID, Location: core.LocationJSONBody, Key: "metadata.details.0.item_id"},
		{Value: "1002", Type: core.TypeNumericID, Location: core.LocationJSONBody, Key: "metadata.details.1.item_id"},
		// Headers
		{Value: "99999", Type: core.TypeNumericID, Location: core.LocationHeader, Key: "X-Correlation-ID"},
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

// TestGenerateTestValue verifies the logic for creating plausible, predictable 