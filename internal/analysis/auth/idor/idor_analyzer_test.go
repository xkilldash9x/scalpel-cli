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
	"go.uber.org/zaptest"

	"github.com/xkilldash9x/scalpel-cli/internal/analysis/core"
)

// -- Mock Definitions --

// Mocks the core.Reporter interface, capturing findings concurrently
// and providing safe access for verification.
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

// Safely retrieves the recorded findings.
func (m *MockReporter) GetFindings() []core.AnalysisResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Return a copy to prevent race conditions in tests accessing the slice concurrently
	findings := make([]core.AnalysisResult, len(m.findings))
	copy(findings, m.findings)
	return findings
}

// -- Test Setup Helpers --

const (
	RolePrimary   = "UserA_Victim"
	RoleSecondary = "UserB_Attacker"
	RoleUnrelated = "UserC_Other"
)

// Creates a standard Analyzer instance for testing, along with its mocks.
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

// Initializes the analyzer with standard roles (Primary and Secondary).
func setupInitializedAnalyzer(t *testing.T) (*Analyzer, *MockReporter) {
	t.Helper()
	// Use default concurrency (5)
	analyzer, reporter, _ := setupAnalyzer(t, 5)

	require.NoError(t, analyzer.InitializeSession(RolePrimary), "Initializing Primary role failed")
	require.NoError(t, analyzer.InitializeSession(RoleSecondary), "Initializing Secondary role failed")

	return analyzer, reporter
}

// Creates a mock HTTP server for testing request execution and application behavior.
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

// -- Test Cases: Initialization and Configuration --

// Verifies constructor behavior and default settings.
func TestNewAnalyzer_Defaults(t *testing.T) {
	scanID := uuid.New()
	logger := zaptest.NewLogger(t)
	reporter := new(MockReporter)

	// Test 1: Default concurrency when provided 0 (as defined in NewAnalyzer implementation)
	analyzer1 := NewAnalyzer(scanID, logger, reporter, 0)
	// White box access to the unexported 'concurrency' field.
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

// Verifies session creation and HTTP client configuration.
func TestInitializeSession_Success(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, 5)
	role := "TestRole"

	err := analyzer.InitializeSession(role)
	require.NoError(t, err)

	// Verify session exists (Thread safe access)
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

// Verifies that roles must be unique.
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

// Verifies thread safe session initialization.
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
			// Use require fail fast if initialization fails, as it indicates a potential data race or locking issue.
			require.NoError(t, err, "Concurrent initialization failed for %s", role)
		}(i)
	}
	wg.Wait()

	// Verify all sessions were created successfully
	analyzer.mu.RLock()
	defer analyzer.mu.RUnlock()
	assert.Len(t, analyzer.sessions, count)
}

// -- Test Cases: Observation Phase (ObserveAndExecute) --

// Verifies request execution and storage when identifiers are found.
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
	// Crucial: ensure the response body is closed by the caller (the test in this case).
	defer resp.Body.Close()

	// Verify Response (Ensuring the analyzer correctly proxies the response and resets the body)
	assert.Equal(t, expectedStatus, resp.StatusCode)
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, expectedBody, string(respBody))

	// Verify Observation Storage (Thread safe white box access)
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

// Verifies that requests without interesting identifiers are executed but not stored.
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

// Verifies handling of requests with bodies (e.g., JSON) and identifier extraction.
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

// Verifies error handling for missing sessions.
func TestObserveAndExecute_UninitializedRole(t *testing.T) {
	analyzer, _, _ := setupAnalyzer(t, 5) // Analyzer not initialized with roles
	ctx := context.Background()

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)

	resp, err := analyzer.ObserveAndExecute(ctx, "NonExistentRole", req, nil)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "not initialized")
}

// Verifies handling of connection failures during observation.
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

// Verifies thread safe observation recording for the same session.
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

// -- Test Cases: Analysis - Horizontal IDOR (User A vs User B) --
// Tests the strategy of replaying Victim's requests using the Attacker's session.

// Verifies detection when the attacker successfully accesses the victim's resource.
func TestRunAnalysis_Horizontal_Vulnerable(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// A vulnerable endpoint that checks for authentication (any valid session) but lacks authorization (object level checks).
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
			return
		}

		// Only respond positively to the specific resource path to isolate the horizontal test.
		// This prevents the predictive test (which tries /api/resource/12346) from also succeeding.
		if r.URL.Path != "/api/resource/12345" {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("Not Found"))
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

// Verifies no findings when the attacker is correctly blocked (e.g., 403 Forbidden).
func TestRunAnalysis_Horizontal_Secure(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// A secure endpoint that correctly implements object level authorization.
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

// Verifies handling of authorization via redirects (e.g., 302 Found).
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

// Verifies the detection logic handles minor variations in content length (e.g., dynamic content).
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

// Verifies no detection if content length varies significantly, even if status codes match.
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

// -- Test Cases: Analysis - Predictive IDOR (Resource Enumeration) --
// Tests the strategy of modifying identifiers (e.g., incrementing IDs) and checking if the modified request succeeds.

// Verifies detection when an incremented numeric ID returns a valid resource.
func TestRunAnalysis_Predictive_Vulnerable_Numeric(t *testing.T) {
	// Predictive analysis uses the original user's session.
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// --- Setup Scenario ---
	// An endpoint where resources are sequentially numbered (100, 101) and authorization checks are missing.
	server := setupObservationServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Added an authorization check to isolate this test to *predictive* vulnerabilities.
		// This prevents the horizontal replay by the secondary user from succeeding and causing a panic
		// because the test only expects one finding (the predictive one).
		cookie, err := r.Cookie("session_id")
		if err != nil || cookie.Value != RolePrimary {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("Forbidden"))
			return
		}

		resourceID := r.URL.Path[len("/api/items/"):]

		// Vulnerable logic: Allows access to specific sequential IDs *for the primary user*.
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
	// Set a session cookie for the primary user to pass the new authorization check.
	// The secondary user's session remains clean, so their horizontal replay will fail.
	u, _ := url.Parse(targetURL)
	analyzer.sessions[RolePrimary].Client.Jar.SetCookies(u, []*http.Cookie{{Name: "session_id", Value: RolePrimary}})

	req, _ := http.NewRequest(http.MethodGet, targetURL, nil)
	resp, err := analyzer.ObserveAndExecute(ctx, RolePrimary, req, nil)
	require.NoError(t, err)
	resp.Body.Close()

	// Verify observation and identifier type
	observed := analyzer.sessions[RolePrimary].ObservedRequests["GET /api/items/100"]
	require.Len(t, observed.Identifiers, 1)
	assert.Equal(t, core.TypeNumericID, observed.Identifiers[0].Type)

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

// Verifies no findings when the predicted ID returns 404 or 403.
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
	// No findings because the predicted request resulted in a non successful status (404).
	assert.Empty(t, reporter.GetFindings())
}

// Verifies that UUIDs are correctly skipped for predictive testing as they are non enumerable.
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
	assert.Equal(t, core.TypeUUID, observed.Identifiers[0].Type)

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

// Verifies predictive testing works correctly for identifiers within JSON payloads.
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

// -- Test Cases: Concurrency, Robustness, and Edge Cases --

// Verifies the worker pool implementation handles many concurrent tests correctly and efficiently.
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
			Identifiers:    []core.ObservedIdentifier{{Type: core.TypeNumericID, Value: fmt.Sprintf("%d", id)}},
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

// Verifies that the analysis stops promptly when the context is cancelled, preventing deadlocks.
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
			Identifiers:    []core.ObservedIdentifier{{Type: core.TypeNumericID}},
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

// Verifies behavior when no interesting requests were observed.
func TestRunAnalysis_EmptyObservationSet(t *testing.T) {
	analyzer, reporter := setupInitializedAnalyzer(t)
	ctx := context.Background()

	// No observation calls made.

	err := analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err, "RunAnalysis should handle empty observation sets gracefully")

	assert.Empty(t, reporter.GetFindings())
}

// Verifies that analysis requires both roles to be initialized before starting.
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

// Verifies that network errors during the analysis replay do not crash the analyzer.
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
		Identifiers:    []core.ObservedIdentifier{{Type: core.TypeNumericID, Value: "1"}}, // Add identifier for predictive test robustness too
	}

	// Run Analysis (Should not panic, deadlock, or return an error)
	// The errors are handled within the workers.
	err := analyzer.RunAnalysis(ctx, RolePrimary, RoleSecondary)
	require.NoError(t, err)

	// No findings expected, but the process must complete successfully.
	assert.Empty(t, reporter.GetFindings())
}