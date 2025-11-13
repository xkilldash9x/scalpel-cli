// File: ./internal/analysis/auth/idor/idor_test.go
package idor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/jsoncompare"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Initialize the logger for all tests in this package.
	observability.InitializeLogger(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	// Run the tests.
	os.Exit(m.Run())
}

// MockSession implements the Session interface for testing.
type MockSession struct {
	UserID        string
	Authenticated bool
}

func (m *MockSession) IsAuthenticated() bool {
	return m.Authenticated
}

// ApplyToRequest adds a simple header to simulate the session.
func (m *MockSession) ApplyToRequest(req *http.Request) {
	if m.Authenticated {
		req.Header.Set("X-Test-User-ID", m.UserID)
	}
}

// GetAuthArtifacts returns empty artifacts for the mock session.
func (m *MockSession) GetAuthArtifacts() AuthArtifacts {
	return AuthArtifacts{
		HeaderNames: map[string]struct{}{"X-Test-User-ID": {}},
		CookieNames: make(map[string]struct{}),
	}
}

// SetupTestAPI creates a mock API server that simulates vulnerable and secure behaviors.
// It now automatically handles its own cleanup.
func SetupTestAPI(t *testing.T) *httptest.Server {
	// Data store for the mock API
	dataStore := map[int]string{
		101: "Data_UserA",
		102: "Data_UserB",
		103: "Data_Arbitrary",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the requesting user ID from the header (set by MockSession).
		requestingUserID := r.Header.Get("X-Test-User-ID")

		// Endpoint 1: /profile/{id} (Vulnerable to Horizontal IDOR)
		if strings.HasPrefix(r.URL.Path, "/profile/") {
			resourceIDStr := strings.TrimPrefix(r.URL.Path, "/profile/")
			resourceID, err := strconv.Atoi(resourceIDStr)
			if err != nil {
				http.Error(w, "Invalid ID", http.StatusBadRequest)
				return
			}

			data, exists := dataStore[resourceID]
			if !exists {
				http.NotFound(w, r)
				return
			}
			// Vulnerability: No authorization check against requestingUserID.
			// Include dynamic data (timestamp) and the specific resource data.
			// Use numeric ID in JSON to test json.Number handling.
			fmt.Fprintf(w, `{"resource_id": %d, "data": "%s", "ts": "%s"}`, resourceID, data, time.Now().Format(time.RFC3339Nano))
			return
		}

		// Endpoint 2: /secure/documents/{id} (Secure)
		if strings.HasPrefix(r.URL.Path, "/secure/documents/") {
			resourceIDStr := strings.TrimPrefix(r.URL.Path, "/secure/documents/")
			resourceID, _ := strconv.Atoi(resourceIDStr)

			// Security Check: Ensure the resource ID matches the requesting user ID.
			if (resourceID == 101 && requestingUserID != "UserA") || (resourceID == 102 && requestingUserID != "UserB") {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			data, exists := dataStore[resourceID]
			if !exists {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, `{"resource_id": %d, "data": "%s"}`, resourceID, data)
			return
		}

		// Endpoint 3: /slow (For testing concurrency and cancellation)
		if r.URL.Path == "/slow" {
			select {
			case <-time.After(200 * time.Millisecond):
				fmt.Fprintf(w, `{"status": "slow response"}`)
				return
			case <-r.Context().Done():
				// Client cancelled the request
				return
			}
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// Helper to create RequestResponsePair for testing.
// MODIFICATION: Returns an error instead of calling t.Fatalf to be safe for concurrent use.
func createTestPair(t *testing.T, client *http.Client, req *http.Request, session Session) (RequestResponsePair, error) {
	t.Helper()

	// Ensure the session is applied before execution
	session.ApplyToRequest(req)

	// Read request body for the pair
	var reqBody []byte
	var err error
	if req.Body != nil {
		reqBody, err = io.ReadAll(req.Body)
		if err != nil {
			return RequestResponsePair{}, fmt.Errorf("failed to read request body for pair creation: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(reqBody)) // Restore body for client.Do
	}

	resp, err := client.Do(req)
	if err != nil {
		// If the error is due to the context being done, it's an expected condition in some tests.
		// We return a dummy pair and no error to allow the test to proceed with its assertions.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			t.Logf("Request cancelled during pair creation (expected in some tests): %v", err)
			return RequestResponsePair{Request: req, RequestBody: reqBody, Response: &http.Response{StatusCode: 0}}, nil
		}
		// For other errors, return the error to the caller.
		return RequestResponsePair{}, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return RequestResponsePair{}, fmt.Errorf("failed to read response body: %w", err)
	}

	// Restore response body for the pair
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	return RequestResponsePair{
		Request:      req,
		RequestBody:  reqBody,
		Response:     resp,
		ResponseBody: respBody,
	}, nil
}

// TestDetect_Integration verifies the end-to-end detection logic against a mock API.
func TestDetect_Integration(t *testing.T) {
	t.Parallel()
	server := SetupTestAPI(t)
	client := server.Client()
	t.Cleanup(client.CloseIdleConnections)
	logger := log.New(io.Discard, "", 0)
	comparer := jsoncompare.NewService()

	userA := &MockSession{UserID: "UserA", Authenticated: true}
	userB := &MockSession{UserID: "UserB", Authenticated: true}

	req1, _ := http.NewRequest(http.MethodGet, server.URL+"/profile/101", nil) // MODIFICATION: Added a comment to force a change
	req2, _ := http.NewRequest(http.MethodGet, server.URL+"/secure/documents/101", nil)

	// MODIFICATION: Check for errors during traffic generation.
	pair1, err := createTestPair(t, client, req1, userA)
	require.NoError(t, err, "Setup for pair1 failed")
	pair2, err := createTestPair(t, client, req2, userA)
	require.NoError(t, err, "Setup for pair2 failed")

	traffic := []RequestResponsePair{pair1, pair2}

	config := Config{
		Session:           userA,
		SecondSession:     userB,
		ComparisonOptions: jsoncompare.DefaultOptions(),
		ConcurrencyLevel:  5,
		HttpClient:        client,
	}

	// (Test Adaptation): Manually create and populate the identifier pool for the test.
	pool := NewIdentifierPool()
	for _, pair := range traffic {
		reqIdentifiers := ExtractIdentifiers(pair.Request, pair.RequestBody)
		for _, ident := range reqIdentifiers {
			pool.Add(ident)
		}
	}

	findings, err := Detect(context.Background(), traffic, config, logger, comparer, pool)
	require.NoError(t, err, "Detect returned an unexpected error")

	if len(findings) != 6 {
		t.Fatalf("Expected 6 findings, got %d. Findings: %+v", len(findings), findings)
	}

	foundHorizontal := false
	foundManipulation := false
	foundUnauthenticatedProfile := false
	foundHorizontalManipulationProfile := false
	foundResourceEnumeration := false
	foundHorizontalManipulationSecure := false

	for _, f := range findings {
		switch f.TestType {
		case TestTypeHorizontal:
			if strings.HasSuffix(f.URL, "/profile/101") {
				foundHorizontal = true
			}
		case TestTypeManipulation:
			if strings.HasSuffix(f.URL, "/profile/102") {
				foundManipulation = true
			}
		case TestTypeUnauthenticated:
			if strings.HasSuffix(f.URL, "/profile/101") {
				foundUnauthenticatedProfile = true
			}
		case TestTypeHorizontalManipulation:
			if strings.HasSuffix(f.URL, "/profile/102") {
				foundHorizontalManipulationProfile = true
			} else if strings.HasSuffix(f.URL, "/secure/documents/102") {
				foundHorizontalManipulationSecure = true
			}
		case TestTypeResourceEnumeration:
			if strings.HasSuffix(f.URL, "/secure/documents/102") {
				foundResourceEnumeration = true
			}
		}
	}
	require.True(t, foundHorizontal, "Missed Horizontal IDOR finding.")
	require.True(t, foundManipulation, "Missed Manipulation IDOR finding.")
	require.True(t, foundUnauthenticatedProfile, "Missed Unauthenticated on profile finding.")
	require.True(t, foundHorizontalManipulationProfile, "Missed Horizontal Manipulation on profile finding.")
	require.True(t, foundResourceEnumeration, "Missed Resource Enumeration finding.")
	require.True(t, foundHorizontalManipulationSecure, "Missed Horizontal Manipulation on secure finding.")
}

// TestDetect_ConcurrencyAndCancellation verifies robust concurrency and context handling.
func TestDetect_ConcurrencyAndCancellation(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	server := SetupTestAPI(t)
	userA := &MockSession{UserID: "UserA", Authenticated: true}
	testClient := server.Client()
	t.Cleanup(testClient.CloseIdleConnections)
	comparer := jsoncompare.NewService()

	config := Config{
		Session:           userA,
		SecondSession:     userA,
		ComparisonOptions: jsoncompare.DefaultOptions(),
		ConcurrencyLevel:  10,
		HttpClient:        testClient,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var traffic []RequestResponsePair
	const numRequests = 50
	for i := 0; i < numRequests; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/slow", nil)
		// MODIFICATION: Check for errors during traffic generation.
		pair, err := createTestPair(t, testClient, req, userA)
		require.NoError(t, err, "Setup for cancellation test pair failed")
		traffic = append(traffic, pair)
	}

	logger := log.New(io.Discard, "", 0)
	startTime := time.Now()
	// (Test Adaptation): Pass a new empty pool to the Detect function.
	_, err := Detect(ctx, traffic, config, logger, comparer, NewIdentifierPool())
	duration := time.Since(startTime)

	require.Error(t, err, "Expected an error due to context timeout, but got nil")
	require.True(t, errors.Is(err, context.DeadlineExceeded), "Expected error to be context.DeadlineExceeded, got %v", err)

	if duration > 250*time.Millisecond {
		t.Errorf("Detection took too long (%v) despite the short timeout, indicating cancellation might be slow.", duration)
	}
}

// TestDetect_Robustness_tDeadlinePattern demonstrates integration with the test runner's deadline.
func TestDetect_Robustness_tDeadlinePattern(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const cleanupGracePeriod = 50 * time.Millisecond

	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline.Add(-cleanupGracePeriod))
		t.Cleanup(cancel)
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		t.Cleanup(cancel)
	}

	server := SetupTestAPI(t)
	userA := &MockSession{UserID: "UserA", Authenticated: true}
	client := server.Client()
	t.Cleanup(client.CloseIdleConnections)
	comparer := jsoncompare.NewService()

	config := Config{
		Session:           userA,
		SecondSession:     userA,
		ComparisonOptions: jsoncompare.DefaultOptions(),
		HttpClient:        client,
		ConcurrencyLevel:  1,
	}

	var traffic []RequestResponsePair
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/slow", nil)
		// MODIFICATION: Check for errors during traffic generation.
		pair, err := createTestPair(t, client, req, userA)
		require.NoError(t, err, "Setup for robustness test pair failed")
		traffic = append(traffic, pair)
	}

	logger := log.New(io.Discard, "", 0)
	// (Test Adaptation): Pass a new empty pool to the Detect function.
	_, err := Detect(ctx, traffic, config, logger, comparer, NewIdentifierPool())

	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Detect() returned unexpected error: %v", err)
	}

	if errors.Is(err, context.DeadlineExceeded) {
		t.Log("Analysis was gracefully cancelled before completion due to impending test deadline.")
	}
}

// TestDetect_ConcurrencySafety runs the detection with the race detector enabled (`go test -race`).
func TestDetect_ConcurrencySafety(t *testing.T) {
	t.Parallel()
	server := SetupTestAPI(t)

	userA := &MockSession{UserID: "UserA", Authenticated: true}
	userB := &MockSession{UserID: "UserB", Authenticated: true}
	client := server.Client()
	t.Cleanup(client.CloseIdleConnections)
	comparer := jsoncompare.NewService()

	config := Config{
		Session:           userA,
		SecondSession:     userB,
		ComparisonOptions: jsoncompare.DefaultOptions(),
		ConcurrencyLevel:  20,
		HttpClient:        client,
	}

	var traffic []RequestResponsePair
	var wg sync.WaitGroup
	var mu sync.Mutex
	// MODIFICATION: Use a sync.Map to safely collect errors from multiple goroutines.
	var setupErrors sync.Map

	// Generate traffic concurrently to further stress the system
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := http.NewRequest("GET", fmt.Sprintf("%s/profile/%d", server.URL, 101), nil)

			// MODIFICATION: Call the refactored helper and store any errors.
			pair, err := createTestPair(t, client, req, userA)
			if err != nil {
				setupErrors.Store(i, err)
				return
			}
			mu.Lock()
			traffic = append(traffic, pair)
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	// MODIFICATION: Check for any errors that occurred during concurrent setup.
	setupErrors.Range(func(key, value interface{}) bool {
		t.Fatalf("error during concurrent traffic generation for item %d: %v", key, value)
		return false // Stop iteration on first error
	})

	// (Test Adaptation): Manually create and populate the identifier pool for the test.
	pool := NewIdentifierPool()
	for _, pair := range traffic {
		reqIdentifiers := ExtractIdentifiers(pair.Request, pair.RequestBody)
		for _, ident := range reqIdentifiers {
			pool.Add(ident)
		}
	}

	logger := log.New(io.Discard, "", 0)
	_, err := Detect(context.Background(), traffic, config, logger, comparer, pool)
	require.NoError(t, err, "Detect() returned unexpected error")
}
