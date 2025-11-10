// File: internal/analysis/active/timeslip/integration_test.go
package timeslip

import (
	"context"
	"crypto/tls"
	"encoding/json"

	// "errors" // Not currently used
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// -- ADDED --
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// Helper struct to track requests received by the mock server in a thread-safe manner.
type requestTracker struct {
	mu       sync.Mutex
	requests []struct {
		Body       string
		Headers    http.Header
		ProtoMajor int
	}
}

func (rt *requestTracker) Track(r *http.Request) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	bodyBytes, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))

	rt.requests = append(rt.requests, struct {
		Body       string
		Headers    http.Header
		ProtoMajor int
	}{
		Body:       string(bodyBytes),
		Headers:    r.Header.Clone(),
		ProtoMajor: r.ProtoMajor,
	})
}

func (rt *requestTracker) Count() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.requests)
}

// --- II. Integration Tests (Strategy Execution) ---

// --- 2.1 H1 Concurrent Strategy Tests ---

func TestExecuteH1Concurrent_BasicExecutionAndMutation(t *testing.T) {
	t.Parallel()

	// -- CORRECTED --
	log := observability.GetLogger().Named(t.Name())

	const concurrency = 10
	tracker := &requestTracker{}

	// Setup Mock Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker.Track(r)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	// Setup Candidate and Config
	candidate := &RaceCandidate{
		Method: "POST",
		URL:    server.URL,
		Body:   []byte(`{"value":"{{NONCE}}"}`),
	}
	config := &Config{
		Concurrency: concurrency,
		Timeout:     2 * time.Second,
	}
	oracle, _ := NewSuccessOracle(&Config{
		Success: SuccessCondition{BodyRegex: `"status":"ok"`},
	}, false)

	// Execute Strategy
	ctx := context.Background()
	// -- CORRECTED --
	result, err := ExecuteH1Concurrent(ctx, candidate, config, oracle, log)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, concurrency, tracker.Count(), "Server should receive exactly N requests")
	require.Len(t, result.Responses, concurrency)

	// Verify Mutations were unique
	uniqueNonces := make(map[string]bool)
	for _, req := range tracker.requests {
		var bodyData map[string]string
		if err := json.Unmarshal([]byte(req.Body), &bodyData); err != nil {
			t.Fatalf("Failed to parse request body: %v", err)
		}
		nonce := bodyData["value"]
		uniqueNonces[nonce] = true
	}
	assert.Equal(t, concurrency, len(uniqueNonces), "All nonces should be unique")
}

func TestExecuteH1Concurrent_Timeout(t *testing.T) {
	t.Parallel()

	// -- CORRECTED --
	log := observability.GetLogger().Named(t.Name())

	// Server that delays significantly
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := &Config{
		Concurrency: 5,
		Timeout:     50 * time.Millisecond, // Short timeout
	}
	oracle, _ := NewSuccessOracle(&Config{}, false)
	candidate := &RaceCandidate{URL: server.URL, Method: "GET"}

	// Execute
	// -- CORRECTED --
	_, err := ExecuteH1Concurrent(context.Background(), candidate, config, oracle, log)

	// Assertions
	require.Error(t, err)
	// We expect ErrTargetUnreachable because all requests failed due to timeout (h1_concurrent.go lines 157-159)
	assert.ErrorIs(t, err, ErrTargetUnreachable)
}

func TestExecuteH1Concurrent_ResourceLimits(t *testing.T) {
	t.Parallel()

	// -- CORRECTED --
	log := observability.GetLogger().Named(t.Name())

	// Create a large response body (e.g., 3MB, exceeding the 2MB maxResponseBodyBytes limit in types.go)
	largeBody := make([]byte, 3*1024*1024)
	for i := range largeBody {
		largeBody[i] = 'A'
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(largeBody)
	}))
	defer server.Close()

	config := &Config{Concurrency: 1, Timeout: 5 * time.Second}
	oracle, _ := NewSuccessOracle(&Config{}, false)
	candidate := &RaceCandidate{URL: server.URL, Method: "GET"}

	// Execute
	// -- CORRECTED --
	result, err := ExecuteH1Concurrent(context.Background(), candidate, config, oracle, log)

	// Assertions: The error might be returned directly or within the result object.
	if err != nil {
		assert.ErrorIs(t, err, ErrTargetUnreachable)
		assert.Contains(t, err.Error(), "response body exceeded limit")
		return
	}

	require.Len(t, result.Responses, 1)
	resp := result.Responses[0]
	assert.Error(t, resp.Error)
	assert.Contains(t, resp.Error.Error(), "response body exceeded limit")
}

// --- 2.2 H1 Single Byte Send (Pipelining) Strategy Tests (Added) ---

func TestExecuteH1SingleByteSend_BasicPipelining(t *testing.T) {
	t.Parallel()

	// -- CORRECTED --
	log := observability.GetLogger().Named(t.Name())

	const concurrency = 5
	tracker := &requestTracker{}

	// FIX: Define the response body content and length for reliable pipelining.
	responseBody := `{"pipelined":true}`
	responseLength := len(responseBody)

	// Setup Mock Server (httptest supports pipelining by default)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker.Track(r)
		// Verify Connection: keep-alive is present, essential for pipelining
		if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "keep-alive") {
			http.Error(w, "Expected keep-alive", http.StatusBadRequest)
			return
		}
		// FIX: Explicitly set Connection: keep-alive AND Content-Length.
		// This provides stronger guarantees that the httptest server keeps the connection open
		// for subsequent pipelined responses, fixing the failure where only partial requests were processed.
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", responseLength))
		w.WriteHeader(http.StatusOK)
		// Use io.WriteString or w.Write for precise control when Content-Length is set.
		io.WriteString(w, responseBody)
	}))
	defer server.Close()

	// Setup Candidate and Config
	config := &Config{
		Concurrency: concurrency,
		Timeout:     2 * time.Second,
	}
	oracle, _ := NewSuccessOracle(&Config{Success: SuccessCondition{BodyRegex: `"pipelined":true`}}, false)
	candidate := &RaceCandidate{
		Method: "POST",
		URL:    server.URL,
		Body:   []byte(`{"data":"{{UUID}}"}`),
	}

	// Execute Strategy
	// -- CORRECTED --
	result, err := ExecuteH1SingleByteSend(context.Background(), candidate, config, oracle, log)

	// Assertions
	// Check error first. If error occurred, we might have partial results, but we expect success here.
	if err != nil {
		t.Logf("ExecuteH1SingleByteSend returned error: %v", err)
	}

	// The server handler tracks requests sequentially as they are processed.
	assert.Equal(t, concurrency, tracker.Count(), "Server should process N requests")
	// The strategy should parse N responses from the single connection stream.
	assert.Equal(t, concurrency, len(result.Responses), "Client should parse N responses")

	// Verify mutations were unique (ensures preparePipelinedRequests worked)
	uniqueUUIDs := make(map[string]bool)
	for i, req := range tracker.requests {
		var bodyData map[string]string
		if err := json.Unmarshal([]byte(req.Body), &bodyData); err != nil {
			t.Errorf("Failed to parse request body %d: %v. Body: %s", i, err, req.Body)
			continue
		}
		uuid := bodyData["data"]
		uniqueUUIDs[uuid] = true
	}
	assert.Equal(t, concurrency, len(uniqueUUIDs), "All UUIDs should be unique")
}

// --- 2.3 H2 Multiplexing Strategy Tests ---

func TestExecuteH2Multiplexing_Basic(t *testing.T) {
	t.Parallel()

	// -- CORRECTED --
	log := observability.GetLogger().Named(t.Name())

	const concurrency = 15
	tracker := &requestTracker{}

	// Setup Mock H2 Server (httptest.NewTLSServer enables H2 by default)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker.Track(r)
		if r.ProtoMajor != 2 {
			http.Error(w, "Expected HTTP/2", http.StatusHTTPVersionNotSupported)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"h2":true}`)
	}))
	// Explicitly configure the test server to use H2
	require.NoError(t, http2.ConfigureServer(server.Config, &http2.Server{}))
	// FIX: Assign the configured TLSConfig (which includes H2 ALPN settings) to the server's TLS field before StartTLS().
	server.TLS = server.Config.TLSConfig
	server.StartTLS()
	defer server.Close()

	// Setup Candidate and Config
	config := &Config{
		Concurrency:        concurrency,
		Timeout:            2 * time.Second,
		InsecureSkipVerify: true, // Crucial for httptest self-signed certs
	}
	oracle, _ := NewSuccessOracle(&Config{Success: SuccessCondition{BodyRegex: `"h2":true`}}, false)
	candidate := &RaceCandidate{
		Method: "GET",
		URL:    server.URL, // Must be https://
	}

	// Execute Strategy
	// -- CORRECTED --
	result, err := ExecuteH2Multiplexing(context.Background(), candidate, config, oracle, log)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, concurrency, tracker.Count())
	require.Equal(t, concurrency, len(result.Responses))

	// Verify client-side detection of H2
	for _, resp := range result.Responses {
		// h2_multiplex.go lines 81-85 check this
		assert.Equal(t, 2, resp.Raw.ProtoMajor, "Response should confirm H2 usage")
	}
}

func TestExecuteH2Multiplexing_Downgrade(t *testing.T) {
	t.Parallel()

	// -- CORRECTED --
	log := observability.GetLogger().Named(t.Name())

	// Setup Mock Server configured to *only* support HTTP/1.1
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	// Configure TLS to exclude H2 via ALPN
	server.TLS = &tls.Config{
		NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	defer server.Close()

	config := &Config{Concurrency: 5, Timeout: 1 * time.Second, InsecureSkipVerify: true}
	oracle, _ := NewSuccessOracle(&Config{}, false)
	candidate := &RaceCandidate{URL: server.URL, Method: "GET"}

	// Execute
	// -- CORRECTED --
	_, err := ExecuteH2Multiplexing(context.Background(), candidate, config, oracle, log)

	// Assertions
	require.Error(t, err)
	// The strategy should detect the downgrade (h2_multiplex.go lines 150-152)
	assert.ErrorIs(t, err, ErrH2Unsupported)
}

// --- 2.4 H2 Dependency Strategy Tests (Added) ---

func TestExecuteH2Dependency_BasicExecution(t *testing.T) {
	t.Parallel()

	// -- CORRECTED --
	log := observability.GetLogger().Named(t.Name())

	const concurrency = 5
	tracker := &requestTracker{}

	// Setup Mock H2 Server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker.Track(r)
		if r.ProtoMajor != 2 {
			http.Error(w, "Expected HTTP/2", http.StatusHTTPVersionNotSupported)
			return
		}
		// Simulate some minor processing time
		time.Sleep(5 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"dependency_ok":true}`)
	}))
	// Explicitly configure the test server to use H2
	require.NoError(t, http2.ConfigureServer(server.Config, &http2.Server{}))
	// FIX: Assign the configured TLSConfig (which includes H2 ALPN settings) to the server's TLS field before StartTLS().
	server.TLS = server.Config.TLSConfig
	server.StartTLS()
	defer server.Close()

	// Setup Candidate and Config
	config := &Config{
		Concurrency:        concurrency,
		Timeout:            3 * time.Second,
		InsecureSkipVerify: true,
	}
	oracle, _ := NewSuccessOracle(&Config{Success: SuccessCondition{BodyRegex: `"dependency_ok":true`}}, false)
	candidate := &RaceCandidate{
		Method: "PATCH",
		URL:    server.URL,
		Body:   []byte(`{"id":"{{NONCE}}"}`),
	}

	// Execute Strategy
	// NOTE: The failure previously occurred here due to PROTOCOL_ERROR (non-monotonic stream IDs).
	// -- CORRECTED --
	result, err := ExecuteH2Dependency(context.Background(), candidate, config, oracle, log)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, concurrency, tracker.Count(), "Server should receive N requests")
	require.Equal(t, concurrency, len(result.Responses), "Client should parse N responses")

	// Verify success and mutation
	successCount := 0
	uniqueNonces := make(map[string]bool)
	for _, resp := range result.Responses {
		assert.Nil(t, resp.Error)
		if resp.IsSuccess {
			successCount++
		}
	}
	assert.Equal(t, concurrency, successCount)

	for _, req := range tracker.requests {
		var bodyData map[string]string
		if err := json.Unmarshal([]byte(req.Body), &bodyData); err != nil {
			t.Fatalf("Failed to parse request body: %v", err)
		}
		uniqueNonces[bodyData["id"]] = true
	}
	assert.Equal(t, concurrency, len(uniqueNonces), "All nonces should be unique")
}

// --- 2.5 GraphQL Async Strategy Tests ---

func TestExecuteGraphQLAsync_BasicBatching(t *testing.T) {
	t.Parallel()

	// -- CORRECTED --
	log := observability.GetLogger().Named(t.Name())

	const concurrency = 3
	tracker := &requestTracker{}

	// Setup Mock GraphQL Server supporting batching
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker.Track(r)

		// Return a batched response with one failure
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `[
				{"data": {"op": "success1"}},
				{"errors": [{"message": "failure2"}]},
				{"data": {"op": "success3"}}
			]`)
	}))
	defer server.Close()

	// Setup Candidate and Config
	config := &Config{Concurrency: concurrency, Timeout: 2 * time.Second}
	// Oracle expects standard GraphQL success (no "errors" key)
	oracle, _ := NewSuccessOracle(&Config{}, true)
	candidate := &RaceCandidate{
		Method:    "POST",
		URL:       server.URL,
		Body:      []byte(`{"query":"mutation { action(id: \"{{UUID}}\") }"}`),
		IsGraphQL: true,
	}

	// Execute Strategy
	// -- CORRECTED --
	result, err := ExecuteGraphQLAsync(context.Background(), candidate, config, oracle, log)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 1, tracker.Count(), "Server should receive exactly 1 batched request")
	require.Len(t, result.Responses, concurrency, "Result should contain N parsed responses")

	// Verify individual operation results
	assert.True(t, result.Responses[0].IsSuccess)
	assert.False(t, result.Responses[1].IsSuccess) // Due to "errors" key
	assert.True(t, result.Responses[2].IsSuccess)
}
