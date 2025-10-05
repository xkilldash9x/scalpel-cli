//go:build integration
// +build integration

package timeslip

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// --- 2.1 & 2.2 H1 Concurrent Strategy Tests ---

func TestExecuteH1Concurrent_BasicExecutionAndMutation(t *testing.T) {
	t.Parallel()

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
	result, err := ExecuteH1Concurrent(ctx, candidate, config, oracle)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, concurrency, tracker.Count(), "Server should receive exactly N requests")
	require.Len(t, result.Responses, concurrency)

	// Verify Mutations were unique
	uniqueNonces := make(map[string]bool)
	for _, req := range tracker.requests {
		var bodyData map[string]string
		json.Unmarshal([]byte(req.Body), &bodyData)
		nonce := bodyData["value"]
		uniqueNonces[nonce] = true
	}
	assert.Equal(t, concurrency, len(uniqueNonces), "All nonces should be unique")
}

func TestExecuteH1Concurrent_Timeout(t *testing.T) {
	t.Parallel()

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
	_, err := ExecuteH1Concurrent(context.Background(), candidate, config, oracle)

	// Assertions
	require.Error(t, err)
	// We expect ErrTargetUnreachable because all requests failed due to timeout (h1_concurrent.go lines 157-159)
	assert.ErrorIs(t, err, ErrTargetUnreachable)
}

func TestExecuteH1Concurrent_ResourceLimits(t *testing.T) {
	t.Parallel()

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
	result, err := ExecuteH1Concurrent(context.Background(), candidate, config, oracle)

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

// --- 2.2 H2 Multiplexing Strategy Tests ---

func TestExecuteH2Multiplexing_Basic(t *testing.T) {
	t.Parallel()

	const concurrency = 15
	tracker := &requestTracker{}

	// Setup Mock H2 Server (httptest.NewTLSServer enables H2 by default)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracker.Track(r)
		if r.ProtoMajor != 2 {
			http.Error(w, "Expected HTTP/2", http.StatusHTTPVersionNotSupported)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"h2":true}`)
	}))
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
	result, err := ExecuteH2Multiplexing(context.Background(), candidate, config, oracle)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, concurrency, tracker.Count())

	// Verify client-side detection of H2
	for _, resp := range result.Responses {
		// h2_multiplex.go lines 81-85 check this
		assert.Equal(t, 2, resp.Raw.ProtoMajor, "Response should confirm H2 usage")
	}
}

func TestExecuteH2Multiplexing_Downgrade(t *testing.T) {
	t.Parallel()

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
	_, err := ExecuteH2Multiplexing(context.Background(), candidate, config, oracle)

	// Assertions
	require.Error(t, err)
	// The strategy should detect the downgrade (h2_multiplex.go lines 150-152)
	assert.ErrorIs(t, err, ErrH2Unsupported)
}

// --- 2.2 GraphQL Async Strategy Tests ---

func TestExecuteGraphQLAsync_BasicBatching(t *testing.T) {
	t.Parallel()
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
	result, err := ExecuteGraphQLAsync(context.Background(), candidate, config, oracle)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 1, tracker.Count(), "Server should receive exactly 1 batched request")
	require.Len(t, result.Responses, concurrency, "Result should contain N parsed responses")

	// Verify individual operation results
	assert.True(t, result.Responses[0].IsSuccess)
	assert.False(t, result.Responses[1].IsSuccess) // Due to "errors" key
	assert.True(t, result.Responses[2].IsSuccess)
}