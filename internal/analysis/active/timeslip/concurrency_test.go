package timeslip

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

// --- III. Concurrency & Reliability Tests ---

// TestGoroutineLeaks_H1Concurrent validates that all worker goroutines are cleaned up properly after execution.
func TestGoroutineLeaks_H1Concurrent(t *testing.T) {
	// goleak.VerifyNone(t) will fail if any unexpected goroutines are still running when the test finishes.
	defer goleak.VerifyNone(t)

	// 1. Setup Mock Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Introduce a small delay
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// 2. Setup Configuration
	config := &Config{Concurrency: 50, Timeout: 2 * time.Second} // High concurrency
	oracle, _ := NewSuccessOracle(config, false)
	candidate := &RaceCandidate{Method: "GET", URL: server.URL}

	// 3. Execution
	_, err := ExecuteH1Concurrent(context.Background(), candidate, config, oracle, zap.NewNop())
	assert.NoError(t, err)

	// 4. Verification (handled by the defer goleak.VerifyNone(t))
}

// TestGoroutineLeaks_Cancellation validates cleanup when the context is canceled during execution.
func TestGoroutineLeaks_Cancellation(t *testing.T) {
	// Set a slightly longer timeout for leak detection to account for cleanup time.
	defer goleak.VerifyNone(t)

	// 1. Setup Mock Server with significant delay
	// FIX: Use NewTLSServer as H2Multiplexing requires HTTPS.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second) // Long delay
	}))
	defer server.Close()

	// 2. Setup Configuration
	// FIX: Set InsecureSkipVerify for the self-signed TLS server.
	config := &Config{Concurrency: 10, Timeout: 15 * time.Second, InsecureSkipVerify: true}
	oracle, _ := NewSuccessOracle(config, false)
	candidate := &RaceCandidate{Method: "GET", URL: server.URL}

	// 3. Setup Context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// 4. Execution in a separate goroutine so we can cancel it
	done := make(chan error)
	go func() {
		// We use H2Multiplexing as an example strategy
		_, err := ExecuteH2Multiplexing(ctx, candidate, config, oracle, zap.NewNop())
		done <- err
	}()

	// 5. Cancel the context shortly after starting
	time.Sleep(100 * time.Millisecond)
	cancel()

	// 6. Wait for execution to stop
	select {
	case <-done:
		t.Log("Execution stopped as expected.")
	case <-time.After(5 * time.Second):
		t.Fatal("Execution did not terminate promptly after context cancellation")
	}

	// 7. Verification (handled by goleak)
}

// TestStress_AnalyzerConcurrency runs the analyzer itself concurrently multiple times.
// This is primarily to ensure stability and detect data races when run with `go test -race`.
func TestStress_AnalyzerConcurrency(t *testing.T) {
	// Setup shared components
	logger := zap.NewNop()
	reporter := &MockReporter{} // Thread-safe mock

	// Setup Mock Server
	// Use NewUnstartedServer and explicitly configure H2 to support all strategies.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add minor delay to increase chance of race conditions if they exist
		time.Sleep(1 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "{\"success\":true}")
	}))
	// Explicitly enable HTTP/2 on the test server.
	require.NoError(t, http2.ConfigureServer(server.Config, &http2.Server{}))
	// FIX: Assign the configured TLSConfig back to the server before starting.
	server.TLS = server.Config.TLSConfig
	server.StartTLS()
	defer server.Close()

	config := &Config{
		Concurrency:        5,
		Timeout:            2 * time.Second,
		Success:            SuccessCondition{BodyRegex: "success"},
		InsecureSkipVerify: true, // FIX: Added InsecureSkipVerify
	}
	candidate := &RaceCandidate{Method: "GET", URL: server.URL}

	const parallelAnalyses = 50
	var wg sync.WaitGroup

	// Run multiple analyses in parallel
	for i := 0; i < parallelAnalyses; i++ {
		wg.Add(1)
		go func(analysisID int) {
			defer wg.Done()

			// Each goroutine gets its own analyzer instance
			// The data race previously occurred here due to shared Config modification.
			analyzer, err := NewAnalyzer(uuid.New(), config, logger, reporter)
			if !assert.NoError(t, err) {
				return
			}

			// Run the analysis
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err = analyzer.Analyze(ctx, candidate)
			// We might see target unreachable errors under heavy load, which is acceptable in a stress test.
			if err != nil && !assert.ErrorIs(t, err, ErrTargetUnreachable) {
				assert.NoError(t, err)
			}
		}(i)
	}

	wg.Wait()
}
