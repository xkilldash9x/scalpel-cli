// internal/analysis/core/context_test.go
package core_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// --- Section 3.1 & 3.2: Goroutine Leaks and Timeout Leaks ---

// Leaking implementation (Anti-Pattern): Goroutine blocks on unbuffered channel send if context is canceled.
func processDataLeaking(ctx context.Context) error {
	resultChan := make(chan string) // Unbuffered
	go func() {
		time.Sleep(100 * time.Millisecond) // Simulate work
		// BLOCKS HERE if ctx is canceled and the receiver is gone (Section 3.1).
		resultChan <- "data"
	}()

	select {
	case <-resultChan:
		return nil
	case <-ctx.Done():
		return ctx.Err() // Returns, abandoning the goroutine
	}
}

func TestGoroutineLeak_AntiPattern(t *testing.T) {
	// This test demonstrates the scenario causing the leak.
	// In a real suite, use go.uber.org/goleak to verify no goroutines remain.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel() // Best Practice 2.2

	err := processDataLeaking(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded error, got %v", err)
	}
	// The goroutine is now leaked and blocked on the channel send.
}

// Fixed implementation (Pattern 1): Use select in the worker goroutine (Section 3.1).
func processDataFixedCooperative(ctx context.Context) error {
	resultChan := make(chan string)
	go func() {
		time.Sleep(100 * time.Millisecond)
		// Cooperatively check context before sending.
		select {
		case resultChan <- "data":
		case <-ctx.Done():
			return // Exit gracefully
		}
	}()

	select {
	case <-resultChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Fixed implementation (Pattern 2): Use a buffered channel (Section 3.2).
func processDataFixedBuffered(ctx context.Context) error {
	resultChan := make(chan string, 1) // Buffered
	go func() {
		time.Sleep(100 * time.Millisecond)
		// This send succeeds immediately due to the buffer, allowing the goroutine to exit.
		resultChan <- "data"
	}()

	select {
	case <-resultChan:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestGoroutineLeak_Fixed(t *testing.T) {
	// Test both fixed patterns
	t.Run("Cooperative", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		processDataFixedCooperative(ctx)
	})
	t.Run("Buffered", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		processDataFixedBuffered(ctx)
	})
}

// --- Section 3.3: Propagating the Wrong Context ---

// Test the anti-pattern: passing short-lived r.Context() to a long-running background task.
func TestPropagatingRequestContext_AntiPattern(t *testing.T) {
	var wg sync.WaitGroup
	taskStatus := "running"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wg.Add(1)
		// Anti-pattern: passing r.Context() directly.
		go func(ctx context.Context) {
			defer wg.Done()
			select {
			case <-time.After(500 * time.Millisecond):
				taskStatus = "finished"
			case <-ctx.Done():
				// r.Context() is canceled when the handler returns (Section 3.3).
				taskStatus = "canceled_prematurely"
			}
		}(r.Context())
		w.WriteHeader(http.StatusOK)
		// Handler returns immediately.
	})
	
	// **FIX START**: Manually create a cancellable context to simulate a real server.
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	// **FIX END**

	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// **FIX**: Immediately cancel the context after the handler returns, just like a real server would.
	cancel()

	wg.Wait()

	if taskStatus != "canceled_prematurely" {
		t.Errorf("Expected background task to be 'canceled_prematurely', but it was '%s'.", taskStatus)
	}
}

// Detached context implementation (from the document, Section 3.3)
type detachedContext struct{ context.Context }

func (d detachedContext) Done() <-chan struct{}       { return nil }
func (d detachedContext) Err() error                  { return nil }
func (d detachedContext) Deadline() (time.Time, bool) { return time.Time{}, false }

// Test the correct pattern: using a detached context to inherit values but not cancellation.
func TestPropagatingDetachedContext_CorrectPattern(t *testing.T) {
	var wg sync.WaitGroup
	taskStatus := "running"
	// Use unexported key type (Best Practice 2.3)
	type key int
	const traceKey key = 0

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add value to the context
		ctxWithValue := context.WithValue(r.Context(), traceKey, "123")

		wg.Add(1)
		// Correct pattern: detach from cancellation signal, but keep values.
		go func(ctx context.Context) {
			defer wg.Done()
			// Check if value is preserved
			if ctx.Value(traceKey) != "123" {
				taskStatus = "value_missing"
				return
			}
			select {
			case <-time.After(100 * time.Millisecond):
				taskStatus = "finished"
			case <-ctx.Done():
				taskStatus = "canceled" // Should not happen
			}
		}(detachedContext{ctxWithValue})
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
	wg.Wait()

	if taskStatus != "finished" {
		t.Errorf("Expected background task to be 'finished', but it was '%s'.", taskStatus)
	}
}

// --- Section 4.4: Premature Cancellation in Test Suites ---

// Test the correct pattern for parallel subtests using t.Cleanup (Go 1.14+).
func TestContextWithParallelSubtests_tCleanup(t *testing.T) {
	// Create context in the parent test.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)

	// t.Cleanup ensures cancel runs only after all subtests (even parallel ones) complete (Section 4.4).
	t.Cleanup(cancel)

	t.Run("subtest1_parallel", func(t *testing.T) {
		t.Parallel()
		time.Sleep(100 * time.Millisecond)

		// Context should still be active because t.Cleanup hasn't run yet.
		if ctx.Err() != nil {
			t.Errorf("Context should not be canceled prematurely: %v", ctx.Err())
		}
	})

	t.Run("subtest2_parallel", func(t *testing.T) {
		t.Parallel()
		time.Sleep(100 * time.Millisecond)

		if ctx.Err() != nil {
			t.Errorf("Context should not be canceled prematurely: %v", ctx.Err())
		}
	})
}