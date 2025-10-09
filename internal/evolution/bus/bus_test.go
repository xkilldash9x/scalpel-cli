package bus_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/bus"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
)

func newTestBus(t *testing.T, bufferSize int) *bus.EvolutionBus {
	logger := zaptest.NewLogger(t)
	return bus.NewEvolutionBus(logger, bufferSize)
}

// TestBus_Post_CancellationCorrectness verifies Strategy 1.2.
func TestBus_Post_CancellationCorrectness(t *testing.T) {
	// 1. Setup: Use buffer size 0 (unbuffered behavior) to guarantee blocking.
	eb := newTestBus(t, 0)
	defer eb.Shutdown()

	// 2. Subscribe. This channel blocks until read.
	msgChan, unsubscribe := eb.Subscribe(models.TypeGoal)
	defer unsubscribe()

	// 3. Prepare context and operation.
	ctx, cancel := context.WithCancel(context.Background())
	postDone := make(chan error)

	go func() {
		// This Post call will block as the channel is unbuffered and unread.
		err := eb.Post(ctx, models.TypeGoal, "payload")
		postDone <- err
	}()

	// 4. Ensure Post is blocking.
	time.Sleep(20 * time.Millisecond)

	// 5. Cancel the context.
	cancel()

	// 6. Assertions (Cancellation Correctness).
	select {
	case err := <-postDone:
		// Must return promptly with context.Canceled.
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(1 * time.Second):
		t.Fatal("Post operation did not return promptly after context cancellation.")
	}

	// Ensure message was not delivered.
	select {
	case <-msgChan:
		t.Error("Message should not have been delivered after cancellation.")
	default:
		// Expected.
	}
}

// TestBus_Shutdown_UnderLoad verifies Strategy 2.2 (Graceful Shutdown) and Strategy 1.1 (Leak Detection).
func TestBus_Shutdown_UnderLoad(t *testing.T) {
	// Strategy 1.1: Goroutine Leak Detection.
	defer goleak.VerifyNone(t)

	// 1. Setup: Small buffer to induce contention.
	eb := newTestBus(t, 5)

	// 2. Create slow subscribers.
	var subscriberWg sync.WaitGroup
	const numSubscribers = 10
	for i := 0; i < numSubscribers; i++ {
		subscriberWg.Add(1)
		// P4: Align test with application pattern (ignore unsubscribe).
		msgChan, _ := eb.Subscribe(models.TypeAction)

		go func() {
			defer subscriberWg.Done()
			// Process until the channel is closed by Shutdown().
			for msg := range msgChan {
				// Simulate work.
				time.Sleep(1 * time.Millisecond)
				eb.Acknowledge(msg)
			}
		}()
	}

	// 3. Start producers flooding the bus.
	producerCtx, producerCancel := context.WithCancel(context.Background())
	var producerWg sync.WaitGroup
	const numProducers = 10
	for i := 0; i < numProducers; i++ {
		producerWg.Add(1)
		go func(id int) {
			defer producerWg.Done()
			for j := 0; j < 50; j++ {
				// Posts might fail during shutdown (expected).
				_ = eb.Post(producerCtx, models.TypeAction, fmt.Sprintf("msg-%d-%d", id, j))
				if producerCtx.Err() != nil {
					return
				}
			}
		}(i)
	}

	// 4. Run under load.
	time.Sleep(100 * time.Millisecond)

	// 5. Initiate graceful shutdown.
	shutdownDone := make(chan struct{})
	go func() {
		// Should block until all active posts complete and delivered messages are acknowledged.
		eb.Shutdown()
		close(shutdownDone)
	}()

	// 6. Stop producers shortly after.
	producerCancel()

	// 7. Assertions (Graceful Shutdown).
	select {
	case <-shutdownDone:
		// Success.
	case <-time.After(10 * time.Second):
		t.Fatal("Bus shutdown timed out. Potential deadlock or failure to drain.")
	}

	producerWg.Wait()
	subscriberWg.Wait()
}

// TestBus_ResourceContention_NoDeadlock verifies Strategy 2.1 (Resource Pool Contention) using Strategy 3.1 (t.Deadline).
func TestBus_ResourceContention_NoDeadlock(t *testing.T) {
	// Strategy 3.1: Use the t.Deadline() pattern for robust timeouts.
	testCtx := context.Background()
	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		// Set context deadline slightly shorter than the test runner deadline.
		testCtx, cancel = context.WithDeadline(testCtx, deadline.Add(-500*time.Millisecond))
		defer cancel()
	} else {
		// Fallback timeout if run without -timeout.
		var cancel context.CancelFunc
		testCtx, cancel = context.WithTimeout(testCtx, 10*time.Second)
		defer cancel()
	}

	// 1. Setup: Intentionally small resource pool (buffer size 1).
	eb := newTestBus(t, 1)
	defer eb.Shutdown()

	// 2. Create a slow consumer.
	msgChan, unsubscribe := eb.Subscribe(models.TypeGoal)
	defer unsubscribe()

	go func() {
		for {
			select {
			case msg, ok := <-msgChan:
				if !ok {
					return
				}
				// Simulate significant processing time.
				time.Sleep(50 * time.Millisecond)
				eb.Acknowledge(msg)
			case <-testCtx.Done():
				return
			}
		}
	}()

	// 3. Launch a significantly larger number of concurrent producers.
	const numProducers = 20
	var producerWg sync.WaitGroup
	producerWg.Add(numProducers)

	for i := 0; i < numProducers; i++ {
		go func(id int) {
			defer producerWg.Done()
			// Many will block. We pass testCtx so they respect the overall test timeout.
			err := eb.Post(testCtx, models.TypeGoal, fmt.Sprintf("payload-%d", id))
			if err != nil && testCtx.Err() == nil {
				t.Logf("Producer %d failed (expected during contention): %v", id, err)
			}
		}(i)
	}

	// 4. Wait for producers to finish or timeout.
	producersFinished := make(chan struct{})
	go func() {
		producerWg.Wait()
		close(producersFinished)
	}()

	// 5. Monitor for completion or timeout (Deadlock detection).
	select {
	case <-producersFinished:
		// Success: System remained responsive.
	case <-testCtx.Done():
		// Failure: Deadline exceeded, indicating deadlock or gridlock (Strategy 2.1 failure).
		t.Fatalf("Test timed out (DeadlineExceeded). Potential deadlock or gridlock detected.")
	}
}
