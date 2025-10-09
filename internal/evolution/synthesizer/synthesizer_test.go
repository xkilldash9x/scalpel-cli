package synthesizer_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/bus"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/synthesizer"
	"github.com/xkilldash9x/scalpel-cli/internal/mocks"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
)

// TestSynthesizer_GoroutineLeakDetection verifies Strategy 1.1, specifically targeting timer leaks.
func TestSynthesizer_GoroutineLeakDetection(t *testing.T) {
	// Strategy 1.1: Use goleak to detect leaked timers (from time.AfterFunc).
	defer goleak.VerifyNone(t)

	logger := zaptest.NewLogger(t)
	eb := bus.NewEvolutionBus(logger, 100)
	mockLLM := new(mocks.MockLLMClient)
	mockKG := new(mocks.MockKGClient)

	// Initialize the synthesizer (relies on default 500ms settle time).
	s := synthesizer.NewSynthesizer(logger, eb, mockLLM, mockKG)

	// Setup mocks to return quickly once synthesis starts.
	mockKG.On("AddNode", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockKG.On("AddEdge", mock.Anything, mock.Anything).Return(nil).Maybe()
	mockKG.On("GetEdges", mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	mockKG.On("GetNeighbors", mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	mockKG.On("GetNode", mock.Anything, mock.Anything).Return(schemas.Node{}, nil).Maybe()
	mockKG.On("QueryImprovementHistory", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)
	mockLLM.On("Generate", mock.Anything, mock.Anything).Return(`[]`, nil) // Return empty strategies.
	// Start the Synthesizer.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.Start(ctx)
		close(done)
	}()

	// Simulate rapid influx of observations to trigger frequent timer resets.
	goalID := "test-goal-leak"
	eb.Post(ctx, models.TypeGoal, models.Goal{ID: goalID, Objective: "test"})

	const numObservations = 50
	for i := 0; i < numObservations; i++ {
		err := eb.Post(ctx, models.TypeObservation, models.Observation{GoalID: goalID})
		if err != nil {
			t.Fatalf("Failed to post: %v", err)
		}
		// Small delay allows the timer mechanism (time.AfterFunc) to execute and reset.
		time.Sleep(1 * time.Millisecond)
	}

	// Wait for the synthesis to occur (past the 500ms default settle time).
	time.Sleep(600 * time.Millisecond)

	// Stop the Synthesizer.
	cancel()

	// Wait for Start to return.
	select {
	case <-done:
	// Graceful stop.
	case <-time.After(2 * time.Second):
		t.Fatal("Synthesizer did not shut down promptly.")
	}

	eb.Shutdown()
	// goleak.VerifyNone ensures no timers or processing goroutines were left behind.
}

// TestSynthesizer_CancellationCorrectness verifies Strategy 1.2 during processing.
func TestSynthesizer_CancellationCorrectness(t *testing.T) {
	defer goleak.VerifyNone(t)

	logger := zaptest.NewLogger(t)
	eb := bus.NewEvolutionBus(logger, 10)
	// FIX: Ensure the bus is shut down at the end of the test, after assertions.
	defer eb.Shutdown()

	mockLLM := new(mocks.MockLLMClient)
	mockKG := new(mocks.MockKGClient)
	s := synthesizer.NewSynthesizer(logger, eb, mockLLM, mockKG)

	// Create a context to cancel during the operation.
	testCtx, cancelTest := context.WithCancel(context.Background())
	defer cancelTest()

	// Configure mocks: (Removed unnecessary mocks, keeping essential ones)
	mockKG.On("QueryImprovementHistory", mock.Anything, mock.Anything, mock.Anything).Return(nil, nil)

	// FIX: Ensure the mock respects the specific context passed to Generate.
	mockLLM.On("Generate", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			// Use the context passed in the arguments (derived by Synthesizer from testCtx).
			ctx := args.Get(0).(context.Context)
			// Block until this specific context is done.
			<-ctx.Done()
		}).
		Return("", context.Canceled)

	// FIX: Subscribe BEFORE starting the synthesizer to reliably capture any posted messages.
	// We don't need to unsubscribe manually if the bus is shut down at the end.
	synthesisChan, _ := eb.Subscribe(models.TypeSynthesis)

	// Start the Synthesizer.
	synthDone := make(chan struct{})
	go func() {
		s.Start(testCtx)
		close(synthDone)
	}()

	// Trigger the synthesis.
	goalID := "cancel-goal"
	// Use context.Background() for posting as the test harness.
	eb.Post(context.Background(), models.TypeGoal, models.Goal{ID: goalID, Objective: "cancel"})
	eb.Post(context.Background(), models.TypeObservation, models.Observation{GoalID: goalID})

	// Wait for the process to reach the blocked LLM call (past settle time).
	time.Sleep(600 * time.Millisecond)

	// Cancel the context.
	cancelTest()

	// Assert prompt shutdown (Cancellation Correctness).
	select {
	case <-synthDone:
	// Expected.
	case <-time.After(2 * time.Second):
		t.Fatal("Synthesizer did not return promptly after cancellation during processing.")
	}

	// Verification: Ensure no Synthesis message was posted.
	// FIX: Check the channel state correctly using a non-blocking select BEFORE Shutdown.
	select {
	case msg, ok := <-synthesisChan:
		if ok {
			assert.Fail(t, "Synthesis message should not have been posted after cancellation.", "Got: %v", msg)
		}
		// If !ok, the channel was closed (unexpected before Shutdown).
	default:
		// Expected: Channel is empty.
	}
}
