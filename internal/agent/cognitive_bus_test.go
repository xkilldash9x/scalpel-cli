// internal/agent/cognitive_bus_test.go
package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

// -- Test Helpers --

// Creates a standard CognitiveBus instance for testing.
func setupCognitiveBus(t *testing.T, bufferSize int) *CognitiveBus {
	t.Helper()
	logger := zaptest.NewLogger(t)
	bus := NewCognitiveBus(logger, bufferSize)
	// Make sure the bus is shutdown after the test, keeps things tidy and prevents resource leaks.
	t.Cleanup(func() {
		// Shutdown is idempotent (uses sync.Once), so it's safe to call unconditionally.
		// The previous check for bus.isShutdown was a data race.
		bus.Shutdown()
	})
	return bus
}

// -- Test Cases: Initialization --

// NEW: Verifies that a zero or negative buffer size defaults to 100.
func TestCognitiveBus_New_DefaultBufferSize(t *testing.T) {
	logger := zaptest.NewLogger(t)

	bus1 := NewCognitiveBus(logger, 0)
	assert.Equal(t, 100, bus1.bufferSize)

	bus2 := NewCognitiveBus(logger, -10)
	assert.Equal(t, 100, bus2.bufferSize)
}

// -- Test Cases: Basic Functionality --

// Verifies the basic message flow from posting to acknowledging.
func TestCognitiveBus_PostSubscribe_HappyPath(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// 1. Subscribe to all message types.
	msgChan, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	// 2. Post a message.
	expectedPayload := "test payload"
	msg := CognitiveMessage{Type: MessageTypeAction, Payload: expectedPayload}
	err := bus.Post(ctx, msg)
	require.NoError(t, err)

	// 3. Receive and verify the message.
	select {
	case receivedMsg := <-msgChan:
		assert.Equal(t, MessageTypeAction, receivedMsg.Type)
		assert.Equal(t, expectedPayload, receivedMsg.Payload)
		// Let's check that the bus did its job enriching the message.
		assert.NotEmpty(t, receivedMsg.ID, "Bus should enrich message with an ID")
		assert.False(t, receivedMsg.Timestamp.IsZero(), "Bus should enrich message with a Timestamp")

		// 4. Acknowledge the message.
		bus.Acknowledge(receivedMsg)

	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for message delivery")
	}

	// Double check that the processing wait group is zero after acknowledgment.
	assert.True(t, waitTimeout(&bus.processingWg, 100*time.Millisecond), "Message acknowledgment did not decrement processingWg")
}

// Verifies that subscribers only receive messages that match their filters.
func TestCognitiveBus_Filtering(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// This subscriber is only interested in Actions.
	actionChan, unsubAction := bus.Subscribe(MessageTypeAction)
	defer unsubAction()

	// This one's only looking for Observations.
	obsChan, unsubObs := bus.Subscribe(MessageTypeObservation)
	defer unsubObs()

	// Post one of each type.
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "A1"}))
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: "O1"}))

	// Verify the Action channel got its message.
	select {
	case msg := <-actionChan:
		assert.Equal(t, "A1", msg.Payload)
		bus.Acknowledge(msg)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for Action message")
	}

	// Verify the Observation channel got its message.
	select {
	case msg := <-obsChan:
		assert.Equal(t, "O1", msg.Payload)
		bus.Acknowledge(msg)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for Observation message")
	}

	// The final check: ensure no unexpected messages slipped through.
	assert.Empty(t, actionChan, "Action channel should be empty")
	assert.Empty(t, obsChan, "Observation channel should be empty")
}

// NEW: Verifies subscribing to multiple specific types.
func TestCognitiveBus_SubscribeMultipleTypes(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// Subscribe to Action OR Observation
	multiChan, unsub := bus.Subscribe(MessageTypeAction, MessageTypeObservation)
	defer unsub()

	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "A1"}))
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeStateChange, Payload: "S1"})) // Should be ignored
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: "O1"}))

	// Receive A1
	select {
	case msg := <-multiChan:
		assert.Equal(t, "A1", msg.Payload)
		bus.Acknowledge(msg)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for A1")
	}

	// Receive O1
	select {
	case msg := <-multiChan:
		assert.Equal(t, "O1", msg.Payload)
		bus.Acknowledge(msg)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for O1")
	}

	assert.Empty(t, multiChan, "Channel should be empty, S1 should have been ignored")
}

// NEW: Verifies that a subscriber listening to both a specific type and "all" only receives the message once.
func TestCognitiveBus_SubscribeSpecificAndAll_Uniqueness(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// Manually manipulate subscribers to simulate a channel listening to both specific and "all".
	// This tests the uniqueness logic within the Post method.
	ch := make(chan CognitiveMessage, 10)
	bus.mu.Lock()
	bus.subscribers[MessageTypeAction] = append(bus.subscribers[MessageTypeAction], ch)
	bus.subscribers[""] = append(bus.subscribers[""], ch) // "" represents "all"
	bus.mu.Unlock()

	// Act
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "A1"}))

	// Assert
	select {
	case msg := <-ch:
		bus.Acknowledge(msg)
		assert.Equal(t, "A1", msg.Payload)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for message")
	}

	// Crucial check: Ensure the channel is now empty (no duplicate delivery)
	assert.Empty(t, ch, "Subscriber received the message more than once")
}

// NEW: Verifies the unsubscribe logic works correctly and cleans up internal maps.
func TestCognitiveBus_Unsubscribe(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	ch1, unsub1 := bus.Subscribe(MessageTypeAction)
	ch2, unsub2 := bus.Subscribe(MessageTypeAction)

	// Unsubscribe the first listener
	unsub1()

	// Act
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "A1"}))

	// Assert
	// ch1 should receive nothing
	select {
	case msg, ok := <-ch1:
		if ok {
			t.Fatalf("Unsubscribed channel received a message: %+v", msg)
		}
	default:
		// Expected path if not closed yet
	}

	// ch2 should receive the message
	select {
	case msg := <-ch2:
		bus.Acknowledge(msg)
		assert.Equal(t, "A1", msg.Payload)
	case <-time.After(1 * time.Second):
		t.Fatal("Active subscriber did not receive message")
	}

	// Verify internal state (requires RLock)
	bus.mu.RLock()
	assert.Len(t, bus.subscribers[MessageTypeAction], 1, "Internal subscribers map not cleaned up")
	bus.mu.RUnlock()

	// Unsubscribe the second listener
	unsub2()

	// Verify map cleanup when empty
	bus.mu.RLock()
	_, exists := bus.subscribers[MessageTypeAction]
	assert.False(t, exists, "Map entry should be deleted when subscriber list is empty")
	bus.mu.RUnlock()
}

// NEW TEST: Verifies that the unsubscribe function is idempotent and safe to call multiple times.
func TestCognitiveBus_UnsubscribeIdempotent(t *testing.T) {
	bus := setupCognitiveBus(t, 10)

	_, unsub := bus.Subscribe(MessageTypeAction)

	// Verify it is subscribed initially (requires RLock for internal inspection)
	bus.mu.RLock()
	initialCount := 0
	if subs, ok := bus.subscribers[MessageTypeAction]; ok {
		initialCount = len(subs)
	}
	bus.mu.RUnlock()
	require.Equal(t, 1, initialCount, "Should have 1 subscriber initially")

	// Call unsubscribe multiple times concurrently
	var wg sync.WaitGroup
	const numCalls = 10
	for i := 0; i < numCalls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unsub()
		}()
	}

	// Wait for all calls to complete. This primarily checks for deadlocks.
	if !waitTimeout(&wg, 2*time.Second) {
		t.Fatal("Timeout waiting for concurrent unsubscribe calls; potential deadlock.")
	}

	// Verify internal state (requires RLock): it should be completely cleaned up.
	bus.mu.RLock()
	_, exists := bus.subscribers[MessageTypeAction]
	bus.mu.RUnlock()
	assert.False(t, exists, "Map entry should be deleted after unsubscribe, regardless of call count.")
}

// -- Test Cases: Robustness and Backpressure --

// Verifies that Post blocks when a subscriber's buffer is full.
func TestCognitiveBus_Backpressure(t *testing.T) {
	// Set up a bus with a tiny buffer size of 1.
	bus := setupCognitiveBus(t, 1)
	ctx := context.Background()

	// Subscribe but don't consume just yet.
	msgChan, unsubscribe := bus.Subscribe(MessageTypeAction)
	defer unsubscribe()

	// Post 1: This one should fill the buffer.
	err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "Msg1"})
	require.NoError(t, err)

	// Post 2: This should block since the buffer is full.
	post2Done := make(chan struct{})
	go func() {
		// This Post call should patiently wait until we read Msg1.
		err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "Msg2"})
		require.NoError(t, err)
		close(post2Done)
	}()

	// Give it a moment to ensure Post 2 is actually blocked.
	select {
	case <-post2Done:
		t.Fatal("Post 2 did not block as expected when subscriber buffer was full.")
	case <-time.After(100 * time.Millisecond):
		// This is what we expect: it's blocked.
	}

	// Now, consume Msg1 to unblock the second Post.
	msg1 := <-msgChan
	bus.Acknowledge(msg1)

	// Verify that Post 2 now completes.
	select {
	case <-post2Done:
		// Success! It unblocked.
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for Post 2 to complete after unblocking.")
	}

	//
	// Consume and acknowledge the second message. This is the crucial step
	// to prevent the test cleanup (bus.Shutdown) from hanging.
	//
	msg2 := <-msgChan
	bus.Acknowledge(msg2)
}

// Verifies that a blocked Post call respects context cancellation.
func TestCognitiveBus_PostContextCancellation(t *testing.T) {
	bus := setupCognitiveBus(t, 1)
	ctx, cancel := context.WithCancel(context.Background())

	// Subscribe and fill the buffer to force a block.
	msgChan, unsubscribe := bus.Subscribe(MessageTypeAction)
	defer unsubscribe()
	require.NoError(t, bus.Post(context.Background(), CognitiveMessage{Type: MessageTypeAction, Payload: "Msg1"}))

	// Attempt Post 2 in a goroutine, which will block.
	postErrChan := make(chan error, 1)
	go func() {
		// This uses the cancellable context.
		postErrChan <- bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "Msg2"})
	}()

	// Let it block for a moment, then pull the plug.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Verify that Post 2 returns with a context error.
	select {
	case err := <-postErrChan:
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for Post to respect context cancellation.")
	}

	// Clean up after ourselves so Shutdown doesn't hang.
	msg1 := <-msgChan
	bus.Acknowledge(msg1)
}

// -- Test Cases: Shutdown and Lifecycle --

// Verifies that Shutdown waits for in flight messages to be acknowledged.
func TestCognitiveBus_Shutdown_DrainsMessages(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// Subscribe but we're going to delay acknowledgment.
	msgChan, _ := bus.Subscribe(MessageTypeAction)
	// No need to call unsubscribe, Shutdown will handle closing channels.

	// Post a couple of messages.
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "Msg1"}))
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "Msg2"}))

	// Consume the messages, but hold off on acknowledging.
	received1 := <-msgChan
	received2 := <-msgChan

	// Kick off the shutdown in a goroutine. It should block.
	shutdownDone := make(chan struct{})
	go func() {
		bus.Shutdown()
		close(shutdownDone)
	}()

	// Verify that Shutdown is indeed blocked.
	select {
	case <-shutdownDone:
		t.Fatal("Shutdown completed before messages were acknowledged.")
	case <-time.After(100 * time.Millisecond):
		// Expected: it's blocked, waiting for us.
	}

	// Now, acknowledge the messages.
	bus.Acknowledge(received1)
	bus.Acknowledge(received2)

	// Verify Shutdown completes now.
	select {
	case <-shutdownDone:
		// Sweet success.
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for Shutdown to complete after acknowledgment.")
	}
}

// Verifies that Shutdown unblocks a pending Post and returns the correct error.
func TestCognitiveBus_Shutdown_UnblocksPost(t *testing.T) {
	bus := setupCognitiveBus(t, 1)
	ctx := context.Background()

	// Create a backpressure scenario.
	channel, _ := bus.Subscribe(MessageTypeAction)
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "Msg1"})) // Fills the buffer

	// Start a Post operation that we know will block.
	postErrChan := make(chan error, 1)
	go func() {
		// This Post should be unblocked by Shutdown and return an error.
		err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "Msg2"})
		postErrChan <- err
	}()

	// Give the goroutine a moment to get into its blocked state.
	time.Sleep(50 * time.Millisecond)

	// Start Shutdown in parallel. The test consumer hasn't acknowledged Msg1,
	// so Shutdown will wait for it after unblocking the Post.
	shutdownDone := make(chan struct{})
	go func() {
		bus.Shutdown()
		close(shutdownDone)
	}()

	// Verify that the blocked Post returns with an error because the bus is shutting down.
	select {
	case err := <-postErrChan:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bus is shutting down")
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for blocked Post to be unblocked by Shutdown.")
	}

	// Now that the Post is done, the shutdown process is waiting for Msg1 to be acknowledged.
	// We must do this for the test to complete cleanly.
	msg1 := <-channel
	bus.Acknowledge(msg1)

	// Finally, verify the Shutdown process fully completes.
	select {
	case <-shutdownDone:
		// Sweet success.
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for Shutdown to complete.")
	}
}

// NEW: Verifies that Post returns an error if called after Shutdown has started.
func TestCognitiveBus_PostAfterShutdown(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// Initiate shutdown
	bus.Shutdown()

	// Attempt to post
	err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "Late message"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CognitiveBus is shut down")
}

// -- Test Cases: Concurrency --

// Verifies thread safety and reliable message delivery under concurrent load.
func TestCognitiveBus_ConcurrentPostersAndSubscribers(t *testing.T) {
	bus := setupCognitiveBus(t, 50) // Use a larger buffer for this one.
	ctx := context.Background()

	const numPosters = 5
	const messagesPerPoster = 20
	const numSubscribers = 3
	totalMessages := numPosters * messagesPerPoster

	// -- Subscriber Setup --
	subscriberWG := sync.WaitGroup{}
	// Each subscriber gets its own sync.Map to track received message IDs safely.
	receivedMessages := make([]sync.Map, numSubscribers)

	for i := 0; i < numSubscribers; i++ {
		subscriberWG.Add(1)
		index := i
		msgChan, unsubscribe := bus.Subscribe()
		defer unsubscribe()

		go func() {
			defer subscriberWG.Done()
			count := 0
			// A timeout to prevent the test from running forever if something goes wrong.
			timeout := time.After(5 * time.Second)
			for count < totalMessages {
				select {
				case msg, ok := <-msgChan:
					if !ok {
						return // Channel closed, time to go home.
					}
					// Store the message ID to verify we get everything and no duplicates.
					if _, loaded := receivedMessages[index].LoadOrStore(msg.ID, true); loaded {
						t.Errorf("Subscriber %d received duplicate message ID: %s", index, msg.ID)
					}
					bus.Acknowledge(msg)
					count++
				case <-timeout:
					t.Errorf("Subscriber %d timed out waiting for messages. Received %d/%d.", index, count, totalMessages)
					return
				}
			}
		}()
	}

	// -- Poster Setup --
	posterWG := sync.WaitGroup{}
	for i := 0; i < numPosters; i++ {
		posterWG.Add(1)
		go func() {
			defer posterWG.Done()
			for j := 0; j < messagesPerPoster; j++ {
				err := bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction})
				require.NoError(t, err)
			}
		}()
	}

	// Wait for all posters to finish, then wait for the subscribers to catch up.
	posterWG.Wait()
	subscriberWG.Wait()

	// -- Verification --
	// Ensure every single subscriber received every single message.
	for i := 0; i < numSubscribers; i++ {
		count := 0
		receivedMessages[i].Range(func(key, value interface{}) bool {
			count++
			return true
		})
		assert.Equal(t, totalMessages, count, "Subscriber %d did not receive all messages.", i)
	}
}

// NEW TEST: Verifies that there is no race condition between Post and Shutdown
// regarding the activePostsWg (WaitGroup misuse: Add called concurrently with Wait).
func TestCognitiveBus_PostShutdownRace(t *testing.T) {
	// This test is designed to be run with the race detector (-race).
	// It attempts to trigger a panic if Add() is called on activePostsWg while Wait() is active.
	logger := zaptest.NewLogger(t)

	// We need to run this in a loop because a single iteration might not hit the race condition.
	for i := 0; i < 100; i++ {
		// Initialize a fresh bus for each iteration.
		bus := NewCognitiveBus(logger, 10)
		ctx := context.Background()

		var iterationWg sync.WaitGroup

		// Use a channel to synchronize the start of Post and Shutdown.
		startChan := make(chan struct{})

		// Goroutine 1: Call Post
		iterationWg.Add(1)
		go func() {
			defer iterationWg.Done()
			<-startChan
			// If the bus shuts down first, this will return an error, which is expected.
			_ = bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction})
		}()

		// Goroutine 2: Call Shutdown
		iterationWg.Add(1)
		go func() {
			defer iterationWg.Done()
			<-startChan
			bus.Shutdown() // This calls activePostsWg.Wait()
		}()

		close(startChan) // Start both concurrently
		iterationWg.Wait()
	}
}
