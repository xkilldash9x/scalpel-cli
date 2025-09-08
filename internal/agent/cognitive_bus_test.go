package agent

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)


// Test Setup Helper


// Creates a standard CognitiveBus instance for testing.
func setupCognitiveBus(t *testing.T, bufferSize int) *CognitiveBus {
	t.Helper()
	logger := zaptest.NewLogger(t)
	bus := NewCognitiveBus(logger, bufferSize)
	// Ensure the bus is shutdown after the test, providing safety against resource leaks.
	t.Cleanup(func() {
		// Check the internal state (white box) to avoid calling Shutdown if already called by the test.
		if !bus.isShutdown {
			bus.Shutdown()
		}
	})
	return bus
}


// Test Cases: Basic Functionality (Post, Subscribe, Acknowledge)


// Verifies the basic message flow.
func TestCognitiveBus_PostSubscribe_HappyPath(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// 1. Subscribe
	msgChan, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	// 2. Post
	expectedPayload := "test payload"
	msg := CognitiveMessage{Type: MessageTypeAction, Payload: expectedPayload}
	err := bus.Post(ctx, msg)
	require.NoError(t, err)

	// 3. Receive and Verify
	select {
	case receivedMsg := <-msgChan:
		assert.Equal(t, MessageTypeAction, receivedMsg.Type)
		assert.Equal(t, expectedPayload, receivedMsg.Payload)
		// White box check: Bus should enrich the message.
		assert.NotEmpty(t, receivedMsg.ID, "Bus should enrich message with ID")
		assert.False(t, receivedMsg.Timestamp.IsZero(), "Bus should enrich message with Timestamp")

		// 4. Acknowledge
		bus.Acknowledge(receivedMsg)

	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for message delivery")
	}

	// White box check: Ensure processingWg is zero after acknowledgment.
	assert.True(t, waitTimeout(&bus.processingWg, 100*time.Millisecond), "Message acknowledgment did not decrement processingWg")
}

// Verifies that subscribers only receive messages matching their filters.
func TestCognitiveBus_Filtering(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// Subscriber interested only in Actions
	actionChan, unsubAction := bus.Subscribe(MessageTypeAction)
	defer unsubAction()

	// Subscriber interested only in Observations
	obsChan, unsubObs := bus.Subscribe(MessageTypeObservation)
	defer unsubObs()

	// Post both types
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeAction, Payload: "A1"}))
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Type: MessageTypeObservation, Payload: "O1"}))

	// Verify Action Channel
	select {
	case msg := <-actionChan:
		assert.Equal(t, "A1", msg.Payload)
		bus.Acknowledge(msg)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for Action message")
	}

	// Verify Observation Channel
	select {
	case msg := <-obsChan:
		assert.Equal(t, "O1", msg.Payload)
		bus.Acknowledge(msg)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for Observation message")
	}

	// Ensure channels did not receive the wrong type.
	assert.Empty(t, actionChan, "Action channel should be empty")
	assert.Empty(t, obsChan, "Observation channel should be empty")
}


// Test Cases: Robustness and Backpressure


// Verifies that Post blocks when the subscriber's buffer is full.
func TestCognitiveBus_Backpressure(t *testing.T) {
	// Setup bus with a subscriber buffer size of 1.
	bus := setupCognitiveBus(t, 1)
	ctx := context.Background()

	// Subscribe but do not consume yet.
	msgChan, unsubscribe := bus.Subscribe()
	defer unsubscribe()

	// Post 1: Fills the buffer.
	err := bus.Post(ctx, CognitiveMessage{Payload: "Msg1"})
	require.NoError(t, err)

	// Post 2: Should block because the buffer (size 1) is full and the implementation uses blocking sends.
	post2Done := make(chan struct{})
	go func() {
		// This should block until we read Msg1.
		err := bus.Post(ctx, CognitiveMessage{Payload: "Msg2"})
		require.NoError(t, err)
		close(post2Done)
	}()

	// Wait briefly to ensure Post 2 is blocked.
	select {
	case <-post2Done:
		t.Fatal("Post 2 did not block as expected when subscriber buffer was full.")
	case <-time.After(100 * time.Millisecond):
		// Expected: Blocked.
	}

	// Consume Msg1 to unblock Post 2.
	msg1 := <-msgChan
	bus.Acknowledge(msg1)

	// Verify Post 2 completes.
	select {
	case <-post2Done:
		// Success.
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for Post 2 to complete after unblocking.")
	}
}

// Verifies that a blocked Post respects context cancellation.
func TestCognitiveBus_PostContextCancellation(t *testing.T) {
	bus := setupCognitiveBus(t, 1)
	ctx, cancel := context.WithCancel(context.Background())

	// Subscribe (buffer size 1) and fill the buffer.
	msgChan, unsubscribe := bus.Subscribe()
	defer unsubscribe()
	require.NoError(t, bus.Post(context.Background(), CognitiveMessage{Payload: "Msg1"}))

	// Attempt Post 2, which will block.
	postErrChan := make(chan error, 1)
	go func() {
		// This uses the cancellable context.
		postErrChan <- bus.Post(ctx, CognitiveMessage{Payload: "Msg2"})
	}()

	// Wait briefly to ensure it's blocked, then cancel the context.
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Verify Post 2 returns with a context error.
	select {
	case err := <-postErrChan:
		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for Post to respect context cancellation.")
	}

	// Cleanup: Acknowledge the first message so Shutdown doesn't hang.
	msg1 := <-msgChan
	bus.Acknowledge(msg1)
}


// Test Cases: Shutdown and Lifecycle


// Verifies that Shutdown waits for consumers to acknowledge messages.
func TestCognitiveBus_Shutdown_DrainsMessages(t *testing.T) {
	bus := setupCognitiveBus(t, 10)
	ctx := context.Background()

	// Subscribe but delay acknowledgment.
	msgChan, _ := bus.Subscribe()
	// Do not call unsubscribe, as Shutdown handles channel closure.

	// Post messages.
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Payload: "Msg1"}))
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Payload: "Msg2"}))

	// Consume messages.
	received1 := <-msgChan
	received2 := <-msgChan

	// Start shutdown in a goroutine. It should block waiting for Acknowledge (processingWg).
	shutdownDone := make(chan struct{})
	go func() {
		bus.Shutdown()
		close(shutdownDone)
	}()

	// Verify Shutdown is blocked.
	select {
	case <-shutdownDone:
		t.Fatal("Shutdown completed before messages were acknowledged.")
	case <-time.After(100 * time.Millisecond):
		// Expected: Blocked.
	}

	// Acknowledge messages.
	bus.Acknowledge(received1)
	bus.Acknowledge(received2)

	// Verify Shutdown completes.
	select {
	case <-shutdownDone:
		// Success.
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for Shutdown to complete after acknowledgment.")
	}
}

// Verifies the synchronization between Shutdown and active Post calls.
func TestCognitiveBus_Shutdown_RaceWithPost(t *testing.T) {
	bus := setupCognitiveBus(t, 1)
	ctx := context.Background()

	// Create a scenario where Post is blocked (backpressure).
	channel, _ := bus.Subscribe()
	require.NoError(t, bus.Post(ctx, CognitiveMessage{Payload: "Msg1"})) // Fills buffer

	// Start a Post operation that will block
	postDone := make(chan struct{})
	go func() {
		// This Post will block until Msg1 is consumed.
		// activePostsWg is incremented inside Post before the block.
		bus.Post(ctx, CognitiveMessage{Payload: "Msg2"})
		close(postDone)
	}()

	// Wait briefly to ensure the Post goroutine is running and blocked.
	time.Sleep(50 * time.Millisecond)

	// Start Shutdown in parallel
	shutdownDone := make(chan struct{})
	go func() {
		// Shutdown will block waiting for activePostsWg (held by the blocked Post).
		bus.Shutdown()
		close(shutdownDone)
	}()

	// Verify both are blocked
	select {
	case <-postDone:
		t.Fatal("Post should be blocked")
	case <-shutdownDone:
		t.Fatal("Shutdown should be blocked waiting for active Post")
	case <-time.After(100 * time.Millisecond):
		// Expected state
	}

	// Unblock the Post operation by consuming Msg1
	msg1 := <-channel
	bus.Acknowledge(msg1)

	// Verify Post completes
	<-postDone

	// Now that Post is done, activePostsWg decrements. Shutdown proceeds but waits for Msg2 processing.
	msg2 := <-channel
	bus.Acknowledge(msg2)

	// Verify Shutdown completes
	<-shutdownDone
}


// Test Cases: Concurrency


// Verifies thread safety and reliable delivery under load.
func TestCognitiveBus_ConcurrentPostersAndSubscribers(t *testing.T) {
	bus := setupCognitiveBus(t, 50) // Use a larger buffer.
	ctx := context.Background()

	const numPosters = 5
	const messagesPerPoster = 20
	const numSubscribers = 3
	totalMessages := numPosters * messagesPerPoster

	// -- Subscribers Setup --
	subscriberWG := sync.WaitGroup{}
	// Use sync.Map per subscriber to track received message IDs safely across goroutines.
	receivedMessages := make([]sync.Map, numSubscribers)

	for i := 0; i < numSubscribers; i++ {
		subscriberWG.Add(1)
		index := i
		msgChan, unsubscribe := bus.Subscribe()
		defer unsubscribe()

		go func() {
			defer subscriberWG.Done()
			count := 0
			// Use a timeout mechanism to prevent infinite waiting if messages are lost.
			timeout := time.After(5 * time.Second)
			for count < totalMessages {
				select {
				case msg, ok := <-msgChan:
					if !ok {
						return // Channel closed
					}
					// Store the message ID to verify completeness and detect duplicates.
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

	// -- Posters Setup --
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

	// Wait for posters to finish, then wait for subscribers.
	posterWG.Wait()
	subscriberWG.Wait()

	// -- Verification --
	// Ensure every subscriber received exactly the total number of messages.
	for i := 0; i < numSubscribers; i++ {
		count := 0
		receivedMessages[i].Range(func(key, value interface{}) bool {
			count++
			return true
		})
		assert.Equal(t, totalMessages, count, "Subscriber %d did not receive all messages.", i)
	}
}
