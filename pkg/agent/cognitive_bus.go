// -- pkg/agent/cognitive_bus.go --
package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// CognitiveMessage is the envelope for communication on the CognitiveBus.
// Moved here from models.go and enhanced with tracking fields.
type CognitiveMessage struct {
	ID        string
	Type      CognitiveMessageType
	Payload   interface{}
	Timestamp time.Time
}

// Subscriber represents a consumer listening on the bus.
type Subscriber struct {
	ID      string
	Channel chan CognitiveMessage
	Filters map[CognitiveMessageType]bool
}

// CognitiveBus manages the flow of information between the Agent's environment and the Mind.
// Refactored to support multiple subscribers with filtering (fan-out).
type CognitiveBus struct {
	logger *zap.Logger

	// Using a mutex to protect the subscribers map.
	subscribersMutex sync.RWMutex
	subscribers      map[string]*Subscriber

	// activePostsWg tracks currently active Post() calls to prevent a race with Shutdown.
	activePostsWg sync.WaitGroup
	// processingWg tracks messages currently being processed by subscribers.
	processingWg sync.WaitGroup
	// Mutex to ensure shutdown is handled correctly.
	shutdownMutex sync.Mutex
	isShutdown    bool
	bufferSize    int
}

// NewCognitiveBus initializes the CognitiveBus.
func NewCognitiveBus(logger *zap.Logger, bufferSize int) *CognitiveBus {
	if bufferSize <= 0 {
		bufferSize = 100 // Default buffer size if not specified or invalid.
	}
	return &CognitiveBus{
		logger:      logger.Named("cognitive_bus"),
		subscribers: make(map[string]*Subscriber),
		bufferSize:  bufferSize,
	}
}

// Post sends a message onto the bus.
func (cb *CognitiveBus) Post(ctx context.Context, msg CognitiveMessage) error {
	cb.shutdownMutex.Lock()
	if cb.isShutdown {
		cb.shutdownMutex.Unlock()
		return fmt.Errorf("cannot post message: CognitiveBus is shutting down")
	}
	// Crucial: Indicate that a Post operation is starting BEFORE unlocking to prevent a race with Shutdown.
	cb.activePostsWg.Add(1)
	cb.shutdownMutex.Unlock()

	// Ensure we mark the Post operation as done when the function returns.
	defer cb.activePostsWg.Done()

	// Enrich the message with an ID and timestamp if they are missing.
	if msg.ID == "" {
		msg.ID = uuid.NewString()
	}
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now().UTC()
	}

	// Minimize lock contention by creating a snapshot of interested subscribers.
	cb.subscribersMutex.RLock()
	// Pre-allocate the slice with a capacity based on the number of subscribers.
	subscribersSnapshot := make([]*Subscriber, 0, len(cb.subscribers))
	for _, sub := range cb.subscribers {
		// Check filter while holding the lock. An empty filter map means subscribe to all.
		if len(sub.Filters) > 0 && !sub.Filters[msg.Type] {
			continue
		}
		subscribersSnapshot = append(subscribersSnapshot, sub)
	}
	cb.subscribersMutex.RUnlock()

	if len(subscribersSnapshot) == 0 {
		cb.logger.Warn("Message posted but no subscribers are active or interested.", zap.String("type", string(msg.Type)))
		return nil
	}

	// Fan-out the message to the snapshot (outside the lock).
	for _, sub := range subscribersSnapshot {
		// Increment the WG *before* sending to the channel to avoid a race with Acknowledge.
		cb.processingWg.Add(1)

		select {
		case sub.Channel <- msg:
			cb.logger.Debug("Message dispatched", zap.String("msg_id", msg.ID), zap.String("type", string(msg.Type)), zap.String("subscriber_id", sub.ID))
		case <-ctx.Done():
			// Handle context cancellation during a blocking dispatch.
			cb.processingWg.Done() // Decrement the WG as this message won't be processed.
			cb.logger.Warn("Failed to dispatch message due to context cancellation", zap.Error(ctx.Err()))
			return ctx.Err()
		// 'default' case is removed to apply backpressure. This send will block if the consumer is slow.
		}
	}
	return nil
}

// Subscribe registers a new subscriber and returns a channel and an unsubscribe function.
// Optional filters can be provided to receive only specific message types.
func (cb *CognitiveBus) Subscribe(filters ...CognitiveMessageType) (<-chan CognitiveMessage, func()) {
	cb.subscribersMutex.Lock()
	defer cb.subscribersMutex.Unlock()

	// Use a buffered channel for the subscriber to prevent blocking the Post operation.
	channel := make(chan CognitiveMessage, cb.bufferSize)
	filterMap := make(map[CognitiveMessageType]bool)
	for _, f := range filters {
		filterMap[f] = true
	}

	subID := uuid.NewString() // Use the full UUID to guarantee uniqueness.
	subscriber := &Subscriber{
		ID:      subID,
		Channel: channel,
		Filters: filterMap,
	}
	cb.subscribers[subID] = subscriber
	cb.logger.Info("New subscriber registered.", zap.String("subscriber_id", subID), zap.Int("active_subscribers", len(cb.subscribers)))

	// Create the unsubscribe closure, capturing the subID.
	unsubscribe := func() {
		cb.unsubscribe(subID)
	}

	return channel, unsubscribe
}

// unsubscribe removes a subscriber from the bus.
func (cb *CognitiveBus) unsubscribe(subID string) {
	cb.subscribersMutex.Lock()
	defer cb.subscribersMutex.Unlock()

	// Do not proceed if the bus is already shut down (subscribers map might be nil).
	if cb.subscribers == nil {
		return
	}

	sub, ok := cb.subscribers[subID]
	if !ok {
		// Subscriber already unregistered.
		return
	}

	close(sub.Channel)
	delete(cb.subscribers, subID)
	cb.logger.Info("Subscriber unregistered.", zap.String("subscriber_id", subID), zap.Int("active_subscribers", len(cb.subscribers)))
}

// Acknowledge signals that a message has been processed by a subscriber.
// Consumers MUST call this after processing a message received from Subscribe().
func (cb *CognitiveBus) Acknowledge(msg CognitiveMessage) {
	// Decrement the WaitGroup counter when a consumer finishes processing a message.
	cb.processingWg.Done()
	cb.logger.Debug("Message acknowledged", zap.String("msg_id", msg.ID))
}

// waitTimeout is a helper to wait for a WaitGroup with a timeout.
func waitTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()
	select {
	case <-c:
		return true // Completed normally.
	case <-time.After(timeout):
		return false // Timed out.
	}
}

// Shutdown gracefully closes the bus, waiting for all messages to be processed.
func (cb *CognitiveBus) Shutdown() {
	cb.shutdownMutex.Lock()
	if cb.isShutdown {
		cb.shutdownMutex.Unlock()
		return
	}
	cb.isShutdown = true
	cb.shutdownMutex.Unlock()

	cb.logger.Info("Shutting down CognitiveBus, waiting for active posts to finish.")
	// 1. Wait for all active Post() calls to complete their dispatch logic.
	cb.activePostsWg.Wait()

	cb.logger.Info("Waiting for message drain.")
	// 2. Wait for consumers to finish processing the messages (via Acknowledge), with a timeout.
	const shutdownTimeout = 10 * time.Second
	if !waitTimeout(&cb.processingWg, shutdownTimeout) {
		cb.logger.Error("Timeout waiting for CognitiveBus messages to drain. Shutting down forcefully.", zap.Duration("timeout", shutdownTimeout))
	}

	// 3. Close all subscriber channels to signal consumers to stop.
	cb.subscribersMutex.Lock()
	for _, sub := range cb.subscribers {
		close(sub.Channel)
	}
	cb.subscribers = nil // Clear subscribers map.
	cb.subscribersMutex.Unlock()

	cb.logger.Info("CognitiveBus shutdown complete.")
}
