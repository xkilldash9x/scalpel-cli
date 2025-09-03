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

	// WaitGroup to track messages currently being processed by subscribers.
	processingWg sync.WaitGroup
	// Mutex to ensure shutdown is handled correctly.
	shutdownMutex sync.Mutex
	isShutdown    bool
	bufferSize    int
}

// NewCognitiveBus initializes the CognitiveBus.
func NewCognitiveBus(logger *zap.Logger, bufferSize int) *CognitiveBus {
	if bufferSize <= 0 {
		bufferSize = 100
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
	cb.shutdownMutex.Unlock()

	// Enrich the message.
	if msg.ID == "" {
		msg.ID = uuid.NewString()
	}
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now().UTC()
	}

	cb.subscribersMutex.RLock()
	defer cb.subscribersMutex.RUnlock()

	if len(cb.subscribers) == 0 {
		cb.logger.Warn("Message posted but no subscribers are active.", zap.String("type", string(msg.Type)))
		return nil
	}

	// Fan-out the message to interested subscribers.
	for _, sub := range cb.subscribers {
		// Check if the subscriber is interested in this message type.
		if len(sub.Filters) > 0 && !sub.Filters[msg.Type] {
			continue
		}

		// Increment the WG *before* sending to the channel.
		cb.processingWg.Add(1)

		select {
		case sub.Channel <- msg:
			cb.logger.Debug("Message dispatched", zap.String("msg_id", msg.ID), zap.String("type", string(msg.Type)), zap.String("subscriber_id", sub.ID))
		case <-ctx.Done():
			// Handle context cancellation during dispatch.
			cb.processingWg.Done()
			cb.logger.Warn("Failed to dispatch message due to context cancellation", zap.Error(ctx.Err()))
			return ctx.Err()
		default:
			// Handle backpressure if the subscriber's buffer is full.
			cb.processingWg.Done()
			cb.logger.Error("Subscriber buffer full, dropping message. System overloaded.", zap.String("type", string(msg.Type)), zap.String("subscriber_id", sub.ID))
			// In a critical system, consider a retry or dead-letter queue instead of dropping.
		}
	}
	return nil
}

// Subscribe registers a new subscriber and returns a channel to listen for messages.
// Optional filters can be provided to receive only specific message types.
func (cb *CognitiveBus) Subscribe(filters ...CognitiveMessageType) <-chan CognitiveMessage {
	cb.subscribersMutex.Lock()
	defer cb.subscribersMutex.Unlock()

	// Use a buffered channel for the subscriber to prevent blocking the Post operation.
	channel := make(chan CognitiveMessage, cb.bufferSize)
	filterMap := make(map[CognitiveMessageType]bool)
	for _, f := range filters {
		filterMap[f] = true
	}

	subID := uuid.NewString()[:8]
	subscriber := &Subscriber{
		ID:      subID,
		Channel: channel,
		Filters: filterMap,
	}
	cb.subscribers[subID] = subscriber
	cb.logger.Info("New subscriber registered.", zap.String("subscriber_id", subID), zap.Int("active_subscribers", len(cb.subscribers)))
	return channel
}

// Acknowledge signals that a message has been processed by a subscriber.
// Consumers MUST call this after processing a message received from Subscribe().
func (cb *CognitiveBus) Acknowledge(msg CognitiveMessage) {
	// Decrement the WaitGroup counter when a consumer finishes processing a message.
	cb.processingWg.Done()
	cb.logger.Debug("Message acknowledged", zap.String("msg_id", msg.ID))
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

	cb.logger.Info("Shutting down CognitiveBus, waiting for message drain.")

	// Wait for consumers to finish processing the messages (via Acknowledge).
	cb.processingWg.Wait()

	// Close all subscriber channels.
	cb.subscribersMutex.Lock()
	for _, sub := range cb.subscribers {
		close(sub.Channel)
	}
	cb.subscribers = nil // Clear subscribers list
	cb.subscribersMutex.Unlock()

	cb.logger.Info("CognitiveBus shutdown complete.")
}
