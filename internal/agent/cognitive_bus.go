// internal/agent/cognitive_bus.go
package agent

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// CognitiveMessageType defines the message types used on the CognitiveBus.
// Moved here as it's specific to the bus implementation.
type CognitiveMessageType string

const (
	MessageTypeAction      CognitiveMessageType = "ACTION"
	MessageTypeObservation CognitiveMessageType = "OBSERVATION"
	MessageTypeStateChange CognitiveMessageType = "STATE_CHANGE"
	MessageTypeInterrupt   CognitiveMessageType = "INTERRUPT"
)

// CognitiveMessage is the envelope for data transmitted over the CognitiveBus.
type CognitiveMessage struct {
	Type    CognitiveMessageType
	Payload interface{}
}

// CognitiveBus manages the flow of information using a Pub/Sub model.
type CognitiveBus struct {
	logger *zap.Logger

	// Map of message type to a list of channels (subscribers).
	subscribers map[CognitiveMessageType][]chan CognitiveMessage
	mu          sync.RWMutex
	bufferSize  int

	// WaitGroup to track outstanding messages for graceful shutdown.
	wg sync.WaitGroup
}

// NewCognitiveBus initializes the CognitiveBus.
func NewCognitiveBus(logger *zap.Logger, bufferSize int) *CognitiveBus {
	if bufferSize <= 0 {
		bufferSize = 100 // Default buffer size
	}
	return &CognitiveBus{
		logger:      logger.Named("cognitive_bus"),
		subscribers: make(map[CognitiveMessageType][]chan CognitiveMessage),
		bufferSize:  bufferSize,
	}
}

// Post sends a message onto the bus, distributing it to all relevant subscribers.
func (cb *CognitiveBus) Post(ctx context.Context, msg CognitiveMessage) error {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	subscribers, ok := cb.subscribers[msg.Type]
	if !ok || len(subscribers) == 0 {
		cb.logger.Debug("Message posted, but no subscribers for type", zap.String("type", string(msg.Type)))
		return nil
	}

	// Track the message in the WaitGroup for the number of expected deliveries.
	cb.wg.Add(len(subscribers))

	deliverySuccess := false
	for _, ch := range subscribers {
		select {
		case ch <- msg:
			deliverySuccess = true
		case <-ctx.Done():
			// Context cancelled during delivery.
			cb.wg.Done() // Decrement as this delivery failed.
			cb.logger.Warn("Context cancelled during message delivery", zap.Error(ctx.Err()))
			return ctx.Err()
		default:
			// Handle backpressure: If a subscriber's buffer is full.
			cb.wg.Done() // Decrement as this message is dropped for this subscriber.
			cb.logger.Error("Subscriber buffer full, dropping message.", zap.String("type", string(msg.Type)))
		}
	}

	if !deliverySuccess && len(subscribers) > 0 {
		// Occurs if all subscribers were busy/full.
		return fmt.Errorf("failed to deliver message to any subscriber for type %s", msg.Type)
	}

	cb.logger.Debug("Message distributed to subscribers", zap.String("type", string(msg.Type)), zap.Int("count", len(subscribers)))
	return nil
}

// Subscribe returns a channel to listen for a specific message type and an unsubscribe function.
func (cb *CognitiveBus) Subscribe(msgType CognitiveMessageType) (<-chan CognitiveMessage, func()) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	ch := make(chan CognitiveMessage, cb.bufferSize)
	cb.subscribers[msgType] = append(cb.subscribers[msgType], ch)

	unsubscribe := func() {
		cb.mu.Lock()
		defer cb.mu.Unlock()

		subs := cb.subscribers[msgType]
		for i, subscriberCh := range subs {
			if subscriberCh == ch {
				// Remove the channel from the slice
				cb.subscribers[msgType] = append(subs[:i], subs[i+1:]...)
				// It is safe to close the channel here as we hold the lock and removed it from the list.
				close(ch)
				return
			}
		}
	}

	cb.logger.Debug("New subscription created", zap.String("type", string(msgType)))
	return ch, unsubscribe
}

// Acknowledge signals that a message has been processed by a consumer.
// Consumers MUST call this after processing a message received from Subscribe().
func (cb *CognitiveBus) Acknowledge(msg CognitiveMessage) {
	// Decrement the WaitGroup counter when a consumer finishes processing a message.
	cb.wg.Done()
}

// Shutdown gracefully closes the bus, waiting for all posted messages to be acknowledged.
func (cb *CognitiveBus) Shutdown() {
	cb.logger.Info("Shutting down CognitiveBus, waiting for message drain.")

	// Wait for consumers to finish processing the remaining messages.
	cb.wg.Wait()

	// Close all subscriber channels after draining is complete.
	cb.mu.Lock()
	defer cb.mu.Unlock()
	for msgType, subs := range cb.subscribers {
		for _, ch := range subs {
			// Since we hold the lock and wg.Wait() has passed, no more messages will be sent.
			close(ch)
		}
		delete(cb.subscribers, msgType)
	}

	cb.logger.Info("CognitiveBus shutdown complete.")
}