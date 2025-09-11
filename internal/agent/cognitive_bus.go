// internal/agent/cognitive_bus.go
package agent

package agent

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"
	"api/schemas"
)

// CognitiveBus manages the flow of information between the Agent's environment and the Mind.
// It acts as the central message broker for the OODA loop.
type CognitiveBus struct {
	logger *zap.Logger

	// Rationale: Using buffered channels allows for asynchronous communication and prevents blocking.
	messageChannel chan CognitiveMessage
	bufferSize     int

	// Rationale: WaitGroup to ensure all messages are processed during shutdown.
	wg sync.WaitGroup
}

// NewCognitiveBus initializes the CognitiveBus.
func NewCognitiveBus(logger *zap.Logger, bufferSize int) *CognitiveBus {
	if bufferSize <= 0 {
		bufferSize = 100 // Default buffer size
	}
	return &CognitiveBus{
		logger:         logger.Named("cognitive_bus"),
		messageChannel: make(chan CognitiveMessage, bufferSize),
		bufferSize:     bufferSize,
	}
}

// Post sends a message onto the bus.
func (cb *CognitiveBus) Post(ctx context.Context, msg CognitiveMessage) error {
	cb.wg.Add(1)
	select {
	case cb.messageChannel <- msg:
		cb.logger.Debug("Message posted to bus", zap.String("type", string(msg.Type)))
		return nil
	case <-ctx.Done():
		// Rationale: Handle context cancellation (e.g., timeout) during message posting.
		cb.wg.Done()
		cb.logger.Warn("Failed to post message due to context cancellation", zap.Error(ctx.Err()))
		return ctx.Err()
	default:
		// Rationale: Handle backpressure if the buffer is full. This prevents the system from crashing due to excessive load.
		cb.wg.Done()
		cb.logger.Error("CognitiveBus buffer full, dropping message. System overloaded.", zap.String("type", string(msg.Type)))
		return fmt.Errorf("cognitive bus buffer full")
	}
}

// Subscribe returns the channel to listen for messages.
func (cb *CognitiveBus) Subscribe() <-chan CognitiveMessage {
	return cb.messageChannel
}

// Acknowledge signals that a message has been processed.
// Consumers MUST call this after processing a message received from Subscribe().
func (cb *CognitiveBus) Acknowledge() {
	// Rationale: Decrement the WaitGroup counter when a consumer finishes processing a message.
	cb.wg.Done()
}

// Shutdown gracefully closes the bus, waiting for all messages to be processed.
func (cb *CognitiveBus) Shutdown() {
	cb.logger.Info("Shutting down CognitiveBus, waiting for message drain.")
	// Close the channel to signal no more messages will be posted.
	close(cb.messageChannel)
	// Wait for consumers to finish processing the remaining messages (via Acknowledge).
	cb.wg.Wait()
	cb.logger.Info("CognitiveBus shutdown complete.")
}