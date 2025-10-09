// internal/evolution/bus/bus.go
package bus

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/models"
	"go.uber.org/zap"
)

// Message is the envelope for data transmitted over the EvolutionBus.
type Message struct {
	ID        string
	Timestamp time.Time
	Type      models.MessageType
	Payload   interface{}
}

// EvolutionBus manages the flow of information using a Pub/Sub model for the OODA loop.
type EvolutionBus struct {
	logger *zap.Logger

	// Map of message type to a list of channels (subscribers).
	subscribers map[models.MessageType][]chan Message
	mu          sync.RWMutex
	bufferSize  int

	// WaitGroup to track messages currently being processed by consumers.
	processingWg sync.WaitGroup
	// WaitGroup to track active Post operations.
	activePostsWg sync.WaitGroup

	// Shutdown mechanism
	shutdownChan chan struct{}
	shutdownOnce sync.Once
	isShutdown   bool
	shutdownMu   sync.Mutex
}

// NewEvolutionBus initializes the EvolutionBus.
func NewEvolutionBus(logger *zap.Logger, bufferSize int) *EvolutionBus {
	if bufferSize < 0 {
		bufferSize = 0
	}

	return &EvolutionBus{
		logger:       logger.Named("evolution_bus"),
		subscribers:  make(map[models.MessageType][]chan Message),
		bufferSize:   bufferSize,
		shutdownChan: make(chan struct{}),
	}
}

// Post sends a message onto the bus. Blocks if subscriber buffers are full.
func (eb *EvolutionBus) Post(ctx context.Context, msgType models.MessageType, payload interface{}) error {
	// 1. Check shutdown state and increment activePostsWg.
	eb.shutdownMu.Lock()
	if eb.isShutdown {
		eb.shutdownMu.Unlock()
		return fmt.Errorf("cannot post message: EvolutionBus is shut down")
	}
	eb.activePostsWg.Add(1)
	eb.shutdownMu.Unlock()
	defer eb.activePostsWg.Done()

	// 2. Create the message envelope.
	msg := Message{
		ID:        uuid.New().String(),
		Timestamp: time.Now().UTC(),
		Type:      msgType,
		Payload:   payload,
	}

	eb.logger.Debug("Posting message", zap.String("type", string(msg.Type)), zap.String("id", msg.ID))

	// 3. Acquire read lock to access subscribers.
	eb.mu.RLock()

	subscribers, ok := eb.subscribers[msg.Type]
	if !ok || len(subscribers) == 0 {
		eb.mu.RUnlock()
		return nil // No one is listening.
	}

	// Create a copy to avoid holding the lock during channel sends.
	subsCopy := make([]chan Message, len(subscribers))
	copy(subsCopy, subscribers)
	eb.mu.RUnlock()

	// 4. Distribute the message, tracking each delivery.
	for _, ch := range subsCopy {
		eb.processingWg.Add(1)
		select {
		case ch <- msg:
			// Delivered successfully. The consumer must call Acknowledge.
		case <-ctx.Done():
			// Context cancelled before delivery. Decrement WG as it won't be acknowledged.
			eb.processingWg.Done()
			return ctx.Err()
		case <-eb.shutdownChan:
			// Shutdown initiated before delivery. Decrement WG.
			eb.processingWg.Done()
			return fmt.Errorf("failed to post message: bus is shutting down")
		}
	}
	return nil
}

// Subscribe returns a channel to listen for specific message types.
func (eb *EvolutionBus) Subscribe(msgTypes ...models.MessageType) (<-chan Message, func()) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// Check shutdown state (optional, but good practice)
	if eb.isShutdown {
		closedCh := make(chan Message)
		close(closedCh)
		return closedCh, func() {}
	}

	if len(msgTypes) == 0 {
		panic("must subscribe to at least one message type")
	}

	ch := make(chan Message, eb.bufferSize)
	subscribedTypes := make([]models.MessageType, len(msgTypes))
	copy(subscribedTypes, msgTypes)

	for _, msgType := range subscribedTypes {
		eb.subscribers[msgType] = append(eb.subscribers[msgType], ch)
	}

	unsubscribe := func() {
		eb.mu.Lock()
		defer eb.mu.Unlock()

		// Note: We don't check eb.isShutdown here because we need to allow cleanup even if shutdown started.
		// We rely on the subscribers map still being valid until Shutdown() clears it.

		for _, msgType := range subscribedTypes {
			subs, exists := eb.subscribers[msgType]
			if !exists {
				continue
			}
			for i, subscriberCh := range subs {
				if subscriberCh == ch {
					// Remove the channel from the slice
					copy(subs[i:], subs[i+1:])
					eb.subscribers[msgType] = subs[:len(subs)-1]

					if len(eb.subscribers[msgType]) == 0 {
						delete(eb.subscribers, msgType)
					}
					break
				}
			}
		}
		// We do not close(ch) here; the bus manages channel closure during Shutdown.
	}

	return ch, unsubscribe
}

// Acknowledge signals that a message has been processed by a consumer.
func (eb *EvolutionBus) Acknowledge(msg Message) {
	eb.processingWg.Done()
}

// Shutdown gracefully closes the bus.
func (eb *EvolutionBus) Shutdown() {
	eb.shutdownOnce.Do(func() {
		eb.logger.Info("Shutting down EvolutionBus...")

		// 1. Set shutdown flag.
		eb.shutdownMu.Lock()
		eb.isShutdown = true
		eb.shutdownMu.Unlock()

		// 2. Signal Post operations.
		close(eb.shutdownChan)

		// 3. Wait for in-flight Post calls to finish attempting delivery.
		eb.activePostsWg.Wait()

		// 4. Close all subscriber channels AND drain buffers (Fix for Shutdown Deadlock).
		eb.mu.Lock()
		uniqueChannels := make(map[chan Message]struct{})
		for _, subs := range eb.subscribers {
			for _, ch := range subs {
				uniqueChannels[ch] = struct{}{}
			}
		}

		// Close the channels first. Since activePostsWg.Wait() finished,
		// we know no other goroutine is trying to send on these channels.
		for ch := range uniqueChannels {
			close(ch)
		}

		// Now drain the channels and decrement the WaitGroup for buffered messages.
		// These messages were counted as 'delivered' but might not be 'acknowledged' if consumers exited early.
		drainedCount := 0
		for ch := range uniqueChannels {
			// Range over a closed channel drains the buffer and then stops.
			for range ch {
				drainedCount++
				eb.processingWg.Done()
			}
		}

		// Clear subscribers map
		eb.subscribers = make(map[models.MessageType][]chan Message)
		eb.mu.Unlock()

		if drainedCount > 0 {
			eb.logger.Debug("Drained buffered messages during shutdown.", zap.Int("count", drainedCount))
		}

		// 5. Wait for messages actively being processed (those already received and being worked on by consumers).
		eb.processingWg.Wait()
		eb.logger.Info("EvolutionBus shut down gracefully.")
	})
}
