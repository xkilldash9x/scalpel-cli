package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// CognitiveMessage is the envelope for data transmitted over the CognitiveBus.
type CognitiveMessage struct {
	ID        string
	Timestamp time.Time
	Type      CognitiveMessageType
	Payload   interface{}
}

// CognitiveBusService manages the flow of information using a Pub/Sub model.
// Implements blocking sends (backpressure) and graceful shutdown.
type CognitiveBusService struct {
	logger *zap.Logger

	// Map of message type to a list of channels (subscribers).
	subscribers map[CognitiveMessageType][]chan CognitiveMessage
	mu          sync.RWMutex
	bufferSize  int

	// WaitGroup to track messages currently being processed by consumers.
	processingWg sync.WaitGroup
	// WaitGroup to track active Post operations.
	activePostsWg sync.WaitGroup

	// Shutdown mechanism
	shutdownChan chan struct{} // Used to signal all operations to stop.
	shutdownOnce sync.Once
	isShutdown   bool
	shutdownMu   sync.Mutex
}

// NewCognitiveBus initializes the CognitiveBus.
func NewCognitiveBus(logger *zap.Logger, bufferSize int) *CognitiveBusService {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	return &CognitiveBusService{
		logger:       logger.Named("cognitive_bus"),
		subscribers:  make(map[CognitiveMessageType][]chan CognitiveMessage),
		bufferSize:   bufferSize,
		shutdownChan: make(chan struct{}),
	}
}

// Post sends a message onto the bus. Blocks if subscriber buffers are full.
func (cb *CognitiveBusService) Post(ctx context.Context, msg CognitiveMessage) error {
	// 1. Check shutdown state and increment activePostsWg.
	cb.shutdownMu.Lock()
	if cb.isShutdown {
		cb.shutdownMu.Unlock()
		return fmt.Errorf("cannot post message: CognitiveBus is shut down")
	}
	cb.activePostsWg.Add(1)
	cb.shutdownMu.Unlock()
	defer cb.activePostsWg.Done()

	// 2. Enrich the message.
	if msg.ID == "" {
		msg.ID = uuid.New().String()
	}
	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now().UTC()
	}

	// 3. Acquire read lock to access subscribers.
	cb.mu.RLock()

	// Start with subscribers specific to the message type.
	subscribers, ok := cb.subscribers[msg.Type]
	allSubscribers, allOk := cb.subscribers[""]

	if (!ok || len(subscribers) == 0) && (!allOk || len(allSubscribers) == 0) {
		cb.mu.RUnlock()
		return nil // No one is listening.
	}

	// Combine specific and "all" subscribers.
	combinedSubscribers := append(subscribers, allSubscribers...)

	// Create a copy of the subscribers slice to avoid holding the lock during channel sends.
	// We must ensure uniqueness if a subscriber listens to both specific and "all" types.
	uniqueSubs := make(map[chan CognitiveMessage]struct{})
	for _, sub := range combinedSubscribers {
		uniqueSubs[sub] = struct{}{}
	}

	subsCopy := make([]chan CognitiveMessage, 0, len(uniqueSubs))
	for ch := range uniqueSubs {
		subsCopy = append(subsCopy, ch)
	}

	cb.mu.RUnlock()

	// 4. Distribute the message, tracking each delivery.
	for _, ch := range subsCopy {
		cb.processingWg.Add(1)
		select {
		case ch <- msg:
			// Delivered successfully. The consumer is responsible for calling Acknowledge.
		case <-ctx.Done():
			// Delivery failed due to context cancellation, so undo the Add.
			cb.processingWg.Done()
			return ctx.Err()
		case <-cb.shutdownChan:
			// Bus is shutting down, so undo the Add.
			cb.processingWg.Done()
			return fmt.Errorf("failed to post message: bus is shutting down")
		}
	}
	return nil
}

// Subscribe returns a channel to listen for specific message types.
// Supports variadic arguments to align with test usage (e.g. Subscribe(TypeA, TypeB)).
func (cb *CognitiveBusService) Subscribe(msgTypes ...CognitiveMessageType) (<-chan CognitiveMessage, func()) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	ch := make(chan CognitiveMessage, cb.bufferSize)

	if len(msgTypes) == 0 {
		msgTypes = []CognitiveMessageType{""} // Empty string for "all"
	}

	subscribedTypes := make([]CognitiveMessageType, len(msgTypes))
	copy(subscribedTypes, msgTypes)

	for _, msgType := range subscribedTypes {
		cb.subscribers[msgType] = append(cb.subscribers[msgType], ch)
	}

	unsubscribe := func() {
		cb.mu.Lock()
		defer cb.mu.Unlock()

		// Removed the check for cb.isShutdown here as it caused a data race (it's protected by shutdownMu, not mu).
		// The operation is safe regardless, as Shutdown replaces the subscribers map.

		for _, msgType := range subscribedTypes {
			subs, exists := cb.subscribers[msgType]
			if !exists {
				continue
			}
			for i, subscriberCh := range subs {
				if subscriberCh == ch {
					copy(subs[i:], subs[i+1:])
					cb.subscribers[msgType] = subs[:len(subs)-1]

					if len(cb.subscribers[msgType]) == 0 {
						delete(cb.subscribers, msgType)
					}
					break
				}
			}
		}
	}

	return ch, unsubscribe
}

// Acknowledge signals that a message has been processed by a consumer.
func (cb *CognitiveBusService) Acknowledge(msg CognitiveMessage) {
	cb.processingWg.Done()
}

// Shutdown gracefully closes the bus, waiting for all messages to be acknowledged.
func (cb *CognitiveBusService) Shutdown() {
	cb.shutdownOnce.Do(func() {
		// 1. Set shutdown flag to prevent new posts from starting.
		cb.shutdownMu.Lock()
		cb.isShutdown = true
		cb.shutdownMu.Unlock()

		// 2. Signal all active Post operations to unblock and terminate.
		close(cb.shutdownChan)

		// 3. Wait for any Post calls that were in-flight to finish their logic.
		// This is now safe because close(cb.shutdownChan) will unblock them.
		cb.activePostsWg.Wait()

		// 4. Close all subscriber channels to signal consumers.
		cb.mu.Lock()
		uniqueChannels := make(map[chan CognitiveMessage]struct{})
		for _, subs := range cb.subscribers {
			for _, ch := range subs {
				uniqueChannels[ch] = struct{}{}
			}
		}
		for ch := range uniqueChannels {
			close(ch)
		}
		cb.subscribers = make(map[CognitiveMessageType][]chan CognitiveMessage)
		cb.mu.Unlock()

		// 5. Wait for any successfully delivered messages to be acknowledged.
		cb.processingWg.Wait()
	})
}
