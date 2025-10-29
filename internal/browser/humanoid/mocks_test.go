// FILE: ./internal/browser/humanoid/mocks_test.go
package humanoid

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// mockExecutor implements the agnostic Executor interface for testing.
// This is centralized here to be reusable across all tests in the package.
type mockExecutor struct {
	t                *testing.T
	dispatchedEvents []schemas.MouseEventData
	sentKeys         []string
	structuredKeys   []schemas.KeyEventData // Added for shortcut testing
	sleepDurations   []time.Duration
	returnErr        error
	mu               sync.Mutex

	// For advanced scenario control.
	cancelOnCall int
	failOnCall   int
	callCount    int
	cancelFunc   context.CancelFunc

	// Function overrides for specific behaviors.
	// R3: Formalize the "Atomic Side-Channel" Pattern.
	// Architectural Guideline: Mock implementations MUST NOT attempt to acquire the Humanoid mutex (h.mu)
	// or directly access Humanoid's internal state (e.g., h.currentButtonState) if the mock is called
	// by a Humanoid method that already holds h.mu. Doing so will cause a deadlock.
	//
	// Communication between the mock and the test goroutine must occur via "Side-Channels":
	// 1. Lock-free primitives (e.g., sync/atomic variables) managed by the test function.
	// 2. Context cancellation (cancel()).
	//
	// If set, these replace the default behavior. The override can call the corresponding
	// Default* method (e.g., DefaultDispatchMouseEvent) if the default logic is still required.
	MockGetElementGeometry    func(ctx context.Context, selector string) (*schemas.ElementGeometry, error)
	MockExecuteScript         func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error)
	MockSleep                 func(ctx context.Context, d time.Duration) error
	MockDispatchMouseEvent    func(ctx context.Context, data schemas.MouseEventData) error
	MockSendKeys              func(ctx context.Context, keys string) error
	MockDispatchStructuredKey func(ctx context.Context, data schemas.KeyEventData) error // Added for shortcut testing
}

// newMockExecutor creates a new mock executor.
func newMockExecutor(t *testing.T) *mockExecutor {
	m := &mockExecutor{
		t:                t,
		dispatchedEvents: make([]schemas.MouseEventData, 0),
		sentKeys:         make([]string, 0),
		structuredKeys:   make([]schemas.KeyEventData, 0), // Init new field
		sleepDurations:   make([]time.Duration, 0),
	}
	return m
}

// DispatchMouseEvent handles mouse events, checking for overrides first.
func (m *mockExecutor) DispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	// REFACTOR: Check for override first.
	if m.MockDispatchMouseEvent != nil {
		return m.MockDispatchMouseEvent(ctx, data)
	}
	return m.DefaultDispatchMouseEvent(ctx, data)
}

// DefaultDispatchMouseEvent is the standard mock behavior for DispatchMouseEvent.
// This allows overrides to call the standard behavior.
func (m *mockExecutor) DefaultDispatchMouseEvent(ctx context.Context, data schemas.MouseEventData) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// FIX: Always record the event first. This is crucial for cleanup actions (like releaseMouse)
	// which might be called with context.Background() after a failure.
	m.dispatchedEvents = append(m.dispatchedEvents, data)
	m.callCount++

	// Check for forced failure
	if m.returnErr != nil && (m.failOnCall == 0 || m.callCount >= m.failOnCall) {
		return m.returnErr
	}

	// FIX: Check context cancellation, but allow context.Background() (used for cleanup).
	if ctx.Err() != nil && ctx != context.Background() {
		return ctx.Err()
	}

	// Check for forced cancellation trigger
	if m.cancelOnCall > 0 && m.callCount == m.cancelOnCall && m.cancelFunc != nil {
		m.cancelFunc()
	}
	return nil
}

// Sleep handles sleep requests, checking for overrides first.
func (m *mockExecutor) Sleep(ctx context.Context, d time.Duration) error {
	// Allow overriding behavior for complex tests (like interruption tests)
	if m.MockSleep != nil {
		return m.MockSleep(ctx, d)
	}
	return m.DefaultSleep(ctx, d)
}

// DefaultSleep is the standard mock behavior for Sleep.
// This allows overrides to call the standard behavior without recursion.
func (m *mockExecutor) DefaultSleep(ctx context.Context, d time.Duration) error {
	// FIX: Check context cancellation, but allow context.Background().
	if ctx.Err() != nil && ctx != context.Background() {
		return ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sleepDurations = append(m.sleepDurations, d)
	return nil
}

// SendKeys records the keys that were sent.
func (m *mockExecutor) SendKeys(ctx context.Context, keys string) error {
	// COVERAGE: Check for override first.
	if m.MockSendKeys != nil {
		return m.MockSendKeys(ctx, keys)
	}
	return m.DefaultSendKeys(ctx, keys)
}

// DefaultSendKeys is the standard mock behavior for SendKeys.
func (m *mockExecutor) DefaultSendKeys(ctx context.Context, keys string) error {
	// FIX: Check context cancellation, but allow context.Background().
	if ctx.Err() != nil && ctx != context.Background() {
		return ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check for forced failure (using failOnCall=0 for simplicity here, as callCount isn't tracked for keys)
	if m.returnErr != nil && m.failOnCall == 0 {
		// Record the key attempt before failing
		m.sentKeys = append(m.sentKeys, keys)
		return m.returnErr
	}

	m.sentKeys = append(m.sentKeys, keys)
	return nil
}

// DispatchStructuredKey handles structured key events, checking for overrides first.
func (m *mockExecutor) DispatchStructuredKey(ctx context.Context, data schemas.KeyEventData) error {
	if m.MockDispatchStructuredKey != nil {
		return m.MockDispatchStructuredKey(ctx, data)
	}
	return m.DefaultDispatchStructuredKey(ctx, data)
}

// DefaultDispatchStructuredKey is the standard mock behavior for DispatchStructuredKey.
func (m *mockExecutor) DefaultDispatchStructuredKey(ctx context.Context, data schemas.KeyEventData) error {
	if ctx.Err() != nil && ctx != context.Background() {
		return ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.returnErr != nil && m.failOnCall == 0 {
		return m.returnErr
	}

	m.structuredKeys = append(m.structuredKeys, data)
	return nil
}

// GetElementGeometry mocks geometry retrieval.
func (m *mockExecutor) GetElementGeometry(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	if m.MockGetElementGeometry != nil {
		return m.MockGetElementGeometry(ctx, selector)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Global error check (only if failOnCall is 0, as callCount isn't tracked here)
	m.mu.Lock()
	if m.returnErr != nil && m.failOnCall == 0 {
		m.mu.Unlock()
		return nil, m.returnErr
	}
	m.mu.Unlock()

	// Default mock behavior: A 10x10 box at (0,0).
	return &schemas.ElementGeometry{
		Vertices: []float64{0, 0, 10, 0, 10, 10, 0, 10},
		Width:    10,
		Height:   10,
		TagName:  "DIV",
	}, nil
}

// ExecuteScript mocks script execution.
func (m *mockExecutor) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	if m.MockExecuteScript != nil {
		return m.MockExecuteScript(ctx, script, args)
	}
	return m.DefaultExecuteScript(ctx, script, args)
}

// DefaultExecuteScript is the standard mock behavior for ExecuteScript.
func (m *mockExecutor) DefaultExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Global error check (only if failOnCall is 0)
	m.mu.Lock()
	if m.returnErr != nil && m.failOnCall == 0 {
		m.mu.Unlock()
		return nil, m.returnErr
	}
	m.mu.Unlock()

	// Default mock behavior for scrolling script
	if script == scrollIterationJS {
		// Simulate immediate success.
		result := scrollResult{
			IsIntersecting: true,
			IsComplete:     true,
			ElementExists:  true,
		}
		jsonBytes, err := json.Marshal(result)
		if err != nil {
			if m.t != nil {
				m.t.Fatalf("Failed to marshal default mock scroll result: %v", err)
			}
			return nil, err
		}
		return jsonBytes, nil
	}

	// Default mock behavior for other scripts.
	return json.Marshal(map[string]interface{}{})
}
