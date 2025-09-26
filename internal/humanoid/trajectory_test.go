// Filename: internal/humanoid/trajectory_test.go
package humanoid

import (
	"context"
	"encoding/json"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/aquilax/go-perlin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// =============================================================================
// Test Infrastructure: Mocks and Helpers
// =============================================================================

// mockExecutor implements the new, agnostic Executor interface for testing.
type mockExecutor struct {
	dispatchedEvents []MouseEventData
	sentKeys         []string
	sleepDurations   []time.Duration
	returnErr        error
	mu               sync.Mutex

	// For advanced scenario control.
	cancelOnCall int
	failOnCall   int
	callCount    int
	cancelFunc   context.CancelFunc

	// Mocks for the new interface methods.
	MockGetElementGeometry func(ctx context.Context, selector string) (*ElementGeometry, error)
	// ADDED: Mock function for ExecuteScript
	MockExecuteScript      func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error)
}

// newMockExecutor creates a new mock executor.
func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		dispatchedEvents: make([]MouseEventData, 0),
		sentKeys:         make([]string, 0),
		sleepDurations:   make([]time.Duration, 0),
	}
}

// DispatchMouseEvent records the mouse event dispatch call using the agnostic MouseEventData.
func (m *mockExecutor) DispatchMouseEvent(ctx context.Context, data MouseEventData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	if m.returnErr != nil && m.failOnCall > 0 && m.callCount >= m.failOnCall {
		return m.returnErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	m.dispatchedEvents = append(m.dispatchedEvents, data)
	if m.cancelOnCall > 0 && len(m.dispatchedEvents) == m.cancelOnCall && m.cancelFunc != nil {
		m.cancelFunc()
	}
	return nil
}

// Sleep records the sleep duration instead of actually sleeping.
func (m *mockExecutor) Sleep(ctx context.Context, d time.Duration) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sleepDurations = append(m.sleepDurations, d)
	return nil
}

// SendKeys records the keys that were sent.
func (m *mockExecutor) SendKeys(ctx context.Context, keys string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sentKeys = append(m.sentKeys, keys)
	return nil
}

// GetElementGeometry mocks geometry retrieval using the agnostic ElementGeometry type.
func (m *mockExecutor) GetElementGeometry(ctx context.Context, selector string) (*ElementGeometry, error) {
	if m.MockGetElementGeometry != nil {
		return m.MockGetElementGeometry(ctx, selector)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Default mock behavior.
	return &ElementGeometry{
		Vertices: []float64{0, 0, 10, 0, 10, 10, 0, 10},
		Width:    10,
		Height:   10,
	}, nil
}

// ADDED: ExecuteScript method to satisfy the Executor interface.
func (m *mockExecutor) ExecuteScript(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
	if m.MockExecuteScript != nil {
		return m.MockExecuteScript(ctx, script, args)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	
	// -- Executor Best Practice Mock --
	// The scrollIterationJS is called by intelligentScroll and expects a scrollResult struct.
	if script == scrollIterationJS {
		// This simulates immediate success, which is a fine default for a mock.
		result := scrollResult{
			IsIntersecting: true,
			IsComplete:     true,
			ElementExists:  true,
		}
		// The Go side expects JSON bytes representing the JS object.
		jsonBytes, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		return jsonBytes, nil
	}
	
	// Default mock behavior for other scripts.
	return json.Marshal(map[string]interface{}{})
}


// newTestHumanoid creates a Humanoid instance with deterministic dependencies for testing.
func newTestHumanoid(executor Executor) *Humanoid {
	const seed = 12345
	config := DefaultConfig()

	// Pass the agnostic executor to the updated New function.
	h := New(config, zap.NewNop(), executor)

	rng := rand.New(rand.NewSource(seed))
	h.rng = rng
	h.noiseX = perlin.NewPerlin(2, 2, 3, seed)
	h.noiseY = perlin.NewPerlin(2, 2, 3, seed+1)
	h.dynamicConfig.FittsA = 100.0
	h.dynamicConfig.FittsB = 150.0
	h.dynamicConfig.PerlinAmplitude = 2.0
	h.dynamicConfig.GaussianStrength = 0.5

	return h
}

// floatAlmostEqual checks if two float64 values are within a tolerance.
func floatAlmostEqual(a, b, tolerance float64) bool {
	return math.Abs(a-b) <= tolerance
}

// =============================================================================
// Unit Tests
// =============================================================================

func TestComputeEaseInOutCubic(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		input    float64
		expected float64
	}{
		{0.0, 0.0},
		{0.25, 0.0625},
		{0.5, 0.5},
		{0.75, 0.9375},
		{1.0, 1.0},
	}
	for _, tc := range testCases {
		assert.True(t, floatAlmostEqual(tc.expected, computeEaseInOutCubic(tc.input), 1e-9), "ease for %.2f", tc.input)
	}
}

// =============================================================================
// Example: How to Update Your Tests
// =============================================================================

// TestSimulateTrajectory_Success demonstrates how to write a test with the new mock.
func TestSimulateTrajectory_Success(t *testing.T) {
	// 1. Setup
	mock := newMockExecutor()
	h := newTestHumanoid(mock)
	h.currentPos = Vector2D{X: 100, Y: 100}

	start := Vector2D{X: 100, Y: 100}
	end := Vector2D{X: 500, Y: 500}
	field := NewPotentialField()

	// 2. Execution
	finalVelocity, err := h.simulateTrajectory(context.Background(), start, end, field, ButtonNone)

	// 3. Assertions
	assert.NoError(t, err)
	assert.NotEmpty(t, mock.dispatchedEvents, "should have dispatched at least one mouse move event")
	assert.NotEmpty(t, mock.sleepDurations, "should have slept between movements")

	// Check the final position recorded by the humanoid.
	// It won't be exactly 'end' due to noise, but it should be very close.
	assert.InDelta(t, end.X, h.currentPos.X, 10.0, "final X position should be close to target")
	assert.InDelta(t, end.Y, h.currentPos.Y, 10.0, "final Y position should be close to target")

	// Check properties of the dispatched events.
	firstEvent := mock.dispatchedEvents[0]
	assert.Equal(t, MouseMove, firstEvent.Type)
	assert.Equal(t, ButtonNone, firstEvent.Button)
	assert.Equal(t, int64(0), firstEvent.Buttons, "no buttons should be held down")

	// Check final velocity (it will be non-zero due to momentum).
	assert.NotEqual(t, 0.0, finalVelocity.Mag(), "final velocity should be non-zero")
}

// TestSimulateTrajectory_Drag demonstrates testing a drag operation.
func TestSimulateTrajectory_Drag(t *testing.T) {
	// 1. Setup
	mock := newMockExecutor()
	h := newTestHumanoid(mock)
	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 200, Y: 200}

	// 2. Execution - Pass ButtonLeft to simulate a drag.
	_, err := h.simulateTrajectory(context.Background(), start, end, nil, ButtonLeft)

	// 3. Assertions
	assert.NoError(t, err)
	assert.NotEmpty(t, mock.dispatchedEvents)

	// CRITICAL: Check that the 'Buttons' bitfield is set correctly for dragging.
	for _, event := range mock.dispatchedEvents {
		assert.Equal(t, int64(1), event.Buttons, "left mouse button bitfield should be set on all drag events")
	}
}

// TestSimulateTrajectory_ContextCancel shows how to test for cancellation.
func TestSimulateTrajectory_ContextCancel(t *testing.T) {
	// 1. Setup
	mock := newMockExecutor()
	h := newTestHumanoid(mock)

	// Configure the mock to cancel the context after 10 mouse move events.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock.cancelFunc = cancel
	mock.cancelOnCall = 10

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 800, Y: 600} // A long move to ensure cancellation happens mid-way.
	// 2. Execution
	_, err := h.simulateTrajectory(ctx, start, end, nil, ButtonNone)

	// 3. Assertions
	assert.ErrorIs(t, err, context.Canceled, "error should be context.Canceled")
	assert.Len(t, mock.dispatchedEvents, 10, "exactly 10 events should have been dispatched before cancellation")
}