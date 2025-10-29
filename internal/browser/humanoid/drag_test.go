// FILE: ./internal/browser/humanoid/drag_test.go
package humanoid

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Setup for drag tests (reusing behavior setup)
func setupDragTest(t *testing.T) (*Humanoid, *mockExecutor) {
	h, mock := setupBehaviorTest(t)

	// Mock geometry for start and end elements
	mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
		if selector == "#start" {
			return &schemas.ElementGeometry{
				Vertices: []float64{10, 10, 60, 10, 60, 60, 10, 60}, // Center 35, 35
				Width:    50, Height: 50, TagName: "DIV",
			}, nil
		}
		if selector == "#end" {
			return &schemas.ElementGeometry{
				Vertices: []float64{200, 200, 250, 200, 250, 250, 200, 250}, // Center 225, 225
				Width:    50, Height: 50, TagName: "DIV",
			}, nil
		}
		return nil, errors.New("element not found")
	}
	// R1: setupBehaviorTest ensures currentPos is reset via resetInteractionState,
	// but we explicitly set it here for clarity in this setup context.
	h.currentPos = Vector2D{X: 0, Y: 0}
	return h, mock
}

func TestDragAndDrop_BasicFlow(t *testing.T) {
	h, mock := setupDragTest(t)
	ctx := context.Background()

	// Test with specific options (Potential Field)
	field := NewPotentialField()
	field.AddSource(Vector2D{X: 100, Y: 100}, 10.0, 10.0)
	opts := &InteractionOptions{Field: field}

	err := h.DragAndDrop(ctx, "#start", "#end", opts)
	require.NoError(t, err)

	// Check the sequence: Move -> Press -> Drag -> Release
	pressIndex := -1
	releaseIndex := -1

	events := getMockEvents(mock)

	for i, event := range events {
		switch event.Type {
		case schemas.MousePress:
			pressIndex = i
		case schemas.MouseRelease:
			releaseIndex = i
		}
	}

	assert.NotEqual(t, -1, pressIndex)
	assert.NotEqual(t, -1, releaseIndex)

	// Verify drag movement
	for i := pressIndex + 1; i < releaseIndex; i++ {
		assert.Equal(t, schemas.MouseMove, events[i].Type)
		assert.Equal(t, int64(1), events[i].Buttons, "Button must be held during drag")
	}

	// Check final state (Locking humanoid state access)
	h.mu.Lock()
	assert.Equal(t, schemas.ButtonNone, h.currentButtonState)
	h.mu.Unlock()
}

func TestDragAndDrop_MoveToStartFails(t *testing.T) {
	h, _ := setupDragTest(t)
	ctx := context.Background()

	// Try to drag from a non-existent element
	err := h.DragAndDrop(ctx, "#nonexistent", "#end", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dragdrop: failed to move to start")
}

func TestDragAndDrop_GetEndPositionFails(t *testing.T) {
	h, mock := setupDragTest(t)
	ctx := context.Background()

	// Try to drag to a non-existent element
	err := h.DragAndDrop(ctx, "#start", "#nonexistent", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dragdrop: could not get end position geometry")

	// CRITICAL: Ensure mouse is released even if the action fails mid-way
	h.mu.Lock()
	assert.Equal(t, schemas.ButtonNone, h.currentButtonState)
	h.mu.Unlock()

	// Check that release event was dispatched
	foundRelease := false

	events := getMockEvents(mock)

	for _, event := range events {
		if event.Type == schemas.MouseRelease {
			foundRelease = true
			break
		}
	}
	assert.True(t, foundRelease)
}

func TestDragAndDrop_InvalidEndGeometry(t *testing.T) {
	h, mock := setupDragTest(t)
	ctx := context.Background()

	// Mock geometry to return invalid geometry for the end selector
	mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
		if selector == "#start" {
			return &schemas.ElementGeometry{
				Vertices: []float64{10, 10, 60, 10, 60, 60, 10, 60},
				Width:    50, Height: 50, TagName: "DIV",
			}, nil
		}
		// Invalid geometry (not enough vertices)
		// Note: getElementBoxBySelector checks this first.
		return &schemas.ElementGeometry{Vertices: []float64{1, 1}, Width: 10, Height: 10}, nil
	}

	err := h.DragAndDrop(ctx, "#start", "#end", nil)
	assert.Error(t, err)
	// The error message comes from getElementBoxBySelector
	assert.Contains(t, err.Error(), "invalid geometry (expected 8 vertices")

	// CRITICAL: Ensure mouse is released
	h.mu.Lock()
	assert.Equal(t, schemas.ButtonNone, h.currentButtonState)
	h.mu.Unlock()
}

func TestDragAndDrop_InterruptedDuringPause(t *testing.T) {
	h, mock := setupDragTest(t)
	ctx, cancel := context.WithCancel(context.Background())

	// Configure the mock Sleep to cancel the context during a pause.
	mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
		// If we detect a cognitive pause (expected > 50ms), cancel.
		if d > 50*time.Millisecond {
			cancel()
		}
		// Allow context.Background() for cleanup sleeps.
		if sleepCtx.Err() != nil && sleepCtx != context.Background() {
			return sleepCtx.Err()
		}
		// Use the standard mock implementation (via a temporary mock) to record the sleep if not cancelled.
		return (&mockExecutor{t: t}).Sleep(sleepCtx, d)
	}

	err := h.DragAndDrop(ctx, "#start", "#end", nil)
	assert.ErrorIs(t, err, context.Canceled)

	// CRITICAL: Ensure cleanup (releaseMouse) was called if the interruption happened after the press
	// Since the cancellation can happen during the very first pause (before press),
	// we only assert that the final state is clean.
	h.mu.Lock()
	assert.Equal(t, schemas.ButtonNone, h.currentButtonState)
	h.mu.Unlock()
}

// COVERAGE: Test failure during the initial MouseDown (Grab).
func TestDragAndDrop_GrabFails(t *testing.T) {
	h, mock := setupDragTest(t)
	ctx := context.Background()

	expectedErr := errors.New("grab failed")

	// Configure the mock to fail specifically on the MousePress event.
	mock.MockDispatchMouseEvent = func(ctx context.Context, data schemas.MouseEventData) error {
		if data.Type == schemas.MousePress {
			// Record the event before failing, as the default mock does.
			mock.DefaultDispatchMouseEvent(ctx, data)
			return expectedErr
		}
		return mock.DefaultDispatchMouseEvent(ctx, data)
	}

	err := h.DragAndDrop(ctx, "#start", "#end", nil)
	assert.ErrorIs(t, err, expectedErr)

	// Ensure state is clean (button not held) as the grab failed to dispatch successfully (DragAndDrop returns early).
	h.mu.Lock()
	assert.Equal(t, schemas.ButtonNone, h.currentButtonState)
	h.mu.Unlock()
}

// COVERAGE: Test interruption during the main drag movement (simulateTrajectory).
func TestDragAndDrop_InterruptedDuringDrag(t *testing.T) {
	h, mock := setupDragTest(t)
	ctx, cancel := context.WithCancel(context.Background())

	// Use atomic flag to detect when dragging starts.
	// R3: Using the "Atomic Side-Channel" pattern here for safe communication.
	var isDragging atomic.Bool
	var cancellationTriggered atomic.Bool

	// Set the flag when MousePress occurs.
	mock.MockDispatchMouseEvent = func(dispatchCtx context.Context, data schemas.MouseEventData) error {
		if data.Type == schemas.MousePress && data.Button == schemas.ButtonLeft {
			isDragging.Store(true)
		} else if data.Type == schemas.MouseRelease {
			isDragging.Store(false)
		}

		// We want to cancel during the movement phase (MouseMove events) that follows the press.
		if data.Type == schemas.MouseMove && isDragging.Load() && cancellationTriggered.CompareAndSwap(false, true) {
			cancel()
			// Return cancellation error immediately during the dispatch of the move event.
			// We must call the default handler first to ensure the event is recorded before returning the error.
			mock.DefaultDispatchMouseEvent(dispatchCtx, data)
			return context.Canceled
		}
		return mock.DefaultDispatchMouseEvent(dispatchCtx, data)
	}

	err := h.DragAndDrop(ctx, "#start", "#end", nil)
	assert.ErrorIs(t, err, context.Canceled)

	// CRITICAL: Ensure cleanup (releaseMouse) was called.
	h.mu.Lock()
	assert.Equal(t, schemas.ButtonNone, h.currentButtonState)
	h.mu.Unlock()

	// Check that the release event was dispatched.
	foundRelease := false
	events := getMockEvents(mock)
	for _, event := range events {
		if event.Type == schemas.MouseRelease {
			foundRelease = true
			break
		}
	}
	assert.True(t, foundRelease, "MouseRelease event should be dispatched during cleanup after drag interruption")
}

// COVERAGE: Test the fallback for attractionStrength calculation when FittsA is invalid.
func TestDragAndDrop_AttractionStrengthFallback(t *testing.T) {
	h, mock := setupDragTest(t)
	ctx := context.Background()

	// Configure FittsA to be invalid (<= 0) to trigger the fallback (100.0)
	h.dynamicConfig.FittsA = 0.0

	// We primarily check that it doesn't panic and completes the flow.
	err := h.DragAndDrop(ctx, "#start", "#end", nil)
	require.NoError(t, err)

	// Verify movement occurred
	events := getMockEvents(mock)
	assert.NotEmpty(t, events)
}
