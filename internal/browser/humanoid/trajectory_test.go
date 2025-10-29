// FILE: ./internal/browser/humanoid/trajectory_test.go
package humanoid

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// =============================================================================
// Unit Tests
// Mocks are now defined in mocks_test.go
// =============================================================================

// Helper to safely access mock events (for -race detector)
func getMockEvents(mock *mockExecutor) []schemas.MouseEventData {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	events := make([]schemas.MouseEventData, len(mock.dispatchedEvents))
	copy(events, mock.dispatchedEvents)
	return events
}

func getMockSleeps(mock *mockExecutor) []time.Duration {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	sleeps := make([]time.Duration, len(mock.sleepDurations))
	copy(sleeps, mock.sleepDurations)
	return sleeps
}

// TestSimulateTrajectory_Success demonstrates how to write a test with the new mock.
func TestSimulateTrajectory_Success(t *testing.T) {
	// 1. Setup
	mock := newMockExecutor(t)
	// NewTestHumanoid ensures a valid configuration is injected.
	h := NewTestHumanoid(mock, 12345)
	h.currentPos = Vector2D{X: 100, Y: 100}

	start := Vector2D{X: 100, Y: 100}
	end := Vector2D{X: 500, Y: 500}
	field := NewPotentialField()

	// 2. Execution
	// We must lock the humanoid before calling the internal, non-locking simulation method in a test context.
	h.mu.Lock()
	finalVelocity, err := h.simulateTrajectory(context.Background(), start, end, field, schemas.ButtonNone)
	h.mu.Unlock()

	// 3. Assertions
	assert.NoError(t, err)
	events := getMockEvents(mock)
	sleeps := getMockSleeps(mock)
	assert.NotEmpty(t, events, "should have dispatched at least one mouse move event")
	assert.NotEmpty(t, sleeps, "should have slept between movements")

	// Check the final position recorded by the humanoid.
	// It won't be exactly 'end' due to noise, but it should be very close.
	assert.InDelta(t, end.X, h.currentPos.X, 10.0, "final X position should be close to target")
	assert.InDelta(t, end.Y, h.currentPos.Y, 10.0, "final Y position should be close to target")

	// Check properties of the dispatched events.
	require.NotEmpty(t, events)
	firstEvent := events[0]
	assert.Equal(t, schemas.MouseMove, firstEvent.Type)
	assert.Equal(t, schemas.ButtonNone, firstEvent.Button)
	assert.Equal(t, int64(0), firstEvent.Buttons, "no buttons should be held down")

	// Check final velocity (it will be non-zero due to momentum).
	assert.NotEqual(t, 0.0, finalVelocity.Mag(), "final velocity should be non-zero")
}

// TestSimulateTrajectory_Drag demonstrates testing a drag operation.
func TestSimulateTrajectory_Drag(t *testing.T) {
	// 1. Setup
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)
	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 200, Y: 200}

	// 2. Execution - Pass ButtonLeft to simulate a drag.
	h.mu.Lock()
	_, err := h.simulateTrajectory(context.Background(), start, end, nil, schemas.ButtonLeft)
	h.mu.Unlock()

	// 3. Assertions
	assert.NoError(t, err)
	events := getMockEvents(mock)
	assert.NotEmpty(t, events)

	// CRITICAL: Check that the 'Buttons' bitfield is set correctly for dragging.
	for _, event := range events {
		assert.Equal(t, int64(1), event.Buttons, "left mouse button bitfield should be set on all drag events")
	}
}

// TestSimulateTrajectory_ContextCancel shows how to test for cancellation.
func TestSimulateTrajectory_ContextCancel(t *testing.T) {
	// 1. Setup
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)

	// Configure the mock to cancel the context after 10 mouse move events.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mock.cancelFunc = cancel
	mock.cancelOnCall = 10

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 800, Y: 600} // A long move to ensure cancellation happens mid-way.
	// 2. Execution
	h.mu.Lock()
	_, err := h.simulateTrajectory(ctx, start, end, nil, schemas.ButtonNone)
	h.mu.Unlock()

	// 3. Assertions
	assert.ErrorIs(t, err, context.Canceled, "error should be context.Canceled")
	// It should be exactly 10 because the improved mock records the event before checking cancellation trigger.
	events := getMockEvents(mock)
	assert.Equal(t, 10, len(events), "exactly 10 events should have been dispatched before cancellation")
}

// TestSimulateTrajectory_Timeout verifies behavior when simulation exceeds MaxSimTime
func TestSimulateTrajectory_Timeout(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)

	// Configure simulation to guarantee timeout
	h.baseConfig.MaxSimTime = 10 * time.Millisecond // Very short timeout
	// FIX: Must set baseConfig, then apply
	h.baseConfig.Omega = 0.1 // Very slow movement
	h.applyCombinedEffects()

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 500, Y: 500}

	h.mu.Lock()
	_, err := h.simulateTrajectory(context.Background(), start, end, nil, schemas.ButtonNone)
	h.mu.Unlock()

	// Simulation should complete without error, but the final position will be far from the target
	assert.NoError(t, err)
	distanceToEnd := h.currentPos.Dist(end)
	assert.Greater(t, distanceToEnd, 100.0, "Should be far from target due to timeout")
}

// TestSimulateTrajectory_PotentialFieldInfluence verifies that the potential field affects the trajectory
func TestSimulateTrajectory_PotentialFieldInfluence(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)

	// FIX: Must set baseConfig, then apply
	// Disable noise for clearer results
	h.baseConfig.PinkNoiseAmplitude = 0.0
	h.baseConfig.GaussianStrength = 0.0
	h.baseConfig.SDNFactor = 0.0
	// Decrease Omega (spring strength) to make external forces more apparent
	h.baseConfig.Omega = 15.0
	h.applyCombinedEffects()

	start := Vector2D{X: 0, Y: 100}
	end := Vector2D{X: 200, Y: 100}

	// Run without field (baseline)
	h.mu.Lock()
	_, err := h.simulateTrajectory(context.Background(), start, end, nil, schemas.ButtonNone)
	h.mu.Unlock()
	require.NoError(t, err)

	baselineEvents := getMockEvents(mock)

	// Clear events for the next run (safely)
	mock.mu.Lock()
	mock.dispatchedEvents = nil
	mock.mu.Unlock()
	h.currentPos = start

	// Ensure state is reset for fair comparison
	// R1: Use standardized reset utility for behavioral state isolation.
	h.resetBehavioralState()
	/* Original manual reset removed:
	h.fatigueLevel = 0.0
	h.habituationLevel = 0.0
	h.applyCombinedEffects()
	*/

	// Run with strong repulsor field above the path
	field := NewPotentialField()
	repulsorPos := Vector2D{X: 100, Y: 50}
	// FIX: Increased strength significantly to ensure measurable deviation
	field.AddSource(repulsorPos, -50000.0, 100.0) // Negative strength for repulsion

	h.mu.Lock()
	_, err = h.simulateTrajectory(context.Background(), start, end, field, schemas.ButtonNone)
	h.mu.Unlock()
	require.NoError(t, err)
	fieldEvents := getMockEvents(mock)

	// Compare trajectories. The field trajectory should dip lower (higher Y) than the baseline.
	deviationFound := false
	// FIX: We need a better way to compare trajectories than simple indexing, as the timing might differ.
	// We iterate through the field events and find the closest corresponding baseline event by X position for comparison.
	for _, fEvent := range fieldEvents {
		// Check mid-trajectory
		if fEvent.X > 20 && fEvent.X < 180 {
			// Find closest baseline event by X
			closestBaselineY := 100.0 // Default if not found
			minDist := 1000.0
			for _, bEvent := range baselineEvents {
				dist := (bEvent.X - fEvent.X)
				if dist < 0 {
					dist = -dist
				}
				if dist < minDist {
					minDist = dist
					closestBaselineY = bEvent.Y
				}
			}

			// Check if the Y position is significantly lower (higher value) than the baseline
			if fEvent.Y > closestBaselineY+5.0 {
				deviationFound = true
				break
			}
		}
	}
	assert.True(t, deviationFound, "Trajectory should deviate due to potential field")
}

// COVERAGE: Test the Adaptive Deviation-Based Micro-Correction logic.
func TestSimulateTrajectory_MicroCorrections(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 1) // Use fixed seed for reproducibility

	// FIX: Redesigning the test methodology.
	// The previous test design assumed an underdamped MSD system (Zeta=0.2) would naturally
	// oscillate around the ideal path. This is incorrect; without external forces or noise,
	// the path is straight, the error vector is zero, and the PID controller remains inactive.
	// We must explicitly introduce deviation using a PotentialField to test the PID controller.

	// 1. Disable noise sources for deterministic comparison.
	h.baseConfig.PinkNoiseAmplitude = 0.0
	h.baseConfig.GaussianStrength = 0.0
	h.baseConfig.SDNFactor = 0.0
	// We assume AntiPeriodicityTimeJitter is 0 in the test config (defined in NewTestHumanoid).

	// 2. System dynamics. Use a standard configuration rather than an underdamped one.
	h.baseConfig.Zeta = 0.8
	h.baseConfig.Omega = 25.0 // k=625

	// 3. Ensure the threshold for corrections is active.
	h.baseConfig.MicroCorrectionThreshold = 1.0

	// Apply all baseConfig changes to dynamicConfig for the first run.
	h.applyCombinedEffects()

	// Use a simple horizontal trajectory for easy analysis.
	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 500, Y: 0}

	// Define a potential field that induces deviation.
	// We place a repulsor above the path to push the cursor down (positive Y).
	field := NewPotentialField()
	repulsorPos := Vector2D{X: 250, Y: -50} // Above the midpoint
	// Strength is tuned to cause a measurable deviation against the main spring (k=625).
	field.AddSource(repulsorPos, -200000.0, 50.0) // Negative strength for repulsion.

	// --- Run 1: With Corrections Enabled ---
	h.mu.Lock()
	// CRITICAL: We must pass the field that causes the deviation.
	_, err := h.simulateTrajectory(context.Background(), start, end, field, schemas.ButtonNone)
	h.mu.Unlock()
	require.NoError(t, err)
	correctedEvents := getMockEvents(mock)

	// Calculate the maximum deviation (Y axis) for the corrected trajectory.
	maxDeviationCorrected := 0.0
	for _, event := range correctedEvents {
		// Deviation is simply the distance from Y=0.
		if math.Abs(event.Y) > maxDeviationCorrected {
			maxDeviationCorrected = math.Abs(event.Y)
		}
	}

	// --- Reset for Baseline Run ---
	mock.mu.Lock()
	mock.dispatchedEvents = nil
	mock.mu.Unlock()
	h.currentPos = start
	h.resetRNG(1) // Use the same seed.

	// CRITICAL: Must reset behavioral state between runs.
	h.resetBehavioralState()

	// Disable micro-corrections by setting the threshold very high.
	h.baseConfig.MicroCorrectionThreshold = 10000.0
	// Re-apply config changes to dynamicConfig.
	h.applyCombinedEffects()

	// --- Run 2: Baseline (No Corrections) ---
	h.mu.Lock()
	// CRITICAL: Must pass the field here as well.
	_, err = h.simulateTrajectory(context.Background(), start, end, field, schemas.ButtonNone)
	h.mu.Unlock()
	require.NoError(t, err)
	baselineEvents := getMockEvents(mock)

	// Calculate the maximum deviation for the baseline trajectory.
	maxDeviationBaseline := 0.0
	for _, event := range baselineEvents {
		if math.Abs(event.Y) > maxDeviationBaseline {
			maxDeviationBaseline = math.Abs(event.Y)
		}
	}

	// --- Assertions ---
	// Ensure the baseline actually had deviation to correct.
	require.Greater(t, maxDeviationBaseline, 5.0, "Baseline deviation should be significant enough (>=5px) to measure correction")

	// Assertion: The trajectory with corrections must have significantly less deviation than the baseline.
	// With the tuned PID (Kp=150, Ki=15, Kd=25), the correction should be strong and stable.
	assert.Less(t, maxDeviationCorrected, maxDeviationBaseline*0.5, "Micro-corrections should significantly reduce trajectory deviation caused by external forces")
}

// TestSimulateTrajectory_DispatchError verifies that errors during event dispatch are propagated.
func TestSimulateTrajectory_DispatchError(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 100, Y: 100}

	// Configure mock to fail on the 5th call
	expectedErr := errors.New("dispatch failed")
	mock.returnErr = expectedErr
	mock.failOnCall = 5

	h.mu.Lock()
	_, err := h.simulateTrajectory(context.Background(), start, end, nil, schemas.ButtonNone)
	h.mu.Unlock()

	assert.ErrorIs(t, err, expectedErr)
	mock.mu.Lock()
	assert.Equal(t, 5, mock.callCount)
	mock.mu.Unlock()
}
