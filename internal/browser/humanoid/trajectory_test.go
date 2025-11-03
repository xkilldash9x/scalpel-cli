// FILE: ./internal/browser/humanoid/trajectory_test.go
package humanoid

import (
	"context"
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// =============================================================================
// Unit Tests
// Mocks (mockExecutor) are assumed to be defined in mocks_test.go (required for execution)
// =============================================================================

// Helper functions to safely retrieve data from the mock executor.
// Assumes the existence of a mockExecutor struct with mutex protection.
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

// TestCalculateScheduledAccelerationGains verifies the correctness of the Gain Scheduling implementation,
// including edge cases and input validation, as mandated by the research (V&V Plan: Unit Testing).
func TestCalculateScheduledAccelerationGains(t *testing.T) {
	// Constants used for verification (Must match trajectory.go):
	// TARGET_OMEGA_CL_SQUARED = 2200.0
	// TARGET_DAMPING_TERM = 100.0
	// KI_KP_RATIO = 0.1
	// TARGET_OMEGA_CL = 46.9041...

	// Standard plant damping ratio for testing.
	const zeta_p = 0.8

	testCases := []struct {
		name          string
		current_omega float64
		current_zeta  float64
		expected_kp_a float64
		expected_ki_a float64
		expected_kd_a float64
	}{
		{
			// The scenario identified in the failure report.
			name:          "Low Omega (Regression Case)",
			current_omega: 25.0,
			current_zeta:  zeta_p,
			// kp_a = 2200.0 - 25^2 = 2200.0 - 625.0 = 1575.0
			expected_kp_a: 1575.0,
			expected_ki_a: 157.5,
			// c_a_p = 2 * 0.8 * 25.0 = 40.0
			// kd_a = 100.0 - 40.0 = 60.0
			expected_kd_a: 60.0,
		},
		{
			name:          "Medium Omega",
			current_omega: 35.0,
			current_zeta:  zeta_p,
			// kp_a = 2200.0 - 35^2 = 2200.0 - 1225.0 = 975.0
			expected_kp_a: 975.0,
			expected_ki_a: 97.5,
			// c_a_p = 2 * 0.8 * 35.0 = 56.0
			// kd_a = 100.0 - 56.0 = 44.0
			expected_kd_a: 44.0,
		},
		{
			name:          "High Omega (At Target)",
			current_omega: TARGET_OMEGA_CL, // 46.9041...
			current_zeta:  zeta_p,
			// kp_a = 2200.0 - 2200.0 = 0
			expected_kp_a: 0.0,
			expected_ki_a: 0.0,
			// c_a_p = 2 * 0.8 * 46.9041575982343 = 75.04665215717488
			// kd_a = 100.0 - 75.0466... = 24.95334784282512
			// Note: Kd_a is active at the target omega due to increased TARGET_DAMPING_TERM.
			expected_kd_a: 24.95334784282512,
		},
		{
			name:          "Edge Case: Omega > Target (Kp Clamping)",
			current_omega: 50.0,
			current_zeta:  zeta_p,
			// kp_a = 2200 - 2500 = -300. Clamped to 0.
			expected_kp_a: 0.0,
			expected_ki_a: 0.0,
			// c_a_p = 80.0. kd_a = 100.0 - 80.0 = 20.0.
			expected_kd_a: 20.0,
		},
		{
			name:          "Edge Case: Omega = 0 (Max Gain)",
			current_omega: 0.0,
			current_zeta:  zeta_p,
			// kp_a = 2200. kd_a = 100.0.
			expected_kp_a: 2200.0,
			expected_ki_a: 220.0,
			expected_kd_a: 100.0,
		},
		{
			name:          "Edge Case: High Damping (Kd Clamping)",
			current_omega: 10.0,
			current_zeta:  5.1, // Increased to 5.1 to ensure clamping occurs with Damping Term = 100.0
			// kp_a = 2200 - 100 = 2100
			expected_kp_a: 2100.0,
			expected_ki_a: 210.0,
			// c_a_p = 2 * 5.1 * 10.0 = 102.0
			// kd_a = 100.0 - 102.0 = -2.0. Clamped to 0.0.
			expected_kd_a: 0.0,
		},
		{
			name:          "Robustness: Negative Inputs (Clamped to Zero)",
			current_omega: -10.0,
			current_zeta:  -1.0,
			// Inputs are clamped to 0. Behaves identically to Omega=0 case.
			expected_kp_a: 2200.0,
			expected_ki_a: 220.0,
			expected_kd_a: 100.0,
		},
		{
			name:          "Robustness: NaN Inputs (Clamped to Zero)",
			current_omega: math.NaN(),
			current_zeta:  math.NaN(),
			// Inputs are clamped to 0.
			expected_kp_a: 2200.0,
			expected_ki_a: 220.0,
			expected_kd_a: 100.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			kp_a, ki_a, kd_a := calculateScheduledAccelerationGains(tc.current_omega, tc.current_zeta)

			assert.InDelta(t, tc.expected_kp_a, kp_a, 1e-9, "Kp_a (Proportional Gain) is incorrect")
			assert.InDelta(t, tc.expected_ki_a, ki_a, 1e-9, "Ki_a (Integral Gain) is incorrect")
			assert.InDelta(t, tc.expected_kd_a, kd_a, 1e-9, "Kd_a (Derivative Gain) is incorrect")
		})
	}
}

// =============================================================================
// Integration Tests
// These tests validate the behavior of the complete simulation loop.
// =============================================================================

// TestSimulateTrajectory_Success verifies the basic functionality of the trajectory simulation.
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
	// Lock required when calling internal methods directly in tests.
	h.mu.Lock()
	finalVelocity, err := h.simulateTrajectory(context.Background(), start, end, field, schemas.ButtonNone)
	h.mu.Unlock()

	// 3. Assertions
	assert.NoError(t, err)
	events := getMockEvents(mock)
	sleeps := getMockSleeps(mock)
	assert.NotEmpty(t, events, "should have dispatched at least one mouse move event")
	assert.NotEmpty(t, sleeps, "should have slept between movements")

	// Check final position (allows tolerance due to noise and termination thresholds).
	assert.InDelta(t, end.X, h.currentPos.X, 10.0, "final X position should be close to target")
	assert.InDelta(t, end.Y, h.currentPos.Y, 10.0, "final Y position should be close to target")

	// Check event properties.
	require.NotEmpty(t, events)
	firstEvent := events[0]
	assert.Equal(t, schemas.MouseMove, firstEvent.Type)
	assert.Equal(t, schemas.ButtonNone, firstEvent.Button)
	assert.Equal(t, int64(0), firstEvent.Buttons, "no buttons should be held down")

	// Check final velocity (non-zero but below termination threshold).
	assert.NotEqual(t, 0.0, finalVelocity.Mag(), "final velocity should not be exactly zero")
}

// TestSimulateTrajectory_ZeroDistance verifies graceful handling of movements with zero distance.
func TestSimulateTrajectory_ZeroDistance(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)
	start := Vector2D{X: 100, Y: 100}

	h.mu.Lock()
	finalVelocity, err := h.simulateTrajectory(context.Background(), start, start, nil, schemas.ButtonNone)
	h.mu.Unlock()

	assert.NoError(t, err)
	assert.Equal(t, 0.0, finalVelocity.Mag(), "final velocity should be zero for zero distance move")
	events := getMockEvents(mock)
	assert.Empty(t, events, "should not dispatch events for zero distance move")
}

// TestSimulateTrajectory_Drag verifies that the correct button state is maintained during a drag.
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

	// CRITICAL: Check that the 'Buttons' bitfield is set correctly.
	for _, event := range events {
		assert.Equal(t, schemas.ButtonNone, event.Button, "Button field should be None during mousemove")
		// Left mouse button corresponds to bit 0 (value 1).
		assert.Equal(t, int64(1), event.Buttons, "left mouse button bitfield (1) should be set on all drag events")
	}
}

// TestSimulateTrajectory_ContextCancel verifies that the simulation aborts correctly when the context is canceled.
func TestSimulateTrajectory_ContextCancel(t *testing.T) {
	// 1. Setup
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)

	// Configure the mock to cancel the context after 10 events.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Assumes mockExecutor has fields to inject this behavior.
	mock.cancelFunc = cancel
	mock.cancelOnCall = 10

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 800, Y: 600} // Long move ensures cancellation mid-way.
	// 2. Execution
	h.mu.Lock()
	_, err := h.simulateTrajectory(ctx, start, end, nil, schemas.ButtonNone)
	h.mu.Unlock()

	// 3. Assertions
	assert.ErrorIs(t, err, context.Canceled, "error should be context.Canceled")
	events := getMockEvents(mock)
	// It should be exactly 10 assuming the mock records the event before triggering the cancellation.
	assert.Equal(t, 10, len(events), "exactly 10 events should have been dispatched before cancellation")
}

// TestSimulateTrajectory_Timeout verifies behavior when the simulation exceeds MaxSimTime.
func TestSimulateTrajectory_Timeout(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)

	// Configure parameters to guarantee a timeout.
	h.baseConfig.MaxSimTime = 10 * time.Millisecond // Very short timeout
	h.baseConfig.Omega = 0.1                        // Very slow movement (low stiffness)
	h.applyCombinedEffects()

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 500, Y: 500}

	h.mu.Lock()
	_, err := h.simulateTrajectory(context.Background(), start, end, nil, schemas.ButtonNone)
	h.mu.Unlock()

	// Simulation should complete without error (timeout is logged but not returned as an error),
	// but the final position will be far from the target.
	assert.NoError(t, err)
	distanceToEnd := h.currentPos.Dist(end)
	assert.Greater(t, distanceToEnd, 100.0, "Should be far from target due to timeout")
}

// TestSimulateTrajectory_DispatchError verifies that errors during event dispatch are propagated.
func TestSimulateTrajectory_DispatchError(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 100, Y: 100}

	// Configure mock to fail on the 5th call.
	expectedErr := errors.New("dispatch failed")
	// Assumes mockExecutor has fields to inject this behavior.
	mock.returnErr = expectedErr
	mock.failOnCall = 5

	h.mu.Lock()
	_, err := h.simulateTrajectory(context.Background(), start, end, nil, schemas.ButtonNone)
	h.mu.Unlock()

	assert.ErrorIs(t, err, expectedErr)
	mock.mu.Lock()
	// Assumes mockExecutor tracks callCount.
	assert.Equal(t, 5, mock.callCount)
	mock.mu.Unlock()
}

// =============================================================================
// Gain Scheduling Validation Suite
// These tests implement the Validation and Verification (V&V) Plan from the research document.
// =============================================================================

// TestGainScheduling_Regression_LowOmegaDisturbance (V&V Plan: Regression Test)
// Validates that the Gain Scheduling implementation successfully corrects the trajectory
// under the original failure conditions (low plant stiffness omega_p=25.0, strong disturbance).
func TestGainScheduling_Regression_LowOmegaDisturbance(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 1) // Use fixed seed for reproducibility

	// 1. Disable noise sources for deterministic comparison.
	h.baseConfig.PinkNoiseAmplitude = 0.0
	h.baseConfig.GaussianStrength = 0.0
	h.baseConfig.SDNFactor = 0.0

	// 2. System dynamics: Set to the failing condition from the report.
	h.baseConfig.Zeta = 0.8   // zeta_p
	h.baseConfig.Omega = 25.0 // omega_p (Low stiffness / Highly compliant)

	// 3. Ensure corrections are active.
	h.baseConfig.MicroCorrectionThreshold = 1.0
	h.applyCombinedEffects()

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 500, Y: 0} // Horizontal movement

	// 4. Define the strong external disturbance (repulsor force).
	field := NewPotentialField()
	repulsorPos := Vector2D{X: 250, Y: -50}
	// The strength (-200000.0) represents an external acceleration (a_ext = F_ext / m).
	field.AddSource(repulsorPos, -200000.0, 50.0)

	// --- Run 1: With Corrections Enabled (Gain Scheduling Active) ---
	h.mu.Lock()
	_, err := h.simulateTrajectory(context.Background(), start, end, field, schemas.ButtonNone)
	h.mu.Unlock()
	require.NoError(t, err)
	correctedEvents := getMockEvents(mock)

	// Calculate maximum deviation.
	maxDeviationCorrected := 0.0
	for _, event := range correctedEvents {
		// Deviation is distance from Y=0.
		if math.Abs(event.Y) > maxDeviationCorrected {
			maxDeviationCorrected = math.Abs(event.Y)
		}
	}

	// --- Reset for Baseline Run ---
	// Reset mock state (assuming mockExecutor fields are cleared).
	mock.mu.Lock()
	mock.dispatchedEvents = nil
	mock.sleepDurations = nil
	mock.callCount = 0
	mock.mu.Unlock()

	h.currentPos = start
	h.resetRNG(1)
	h.resetBehavioralState()

	// Disable micro-corrections by setting the threshold very high.
	h.baseConfig.MicroCorrectionThreshold = 10000.0
	h.applyCombinedEffects()

	// --- Run 2: Baseline (No Corrections) ---
	h.mu.Lock()
	_, err = h.simulateTrajectory(context.Background(), start, end, field, schemas.ButtonNone)
	h.mu.Unlock()
	require.NoError(t, err)
	baselineEvents := getMockEvents(mock)

	// Calculate maximum deviation.
	maxDeviationBaseline := 0.0
	for _, event := range baselineEvents {
		if math.Abs(event.Y) > maxDeviationBaseline {
			maxDeviationBaseline = math.Abs(event.Y)
		}
	}

	// --- Assertions ---
	t.Logf("Max Deviation (Baseline): %.2f", maxDeviationBaseline)
	t.Logf("Max Deviation (Corrected): %.2f", maxDeviationCorrected)

	// Validate test setup: Baseline deviation must be significant (Reported as 31.46).
	require.Greater(t, maxDeviationBaseline, 30.0, "Baseline deviation should be very large without corrections")

	// Primary Assertion: Corrected deviation must be below the required threshold (15.73) and significantly reduced.
	assert.Less(t, maxDeviationCorrected, 15.0, "Corrected deviation must be below the required performance threshold (15.0)")
	assert.Less(t, maxDeviationCorrected, maxDeviationBaseline*0.5, "Gain scheduling should reduce deviation by at least 50%")
}

// TestGainScheduling_OmegaSweep_ConsistentPerformance (V&V Plan: Omega Sweep Performance Test)
// Verifies the primary goal of Gain Scheduling: consistent performance despite varying plant dynamics.
// It asserts that the corrected deviation remains within a "tight, consistent tolerance band" when the scheduler is active.
func TestGainScheduling_OmegaSweep_ConsistentPerformance(t *testing.T) {
	// Define the constant disturbance field.
	field := NewPotentialField()
	repulsorPos := Vector2D{X: 250, Y: -50}
	field.AddSource(repulsorPos, -200000.0, 50.0)

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 500, Y: 0}

	const zeta_p = 0.8
	// TARGET_OMEGA_CL is 46.90.
	// Define the sweep range, covering the spectrum relative to the target.
	testCases := []struct {
		name  string
		omega float64
	}{
		// Active Range (omega_p < omega_cl, Kp_a > 0). Performance should be consistent.
		{name: "Active (Low)", omega: 25.0},
		{name: "Active (Medium)", omega: 35.0},
		// Adjusted test cases to reflect the TARGET_OMEGA_CL (46.90)
		{name: "Active (Near Target)", omega: 46.0},
		// Inactive Range (omega_p >= omega_cl, Kp_a = 0).
		// Performance depends on plant stiffness.
		{name: "Inactive (Above Target)", omega: 48.0},
		{name: "Inactive (High Stiffness)", omega: 60.0},
	}

	var results []float64
	var activeResults []float64 // Stores results where omega_p < omega_cl

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_omega=%.1f", tc.name, tc.omega), func(t *testing.T) {
			mock := newMockExecutor(t)
			h := NewTestHumanoid(mock, 1) // Fixed seed

			// Disable noise, enable corrections.
			h.baseConfig.PinkNoiseAmplitude = 0.0
			h.baseConfig.GaussianStrength = 0.0
			h.baseConfig.SDNFactor = 0.0
			h.baseConfig.MicroCorrectionThreshold = 1.0

			// Set plant dynamics.
			h.baseConfig.Omega = tc.omega
			h.baseConfig.Zeta = zeta_p
			h.applyCombinedEffects()

			// Execute simulation
			h.mu.Lock()
			_, err := h.simulateTrajectory(context.Background(), start, end, field, schemas.ButtonNone)
			h.mu.Unlock()
			require.NoError(t, err)

			// Analyze result
			events := getMockEvents(mock)
			maxDeviation := 0.0
			for _, event := range events {
				if math.Abs(event.Y) > maxDeviation {
					maxDeviation = math.Abs(event.Y)
				}
			}

			// General assertion: Deviation must be controlled and
			// stable (below baseline of ~31.46).
			// Furthermore, with these tuned parameters, it should be below 15.0 across the tested range.
			assert.Less(t, maxDeviation, 15.0,
				"Max deviation (%.2f) should remain stable and below the performance threshold.", maxDeviation)

			results = append(results, maxDeviation)
			if tc.omega < TARGET_OMEGA_CL {
				activeResults = append(activeResults, maxDeviation)
			}
		})
	}

	// --- Consistency Analysis ---
	require.NotEmpty(t, activeResults, "Should have results for the active range")

	// Analyze consistency in the active range (where Kp_a > 0).
	// Control theory dictates that if omega_cl is held constant by the scheduler, performance should be consistent.
	if len(activeResults) > 0 {
		minDev := activeResults[0]
		maxDev := activeResults[0]
		for _, r := range activeResults[1:] {
			if r < minDev {
				minDev = r
			}
			if r > maxDev {
				maxDev = r
			}
		}

		// Use the constant dynamically for logging the boundary.
		t.Logf("Active Range Deviation (omega < %.2f): [%.2f, %.2f]", TARGET_OMEGA_CL, minDev, maxDev)

		// Assert that the variance is small ("tight, consistent tolerance band").
		assert.Less(t, maxDev-minDev, 5.0, "The variance in deviation should be small (<5.0), indicating consistency")
	}

	// Analyze behavior in the inactive range (where Kp_a = 0).
	if len(results) > len(activeResults) {
		// Calculate the slice of inactive results
		inactiveStartIdx := len(activeResults)
		inactiveResults := results[inactiveStartIdx:]

		// Use the constant dynamically for logging the boundary.
		t.Logf("Inactive Range Deviation (omega >= %.2f): %v", TARGET_OMEGA_CL, inactiveResults)
		// In this range, the controller is off (Kp_a=0).
		// Deviation should decrease as omega_p increases (plant gets inherently stiffer).
		if len(inactiveResults) >= 2 {
			// Check that the trend is strictly decreasing.
			isDecreasing := true
			for i := 0; i < len(inactiveResults)-1; i++ {
				// Allow a tiny tolerance for floating point variations
				if inactiveResults[i+1] > inactiveResults[i]+1e-9 {
					isDecreasing = false
					break
				}
			}
			// Note: Although Kp_a=0, Kd_a might still be active due to the high TARGET_DAMPING_TERM (100.0).
			// However, the overall trend should still be decreasing as inherent plant stiffness (omega_p^2) dominates.
			assert.True(t, isDecreasing, "Deviation should decrease as plant stiffness increases when Kp=0")
		}
	}
}

// TestGainScheduling_HighOmega_Stability (V&V Plan: High-Omega Stability Test)
// Verifies the system's stability when the plant dynamics (omega_p) equal the target (omega_cl).
// In this regime, Kp_a and Ki_a are zero. The test ensures smooth settling without excessive oscillation or overshoot.
func TestGainScheduling_HighOmega_Stability(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 1) // Fixed seed

	// 1. Disable noise and disturbances.
	h.baseConfig.PinkNoiseAmplitude = 0.0
	h.baseConfig.GaussianStrength = 0.0
	h.baseConfig.SDNFactor = 0.0
	h.baseConfig.MicroCorrectionThreshold = 1.0

	// 2. Set omega_p to the target omega_cl.
	h.baseConfig.Omega = TARGET_OMEGA_CL
	h.baseConfig.Zeta = 0.8
	h.applyCombinedEffects()

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 500, Y: 0}

	// 3. Execute with no potential field (no external disturbance).
	h.mu.Lock()
	_, err := h.simulateTrajectory(context.Background(), start, end, nil, schemas.ButtonNone)
	h.mu.Unlock()
	require.NoError(t, err)

	// 4. Analyze and assert.
	events := getMockEvents(mock)
	maxLateralDeviation := 0.0
	maxOvershootX := 0.0

	for _, event := range events {
		// Lateral deviation (Y axis).
		deviation := math.Abs(event.Y)
		if deviation > maxLateralDeviation {
			maxLateralDeviation = deviation
		}
		// Overshoot past the target (X axis).
		if event.X > end.X {
			overshoot := event.X - end.X
			if overshoot > maxOvershootX {
				maxOvershootX = overshoot
			}
		}
	}

	t.Logf("High Omega Stability: Max Lateral Deviation: %.2f, Max Overshoot X: %.2f", maxLateralDeviation, maxOvershootX)

	// The path should be almost perfectly straight as the PID controller is inactive (zero Kp/Ki) and there are no disturbances.
	// (Kd_a is active but only opposes error velocity).
	assert.Less(t, maxLateralDeviation, 0.1, "With zero scheduled Kp/Ki gain and no disturbances, lateral deviation should be negligible")

	// Ensure the system does not exhibit excessive overshoot, indicating good damping (zeta_cl ≈ 1.07).
	assert.Less(t, maxOvershootX, 5.0, "Overshoot at the target should be minimal (<5.0 pixels), indicating stability.")
}
