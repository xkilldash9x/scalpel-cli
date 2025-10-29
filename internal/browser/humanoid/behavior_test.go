// FILE: ./internal/browser/humanoid/behavior_test.go
package humanoid

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Setup a Humanoid instance configured for behavior testing.
func setupBehaviorTest(t *testing.T) (*Humanoid, *mockExecutor) {
	mock := newMockExecutor(t)
	// Use NewTestHumanoid for deterministic RNG (seed 12345)
	h := NewTestHumanoid(mock, 12345)

	// R1: Ensure state is clean before configuration. NewTestHumanoid initializes state,
	// but explicitly calling reset functions reinforces the pattern, ensuring isolation
	// if this setup function were to be reused in complex scenarios.
	h.mu.Lock()
	h.resetBehavioralState()
	h.resetInteractionState()
	h.mu.Unlock()

	// Configure behavioral parameters
	h.baseConfig.FatigueIncreaseRate = 0.1
	h.baseConfig.FatigueRecoveryRate = 0.05
	h.baseConfig.HabituationRate = 0.05

	h.baseConfig.GaussianStrength = 1.0
	h.baseConfig.ClickNoise = 2.0

	// Configure Ex-Gaussian parameters
	h.baseConfig.ExGaussianMu = 100.0
	h.baseConfig.ExGaussianTau = 50.0
	h.baseConfig.TaskSwitchMu = 50.0

	// Ensure cognitivePause uses Sleep instead of Hesitate for easier testing initially
	h.baseConfig.AntiPeriodicityMinPause = 5000 * time.Millisecond

	// Sync dynamic config
	h.dynamicConfig = h.baseConfig

	return h, mock
}

func TestRandExGaussian(t *testing.T) {
	h, _ := setupBehaviorTest(t)

	// Test standard parameters
	val := h.randExGaussian(100.0, 10.0, 50.0)
	assert.Greater(t, val, 0.0)

	// Test edge cases (zero/negative inputs)
	val = h.randExGaussian(0, -1, 0)
	assert.Greater(t, val, 0.0, "Should handle zero/negative inputs gracefully")
}

func TestCognitivePause_Basic(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	ctx := context.Background()

	// Expected mean duration: Mu + Tau = 150ms
	err := h.CognitivePause(ctx, 1.0, 1.0)
	assert.NoError(t, err)

	sleeps := getMockSleeps(mock)
	require.Len(t, sleeps, 1)
	// Check action type update
	assert.Equal(t, ActionTypePause, h.lastActionType)
}

// COVERAGE: Test the minimum duration clamping logic in cognitivePause.
func TestCognitivePause_MinDurationClamp(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	ctx := context.Background()

	// Configure parameters to guarantee a duration < 10ms.
	h.baseConfig.ExGaussianMu = 1.0
	h.baseConfig.ExGaussianSigma = 0.0
	h.baseConfig.ExGaussianTau = 1.0
	h.applyCombinedEffects()

	// Ensure hesitation is not triggered
	h.baseConfig.AntiPeriodicityMinPause = 5000 * time.Millisecond

	// Use fixed seed that results in near-zero exponential component.
	h.resetRNG(1)

	// cognitivePause implementation checks if durationMs < 10.0 and resets it.
	err := h.CognitivePause(ctx, 1.0, 1.0)
	assert.NoError(t, err)

	sleeps := getMockSleeps(mock)
	require.Len(t, sleeps, 1)
	// The duration should be clamped to the range [10ms, 15ms].
	assert.GreaterOrEqual(t, sleeps[0], 10*time.Millisecond)
	assert.LessOrEqual(t, sleeps[0], 15*time.Millisecond)
}

func TestCognitivePause_TaskSwitching(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	ctx := context.Background()

	// Set previous action type
	h.lastActionType = ActionTypeMove

	// Execute pause (triggers task switch from MOVE to PAUSE)
	err := h.CognitivePause(ctx, 1.0, 1.0)
	assert.NoError(t, err)

	duration1 := getMockSleeps(mock)[0]

	// Execute pause again (No switch)
	mock.mu.Lock()
	mock.sleepDurations = nil
	mock.mu.Unlock()

	err = h.CognitivePause(ctx, 1.0, 1.0)
	assert.NoError(t, err)
	duration2 := getMockSleeps(mock)[0]

	assert.Greater(t, duration1, duration2, "Duration should be longer when task switching occurs")
}

func TestCognitivePause_HesitationTriggered(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	ctx := context.Background()

	// Lower the threshold to trigger hesitation
	h.baseConfig.AntiPeriodicityMinPause = 10 * time.Millisecond // Low threshold

	// Use scales that likely result in a pause > 10ms
	err := h.CognitivePause(ctx, 0.5, 0.5)
	assert.NoError(t, err)

	sleeps := getMockSleeps(mock)
	events := getMockEvents(mock)

	// Hesitation involves multiple sleeps and mouse movements
	assert.Greater(t, len(sleeps), 1)
	assert.NotEmpty(t, events)
}

func TestHesitate(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	ctx := context.Background()

	startPos := Vector2D{X: 100, Y: 100}
	h.currentPos = startPos
	duration := 50 * time.Millisecond

	// Test while dragging (button held)
	h.currentButtonState = schemas.ButtonLeft

	err := h.Hesitate(ctx, duration)
	assert.NoError(t, err)

	// Check drift
	endPos := h.currentPos
	assert.NotEqual(t, startPos, endPos)

	events := getMockEvents(mock)
	// Check event properties
	for _, event := range events {
		assert.Equal(t, schemas.MouseMove, event.Type)
		assert.Equal(t, int64(1), event.Buttons, "Button state must be maintained during hesitation")
	}
}

// COVERAGE: Test the duration clamping logic within hesitate.
func TestHesitate_DurationClamping(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	ctx := context.Background()

	// Configure a very large TimeStep and Jitter to force the clamping logic.
	h.baseConfig.TimeStep = 100 * time.Millisecond
	h.baseConfig.AntiPeriodicityTimeJitter = 50 * time.Millisecond

	// Total duration is short.
	duration := 50 * time.Millisecond

	err := h.Hesitate(ctx, duration)
	assert.NoError(t, err)

	sleeps := getMockSleeps(mock)
	// Should have at least one sleep, clamped to the remaining duration (approx 50ms).
	require.NotEmpty(t, sleeps)

	// The actual sleep duration might be slightly less than 50ms due to time elapsed before the sleep call,
	// but it should be close and certainly less than the base TimeStep (100ms).
	// We check the last sleep as that's where clamping occurs.
	lastSleep := sleeps[len(sleeps)-1]
	assert.Less(t, lastSleep, 51*time.Millisecond)
	// Ensure it's positive if it wasn't exactly 0ms remaining.
	if lastSleep < 0 {
		assert.Fail(t, "Pause duration should not be negative before sleep", "Duration: %v", lastSleep)
	}
}

// COVERAGE: Test context cancellation during hesitation.
func TestHesitate_Cancellation(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	// Ensure TimeStep is small enough to require multiple iterations
	h.baseConfig.TimeStep = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())

	duration := 500 * time.Millisecond

	// Configure mock Sleep to cancel context mid-hesitation
	// R3: Using atomic counter as a side-channel for coordination.
	var sleepCount int32
	mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
		// Cancel on the 5th sleep iteration
		if atomic.AddInt32(&sleepCount, 1) == 5 {
			cancel()
		}
		// DefaultSleep handles the actual context check
		return mock.DefaultSleep(sleepCtx, d)
	}

	err := h.Hesitate(ctx, duration)
	assert.ErrorIs(t, err, context.Canceled)
}

// COVERAGE: Test failure during hesitate dispatch.
func TestHesitate_DispatchError(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	ctx := context.Background()
	h.baseConfig.TimeStep = 10 * time.Millisecond

	// Configure mock to fail on dispatch
	expectedErr := errors.New("dispatch failed")
	mock.MockDispatchMouseEvent = func(dispatchCtx context.Context, data schemas.MouseEventData) error {
		return expectedErr
	}

	err := h.Hesitate(ctx, 100*time.Millisecond)
	assert.ErrorIs(t, err, expectedErr)
}

// COVERAGE: Test failure during executor.Sleep within hesitate (non-context error).
func TestHesitate_SleepError(t *testing.T) {
	h, mock := setupBehaviorTest(t)
	ctx := context.Background()
	h.baseConfig.TimeStep = 10 * time.Millisecond

	expectedErr := errors.New("sleep failed unexpectedly")

	// Configure mock Sleep to return a specific non-context error.
	mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
		// Ensure we don't return a context error if the context is fine.
		if sleepCtx.Err() == nil {
			return expectedErr
		}
		return mock.DefaultSleep(sleepCtx, d)
	}

	err := h.Hesitate(ctx, 100*time.Millisecond)
	// The specific error from Sleep should be propagated.
	assert.ErrorIs(t, err, expectedErr)
}

func TestApplyNoiseFunctions(t *testing.T) {
	h, _ := setupBehaviorTest(t)
	point := Vector2D{X: 50, Y: 50}

	// Gaussian Noise
	noisyPoint := h.applyGaussianNoise(point)
	assert.NotEqual(t, point, noisyPoint)

	// Click Noise
	clickPoint := h.applyClickNoise(point)
	assert.NotEqual(t, point, clickPoint)
	// Click noise has a downward bias (Y increases)
	assert.GreaterOrEqual(t, clickPoint.Y, point.Y)
}

// COVERAGE: Detailed test for the logic within applyCombinedEffects.
func TestApplyCombinedEffects_Detailed(t *testing.T) {
	h, _ := setupBehaviorTest(t)

	// Set distinct baseline values for comparison
	h.baseConfig.FittsA = 100.0
	h.baseConfig.Omega = 30.0
	h.baseConfig.Zeta = 0.8
	h.baseConfig.GaussianStrength = 1.0
	h.baseConfig.PinkNoiseAmplitude = 2.0
	h.baseConfig.ClickNoise = 1.5
	h.baseConfig.SDNFactor = 0.001
	h.baseConfig.ExGaussianMu = 150.0
	h.baseConfig.ExGaussianTau = 50.0
	h.baseConfig.TypoRate = 0.05

	// Baseline check (Fatigue 0, Habituation 0)
	h.fatigueLevel = 0.0
	h.habituationLevel = 0.0
	h.applyCombinedEffects()
	assert.Equal(t, h.baseConfig.Omega, h.dynamicConfig.Omega)
	assert.Equal(t, h.baseConfig.GaussianStrength, h.dynamicConfig.GaussianStrength)
	assert.Equal(t, h.baseConfig.FittsA, h.dynamicConfig.FittsA)

	// High Fatigue, Low Habituation (Net Impairment = 0.8)
	h.fatigueLevel = 1.0
	h.habituationLevel = 0.2
	netImpairment := 0.8
	impairmentFactor := 1.0 + netImpairment

	h.applyCombinedEffects()

	// Check Noise Increase (Factor 1.8)
	assert.InDelta(t, h.baseConfig.GaussianStrength*impairmentFactor, h.dynamicConfig.GaussianStrength, 1e-9)
	assert.InDelta(t, h.baseConfig.PinkNoiseAmplitude*impairmentFactor, h.dynamicConfig.PinkNoiseAmplitude, 1e-9)
	assert.InDelta(t, h.baseConfig.ClickNoise*impairmentFactor, h.dynamicConfig.ClickNoise, 1e-9)
	assert.InDelta(t, h.baseConfig.SDNFactor*impairmentFactor, h.dynamicConfig.SDNFactor, 1e-9)

	// Check Reaction Time Increase (Factor 1.8 for Mu, higher for Tau)
	assert.InDelta(t, h.baseConfig.FittsA*impairmentFactor, h.dynamicConfig.FittsA, 1e-9)
	assert.InDelta(t, h.baseConfig.ExGaussianMu*impairmentFactor, h.dynamicConfig.ExGaussianMu, 1e-9)
	// Tau factor: (1.0 + netImpairment*1.5) = 1.0 + 1.2 = 2.2
	assert.InDelta(t, h.baseConfig.ExGaussianTau*(1.0+netImpairment*1.5), h.dynamicConfig.ExGaussianTau, 1e-9)

	// Check Motor Control Decrease
	// Omega factor: (1.0 - netImpairment*0.3) = 1.0 - 0.24 = 0.76
	assert.InDelta(t, h.baseConfig.Omega*(1.0-netImpairment*0.3), h.dynamicConfig.Omega, 1e-9)
	// Zeta factor: (1.0 - netImpairment*0.1) = 1.0 - 0.08 = 0.92
	assert.InDelta(t, h.baseConfig.Zeta*(1.0-netImpairment*0.1), h.dynamicConfig.Zeta, 1e-9)

	// Check Typo Rate Increase
	// Typo factor: (1.0 + netImpairment*2.0) = 1.0 + 1.6 = 2.6
	expectedTypoRate := h.baseConfig.TypoRate * (1.0 + netImpairment*2.0)
	// Apply cap if base rate is realistic
	if h.baseConfig.TypoRate <= 1.0 {
		expectedTypoRate = math.Min(0.25, expectedTypoRate)
	}
	assert.InDelta(t, expectedTypoRate, h.dynamicConfig.TypoRate, 1e-9)

	// High Fatigue, High Habituation (Net Impairment = 0.0)
	h.fatigueLevel = 0.5
	h.habituationLevel = 0.5
	h.applyCombinedEffects()
	assert.Equal(t, h.baseConfig.Omega, h.dynamicConfig.Omega, "Habituation should counteract fatigue")

	// Habituation > Fatigue (Net Impairment clamped to 0)
	h.fatigueLevel = 0.1
	h.habituationLevel = 0.5
	h.applyCombinedEffects()
	assert.Equal(t, h.baseConfig.Omega, h.dynamicConfig.Omega, "Impairment should not be negative")
}

func TestUpdateAndRecoverFatigue(t *testing.T) {
	h, _ := setupBehaviorTest(t)
	// Rates: F_inc=0.1, F_rec=0.05, H_rate=0.05

	// 1. Increase
	h.updateFatigueAndHabituation(1.0)
	assert.InDelta(t, 0.1, h.fatigueLevel, 1e-9)
	assert.InDelta(t, 0.05, h.habituationLevel, 1e-9)

	// Check dynamic config update (applyCombinedEffects)
	assert.Greater(t, h.dynamicConfig.GaussianStrength, h.baseConfig.GaussianStrength)

	// 2. Test Caps
	h.updateFatigueAndHabituation(100.0)
	assert.Equal(t, 1.0, h.fatigueLevel)
	assert.Equal(t, 0.5, h.habituationLevel)

	// Test Typo Rate Cap behavior (Updated in behavior.go fix)
	h.baseConfig.TypoRate = 0.5 // Base rate <= 1.0, so cap applies.
	h.applyCombinedEffects()
	// TypoRate = 0.5 * (1.0 + (1.0 - 0.5)*2.0) = 0.5 * 2.0 = 1.0. Capped at 0.25.
	assert.Equal(t, 0.25, h.dynamicConfig.TypoRate)

	// Test Typo Rate Cap Bypass (for testing)
	h.baseConfig.TypoRate = 1.1 // Base rate > 1.0, so cap is bypassed.
	h.applyCombinedEffects()
	// TypoRate = 1.1 * (1.0 + (1.0 - 0.5)*2.0) = 1.1 * 2.0 = 2.2. Not capped.
	assert.InDelta(t, 2.2, h.dynamicConfig.TypoRate, 1e-9)

	// 3. Recovery
	h.recoverFatigue(1 * time.Second) // Recovery = 0.05
	assert.InDelta(t, 0.95, h.fatigueLevel, 1e-9)

	// 4. Recovery Cap
	h.recoverFatigue(100 * time.Second)
	assert.Equal(t, 0.0, h.fatigueLevel)
}

func TestCalculateButtonsBitfield(t *testing.T) {
	h, _ := setupBehaviorTest(t)
	assert.Equal(t, int64(1), h.calculateButtonsBitfield(schemas.ButtonLeft))
	assert.Equal(t, int64(2), h.calculateButtonsBitfield(schemas.ButtonRight))
	assert.Equal(t, int64(4), h.calculateButtonsBitfield(schemas.ButtonMiddle))
	assert.Equal(t, int64(0), h.calculateButtonsBitfield(schemas.ButtonNone))
}
