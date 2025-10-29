// FILE: ./internal/browser/humanoid/scrolling_test.go
package humanoid

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Setup for scrolling tests.
func setupScrollingTest(t *testing.T) (*Humanoid, *mockExecutor) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)
	// Ensure baseConfig is synced from the dynamicConfig initialized by NewTestHumanoid.
	h.baseConfig = h.dynamicConfig
	return h, mock
}

// Helper to mock the scroll JS execution result
func mockScrollJS(mock *mockExecutor, result scrollResult) {
	mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
		if script != scrollIterationJS {
			// Fallback to default mock behavior for non-scroll scripts (e.g., if hesitation is triggered)
			return mock.DefaultExecuteScript(ctx, script, args)
		}
		jsonBytes, _ := json.Marshal(result)
		return jsonBytes, nil
	}
}

func TestIntelligentScroll_AlreadyVisible(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	// Mock JS to report the element is already intersecting
	mockScrollJS(mock, scrollResult{
		IsIntersecting: true,
		IsComplete:     true,
		ElementExists:  true,
	})

	h.mu.Lock()
	err := h.intelligentScroll(ctx, "#target")
	h.mu.Unlock()

	require.NoError(t, err)
}

func TestIntelligentScroll_ElementNotFound(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	// Mock JS to report the element does not exist
	mockScrollJS(mock, scrollResult{
		ElementExists: false,
	})

	h.mu.Lock()
	err := h.intelligentScroll(ctx, "#nonexistent")
	h.mu.Unlock()

	// Should return nil error even if not found
	require.NoError(t, err)
}

func TestIntelligentScroll_MultipleIterations(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	// FIX: Explicitly disable overshoot and regression to ensure deterministic iteration count.
	// The fixed RNG seed (12345) used by NewTestHumanoid apparently triggers overshoot/regression
	// with the default probabilities, causing the iteration count to include the JS executions
	// within simulateOvershoot/simulateRegression.
	// We must update baseConfig because the initial cognitivePause in intelligentScroll
	// might trigger applyCombinedEffects, resetting dynamicConfig from baseConfig.
	h.baseConfig.ScrollOvershootProbability = 0.0
	h.baseConfig.ScrollRegressionProbability = 0.0
	h.applyCombinedEffects() // Apply immediately to dynamicConfig as well.

	iteration := 0
	mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
		if script != scrollIterationJS {
			return mock.DefaultExecuteScript(ctx, script, args)
		}
		iteration++
		var result scrollResult
		if iteration < 3 {
			// Iteration 1 & 2: Still needs scrolling
			result = scrollResult{IsComplete: false, ElementExists: true, VerticalDelta: 500.0}
		} else {
			// Iteration 3: Complete
			result = scrollResult{IsComplete: true, ElementExists: true}
		}
		jsonBytes, _ := json.Marshal(result)
		return jsonBytes, nil
	}

	h.mu.Lock()
	err := h.intelligentScroll(ctx, "#target")
	h.mu.Unlock()

	require.NoError(t, err)
	assert.Equal(t, 3, iteration)
	// Should have pauses between iterations
	sleeps := getMockSleeps(mock)
	assert.NotEmpty(t, sleeps)
}

// COVERAGE: Test cancellation during different phases of intelligentScroll.
func TestIntelligentScroll_Cancellation(t *testing.T) {

	// 1. Cancellation during initial cognitive pause
	t.Run("InitialPause", func(t *testing.T) {
		// FIX: Initialize fresh instances instead of copying (h := *h_base) to avoid copying locks (linter error)
		// and ensure the Humanoid instance uses the correct mock instance where overrides are applied.
		h, mock := setupScrollingTest(t)

		ctx, cancel := context.WithCancel(context.Background())
		// R3: Using atomic flag as a side-channel for coordination.
		var sleepStarted atomic.Bool

		// Configure a long initial pause
		h.baseConfig.ExGaussianMu = 5000.0
		h.applyCombinedEffects()

		mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
			if sleepStarted.CompareAndSwap(false, true) {
				cancel()
				// FIX: Return the error immediately to avoid race condition where DefaultSleep doesn't see the cancellation yet.
				return context.Canceled
			}
			return mock.DefaultSleep(sleepCtx, d)
		}

		h.mu.Lock()
		err := h.intelligentScroll(ctx, "#target")
		h.mu.Unlock()

		assert.ErrorIs(t, err, context.Canceled)
	})

	// 2. Cancellation during JSRetryWait
	t.Run("DuringJSRetryWait", func(t *testing.T) {
		// FIX: Initialize fresh instances instead of copying.
		h, mock := setupScrollingTest(t)

		ctx, cancel := context.WithCancel(context.Background())

		// Mock JS to fail immediately
		mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
			if script == scrollIterationJS {
				return nil, errors.New("JS failed")
			}
			// Fallback
			return mock.DefaultExecuteScript(ctx, script, args)
		}

		// Mock Sleep to cancel during the 100ms retry wait
		mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
			// The retry wait is exactly 100ms.
			if d == 100*time.Millisecond {
				cancel()
				// FIX: Return the error immediately to avoid race condition.
				return context.Canceled
			}
			return mock.DefaultSleep(sleepCtx, d)
		}

		h.mu.Lock()
		err := h.intelligentScroll(ctx, "#target")
		h.mu.Unlock()
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestIntelligentScroll_Overshoot(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	// Enable overshoot (use > 1.0 as RNG returns [0.0, 1.0))
	// FIX: Use baseConfig to ensure setting persists across cognitivePause/applyCombinedEffects.
	h.baseConfig.ScrollOvershootProbability = 1.1
	h.applyCombinedEffects() // Apply to dynamicConfig

	var overshootExecuted bool
	mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
		if script != scrollIterationJS {
			return mock.DefaultExecuteScript(ctx, script, args)
		}
		// Check if this call is the overshoot (injectedDeltaY != 0)
		// Args[1] is injectedDeltaY
		if len(args) > 1 {
			if deltaY, ok := args[1].(float64); ok && deltaY != 0.0 {
				overshootExecuted = true
				result := scrollResult{IsComplete: true, ElementExists: true}
				jsonBytes, _ := json.Marshal(result)
				return jsonBytes, nil
			}
		}

		// Initial scroll completes, triggering the overshoot logic
		result := scrollResult{
			IsIntersecting: false, // Crucial for overshoot trigger
			IsComplete:     true,
			ElementExists:  true,
			VerticalDelta:  200.0,
		}
		jsonBytes, _ := json.Marshal(result)
		return jsonBytes, nil
	}

	h.mu.Lock()
	err := h.intelligentScroll(ctx, "#target")
	h.mu.Unlock()

	require.NoError(t, err)
	assert.True(t, overshootExecuted, "Overshoot simulation should have been executed")
}

// COVERAGE: Test the regression behavior (scrolling back slightly).
func TestIntelligentScroll_Regression(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	// Enable regression (use > 1.0)
	// FIX: Use baseConfig to ensure setting persists across cognitivePause/applyCombinedEffects.
	h.baseConfig.ScrollRegressionProbability = 1.1
	h.applyCombinedEffects() // Apply to dynamicConfig

	var regressionExecuted bool
	iteration := 0

	mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
		if script != scrollIterationJS {
			// Fallback for non-scroll scripts if necessary
			return mock.DefaultExecuteScript(ctx, script, args)
		}

		iteration++

		// Check if this call is the regression (injectedDeltaY != 0 and negative relative to previous delta)
		// Args[1] is injectedDeltaY.
		if len(args) > 1 {
			// In this scenario, VerticalDelta is positive (500.0), so regression must be negative.
			if deltaY, ok := args[1].(float64); ok && deltaY < 0.0 {
				regressionExecuted = true
				// Regression executed, but scrolling is still far from complete
				result := scrollResult{IsComplete: false, ElementExists: true, VerticalDelta: 300.0}
				jsonBytes, _ := json.Marshal(result)
				return jsonBytes, nil
			}
		}

		// Simulate scrolling progress
		if iteration < 5 {
			// Regression triggers after iteration > 2 (in intelligentScroll logic). This state enables it (Delta > 100).
			result := scrollResult{IsComplete: false, ElementExists: true, VerticalDelta: 500.0}
			jsonBytes, _ := json.Marshal(result)
			return jsonBytes, nil
		}

		// Complete after regression and subsequent scrolls
		result := scrollResult{IsComplete: true, ElementExists: true}
		jsonBytes, _ := json.Marshal(result)
		return jsonBytes, nil
	}

	h.mu.Lock()
	err := h.intelligentScroll(ctx, "#target")
	h.mu.Unlock()

	require.NoError(t, err)
	assert.True(t, regressionExecuted, "Regression simulation should have been executed")
}

// COVERAGE: Test behavior when max iterations are reached (timeout).
func TestIntelligentScroll_Timeout(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	// Mock JS to never report completion
	mockScrollJS(mock, scrollResult{
		IsComplete:    false,
		ElementExists: true,
		VerticalDelta: 500.0,
	})

	h.mu.Lock()
	// intelligentScroll has a hardcoded maxIterations = 15.
	err := h.intelligentScroll(ctx, "#target")
	h.mu.Unlock()

	// Should return nil error even on timeout, but execution should stop.
	require.NoError(t, err)
	// Check that many iterations occurred (indicated by many sleeps).
	sleeps := getMockSleeps(mock)
	// We expect at least 15 sleeps (one per iteration, plus initial cognitive pause).
	assert.GreaterOrEqual(t, len(sleeps), 15)
}

// COVERAGE: Test handling of transient JS execution errors.
func TestIntelligentScroll_JSFailureRetry(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	iteration := 0
	mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
		if script != scrollIterationJS {
			// Fallback for non-scroll scripts if necessary
			return mock.DefaultExecuteScript(ctx, script, args)
		}

		iteration++

		// FIX: The mock logic must ensure the sequence: Not Complete -> Fail -> Complete (Retry).

		if iteration == 1 {
			// 1st attempt: Not complete yet
			result := scrollResult{IsComplete: false, ElementExists: true, VerticalDelta: 500.0}
			jsonBytes, _ := json.Marshal(result)
			return jsonBytes, nil
		}

		if iteration == 2 {
			// Fail on the second iteration
			return nil, errors.New("JS execution failed transiently")
		}

		// 3rd attempt (Retry): Succeeds and completes
		result := scrollResult{IsComplete: true, ElementExists: true}
		jsonBytes, _ := json.Marshal(result)
		return jsonBytes, nil
	}

	h.mu.Lock()
	err := h.intelligentScroll(ctx, "#target")
	h.mu.Unlock()

	// Should succeed eventually after the retry.
	require.NoError(t, err)
	// Should have executed 3 times (1st attempt, failed attempt, successful retry/completion)
	assert.Equal(t, 3, iteration)
}

// COVERAGE: Test the different scroll methods (MouseWheel, DetentWheel).
func TestIntelligentScroll_Methods(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	// Test case 1: Force Mouse Wheel (Smooth)
	// FIX: Must update baseConfig.
	h.baseConfig.ScrollMouseWheelProbability = 1.1
	h.baseConfig.ScrollDetentWheelProbability = 0.0 // Ensure smooth wheel
	h.applyCombinedEffects()

	var usedMouseWheel, isDetentWheel bool
	mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
		if script != scrollIterationJS {
			return mock.DefaultExecuteScript(ctx, script, args)
		}
		// Args indices: 4=useMouseWheel, 7=isDetentWheel
		if len(args) > 7 {
			usedMouseWheel, _ = args[4].(bool)
			isDetentWheel, _ = args[7].(bool)
		}
		result := scrollResult{IsComplete: true, ElementExists: true}
		jsonBytes, _ := json.Marshal(result)
		return jsonBytes, nil
	}

	h.mu.Lock()
	h.intelligentScroll(ctx, "#target")
	h.mu.Unlock()

	assert.True(t, usedMouseWheel, "Should have used mouse wheel simulation")
	assert.False(t, isDetentWheel, "Should have used smooth wheel simulation")

	// Test case 2: Force Detent Wheel
	// FIX: Must update baseConfig.
	h.baseConfig.ScrollDetentWheelProbability = 1.1
	h.applyCombinedEffects()

	h.mu.Lock()
	h.intelligentScroll(ctx, "#target")
	h.mu.Unlock()

	assert.True(t, usedMouseWheel, "Should have used mouse wheel simulation")
	assert.True(t, isDetentWheel, "Should have used detent wheel simulation")
}

// COVERAGE: Test error handling during overshoot and regression simulations.
func TestIntelligentScroll_OvershootRegressionFailure(t *testing.T) {
	h, mock := setupScrollingTest(t)

	// Enable overshoot and regression (using baseConfig for persistence)
	h.baseConfig.ScrollOvershootProbability = 1.1
	h.baseConfig.ScrollRegressionProbability = 1.1
	h.dynamicConfig = h.baseConfig

	t.Run("OvershootFailure", func(t *testing.T) {
		// Create a fresh context for this subtest
		oCtx, oCancel := context.WithCancel(context.Background())
		defer oCancel()

		mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
			if script != scrollIterationJS {
				return mock.DefaultExecuteScript(ctx, script, args)
			}

			// Check if this is the overshoot call (deltaY != 0)
			if deltaY, ok := args[1].(float64); ok && deltaY != 0.0 {
				// Fail the overshoot execution (e.g., due to context cancellation)
				oCancel()
				return nil, context.Canceled
			}

			// Initial scroll completes, triggering overshoot
			result := scrollResult{IsIntersecting: false, IsComplete: true, ElementExists: true, VerticalDelta: 200.0}
			jsonBytes, _ := json.Marshal(result)
			return jsonBytes, nil
		}

		h.mu.Lock()
		// Use the subtest context
		err := h.intelligentScroll(oCtx, "#target")
		h.mu.Unlock()

		// The error should be propagated back up from simulateOvershoot.
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("RegressionFailure", func(t *testing.T) {
		// Create a fresh context for this subtest
		rCtx, rCancel := context.WithCancel(context.Background())
		defer rCancel()

		iteration := 0
		mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
			if script != scrollIterationJS {
				return mock.DefaultExecuteScript(ctx, script, args)
			}
			iteration++

			// Check if this is the regression call (deltaY < 0 in this scenario)
			if deltaY, ok := args[1].(float64); ok && deltaY < 0.0 {
				// Fail the regression execution
				rCancel()
				return nil, context.Canceled
			}

			// Simulate progress until regression triggers (iteration > 2)
			if iteration < 4 {
				result := scrollResult{IsComplete: false, ElementExists: true, VerticalDelta: 500.0}
				jsonBytes, _ := json.Marshal(result)
				return jsonBytes, nil
			}

			// Should not reach here if regression fails correctly
			result := scrollResult{IsComplete: true, ElementExists: true}
			jsonBytes, _ := json.Marshal(result)
			return jsonBytes, nil
		}

		h.mu.Lock()
		// Use the subtest context
		err := h.intelligentScroll(rCtx, "#target")
		h.mu.Unlock()

		// The error should be propagated back up from simulateRegression (which returns the error from executeScrollJS).
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestExecuteScrollJS_ErrorHandling(t *testing.T) {
	h, mock := setupScrollingTest(t)
	ctx := context.Background()

	t.Run("NullResult", func(t *testing.T) {
		mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
			return json.RawMessage("null"), nil
		}
		_, err := h.executeScrollJS(ctx, "#t", 0, 0, 1.0, false, Vector2D{}, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "returned null or empty result")
	})

	t.Run("UnmarshalError", func(t *testing.T) {
		mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
			return json.RawMessage(`{invalid json}`), nil
		}
		_, err := h.executeScrollJS(ctx, "#t", 0, 0, 1.0, false, Vector2D{}, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal")
	})

	// COVERAGE: Test context cancellation during ExecuteScript call.
	t.Run("ContextCancelled", func(t *testing.T) {
		cCtx, cancel := context.WithCancel(ctx)
		cancel()
		// Default mock behavior checks context cancellation
		mock.MockExecuteScript = nil
		_, err := h.executeScrollJS(cCtx, "#t", 0, 0, 1.0, false, Vector2D{}, false)
		// Error should originate from the executor's context check (via DefaultExecuteScript).
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// COVERAGE: Unit test for the scroll pause calculation logic.
func TestCalculateScrollPause(t *testing.T) {
	h, _ := setupScrollingTest(t)
	h.dynamicConfig.ScrollReadDensityFactor = 0.5 // Factor for testing

	// Base calculation: 100 + (Density * 1000 * Factor)

	// 1. Low Density (0.2)
	// 100 + (0.2 * 1000 * 0.5) = 100 + 100 = 200ms
	pauseLow := h.calculateScrollPause(0.2)
	assert.Equal(t, 200*time.Millisecond, pauseLow)

	// 2. High Density (1.5)
	// 100 + (1.5 * 1000 * 0.5) = 100 + 750 = 850ms
	pauseHigh := h.calculateScrollPause(1.5)
	assert.Equal(t, 850*time.Millisecond, pauseHigh)

	// 3. Fatigue Impact (Fatigue 1.0)
	h.fatigueLevel = 1.0
	// Fatigue factor: (1.0 + fatigueLevel*0.5) = 1.5
	// 200ms * 1.5 = 300ms
	pauseFatigued := h.calculateScrollPause(0.2)
	assert.Equal(t, 300*time.Millisecond, pauseFatigued)

	// 4. Clamping (Max 2000ms, Min 50ms)
	h.fatigueLevel = 0.0
	// Density 10.0 -> 100 + (10 * 1000 * 0.5) = 5100ms. Clamped to 2000ms.
	pauseMax := h.calculateScrollPause(10.0)
	assert.Equal(t, 2000*time.Millisecond, pauseMax)

	// Density -1.0 -> 100 + (-1 * 1000 * 0.5) = -400ms. Clamped to 50ms.
	pauseMin := h.calculateScrollPause(-1.0)
	assert.Equal(t, 50*time.Millisecond, pauseMin)
}
