// FILE: ./internal/browser/humanoid/movement_test.go
package humanoid

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// Setup for movement tests (reusing behavior setup)
func setupMovementTest(t *testing.T) (*Humanoid, *mockExecutor) {
	h, mock := setupBehaviorTest(t)

	// Mock geometry
	mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
		if selector == "#target" {
			return &schemas.ElementGeometry{
				Vertices: []float64{100, 100, 150, 100, 150, 150, 100, 150}, // Center 125, 125
				Width:    50, Height: 50, TagName: "DIV",
			}, nil
		}
		return nil, errors.New("element not found")
	}
	h.currentPos = Vector2D{X: 0, Y: 0}
	return h, mock
}

func TestMoveToVector_Basic(t *testing.T) {
	h, mock := setupMovementTest(t)
	ctx := context.Background()
	target := Vector2D{X: 200, Y: 200}

	// Test with options (Potential Field)
	field := NewPotentialField()
	opts := &InteractionOptions{Field: field}

	err := h.MoveToVector(ctx, target, opts)
	require.NoError(t, err)

	// Check movement occurred
	events := getMockEvents(mock)
	assert.NotEmpty(t, events)
	// Check final position
	assert.InDelta(t, target.X, h.currentPos.X, 10.0)
}

// COVERAGE: Test that anticipatory movement is triggered for long distances.
func TestMoveToVector_AnticipatoryMovement(t *testing.T) {
	h, mock := setupMovementTest(t)
	ctx := context.Background()

	// Configure a long distance move (e.g., 1000px)
	target := Vector2D{X: 1000, Y: 0}
	start := Vector2D{X: 0, Y: 0}
	h.currentPos = start

	// Ensure threshold is lower than the distance
	h.baseConfig.AnticipatoryMovementThreshold = 500.0
	// Set distinct parameters for anticipatory movement
	h.baseConfig.AnticipatoryMovementDistance = 50.0
	h.baseConfig.AnticipatoryMovementOmegaFactor = 0.1 // Very slow
	h.baseConfig.TimeStep = 10 * time.Millisecond      // Ensure consistent time steps for analysis

	// We analyze the resulting trajectory. The initial phase should be noticeably slower.
	err := h.MoveToVector(ctx, target, nil)
	require.NoError(t, err)

	events := getMockEvents(mock)
	require.NotEmpty(t, events)

	// Analyze the speed of the first few events.
	distanceCovered := 0.0
	prevPos := start

	// We examine the initial segment of the trajectory (e.g., first 10 events = approx 100ms).
	for i := 0; i < len(events) && i < 10; i++ {
		currentPos := Vector2D{X: events[i].X, Y: events[i].Y}
		dist := currentPos.Dist(prevPos)
		distanceCovered += dist
		prevPos = currentPos
	}

	// If anticipatory movement (OmegaFactor 0.1) was active, the distance covered should be small.
	// A ballistic move (Omega ~30) would cover much more ground in 100ms.
	assert.Less(t, distanceCovered, 75.0, "Initial movement phase should be slow (Anticipatory Movement)")

	// Check that the movement completed to the target (implying configuration was restored)
	assert.InDelta(t, target.X, h.currentPos.X, 20.0)
}

// COVERAGE: Test failure path during anticipatory movement.
func TestAnticipatoryMovement_Failure(t *testing.T) {
	h, mock := setupMovementTest(t)
	ctx := context.Background()

	start := Vector2D{X: 0, Y: 0}
	end := Vector2D{X: 1000, Y: 0}

	// Configure mock to fail during the movement dispatch (simulateTrajectory failure)
	expectedErr := errors.New("dispatch failed during anticipation")
	mock.returnErr = expectedErr
	mock.failOnCall = 1 // Fail immediately

	// Store original dynamic config values to check restoration
	originalOmega := h.dynamicConfig.Omega
	originalZeta := h.dynamicConfig.Zeta

	h.mu.Lock()
	// Call the internal function directly as MoveToVector involves other steps.
	err := h.anticipatoryMovement(ctx, start, end, schemas.ButtonNone)
	h.mu.Unlock()

	assert.ErrorIs(t, err, expectedErr)

	// Ensure configuration parameters (Omega/Zeta) are restored even after failure
	assert.Equal(t, originalOmega, h.dynamicConfig.Omega)
	assert.Equal(t, originalZeta, h.dynamicConfig.Zeta)
}

// COVERAGE: Test cancellation during the terminal Fitts's law pause (hesitate).
func TestMoveToVector_InterruptedDuringTerminalPause(t *testing.T) {
	h, mock := setupMovementTest(t)
	ctx, cancel := context.WithCancel(context.Background())

	// Configure a long terminal pause to ensure interruption happens there.
	h.dynamicConfig.FittsA = 2000.0    // Very long pause
	h.baseConfig.FittsWTerminal = 10.0 // Ensure pause is triggered
	h.baseConfig.TimeStep = 10 * time.Millisecond

	// Configure mock Sleep to cancel when the hesitation phase starts.
	mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
		// Trigger cancellation during the small sleeps characteristic of hesitation (TimeStep duration),
		// but only after the main movement phase (indicated by mock.callCount being high).
		mock.mu.Lock()
		callCount := mock.callCount
		mock.mu.Unlock()

		if d <= h.baseConfig.TimeStep*2 && callCount > 20 {
			cancel()
		}
		// DefaultSleep handles the context check and recording.
		return mock.DefaultSleep(sleepCtx, d)
	}

	// Long move to trigger the pause
	err := h.MoveToVector(ctx, Vector2D{X: 500, Y: 500}, nil)
	// The error should propagate from the context cancellation within hesitate/Sleep.
	assert.ErrorIs(t, err, context.Canceled)
}

func TestMoveToVector_ShortDistance(t *testing.T) {
	h, mock := setupMovementTest(t)
	ctx := context.Background()
	h.currentPos = Vector2D{X: 100, Y: 100}
	target := Vector2D{X: 101, Y: 101}
	h.baseConfig.MinMoveDistance = 5.0

	err := h.MoveToVector(ctx, target, nil)
	require.NoError(t, err)

	// Should return immediately
	events := getMockEvents(mock)
	assert.Empty(t, events)
}

func TestMoveTo_Basic(t *testing.T) {
	h, mock := setupMovementTest(t)
	ctx := context.Background()

	err := h.MoveTo(ctx, "#target", nil)
	require.NoError(t, err)

	// Check movement occurred
	events := getMockEvents(mock)
	assert.NotEmpty(t, events)
	// Check final position near center (125, 125)
	assert.InDelta(t, 125.0, h.currentPos.X, 30.0)
}

// COVERAGE: Test various failure paths within moveToSelector.
func TestMoveTo_FailurePaths(t *testing.T) {
	// Use a fresh setup for each subtest to ensure isolation
	ctx := context.Background()

	t.Run("CognitivePauseFails", func(t *testing.T) {
		h, mock := setupMovementTest(t)
		// Configure mock Sleep to fail (cognitivePause uses Sleep/hesitate)
		expectedErr := errors.New("pause failed")
		mock.MockSleep = func(ctx context.Context, d time.Duration) error {
			return expectedErr
		}

		// Call the public locking method MoveTo
		err := h.MoveTo(ctx, "#target", nil)
		// The error from the initial cognitivePause should propagate.
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("EnsureVisibleFails_Continue", func(t *testing.T) {
		h, mock := setupMovementTest(t)
		// Configure mock ExecuteScript to fail for scrolling (ensureVisible uses intelligentScroll)
		mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
			if script == scrollIterationJS {
				// intelligentScroll handles the JS error internally and returns nil, allowing MoveTo to continue.
				return nil, errors.New("scrolling failed")
			}
			// Fallback for others
			return mock.DefaultExecuteScript(ctx, script, args)
		}

		// The implementation logs the error but continues to GetElementGeometry.
		// Since the mock GetElementGeometry succeeds by default (in setupMovementTest), the overall MoveTo should succeed.
		err := h.MoveTo(ctx, "#target", nil)
		assert.NoError(t, err)
	})

	t.Run("InvalidGeometry", func(t *testing.T) {
		h, mock := setupMovementTest(t)
		// Configure mock geometry to return invalid data (handled by getElementBoxBySelector, checked in moveToSelector)
		mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
			// Insufficient vertices
			return &schemas.ElementGeometry{Vertices: []float64{1, 1}, Width: 10, Height: 10}, nil
		}

		err := h.MoveTo(ctx, "#target", nil)
		assert.Error(t, err)
		// The error message originates from getElementBoxBySelector
		assert.Contains(t, err.Error(), "invalid geometry (expected 8 vertices")
	})
}

func TestMoveTo_ElementNotFound(t *testing.T) {
	h, _ := setupMovementTest(t)
	ctx := context.Background()

	err := h.MoveTo(ctx, "#nonexistent", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to locate target")
}

func TestCalculateTargetPoint_ElementAwareness(t *testing.T) {
	h, _ := setupMovementTest(t)
	h.dynamicConfig.ClickNoise = 0.0                // Disable noise
	h.baseConfig.TargetVelocityBiasThresh = 10000.0 // Disable velocity bias

	center := Vector2D{X: 200, Y: 200}
	geo := &schemas.ElementGeometry{Width: 100, Height: 50}
	velocity := Vector2D{}

	// 1. Text Input (Bias Left)
	geo.TagName = "INPUT"
	geo.Type = "text"
	target := h.calculateTargetPoint(geo, center, velocity)
	// BiasX = -100 * 0.3 = -30. Expected X ≈ 170.
	assert.Less(t, target.X, center.X-15.0, "Text inputs should have a left bias")

	// 2. Textarea (Bias Top-Left)
	geo.TagName = "TEXTAREA"
	geo.Type = ""
	target = h.calculateTargetPoint(geo, center, velocity)
	assert.Less(t, target.X, center.X-10.0)
	assert.Less(t, target.Y, center.Y-5.0)
}

// COVERAGE: Test the velocity bias (overshoot tendency).
func TestCalculateTargetPoint_VelocityBias(t *testing.T) {
	h, _ := setupMovementTest(t)
	h.dynamicConfig.ClickNoise = 0.0         // Disable noise
	h.baseConfig.TargetInnerAimPercent = 0.1 // Aim precisely at center
	h.resetRNG(1)                            // Fixed seed for reproducibility

	center := Vector2D{X: 200, Y: 200}
	geo := &schemas.ElementGeometry{Width: 100, Height: 50, TagName: "DIV"}

	// Configure velocity bias parameters
	h.baseConfig.TargetVelocityBiasThresh = 100.0
	h.baseConfig.TargetVelocityBiasMax = 0.2 // Max 20% of width/height bias
	h.baseConfig.MaxVelocity = 1000.0

	// 1. Low Velocity (Below threshold)
	velocityLow := Vector2D{X: 50, Y: 0}
	targetLow := h.calculateTargetPoint(geo, center, velocityLow)

	// 2. High Velocity (Above threshold, moving Right)
	velocityHigh := Vector2D{X: 500, Y: 0} // Normalized velocity = 500/1000 = 0.5
	// Expected Bias Calculation:
	// MaxBiasX = 100 (width) * 0.2 = 20.
	// Bias applied = 1.0 (X direction) * 0.5 (normalized vel) * 20 = 10 pixels.
	targetHigh := h.calculateTargetPoint(geo, center, velocityHigh)

	// High velocity target should be significantly further to the right (positive X) than the low velocity target.
	assert.Greater(t, targetHigh.X, targetLow.X+5.0, "High velocity should bias the target in the direction of movement")

	// 3. High Velocity (Moving Left)
	velocityLeft := Vector2D{X: -500, Y: 0}
	targetLeft := h.calculateTargetPoint(geo, center, velocityLeft)
	assert.Less(t, targetLeft.X, targetLow.X-5.0, "High velocity (left) should bias the target left")
}

func TestCalculateTargetPoint_Clamping(t *testing.T) {
	h, _ := setupMovementTest(t)
	h.baseConfig.TargetInnerAimPercent = 2.0 // Force points outside bounds
	h.dynamicConfig.ClickNoise = 50.0

	center := Vector2D{X: 50, Y: 50}
	geo := &schemas.ElementGeometry{Width: 10, Height: 10}
	// Clamped bounds (1px margin): 46-54.

	for i := 0; i < 50; i++ {
		target := h.calculateTargetPoint(geo, center, Vector2D{})
		assert.GreaterOrEqual(t, target.X, 46.0)
		assert.LessOrEqual(t, target.X, 54.0)
	}

	// Test Nil/Zero size fallback
	targetNil := h.calculateTargetPoint(nil, center, Vector2D{})
	assert.Equal(t, center, targetNil)

	geoZero := &schemas.ElementGeometry{Width: 0, Height: 10}
	targetZero := h.calculateTargetPoint(geoZero, center, Vector2D{})
	assert.Equal(t, center, targetZero)
}
