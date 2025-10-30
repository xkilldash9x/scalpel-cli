// FILE: ./internal/browser/humanoid/humanoid_test.go
package humanoid

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// Helper function to reset RNG for deterministic tests
// Must be called while holding the humanoid lock if used concurrently (though not strictly necessary in these specific tests).
func (h *Humanoid) resetRNG(seed int64) {
	h.rng = rand.New(rand.NewSource(seed))
}

// R1: Implement Standardized State Reset Utilities.
// resetBehavioralState resets fatigue, habituation, and action type, then syncs the dynamic config.
// This ensures test isolation regarding behavioral modeling.
// Must be called while holding the humanoid lock.
func (h *Humanoid) resetBehavioralState() {
	h.fatigueLevel = 0.0
	h.habituationLevel = 0.0
	h.lastActionType = ActionTypeNone // Assuming ActionTypeNone is the zero value or defined elsewhere
	// Synchronize the dynamic configuration based on the reset state.
	h.applyCombinedEffects()
}

// R1: Implement Standardized State Reset Utilities.
// resetInteractionState resets the physical interaction state (mouse position and buttons).
// Must be called while holding the humanoid lock.
func (h *Humanoid) resetInteractionState() {
	h.currentPos = Vector2D{X: 0.0, Y: 0.0}
	h.currentButtonState = schemas.ButtonNone
}

func TestNew(t *testing.T) {
	baseCfg := config.NewDefaultConfig().Browser().Humanoid
	logger := zap.NewNop()
	mock := newMockExecutor(t)

	t.Run("BasicInitialization", func(t *testing.T) {
		h := New(baseCfg, logger, mock)
		require.NotNil(t, h)
		assert.NotNil(t, h.rng)
		assert.Equal(t, mock, h.executor)
		assert.Equal(t, logger, h.logger)
		// Check that the config is finalized and differs from the default base.
		// The skill factor will modify parameters like FittsA.
		assert.NotEqual(t, baseCfg.FittsA, h.baseConfig.FittsA, "Finalized config should differ from base")
	})

	// COVERAGE: Test the clamping of the skillFactor in the New() constructor.
	// Since New() is non-deterministic (uses time for seed), we run it multiple
	// times with a high jitter value to statistically ensure the clamping logic is exercised.
	t.Run("SkillFactorClamping", func(t *testing.T) {
		cfg := config.NewDefaultConfig().Browser().Humanoid
		// Use an extremely high jitter value to force skillFactor outside the [0.5, 1.5] range before clamping.
		cfg.PersonaJitterSkill = 100.0

		for i := 0; i < 100; i++ {
			h := New(cfg, logger, mock)
			require.NotNil(t, h)
			// This assertion verifies that the clamping logic (math.Max/math.Min) works correctly.
			assert.GreaterOrEqual(t, h.skillFactor, 0.5, "skillFactor should be clamped to a minimum of 0.5")
			assert.LessOrEqual(t, h.skillFactor, 1.5, "skillFactor should be clamped to a maximum of 1.5")
		}
	})
}

// COVERAGE: Test NewTestHumanoid initialization and deterministic configuration.
func TestNewTestHumanoid(t *testing.T) {
	mock := newMockExecutor(t)
	seed := int64(12345)
	h := NewTestHumanoid(mock, seed)

	require.NotNil(t, h)
	// Check if the deterministic configuration values (set in NewTestHumanoid) are correctly set.
	assert.Equal(t, 100.0, h.baseConfig.FittsA)
	assert.Equal(t, 30.0, h.baseConfig.Omega)
	assert.Equal(t, 0.0, h.baseConfig.TypoRate)
	// Check if dynamic config matches base config initially.
	assert.Equal(t, h.baseConfig.FittsA, h.dynamicConfig.FittsA)
	// Check if RNG is initialized (non-nil).
	assert.NotNil(t, h.rng)
	// Check if skill factor is forced to 1.0.
	assert.Equal(t, 1.0, h.skillFactor)
}

// TestNormalizeTypoRates was moved to keyboard_test.go

func TestFinalizeSessionPersona(t *testing.T) {
	// We need a base configuration that hasn't been randomized yet.
	baseCfg := config.NewDefaultConfig().Browser().Humanoid
	// FIX: Ensure normalization runs first as finalizeSessionPersona expects normalized input for accurate calculations.
	normalizeTypoRates(&baseCfg)

	t.Run("HighSkill", func(t *testing.T) {
		// Use a deterministic RNG
		rng := rand.New(rand.NewSource(12345))
		highSkillCfg := baseCfg // Make a copy
		skillFactor := 1.5
		finalizeSessionPersona(&highSkillCfg, rng, skillFactor)

		assert.Less(t, highSkillCfg.FittsA, baseCfg.FittsA)
		assert.Greater(t, highSkillCfg.Omega, baseCfg.Omega)
		assert.Less(t, highSkillCfg.TypoRate, baseCfg.TypoRate)

		// COVERAGE: Check noise parameters (inverseSkill = 1/1.5 approx 0.666)
		// Noise reduction factor = (1.0 + (0.666-1.0)*0.5) approx 0.833
		assert.Less(t, highSkillCfg.GaussianStrength, baseCfg.GaussianStrength)
		assert.Less(t, highSkillCfg.PinkNoiseAmplitude, baseCfg.PinkNoiseAmplitude)
		assert.LessOrEqual(t, highSkillCfg.TypoCorrectionProbability, 1.0)
	})

	t.Run("LowSkill", func(t *testing.T) {
		// Reset RNG for independent jitter calculation
		rng := rand.New(rand.NewSource(54321))
		lowSkillCfg := baseCfg // Make a copy
		skillFactor := 0.5
		finalizeSessionPersona(&lowSkillCfg, rng, skillFactor)

		assert.Greater(t, lowSkillCfg.FittsA, baseCfg.FittsA)
		assert.Less(t, lowSkillCfg.Omega, baseCfg.Omega)
		assert.Greater(t, lowSkillCfg.TypoRate, baseCfg.TypoRate)

		// COVERAGE: Check noise parameters (inverseSkill = 1/0.5 = 2.0)
		// Noise increase factor = (1.0 + (2.0-1.0)*0.5) = 1.5
		assert.Greater(t, lowSkillCfg.GaussianStrength, baseCfg.GaussianStrength)
		assert.Greater(t, lowSkillCfg.PinkNoiseAmplitude, baseCfg.PinkNoiseAmplitude)
	})

	// COVERAGE: Test the clamping of TypoCorrectionProbability to a maximum of 1.0.
	t.Run("TypoCorrectionProbabilityClamping", func(t *testing.T) {
		rng := rand.New(rand.NewSource(999))
		clampingCfg := baseCfg // make a copy
		// Set a base probability that, when multiplied by skillFactor, will exceed 1.0.
		clampingCfg.TypoCorrectionProbability = 0.9
		skillFactor := 1.5 // 0.9 * 1.5 = 1.35
		finalizeSessionPersona(&clampingCfg, rng, skillFactor)

		// Assert that the value was clamped to 1.0, not 1.35.
		assert.Equal(t, 1.0, clampingCfg.TypoCorrectionProbability, "Probability should be clamped to 1.0")
	})
}

func TestEnsureVisibleOptions(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 1)
	ctx := context.Background()

	// Helper to check if scroll JS was executed
	scrollExecuted := false
	mock.MockExecuteScript = func(ctx context.Context, script string, args []interface{}) (json.RawMessage, error) {
		// FIX: The script executed is a wrapper, not the raw JS.
		// We check for a unique part of that wrapper script.
		if strings.Contains(script, "window.__scalpel_scrollFunction") {
			scrollExecuted = true
		}
		// Call the default implementation to allow intelligentScroll to proceed.
		return mock.DefaultExecuteScript(ctx, script, args)
	}

	// 1. Nil options (Default: True)
	scrollExecuted = false // Reset for test
	// Must lock h because ensureVisible calls intelligentScroll which requires the lock.
	h.mu.Lock()
	h.ensureVisible(ctx, "#target", nil)
	h.mu.Unlock()
	assert.True(t, scrollExecuted, "Should execute scroll logic when options are nil")

	// 2. Explicitly False
	scrollExecuted = false
	boolFalse := false
	opts := &InteractionOptions{EnsureVisible: &boolFalse}
	h.mu.Lock()
	h.ensureVisible(ctx, "#target", opts)
	h.mu.Unlock()
	assert.False(t, scrollExecuted, "Should NOT execute scroll logic when EnsureVisible is false")

	// 3. Explicitly True
	scrollExecuted = false
	boolTrue := true
	opts = &InteractionOptions{EnsureVisible: &boolTrue}
	h.mu.Lock()
	h.ensureVisible(ctx, "#target", opts)
	h.mu.Unlock()
	assert.True(t, scrollExecuted, "Should execute scroll logic when EnsureVisible is true")
}

func TestReleaseMouse(t *testing.T) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 1)
	ctx := context.Background()

	// 1. Release when pressed
	h.currentButtonState = schemas.ButtonLeft
	// Must lock h when calling internal methods
	h.mu.Lock()
	err := h.releaseMouse(ctx)
	h.mu.Unlock()

	assert.NoError(t, err)

	events := getMockEvents(mock)

	assert.Len(t, events, 1)
	assert.Equal(t, schemas.MouseRelease, events[0].Type)
	assert.Equal(t, schemas.ButtonNone, h.currentButtonState)

	// 2. Release when not pressed
	mock.mu.Lock()
	mock.dispatchedEvents = nil
	mock.mu.Unlock()
	h.currentButtonState = schemas.ButtonNone

	h.mu.Lock()
	err = h.releaseMouse(ctx)
	h.mu.Unlock()

	assert.NoError(t, err)
	events = getMockEvents(mock)
	assert.Empty(t, events)

	// 3. Release when pressed but executor fails
	mock.mu.Lock()
	mock.dispatchedEvents = nil
	mock.returnErr = errors.New("failed")
	// Need to set failOnCall=1 and reset callCount because DispatchMouseEvent tracks it.
	mock.failOnCall = 1
	mock.callCount = 0
	mock.mu.Unlock()

	h.currentButtonState = schemas.ButtonLeft

	h.mu.Lock()
	err = h.releaseMouse(ctx)
	h.mu.Unlock()

	assert.Error(t, err)
	// CRITICAL: State must be updated even if dispatch fails
	assert.Equal(t, schemas.ButtonNone, h.currentButtonState)
}
