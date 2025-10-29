// FILE: ./internal/browser/humanoid/keyboard_test.go
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
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Setup for predictable keyboard testing.
func setupKeyboardTest(t *testing.T) (*Humanoid, *mockExecutor) {
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)

	// Disable typos and burst pauses by default in the base config
	h.baseConfig.TypoRate = 0.0
	h.baseConfig.KeyBurstPauseProbability = 0.0
	// Sync dynamic config initially
	h.dynamicConfig = h.baseConfig

	// Mock geometry for focusing
	mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
		if selector == "#input" {
			return &schemas.ElementGeometry{
				Vertices: []float64{10, 10, 110, 10, 110, 60, 10, 60},
				Width:    100, Height: 50, TagName: "INPUT", Type: "text",
			}, nil
		}
		return nil, errors.New("element not found")
	}
	return h, mock
}

// Helper to safely access mock keys (for -race detector)
func getMockKeys(mock *mockExecutor) []string {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	keys := make([]string, len(mock.sentKeys))
	copy(keys, mock.sentKeys)
	return keys
}

// Helper to get recorded structured keys (New)
func getMockStructuredKeys(mock *mockExecutor) []schemas.KeyEventData {
	mock.mu.Lock()
	defer mock.mu.Unlock()
	keys := make([]schemas.KeyEventData, len(mock.structuredKeys))
	copy(keys, mock.structuredKeys)
	return keys
}

func TestType_BasicFlow(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	ctx := context.Background()
	text := "hello"

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	// 1. Check focus (clicked)
	foundClick := false

	events := getMockEvents(mock)
	for _, event := range events {
		if event.Type == schemas.MousePress {
			foundClick = true
			break
		}
	}
	assert.True(t, foundClick, "Should have clicked to focus")

	// 2. Check keys sent
	keys := getMockKeys(mock)
	require.Len(t, keys, len(text))
	assert.Equal(t, "h", keys[0])
	assert.Equal(t, "o", keys[4])

	// 3. Check pauses occurred
	sleeps := getMockSleeps(mock)
	assert.NotEmpty(t, sleeps)
}

// COVERAGE: Test failure when dispatching a key (sendString fails).
func TestType_KeyDispatchFails(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	ctx := context.Background()
	text := "abc"

	expectedErr := errors.New("key dispatch failed")

	// Configure mock SendKeys to fail.
	mock.MockSendKeys = func(ctx context.Context, keys string) error {
		// We call DefaultSendKeys to ensure the key is recorded *before* the error is returned.
		// This simulates the behavior of the real mock.
		_ = mock.DefaultSendKeys(ctx, keys)
		return expectedErr
	}

	err := h.Type(ctx, "#input", text, nil)
	assert.Error(t, err)
	// The error returned by Type wraps the underlying error.
	assert.ErrorIs(t, err, expectedErr)
	assert.Contains(t, err.Error(), "failed to send key")

	// Check that the failure happened on the first key ('a')
	keys := getMockKeys(mock)
	// We expect 1 key recorded because DefaultSendKeys is called before returning the error.
	require.Len(t, keys, 1)
	assert.Equal(t, "a", keys[0])
}

func TestType_FocusFails(t *testing.T) {
	h, _ := setupKeyboardTest(t)
	ctx := context.Background()
	err := h.Type(ctx, "#nonexistent", "text", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to click/focus selector")
}

// COVERAGE: Test failure scenarios within the internal clickToFocus helper.
func TestClickToFocus_Failures(t *testing.T) {
	ctx := context.Background()

	t.Run("MoveFails", func(t *testing.T) {
		h, _ := setupKeyboardTest(t)
		h.mu.Lock()
		// moveToSelector fails if the selector is not found by the mock.
		err := h.clickToFocus(ctx, "#nonexistent", nil)
		h.mu.Unlock()
		assert.Error(t, err)
		// The error originates from moveToSelector -> getElementBoxBySelector.
		assert.Contains(t, err.Error(), "failed to locate target")
	})

	t.Run("PauseFails", func(t *testing.T) {
		h, mock := setupKeyboardTest(t)
		ctx, cancel := context.WithCancel(ctx)

		// Configure mock Sleep to fail during the cognitivePause before click.
		mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
			// FIX: Check if we are past the initial movement phase (which generates many events).
			// This handles both direct Sleep and hesitation (many small sleeps) reliably, unlike checking duration (d > 50ms).
			if len(getMockEvents(mock)) > 10 {
				cancel()
				// Return the error immediately to avoid race conditions.
				return context.Canceled
			}
			return mock.DefaultSleep(sleepCtx, d)
		}

		h.mu.Lock()
		err := h.clickToFocus(ctx, "#input", nil)
		h.mu.Unlock()
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("PressFails", func(t *testing.T) {
		h, mock := setupKeyboardTest(t)
		expectedErr := errors.New("press failed")

		// Configure mock to fail on MousePress
		mock.MockDispatchMouseEvent = func(dispatchCtx context.Context, data schemas.MouseEventData) error {
			if data.Type == schemas.MousePress {
				// Call default to record, then return error
				_ = mock.DefaultDispatchMouseEvent(dispatchCtx, data)
				return expectedErr
			}
			return mock.DefaultDispatchMouseEvent(dispatchCtx, data)
		}

		h.mu.Lock()
		err := h.clickToFocus(ctx, "#input", nil)
		h.mu.Unlock()
		assert.ErrorIs(t, err, expectedErr)
	})

	t.Run("HesitateFails", func(t *testing.T) {
		h, mock := setupKeyboardTest(t)
		ctx, cancel := context.WithCancel(ctx)

		// Configure mock Sleep to fail during the hesitate (hold duration).
		// R3: Using the "Atomic Side-Channel" pattern here.
		var isHolding atomic.Bool
		mock.MockDispatchMouseEvent = func(dispatchCtx context.Context, data schemas.MouseEventData) error {
			if data.Type == schemas.MousePress {
				isHolding.Store(true)
			}
			return mock.DefaultDispatchMouseEvent(dispatchCtx, data)
		}

		mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
			// Fail during the small sleeps within hesitate (TimeStep duration), only if holding.
			// keyHoldDuration generates the total duration, hesitate breaks it down.
			if d < 50*time.Millisecond && isHolding.Load() {
				cancel()
				return context.Canceled
			}
			return mock.DefaultSleep(sleepCtx, d)
		}

		h.mu.Lock()
		err := h.clickToFocus(ctx, "#input", nil)
		h.mu.Unlock()
		assert.ErrorIs(t, err, context.Canceled)

		// Check cleanup (releaseMouse called)
		h.mu.Lock()
		assert.Equal(t, schemas.ButtonNone, h.currentButtonState)
		h.mu.Unlock()
	})
}

func TestType_BurstPauses(t *testing.T) {
	h, mock := setupKeyboardTest(t)

	// FIX: Ensure cognitivePause uses Sleep instead of hesitate for this test.
	// If Hesitate is used, the long pause is broken into many small sleeps, which the test logic cannot detect.
	h.baseConfig.AntiPeriodicityMinPause = 5000 * time.Millisecond

	// FIX: Guarantee a burst pause (use > 1.0 as RNG returns [0.0, 1.0))
	// Update base config so it persists after applyCombinedEffects
	h.baseConfig.KeyBurstPauseProbability = 1.1
	// Configure pause parameters to be distinct
	h.baseConfig.ExGaussianMu = 200.0
	h.baseConfig.IKDMu = 50.0

	// Minimize randomness for predictable duration (Mu=200 * Scale=3.0 = 600ms)
	h.baseConfig.ExGaussianSigma = 1.0
	h.baseConfig.ExGaussianTau = 1.0

	// Sync dynamic config
	h.dynamicConfig = h.baseConfig

	ctx := context.Background()
	text := "abc" // Use slightly longer text to ensure IKDs also occur.

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	// Analyze sleep durations to find the burst pause.
	foundBurstPause := false
	sleeps := getMockSleeps(mock)
	for _, d := range sleeps {
		// Burst pause should be significantly longer than IKD (Mu 50ms).
		// Threshold of 300ms is reasonable.
		if d > 300*time.Millisecond {
			foundBurstPause = true
			break
		}
	}
	assert.True(t, foundBurstPause, "Should have executed a long burst pause")
}

// --- Shortcut Tests ---

// TestParseKeyExpression tests the shortcut string parser.
func TestParseKeyExpression(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		want       schemas.KeyEventData
		wantErr    bool
	}{
		{
			name:       "Simple Ctrl+A",
			expression: "ctrl+a",
			want:       schemas.KeyEventData{Key: "a", Modifiers: schemas.ModCtrl},
		},
		{
			name:       "Simple Meta+C",
			expression: "meta+c",
			want:       schemas.KeyEventData{Key: "c", Modifiers: schemas.ModMeta},
		},
		{
			name:       "Ctrl+Shift+T (lowercase input)",
			expression: "ctrl+shift+t",
			// Parser should uppercase the key if shift is present
			want: schemas.KeyEventData{Key: "T", Modifiers: schemas.ModCtrl | schemas.ModShift},
		},
		{
			name:       "Alt+F4",
			expression: "alt+f4",
			want:       schemas.KeyEventData{Key: "f4", Modifiers: schemas.ModAlt},
		},
		{
			name:       "Case Insensitive Modifiers",
			expression: "Control+SHIFT+Alt+Meta+z",
			want:       schemas.KeyEventData{Key: "Z", Modifiers: schemas.ModCtrl | schemas.ModShift | schemas.ModAlt | schemas.ModMeta},
		},
		{
			name:       "Alternative Modifier Names (Cmd)",
			expression: "cmd+v",
			want:       schemas.KeyEventData{Key: "v", Modifiers: schemas.ModMeta},
		},
		{
			name:       "Alternative Modifier Names (Win)",
			expression: "win+l",
			want:       schemas.KeyEventData{Key: "l", Modifiers: schemas.ModMeta},
		},
		{
			name:       "Spacing",
			expression: " ctrl +  a ",
			want:       schemas.KeyEventData{Key: "a", Modifiers: schemas.ModCtrl},
		},
		{
			name:       "Implicit Shift (Uppercase Key)",
			expression: "ctrl+A",
			// Parser should infer Shift from uppercase 'A' and keep 'A' as the key.
			want: schemas.KeyEventData{Key: "A", Modifiers: schemas.ModCtrl | schemas.ModShift},
		},
		{
			name:       "Explicit Shift and Uppercase Key",
			expression: "shift+A",
			want:       schemas.KeyEventData{Key: "A", Modifiers: schemas.ModShift},
		},
		{
			name:       "Special Key (Enter)",
			expression: "ctrl+enter",
			want:       schemas.KeyEventData{Key: "enter", Modifiers: schemas.ModCtrl},
		},
		// Error cases
		{
			name:       "No Key",
			expression: "ctrl+shift",
			wantErr:    true,
		},
		{
			name:       "Empty Expression",
			expression: "",
			wantErr:    true,
		},
		{
			name:       "Multiple Keys",
			expression: "ctrl+a+b",
			wantErr:    true,
		},
		{
			name:       "Invalid Separator",
			expression: "ctrl++a",
			wantErr:    true,
		},
		{
			name:       "Shift with Non-Letter (no change)",
			expression: "shift+1",
			want:       schemas.KeyEventData{Key: "1", Modifiers: schemas.ModShift},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseKeyExpression(tt.expression)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyExpression() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestHumanoid_Shortcut tests the controller logic for shortcuts.
func TestHumanoid_Shortcut(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// Setup predictable timing for testing
	h.baseConfig.ExGaussianMu = 100.0
	h.baseConfig.ExGaussianSigma = 1.0
	h.baseConfig.ExGaussianTau = 1.0
	h.baseConfig.KeyHoldMu = 50.0
	h.baseConfig.KeyHoldSigma = 1.0
	h.baseConfig.KeyHoldTau = 1.0

	// Ensure we don't use hesitation for the shortcut pauses, as we expect distinct Sleeps.
	h.baseConfig.AntiPeriodicityMinPause = 5000 * time.Millisecond

	// Apply configuration
	h.resetBehavioralState()

	ctx := context.Background()

	t.Run("Success", func(t *testing.T) {
		// Clear previous recordings
		mock.mu.Lock()
		mock.structuredKeys = nil
		mock.sleepDurations = nil
		mock.mu.Unlock()

		expression := "ctrl+shift+a"
		err := h.Shortcut(ctx, expression)
		require.NoError(t, err)

		// 1. Check that the executor was called correctly
		dispatched := getMockStructuredKeys(mock)
		require.Len(t, dispatched, 1)
		// Parser ensures 'A' is uppercase when Shift is present.
		expected := schemas.KeyEventData{Key: "A", Modifiers: schemas.ModCtrl | schemas.ModShift}
		assert.Equal(t, expected, dispatched[0])

		// 2. Check that pauses occurred (1 cognitive pause + 1 hold duration)
		sleeps := getMockSleeps(mock)
		require.Len(t, sleeps, 2)
		// Cognitive pause (Scale 1.0 * Mu 100ms ≈ 100ms)
		assert.InDelta(t, 100.0, sleeps[0].Milliseconds(), 5.0)
		// Hold duration (Mu 50ms ≈ 50ms)
		assert.InDelta(t, 50.0, sleeps[1].Milliseconds(), 5.0)
	})

	t.Run("Parse Error", func(t *testing.T) {
		err := h.Shortcut(ctx, "ctrl+a+b")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse shortcut expression")
	})

	t.Run("Dispatch Error", func(t *testing.T) {
		expectedErr := errors.New("dispatch failed")
		mock.MockDispatchStructuredKey = func(ctx context.Context, data schemas.KeyEventData) error {
			return expectedErr
		}
		// Ensure mock is cleaned up
		t.Cleanup(func() { mock.MockDispatchStructuredKey = nil })

		err := h.Shortcut(ctx, "ctrl+a")
		assert.Error(t, err)
		assert.ErrorIs(t, err, expectedErr)
		assert.Contains(t, err.Error(), "failed to dispatch shortcut")
	})
}

// --- Typo Generation Tests ---

// Helper to configure typo rates.
func configureTypos(h *Humanoid, rate, homo, neighbor, transpose, omission float64) {
	// We must update the baseConfig, because applyCombinedEffects (called during Type)
	// resets dynamicConfig based on baseConfig and current fatigue levels.
	h.baseConfig.TypoRate = rate
	h.baseConfig.TypoHomoglyphRate = homo
	h.baseConfig.TypoNeighborRate = neighbor
	h.baseConfig.TypoTransposeRate = transpose
	h.baseConfig.TypoOmissionRate = omission

	// We also need to ensure fatigue/habituation don't interfere with the rates during the test.
	// R1: Use standardized reset utility. This calls applyCombinedEffects() internally
	// to set the dynamic config correctly before the Type() call.
	h.resetBehavioralState()
	/* Original manual reset removed:
	h.fatigueLevel = 0.0
	h.habituationLevel = 0.0

	// Apply the effects immediately to set the dynamic config correctly before the Type() call.
	h.applyCombinedEffects()
	*/
}

// COVERAGE: Test error path during keyPause within typeCharacter.
func TestTypeCharacter_KeyPauseFailure(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	runes := []rune("ab")

	// Configure mock Sleep to fail during the keyPause (IKD before 'b')
	mock.MockSleep = func(sleepCtx context.Context, d time.Duration) error {
		cancel()
		return context.Canceled
	}

	h.mu.Lock()
	// Call internal function directly. Index 1 (character 'b').
	_, err := h.typeCharacter(ctx, runes, 1, 1.0)
	h.mu.Unlock()

	assert.ErrorIs(t, err, context.Canceled)
}

func TestTypo_Neighbor_Corrected(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// FIX: Guarantee Neighbor typo (1.1), guarantee correction (1.1)
	configureTypos(h, 1.1, 0.0, 1.0, 0.0, 0.0)
	// Update base config for correction probability as well
	h.baseConfig.TypoCorrectionProbability = 1.1
	h.applyCombinedEffects()

	ctx := context.Background()
	text := "s" // Neighbors: a, w, e, d, x, z

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected sequence: Typo (e.g., 'd'), Backspace, Correct ('s')
	require.Len(t, keys, 3)
	assert.Contains(t, "awedxz", keys[0])
	assert.Equal(t, string(KeyBackspace), keys[1])
	assert.Equal(t, "s", keys[2])
}

func TestTypo_Homoglyph_Uncorrected(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// Guarantee Homoglyph typo (1.1), NO correction (0.0)
	configureTypos(h, 1.1, 1.0, 0.0, 0.0, 0.0)
	h.baseConfig.TypoCorrectionProbability = 0.0
	h.applyCombinedEffects()

	ctx := context.Background()
	text := "o" // Homoglyph: 0

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected sequence: Typo ('0')
	require.Len(t, keys, 1)
	assert.Equal(t, "0", keys[0])
}

func TestTypo_Transposition_Uncorrected(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// FIX: Guarantee Transposition typo (1.1), NO correction (0.0)
	configureTypos(h, 1.1, 0.0, 0.0, 1.0, 0.0)
	h.baseConfig.TypoCorrectionProbability = 0.0
	h.applyCombinedEffects()

	ctx := context.Background()
	text := "ab"

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected sequence: Transposed ('b', 'a')
	expected := []string{"b", "a"}
	assert.Equal(t, expected, keys)
}

// COVERAGE: Test transposition correction path.
func TestTypo_Transposition_Corrected(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// Guarantee Transposition typo (1.1), guarantee correction (1.1)
	configureTypos(h, 1.1, 0.0, 0.0, 1.0, 0.0)
	h.baseConfig.TypoCorrectionProbability = 1.1
	h.applyCombinedEffects()

	ctx := context.Background()
	text := "ab"

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected sequence: 'b', 'a', Backspace, Backspace, 'a', 'b'
	expected := []string{"b", "a", string(KeyBackspace), string(KeyBackspace), "a", "b"}
	assert.Equal(t, expected, keys)
}

// COVERAGE: Test transposition skip conditions (e.g., space or end of string).
func TestTypo_Transposition_Skip(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// Guarantee Transposition typo (1.1)
	configureTypos(h, 1.1, 0.0, 0.0, 1.0, 0.0)

	ctx := context.Background()
	// Test case 1: Space involved
	text1 := "a b"
	err := h.Type(ctx, "#input", text1, nil)
	require.NoError(t, err)
	keys1 := getMockKeys(mock)
	// Expected: 'a', ' ', 'b' (No transposition around space)
	assert.Equal(t, []string{"a", " ", "b"}, keys1)

	// Test case 2: End of string
	mock.mu.Lock()
	mock.sentKeys = nil
	mock.mu.Unlock()

	text2 := "a"
	err = h.Type(ctx, "#input", text2, nil)
	require.NoError(t, err)
	keys2 := getMockKeys(mock)
	// Expected: 'a' (Cannot transpose the last character)
	assert.Equal(t, []string{"a"}, keys2)
}

func TestTypo_Omission_Unnoticed(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// FIX: Guarantee Omission typo (1.1), guarantee NOT noticing it (0.0)
	configureTypos(h, 1.1, 0.0, 0.0, 0.0, 1.0)
	h.baseConfig.TypoOmissionNoticeProbability = 0.0
	h.applyCombinedEffects()

	ctx := context.Background()
	text := "a"

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected sequence: Character omitted
	require.Empty(t, keys)
}

// COVERAGE: Test omission notice path.
func TestTypo_Omission_Noticed(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// Guarantee Omission typo (1.1), guarantee noticing it (1.1)
	configureTypos(h, 1.1, 0.0, 0.0, 0.0, 1.0)
	h.baseConfig.TypoOmissionNoticeProbability = 1.1
	h.applyCombinedEffects()

	ctx := context.Background()
	text := "a"

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected sequence: Character omitted (no key sent), then noticed and typed after a pause.
	expected := []string{"a"}
	assert.Equal(t, expected, keys)
}

// COVERAGE: Test omission skip condition (space).
func TestTypo_Omission_SkipSpace(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// Guarantee Omission typo (1.1)
	configureTypos(h, 1.1, 0.0, 0.0, 0.0, 1.0)

	ctx := context.Background()
	text := " "

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected: ' ' (Space should not be omitted)
	assert.Equal(t, []string{" "}, keys)
}

func TestTypo_Insertion_Corrected(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// Guarantee Insertion typo (by setting others to 0), guarantee correction (1.1)
	configureTypos(h, 1.1, 0.0, 0.0, 0.0, 0.0)
	h.baseConfig.TypoInsertionNoticeProbability = 1.1
	h.applyCombinedEffects()

	ctx := context.Background()
	text := "s"

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected sequence: Insertion (e.g., 'd'), Backspace, Intended ('s')
	require.Len(t, keys, 3)
	assert.Contains(t, "awedxz", keys[0])
	assert.Equal(t, string(KeyBackspace), keys[1])
	assert.Equal(t, "s", keys[2])
}

// COVERAGE: Test insertion unnoticed path.
func TestTypo_Insertion_Unnoticed(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	// Guarantee Insertion typo (by setting others to 0), guarantee NOT noticing (0.0)
	configureTypos(h, 1.1, 0.0, 0.0, 0.0, 0.0)
	h.baseConfig.TypoInsertionNoticeProbability = 0.0
	h.applyCombinedEffects()

	ctx := context.Background()
	text := "s"

	err := h.Type(ctx, "#input", text, nil)
	require.NoError(t, err)

	keys := getMockKeys(mock)
	// Expected sequence: Insertion (e.g., 'd'), Intended ('s')
	require.Len(t, keys, 2)
	assert.Contains(t, "awedxz", keys[0])
	assert.Equal(t, "s", keys[1])
}

// COVERAGE: Test the minimum key hold duration (20-25ms).
func TestKeyHoldDuration_Minimum(t *testing.T) {
	h, _ := setupKeyboardTest(t)

	// Configure parameters to result in a very small duration (< 20ms)
	h.baseConfig.KeyHoldMu = 1.0
	h.baseConfig.KeyHoldSigma = 0.1
	h.baseConfig.KeyHoldTau = 1.0
	h.applyCombinedEffects()

	h.resetRNG(1)

	h.mu.Lock()
	duration := h.keyHoldDuration()
	h.mu.Unlock()

	// The implementation ensures a minimum of 20ms + randomization (20ms to 25ms).
	assert.GreaterOrEqual(t, duration, 20*time.Millisecond)
	assert.LessOrEqual(t, duration, 25*time.Millisecond)
}

// COVERAGE: Test the specific scenario in keyPause where index=0 but runes=nil (correction pause).
func TestKeyPause_CorrectionPause(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	ctx := context.Background()

	// Configure parameters for the correction pause
	h.baseConfig.IKDMu = 100.0
	h.baseConfig.IKDSigma = 1.0
	h.baseConfig.IKDTau = 1.0

	h.dynamicConfig = h.baseConfig
	h.resetRNG(1) // Deterministic randomness

	// Define scales used during correction pauses (e.g., Mean 1.5, StdDev 0.8)
	meanScale := 1.5
	stdDevScale := 0.8

	// Expected duration ≈ (100 * 1.5) = 150ms (with minimal sigma/tau and seed 1)

	h.mu.Lock()
	// Call keyPause with index 0 and nil runes, but non-default scales.
	// This simulates the pause logic used during typo correction (introduceTypo functions).
	err := h.keyPause(ctx, meanScale, stdDevScale, nil, 0)
	h.mu.Unlock()

	require.NoError(t, err)

	sleeps := getMockSleeps(mock)
	require.Len(t, sleeps, 1)
	// Verify the duration reflects the scaling factors.
	assert.InDelta(t, 150.0, sleeps[0].Milliseconds(), 5.0)
}

// COVERAGE: Test specific IKD modeling factors.
// R2: Adopt Comparative Testing. Refactored this test to use comparative assertions
// instead of brittle value-based assertions (e.g., assert.InDelta(t, 91.0, ...)).
func TestKeyPause_IKDModeling(t *testing.T) {
	h, mock := setupKeyboardTest(t)
	ctx := context.Background()

	// Configure IKD parameters for clear distinctions
	h.baseConfig.IKDMu = 100.0
	h.baseConfig.IKDSigma = 1.0 // Minimal variation for testing
	h.baseConfig.IKDTau = 1.0
	h.baseConfig.KeyPauseMin = 10.0

	// Configure factors
	h.baseConfig.KeyPauseNgramFactor2 = 0.5
	h.baseConfig.IKDHandAlternationBonus = 0.7
	h.baseConfig.IKDSameFingerPenalty = 1.5
	h.baseConfig.IKDDistanceFactor = 0.1

	h.dynamicConfig = h.baseConfig

	// Helper to get the IKD duration for a sequence
	getIKD := func(text string) time.Duration {
		mock.mu.Lock()
		mock.sleepDurations = nil
		mock.mu.Unlock()
		h.resetRNG(1) // Deterministic randomness

		// FIX: Reset behavioral state for isolated measurement, as keyPause modifies fatigue.
		h.mu.Lock()
		// R1: Use standardized reset utility for behavioral state isolation.
		h.resetBehavioralState()
		/* Original manual reset removed:
		h.fatigueLevel = 0.0
		h.habituationLevel = 0.0
		h.applyCombinedEffects()
		*/

		// We only care about the pause before the second character.
		// Call the internal keyPause directly (requires holding the lock).
		runes := []rune(text)
		err := h.keyPause(ctx, 1.0, 1.0, runes, 1)
		h.mu.Unlock()
		require.NoError(t, err)

		sleeps := getMockSleeps(mock)
		// Should have exactly one sleep (the IKD).
		require.Len(t, sleeps, 1)
		return sleeps[0]
	}

	// 1. Baseline (e.g., 'as' - Same hand (0), different fingers (0, 1), short distance)
	ikdBaseline := getIKD("as")
	// R2: Removed brittle value-based assertion.
	// assert.InDelta(t, 110.0, ikdBaseline.Milliseconds(), 5.0)

	// 2. N-gram (e.g., 'th' - Common digraph, Hand alternation)
	ikdNgram := getIKD("th")
	assert.Less(t, ikdNgram, ikdBaseline, "N-gram ('th') should be faster than baseline ('as')")
	// R2: Removed brittle value-based assertion.
	// assert.InDelta(t, 39.0, ikdNgram.Milliseconds(), 5.0)

	// 3. Hand Alternation
	// Use 'fj' (Hand alternation, moderate distance).
	ikdHandAlt := getIKD("fj")
	assert.Less(t, ikdHandAlt, ikdBaseline, "Hand alternation ('fj') should be faster than baseline ('as')")
	// R2: Removed brittle value-based assertion.
	// assert.InDelta(t, 91.0, ikdHandAlt.Milliseconds(), 5.0)

	// 4. Same Finger Penalty (e.g., 'ee' - Same finger)
	ikdSameFinger := getIKD("ee")
	assert.Greater(t, ikdSameFinger, ikdBaseline, "Same finger ('ee') should be slower than baseline ('as')")
	// R2: Removed brittle value-based assertion.
	// assert.InDelta(t, 150.0, ikdSameFinger.Milliseconds(), 5.0)

	// 5. Distance (e.g., 'az' - Same hand, same finger (pinky), different rows)
	ikdDistance := getIKD("az")
	assert.Greater(t, ikdDistance, ikdBaseline, "Distance/Same finger ('az') should be slower than baseline ('as')")
	assert.Greater(t, ikdDistance, ikdSameFinger, "Distance ('az') should add penalty compared to same finger minimal distance ('ee')")
	// R2: Removed brittle value-based assertion.
	// assert.InDelta(t, 165.0, ikdDistance.Milliseconds(), 5.0)
}

// Test helper functions
func TestGetKeyInfo(t *testing.T) {
	infoA := getKeyInfo('a')
	assert.Equal(t, 0, infoA.Hand)

	infoJ := getKeyInfo('J') // Test case insensitivity
	assert.Equal(t, 1, infoJ.Hand)

	infoUnknown := getKeyInfo('@') // Test fallback
	assert.Equal(t, 1, infoUnknown.Hand)
}

// Moved from humanoid_test.go as it tests keyboard-specific configuration normalization
func TestNormalizeTypoRates(t *testing.T) {
	cfg := &config.HumanoidConfig{
		TypoRate:          -1.0,
		TypoNeighborRate:  2.0,
		TypoHomoglyphRate: 2.0,
		TypoTransposeRate: 2.0,
		TypoOmissionRate:  2.0,
	}

	normalizeTypoRates(cfg)

	assert.Equal(t, 0.0, cfg.TypoRate, "TypoRate < 0 should be normalized to 0")
	assert.Equal(t, 1.0, cfg.TypoNeighborRate, "Rates > 1.0 should be normalized to 1.0")
	assert.Equal(t, 1.0, cfg.TypoHomoglyphRate)
	assert.Equal(t, 1.0, cfg.TypoTransposeRate)
	assert.Equal(t, 1.0, cfg.TypoOmissionRate)

	cfg.TypoRate = 2.0
	normalizeTypoRates(cfg)
	assert.Equal(t, 1.0, cfg.TypoRate, "TypoRate > 1 should be normalized to 1")
}
