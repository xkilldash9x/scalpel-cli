// FILE: ./internal/browser/humanoid/behavior.go
package humanoid

import (
	"context"
	"math"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// randExGaussian generates a random value from an Ex-Gaussian distribution.
// This distribution models human reaction times accurately (Normal distribution convolved with an Exponential distribution).
// Assumes the caller holds the lock (uses h.rng).
func (h *Humanoid) randExGaussian(mu, sigma, tau float64) float64 {
	if mu <= 0 {
		mu = 1.0 // Ensure Mu is positive.
	}
	if sigma < 0 {
		sigma = 0
	}
	if tau <= 0 {
		tau = 1.0 // Ensure Tau is positive.
	}

	normal := h.rng.NormFloat64()*sigma + mu
	exponential := h.rng.ExpFloat64() * tau

	return normal + exponential
}

// CognitivePause simulates a human-like pause or delay, accounting for cognitive
// load, task switching, and fatigue. This is the primary method for introducing
// realistic delays in user interaction sequences. The duration is determined by
// an Ex-Gaussian distribution, which accurately models human reaction times.
//
// The pause duration is influenced by:
//   - Baseline reaction time parameters from the configuration.
//   - Scaling factors to model simple vs. complex decisions.
//   - A "task switching" penalty if the preceding action was of a different type (e.g., moving then typing).
//   - The current level of simulated fatigue.
//
// During longer pauses, this method will also simulate subtle, continuous mouse
// drift (hesitation) to avoid unnaturally static cursor behavior.
//
// Parameters:
//   - ctx: The context for the operation.
//   - meanScale: A factor to scale the mean (mu) of the Ex-Gaussian distribution.
//     Values > 1.0 simulate longer average pauses (e.g., for complex decisions).
//   - stdDevScale: A factor to scale the standard deviation (sigma) and exponential
//     component (tau), affecting the variability and likelihood of long delays.
//
// Returns an error if the context is cancelled during the pause.
func (h *Humanoid) CognitivePause(ctx context.Context, meanScale, stdDevScale float64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Pass ActionTypePause to the internal implementation.
	return h.cognitivePause(ctx, meanScale, stdDevScale, ActionTypePause)
}

// cognitivePause is the internal, non-locking implementation.
// It calculates the pause duration, handles task switching delays, updates behavioral models, and executes the pause.
func (h *Humanoid) cognitivePause(ctx context.Context, meanScale, stdDevScale float64, currentAction ActionType) error {
	// 1. Calculate Base Pause Duration (Ex-Gaussian Model)
	// Use dynamic config parameters as they are affected by fatigue/habituation.
	cfg := h.dynamicConfig
	rng := h.rng

	// Apply scaling factors to the distribution parameters.
	// stdDevScale affects both Sigma (variability) and Tau (likelihood of long delays).
	mu := cfg.ExGaussianMu * meanScale
	sigma := cfg.ExGaussianSigma * stdDevScale
	tau := cfg.ExGaussianTau * stdDevScale

	durationMs := h.randExGaussian(mu, sigma, tau)

	// 2. Incorporate Task Switching Delay
	taskSwitchDelayMs := 0.0
	// Apply delay if the action type changes, unless the previous action was a pause itself.
	if h.lastActionType != ActionTypeNone && h.lastActionType != currentAction && h.lastActionType != ActionTypePause {
		// Task switch delay is also modeled as Ex-Gaussian, using configured parameters.
		taskSwitchDelayMs = h.randExGaussian(cfg.TaskSwitchMu, cfg.TaskSwitchSigma, cfg.TaskSwitchTau)
		h.logger.Debug("Humanoid: Applying Task Switch Delay",
			zap.String("from", string(h.lastActionType)),
			zap.String("to", string(currentAction)),
			zap.Float64("delay_ms", taskSwitchDelayMs))
	}
	durationMs += taskSwitchDelayMs

	// 3. Apply Fatigue Factor
	// Fatigue increases the duration of cognitive processes.
	fatigueFactor := 1.0 + h.fatigueLevel
	durationMs *= fatigueFactor

	// Ensure a minimum realistic pause.
	if durationMs < 10.0 {
		durationMs = 10.0 + rng.Float64()*5.0
	}

	// FIX: Convert float64 milliseconds to time.Duration (int64 nanoseconds) accurately to prevent truncation.
	duration := time.Duration(durationMs * float64(time.Millisecond))

	// 4. Update Behavioral Models
	// Recover fatigue during the pause.
	h.recoverFatigue(duration)
	// Update the last action type *after* calculating the switch delay.
	h.lastActionType = currentAction

	// 5. Execute Pause (Hesitation/Idling)
	// Simulate active idling (hesitation/drift) if the pause is significant.
	// Use the configured AntiPeriodicityMinPause threshold.
	if duration > h.baseConfig.AntiPeriodicityMinPause {
		// Call the internal, non-locking version of Hesitate.
		return h.hesitate(ctx, duration)
	}

	// For very short pauses, simply sleep.
	return h.executor.Sleep(ctx, duration)
}

// Hesitate simulates a user pausing and idling, causing the cursor to drift
// subtly around its current position using Pink Noise. This is used to model
// user hesitation or brief periods of inactivity, making cursor behavior more
// natural than a simple sleep.
//
// This is a public, thread-safe method. For internal use where a lock is already
// held, call the `hesitate` method directly.
//
// Parameters:
//   - ctx: The context for the operation.
//   - duration: The total duration of the hesitation period.
//
// Returns an error if the context is cancelled during the hesitation.
func (h *Humanoid) Hesitate(ctx context.Context, duration time.Duration) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hesitate(ctx, duration)
}

// hesitate is the internal, non-locking implementation of cursor idling using Pink noise drift and anti-periodicity measures.
func (h *Humanoid) hesitate(ctx context.Context, duration time.Duration) error {
	startPos := h.currentPos
	currentButtons := h.calculateButtonsBitfield(h.currentButtonState)
	startTime := time.Now()

	// Define parameters for the idle drift using injected configuration.
	// Use dynamic config as amplitude is affected by fatigue.
	cfg := h.dynamicConfig
	baseCfg := h.baseConfig

	// Amplitude is increased for idling compared to trajectory waver.
	// We use Pink Noise Amplitude here instead of Perlin.
	driftAmplitude := cfg.PinkNoiseAmplitude * cfg.HesitationDriftFactor

	// Anti-Periodicity parameters
	timeStepBase := baseCfg.TimeStep
	stochasticJitter := baseCfg.AntiPeriodicityTimeJitter
	frameDropProb := baseCfg.AntiPeriodicityFrameDropProb
	rng := h.rng

	for time.Since(startTime) < duration {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// 1. Calculate Drift using Pink Noise (1/f).
		// Pink noise generators are stateful and advanced at each step.
		drift := Vector2D{
			X: h.noiseX.Next() * driftAmplitude,
			Y: h.noiseY.Next() * driftAmplitude,
		}

		targetPos := startPos.Add(drift)

		// 2. Apply Gaussian noise (tremor) on top of the drift.
		finalPos := h.applyGaussianNoise(targetPos)

		// 3. Anti-Periodicity: Probabilistic Frame Dropping
		// Skip dispatching the event occasionally to break rhythmic patterns.
		if rng.Float64() > frameDropProb {
			// Dispatch the movement event.
			eventData := schemas.MouseEventData{
				Type:    schemas.MouseMove,
				X:       finalPos.X,
				Y:       finalPos.Y,
				Button:  schemas.ButtonNone,
				Buttons: currentButtons,
			}

			if err := h.executor.DispatchMouseEvent(ctx, eventData); err != nil {
				return err
			}
		}
		// Always update internal position even if frame was dropped.
		h.currentPos = finalPos

		// 4. Anti-Periodicity: Stochastic Time Step
		// Jitter the sleep duration (e.g., +/- 2ms on a 5ms base).
		jitter := (rng.Float64()*2.0 - 1.0) * stochasticJitter.Seconds()
		pauseDuration := time.Duration((timeStepBase.Seconds() + jitter) * float64(time.Second))

		// Ensure we don't overshoot the total duration.
		if time.Since(startTime)+pauseDuration > duration {
			pauseDuration = duration - time.Since(startTime)
		}
		if pauseDuration <= 0 {
			break
		}

		if err := h.executor.Sleep(ctx, pauseDuration); err != nil {
			return err
		}
	}
	return nil
}

// applyGaussianNoise adds high-frequency "tremor" to a mouse coordinate.
func (h *Humanoid) applyGaussianNoise(point Vector2D) Vector2D {
	// Strength is randomized slightly (50% to 150%) around the configured value.
	strength := h.dynamicConfig.GaussianStrength * (0.5 + h.rng.Float64())
	pX := h.rng.NormFloat64() * strength
	pY := h.rng.NormFloat64() * strength

	return Vector2D{X: point.X + pX, Y: point.Y + pY}
}

// applyClickNoise adds small displacement noise that occurs during the physical action of clicking/grabbing.
func (h *Humanoid) applyClickNoise(point Vector2D) Vector2D {
	// Strength is influenced by the configuration (via dynamicConfig) and randomized slightly.
	strength := h.dynamicConfig.ClickNoise * (0.5 + h.rng.Float64())

	// X noise is randomized normally (reduced effect).
	pX := h.rng.NormFloat64() * strength * 0.5
	// Use Abs() to ensure the Y bias is positive (downwards).
	pY := math.Abs(h.rng.NormFloat64() * strength)

	return Vector2D{X: point.X + pX, Y: point.Y + pY}
}

// applyCombinedEffects adjusts the dynamic configuration based on current fatigue and habituation levels.
// This function encapsulates the logic of how internal states impact motor control and cognitive speed.
func (h *Humanoid) applyCombinedEffects() {
	// FIX: Start by syncing dynamicConfig with baseConfig. This ensures that parameters not directly
	// affected by fatigue/habituation (like TypoCorrectionProbability) are correctly reflected,
	// which is crucial for deterministic testing when baseConfig is modified.
	h.dynamicConfig = h.baseConfig

	fatigueLevel := h.fatigueLevel
	// Habituation counteracts fatigue. The net effect is Fatigue - Habituation.
	netImpairment := math.Max(0.0, fatigueLevel-h.habituationLevel)
	impairmentFactor := 1.0 + netImpairment

	// Impairment increases noise (tremor, drift, and click displacement).
	h.dynamicConfig.GaussianStrength = h.baseConfig.GaussianStrength * impairmentFactor
	// Updated to use PinkNoiseAmplitude.
	h.dynamicConfig.PinkNoiseAmplitude = h.baseConfig.PinkNoiseAmplitude * impairmentFactor
	h.dynamicConfig.ClickNoise = h.baseConfig.ClickNoise * impairmentFactor
	// Signal-Dependent Noise increases with impairment.
	h.dynamicConfig.SDNFactor = h.baseConfig.SDNFactor * impairmentFactor

	// Impairment increases reaction time (FittsA and Ex-Gaussian Mu/Tau).
	h.dynamicConfig.FittsA = h.baseConfig.FittsA * impairmentFactor
	h.dynamicConfig.ExGaussianMu = h.baseConfig.ExGaussianMu * impairmentFactor
	// Tau (long delays) is more sensitive to impairment than Mu (base reaction time).
	h.dynamicConfig.ExGaussianTau = h.baseConfig.ExGaussianTau * (1.0 + netImpairment*1.5)

	// Impairment affects motor control parameters (Omega/Zeta).
	// Movement is slower (lower Omega) and potentially less stable (slightly lower Zeta).
	// These hardcoded multipliers (0.3, 0.1) define the sensitivity of the physics model.
	h.dynamicConfig.Omega = h.baseConfig.Omega * (1.0 - netImpairment*0.3)
	h.dynamicConfig.Zeta = h.baseConfig.Zeta * (1.0 - netImpairment*0.1)

	// Impairment significantly increases the likelihood of making mistakes (TypoRate).
	h.dynamicConfig.TypoRate = h.baseConfig.TypoRate * (1.0 + netImpairment*2.0)

	// FIX: The original cap of 0.25 prevents deterministic testing of typo logic (where rates > 1.0 are used).
	// We adjust the cap behavior: apply the 25% cap only if the base rate is realistic (<= 1.0).
	// If base rate > 1.0, we assume it's a test scenario and do not apply the cap.
	if h.baseConfig.TypoRate <= 1.0 {
		h.dynamicConfig.TypoRate = math.Min(0.25, h.dynamicConfig.TypoRate) // Cap typo rate at 25% for realism.
	}
}

// updateFatigueAndHabituation modifies behavioral levels based on action intensity. It assumes the lock is held.
func (h *Humanoid) updateFatigueAndHabituation(intensity float64) {
	// Increase fatigue based on the configured rate and the intensity of the action.
	fatigueIncrease := h.baseConfig.FatigueIncreaseRate * intensity
	h.fatigueLevel += fatigueIncrease
	h.fatigueLevel = math.Min(1.0, h.fatigueLevel) // Cap fatigue at 1.0.

	// Increase habituation (learning/warming up). Habituation increases slower than fatigue.
	habituationIncrease := h.baseConfig.HabituationRate * intensity
	h.habituationLevel += habituationIncrease
	// Habituation is capped lower than fatigue (e.g., 0.5), representing the limit of improvement within a session.
	h.habituationLevel = math.Min(0.5, h.habituationLevel)

	h.applyCombinedEffects()
}

// recoverFatigue simulates recovery from fatigue during pauses. Habituation does not decay significantly within a session.
// It assumes the lock is held.
func (h *Humanoid) recoverFatigue(duration time.Duration) {
	// Recover fatigue based on the configured rate and the duration of the pause (in seconds).
	recovery := h.baseConfig.FatigueRecoveryRate * duration.Seconds()
	h.fatigueLevel -= recovery
	h.fatigueLevel = math.Max(0.0, h.fatigueLevel) // Ensure fatigue doesn't drop below 0.0.

	h.applyCombinedEffects()
}

// calculateButtonsBitfield converts the internal MouseButton state into the standard bitfield representation.
func (h *Humanoid) calculateButtonsBitfield(buttonState schemas.MouseButton) int64 {
	var buttons int64
	switch buttonState {
	case schemas.ButtonLeft:
		buttons = 1
	case schemas.ButtonRight:
		buttons = 2
	case schemas.ButtonMiddle:
		buttons = 4
	}
	return buttons
}
