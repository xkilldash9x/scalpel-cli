// internal/browser/humanoid/humanoid.go
package humanoid

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// Humanoid defines the state and capabilities for simulating human like interactions.
type Humanoid struct {
	// mu protects all fields within the Humanoid struct from concurrent access.
	mu sync.Mutex
	// baseConfig holds the initial configuration for the session persona.
	baseConfig config.HumanoidConfig
	// dynamicConfig holds the current configuration, which changes based on fatigue and habituation.
	dynamicConfig config.HumanoidConfig
	logger        *zap.Logger
	executor      Executor

	// State variables
	currentPos         Vector2D
	currentButtonState schemas.MouseButton
	// Behavioral state
	fatigueLevel     float64
	habituationLevel float64
	// SkillFactor (0.5 to 1.5) determines the baseline efficiency of the persona.
	skillFactor float64
	// lastActionType used for calculating task switching delays.
	lastActionType ActionType

	// Timing and Noise generation
	rng *rand.Rand
	// noiseX and noiseY use Pink Noise (1/f) for realistic physiological drift.
	noiseX *PinkNoiseGenerator
	noiseY *PinkNoiseGenerator
}

// New creates and initializes a new Humanoid instance.
func New(humanoidCfg config.HumanoidConfig, logger *zap.Logger, executor Executor) *Humanoid {

	// FIX: Refactor New() initialization. The previous implementation used an unnecessary lock
	// (as the object is not yet shared) and partially initialized the struct.
	// We now perform calculations first and initialize the struct atomically.

	// humanoidCfg is passed by value, so we use a local copy for modifications.
	cfg := humanoidCfg

	seed := time.Now().UnixNano()
	source := rand.NewSource(seed)
	rng := rand.New(source)

	// Calculate the SkillFactor first as it influences the persona finalization.
	// Skill is normally distributed around 1.0, clamped between 0.5 and 1.5.
	skillJitter := cfg.PersonaJitterSkill
	skillFactor := 1.0 + rng.NormFloat64()*skillJitter
	skillFactor = math.Max(0.5, math.Min(1.5, skillFactor))

	normalizeTypoRates(&cfg)
	// Randomize the configuration slightly to create a unique session persona.
	finalizeSessionPersona(&cfg, rng, skillFactor)

	// Pink noise parameters (12 oscillators is standard).
	nOscillators := 12

	// Initialize the struct fully.
	h := &Humanoid{
		logger:             logger,
		executor:           executor,
		baseConfig:         cfg,
		dynamicConfig:      cfg, // Dynamic starts the same as base.
		rng:                rng,
		skillFactor:        skillFactor,
		currentButtonState: schemas.ButtonNone,
		lastActionType:     ActionTypeNone,
		// Initialize Pink Noise generators with separate seeds.
		noiseX: NewPinkNoiseGenerator(rand.New(rand.NewSource(seed)), nOscillators),
		noiseY: NewPinkNoiseGenerator(rand.New(rand.NewSource(seed+1)), nOscillators),
	}
	return h
}

// NewTestHumanoid creates a Humanoid instance with deterministic dependencies for testing.
func NewTestHumanoid(executor Executor, seed int64) *Humanoid {
	// Create a default configuration and then override specific values for testing.
	defaultCfg := config.NewDefaultConfig()
	humanoidCfg := defaultCfg.Browser().Humanoid

	// Set specific values for predictable test behavior.
	humanoidCfg.FittsA = 100.0
	humanoidCfg.FittsB = 150.0
	humanoidCfg.Omega = 30.0
	humanoidCfg.Zeta = 0.8
	// Updated noise model configuration
	humanoidCfg.PinkNoiseAmplitude = 2.0
	humanoidCfg.GaussianStrength = 0.5
	humanoidCfg.SDNFactor = 0.001
	humanoidCfg.TypoRate = 0.0
	humanoidCfg.TypoHomoglyphRate = 0.0
	humanoidCfg.ClickNoise = 1.0
	humanoidCfg.FatigueIncreaseRate = 0.01
	humanoidCfg.FatigueRecoveryRate = 0.01
	humanoidCfg.HabituationRate = 0.005

	// FIX: Initialize the struct manually instead of calling New() to ensure determinism
	// and prevent finalizeSessionPersona from running with randomized values.
	source := rand.NewSource(seed)
	rng := rand.New(source)
	nOscillators := 12

	h := &Humanoid{
		logger:             zap.NewNop(),
		executor:           executor,
		baseConfig:         humanoidCfg,
		dynamicConfig:      humanoidCfg, // Ensure dynamic config matches the base config.
		rng:                rng,
		currentButtonState: schemas.ButtonNone,
		lastActionType:     ActionTypeNone,
		// Force skill factor for testing.
		skillFactor: 1.0,
		// Initialize Pink Noise generators with deterministic seeds.
		noiseX: NewPinkNoiseGenerator(rand.New(rand.NewSource(seed)), nOscillators),
		noiseY: NewPinkNoiseGenerator(rand.New(rand.NewSource(seed+1)), nOscillators),
	}

	// We do NOT call finalizeSessionPersona here, as tests rely on the predictable baseConfig values.

	return h
}

// ensureVisible is a private helper that checks options and performs scrolling if needed.
func (h *Humanoid) ensureVisible(ctx context.Context, selector string, opts *InteractionOptions) error {
	// Determine if visibility should be ensured. Defaults to true.
	shouldEnsure := true

	// If options are provided and EnsureVisible is explicitly set (not nil), use that value.
	if opts != nil && opts.EnsureVisible != nil {
		shouldEnsure = *opts.EnsureVisible
	}

	if shouldEnsure {
		// Calls the unexported method from scrolling.go
		return h.intelligentScroll(ctx, selector)
	}
	return nil
}

// releaseMouse is an internal helper that ensures the mouse button (currently only left) is released.
func (h *Humanoid) releaseMouse(ctx context.Context) error {
	currentPos := h.currentPos
	// Currently, we only track the primary (left) button state for dragging/clicking.
	if h.currentButtonState != schemas.ButtonLeft {
		return nil // Nothing to do if the left button isn't pressed according to our state.
	}

	h.logger.Debug("Humanoid: Executing mouse release (cleanup/action completion)")

	mouseUpData := schemas.MouseEventData{
		Type:       schemas.MouseRelease,
		X:          currentPos.X,
		Y:          currentPos.Y,
		Button:     schemas.ButtonLeft,
		ClickCount: 1,
		Buttons:    0, // Bitfield: 0 indicates no buttons are pressed after release.
	}

	err := h.executor.DispatchMouseEvent(ctx, mouseUpData)
	if err != nil {
		// Log the failure but continue to update state to prevent the simulation from getting stuck
		// with the button virtually pressed.
		h.logger.Error("Humanoid: Failed to dispatch mouse release event, but updating internal state anyway", zap.Error(err))
	}

	// Always update the internal state to "none", regardless of dispatch success.
	h.currentButtonState = schemas.ButtonNone

	return err
}

// --- Unexported Helper Functions ---

// normalizeTypoRates ensures the typo rates are clamped within the valid [0.0, 1.0] range.
func normalizeTypoRates(c *config.HumanoidConfig) {
	if c.TypoRate < 0.0 {
		c.TypoRate = 0.0
	}
	if c.TypoRate > 1.0 {
		c.TypoRate = 1.0
	}

	// Ensure individual typo type rates (which are proportions of the total typo rate) don't exceed 1.0.
	if c.TypoHomoglyphRate > 1.0 {
		c.TypoHomoglyphRate = 1.0
	}
	if c.TypoNeighborRate > 1.0 {
		c.TypoNeighborRate = 1.0
	}
	if c.TypoTransposeRate > 1.0 {
		c.TypoTransposeRate = 1.0
	}
	if c.TypoOmissionRate > 1.0 {
		c.TypoOmissionRate = 1.0
	}
}

// Define constants for performance clamping (FIX: TestInteractor/FormInteraction_VariousTypes Timeout)
// These ensure that randomized personas maintain a minimum level of responsiveness, preventing
// excessively slow behavior (especially cognitive pauses during typing) from causing context timeouts.
const (
	MaxFittsA          = 300.0 // ms (Maximum intercept time for movement)
	MaxFittsB          = 400.0 // ms/bit (Maximum slope for movement speed)
	MaxExGaussianMu    = 500.0 // ms (Maximum average cognitive reaction time)
	MaxExGaussianSigma = 150.0 // ms (Maximum standard deviation of reaction time)
)

// finalizeSessionPersona slightly randomizes the configuration parameters
// and applies the correlated SkillFactor to simulate a unique user persona.
func finalizeSessionPersona(c *config.HumanoidConfig, rng *rand.Rand, skillFactor float64) {
	// 1. Apply Random Jitter (Independent variation)
	movementJitter := c.PersonaJitterMovement
	// Calculate randomization factor: (rng.Float64()-0.5) gives range [-0.5, 0.5].
	// Multiplying by (jitter*2) gives the desired range (e.g., +/- 0.15).
	c.FittsA *= 1.0 + (rng.Float64()-0.5)*(movementJitter*2)
	c.FittsB *= 1.0 + (rng.Float64()-0.5)*(movementJitter*2)
	c.Omega *= 1.0 + (rng.Float64()-0.5)*(movementJitter*2)

	dampingJitter := c.PersonaJitterDamping
	c.Zeta *= 1.0 + (rng.Float64()-0.5)*(dampingJitter*2)

	// 2. Apply Skill Factor (Correlated variation)
	// Higher skill (skillFactor > 1.0) means faster movement (lower Fitts A/B, higher Omega)
	// and fewer errors (lower TypoRate, higher CorrectionProbability).
	inverseSkill := 1.0 / skillFactor

	// Movement speed correlates strongly with skill.
	c.FittsA *= inverseSkill
	c.FittsB *= inverseSkill
	c.Omega *= skillFactor

	// Reaction times (Ex-Gaussian Mu/Sigma) correlate with skill.
	c.ExGaussianMu *= inverseSkill
	c.ExGaussianSigma *= inverseSkill
	// The exponential component (Tau) is less affected by skill, more by cognitive load/distraction.

	// Error rates correlate strongly with skill.
	c.TypoRate *= inverseSkill
	// Skilled users correct errors more often.
	c.TypoCorrectionProbability *= skillFactor
	// Clamp probabilities to [0, 1].
	c.TypoCorrectionProbability = math.Min(1.0, c.TypoCorrectionProbability)

	// Motor noise is slightly reduced in skilled users.
	c.GaussianStrength *= (1.0 + (inverseSkill-1.0)*0.5)
	c.PinkNoiseAmplitude *= (1.0 + (inverseSkill-1.0)*0.5)
	c.SDNFactor *= (1.0 + (inverseSkill-1.0)*0.5)

	// 3. Clamp performance parameters to ensure minimum responsiveness.
	c.FittsA = math.Min(c.FittsA, MaxFittsA)
	c.FittsB = math.Min(c.FittsB, MaxFittsB)
	c.ExGaussianMu = math.Min(c.ExGaussianMu, MaxExGaussianMu)
	c.ExGaussianSigma = math.Min(c.ExGaussianSigma, MaxExGaussianSigma)
}
