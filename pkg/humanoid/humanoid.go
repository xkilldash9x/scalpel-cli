// pkg/humanoid/humanoid.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/aquilax/go-perlin"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// maxVelocity defines the maximum physiological mouse velocity (pixels per second).
// This is a fundamental constraint of the simulation used in movement dynamics.
const maxVelocity = 6000.0

// Humanoid manages the interaction simulation for a specific browser context.
type Humanoid struct {
	// Base configuration (The finalized session persona)
	baseConfig       Config
	browserContextID target.BrowserContextID
	logger           *zap.Logger

	// Internal state
	mu         sync.Mutex
	currentPos Vector2D
	rng        *rand.Rand

	// Noise generators for natural movement simulation.
	noiseX *perlin.Perlin
	noiseY *perlin.Perlin

	// Fatigue tracking
	fatigueLevel   float64 // Current fatigue level (0.0 to 1.0)
	lastActionTime time.Time

	// Dynamic configuration (Derived from baseConfig and affected by fatigue)
	dynamicConfig Config
}

// New creates a new Humanoid instance with a specific configuration.
func New(config Config, browserContextID target.BrowserContextID, logger *zap.Logger) *Humanoid {
	// 1. Initialize RNG
	var seed int64
	var rng *rand.Rand
	if config.Rng == nil {
		seed = time.Now().UnixNano()
		source := rand.NewSource(seed)
		rng = rand.New(source)
	} else {
		// Use provided Rng, derive seed for Perlin generators.
		seed = config.Rng.Int63()
		rng = config.Rng
	}

	// 2. Finalize the Session Persona (Temporal Consistency)
	// This samples the distribution parameters defined in the archetype Config
	// to create fixed instance parameters for this session.
	config.NormalizeTypoRates()
	config.FinalizeSessionPersona(rng)

	// Standard Perlin parameters (Alpha=2, Beta=2, N=3)
	alpha, beta, n := 2.0, 2.0, int32(3)

	h := &Humanoid{
		baseConfig:       config,
		dynamicConfig:    config, // Initialize dynamic config (fatigue=0)
		browserContextID: browserContextID,
		logger:           logger,
		rng:              rng,
		// Initial position defaults until InitializePosition is called.
		currentPos:     Vector2D{X: 0.0, Y: 0.0},
		fatigueLevel:   0.0,
		lastActionTime: time.Now(),
		noiseX:         perlin.NewPerlin(alpha, beta, n, seed),
		noiseY:         perlin.NewPerlin(alpha, beta, n, seed+1), // Offset seed for Y noise
	}

	logger.Debug("Humanoid: Initialized new session persona",
		zap.Float64("Omega", config.Omega),
		zap.Float64("Zeta", config.Zeta),
		zap.Float64("TypoRate", config.TypoRate))

	return h
}

// InitializePosition sets the initial cursor position realistically within the viewport.
func (h *Humanoid) InitializePosition(ctx context.Context) error {
	// 1. Get the layout metrics.
	layout, err := page.GetLayoutMetrics().Do(ctx)
	if err != nil {
		// Log error but attempt fallback if metrics are partially available.
		h.logger.Warn("Humanoid: failed to get layout metrics", zap.Error(err))
	}

	var width, height float64
	if layout != nil && layout.VisualViewport != nil {
		width = layout.VisualViewport.ClientWidth
		height = layout.VisualViewport.ClientHeight
	}

	if width <= 0 || height <= 0 {
		// Fallback if visual viewport isn't ready or metrics call failed completely.
		h.logger.Warn("Humanoid: Viewport metrics unavailable or zero, falling back to default size.")
		width, height = 1024, 768
	}

	// 2. Determine starting position (center biased, randomized).
	h.mu.Lock()
	// Gaussian distribution around the center.
	startX := (width / 2.0) + h.rng.NormFloat64()*(width/8.0)
	startY := (height / 2.0) + h.rng.NormFloat64()*(height/8.0)

	// Clamp to viewport bounds.
	startX = math.Max(1.0, math.Min(startX, width-1.0))
	startY = math.Max(1.0, math.Min(startY, height-1.0))

	h.currentPos = Vector2D{X: startX, Y: startY}
	h.lastActionTime = time.Now() // Reset timer
	h.mu.Unlock()

	// 3. Dispatch the initial mouse move event.
	dispatchMove := input.DispatchMouseEvent(input.MouseMoved, startX, startY)
	if err := dispatchMove.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: failed to dispatch initial mouse move: %w", err)
	}

	h.logger.Debug("Humanoid: Initialized position", zap.Float64("X", startX), zap.Float64("Y", startY))
	return nil
}

// SetConfig updates the Humanoid configuration archetype. This involves generating a new session persona.
func (h *Humanoid) SetConfig(config Config) {
	config.NormalizeTypoRates()

	h.mu.Lock()
	defer h.mu.Unlock()

	// Use the existing RNG if a new one isn't provided
	if config.Rng == nil {
		config.Rng = h.rng
	}
	// Generate new session parameters based on the new config archetype
	config.FinalizeSessionPersona(config.Rng)

	h.baseConfig = config
	h.rng = config.Rng
	// Recalculate dynamic config based on current fatigue and new base config.
	h.updateDynamicConfig()
}

// GetCurrentPos safely retrieves the humanoid's current cursor position.
func (h *Humanoid) GetCurrentPos() Vector2D {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.currentPos
}

// updateFatigue updates the fatigue level based on elapsed time (recovery) and the action intensity (increase).
func (h *Humanoid) updateFatigue(actionIntensity float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(h.lastActionTime).Seconds()
	h.lastActionTime = now

	// 1. Recover fatigue during inactivity.
	// Recovery rate is defined in the base config (session persona).
	recovery := h.baseConfig.FatigueRecoveryRate * elapsed
	h.fatigueLevel = math.Max(0.0, h.fatigueLevel-recovery)

	// 2. Increase fatigue due to the action.
	// Increase rate is defined in the base config (session persona).
	increase := h.baseConfig.FatigueIncreaseRate * actionIntensity
	h.fatigueLevel = math.Min(1.0, h.fatigueLevel+increase)

	// 3. Update dynamic configuration based on the new fatigue level.
	h.updateDynamicConfig()
}

// updateDynamicConfig recalculates parameters affected by fatigue.
// Must be called while holding the lock.
func (h *Humanoid) updateDynamicConfig() {
	// Fatigue (f) linearly interpolates parameters between the base config (0 fatigue)
	// and a maximum degradation (1.0 fatigue).

	f := h.fatigueLevel
	base := h.baseConfig

	// Define maximum degradation factors (tunable).
	// These represent how much worse performance gets at maximum fatigue (f=1.0).
	maxFittsADegradation := 1.5 // 50% slower latency
	maxFittsBDegradation := 1.3 // 30% slower throughput
	maxNoiseDegradation := 2.0  // 100% more noise (tremor/drift)
	maxTypoDegradation := 2.5   // 150% more typos
	maxKeyHoldDegradation := 1.3 // 30% longer key holds

	// Apply degradation factors using linear interpolation: NewVal = BaseVal * (1.0 + f * (MaxDegradation - 1.0))
	h.dynamicConfig.FittsA = base.FittsA * (1.0 + f*(maxFittsADegradation-1.0))
	h.dynamicConfig.FittsB = base.FittsB * (1.0 + f*(maxFittsBDegradation-1.0))
	h.dynamicConfig.GaussianStrength = base.GaussianStrength * (1.0 + f*(maxNoiseDegradation-1.0))
	h.dynamicConfig.PerlinAmplitude = base.PerlinAmplitude * (1.0 + f*(maxNoiseDegradation-1.0))
	h.dynamicConfig.TypoRate = base.TypoRate * (1.0 + f*(maxTypoDegradation-1.0))
	h.dynamicConfig.KeyHoldMean = base.KeyHoldMean * (1.0 + f*(maxKeyHoldDegradation-1.0))

	// Ensure TypoRate doesn't exceed a reasonable maximum (e.g., 20%).
	h.dynamicConfig.TypoRate = math.Min(0.20, h.dynamicConfig.TypoRate)
}

// pause introduces a variable delay. Used for short physiological delays (e.g., click duration).
func (h *Humanoid) pause(ctx context.Context, mean, stdDev float64) error {
	// Optimized: Minimize lock duration.
	h.mu.Lock()
	randVal := h.rng.NormFloat64()
	h.mu.Unlock()

	delay := randVal*stdDev + mean

	if delay < 0 {
		delay = 0
	}

	// Kept as a simple sleep for performance during rapid actions.
	select {
	case <-time.After(time.Duration(delay) * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CognitivePause introduces a longer delay simulating thinking or reaction time,
// during which the cursor exhibits idle movements. It also allows for fatigue recovery.
func (h *Humanoid) CognitivePause(ctx context.Context, mean, stdDev float64) error {
	// Update fatigue based on the pause (allowing recovery).
	h.updateFatigue(0.0)

	h.mu.Lock()
	randVal := h.rng.NormFloat64()
	// Fatigue slightly increases cognitive pause times (sluggishness).
	fatigueFactor := 1.0 + h.fatigueLevel*0.5 // Up to 50% longer pause when fatigued.
	h.mu.Unlock()

	mean *= fatigueFactor

	delay := randVal*stdDev + mean
	if delay < 50 {
		delay = 50 // Minimum pause duration
	}

	// Use Hesitate during the pause to simulate idle movement.
	return h.Hesitate(time.Duration(delay) * time.Millisecond).Do(ctx)
}
