// internal/browser/humanoid/humanoid.go
package humanoid

import (
	"context"
	"math/rand"
	"sync"
	"time"

	"github.com/aquilax/go-perlin"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

const maxVelocity = 6000.0

// Humanoid defines the state and capabilities for simulating human like interactions.
type Humanoid struct {
	// mu protects all fields within the Humanoid struct from concurrent access.
	// Any method that reads or writes humanoid state (rng, currentPos, fatigueLevel, etc.)
	// must acquire this lock.
	mu                 sync.Mutex
	baseConfig         Config
	dynamicConfig      Config
	logger             *zap.Logger
	executor           Executor
	currentPos         Vector2D
	currentButtonState schemas.MouseButton
	fatigueLevel       float64
	lastActionTime     time.Time
	lastMovementDistance float64
	noiseTime          float64
	rng                *rand.Rand
	noiseX             *perlin.Perlin
	noiseY             *perlin.Perlin
}

// New creates and initializes a new Humanoid instance.
func New(config Config, logger *zap.Logger, executor Executor) *Humanoid {
	h := &Humanoid{
		logger:   logger,
		executor: executor,
	}

	// Lock immediately and defer unlock to protect all subsequent state changes.
	h.mu.Lock()
	defer h.mu.Unlock()

	var seed int64
	var rng *rand.Rand
	if config.Rng == nil {
		seed = time.Now().UnixNano()
		source := rand.NewSource(seed)
		rng = rand.New(source)
	} else {
		// Even if a specific rng is provided, we seed the perlin noise
		// with a unique value to ensure it's not the same across all instances.
		seed = time.Now().UnixNano()
		rng = config.Rng
	}

	config.NormalizeTypoRates()
	config.FinalizeSessionPersona(rng)

	// Standard Perlin noise parameters.
	alpha, beta, n := 2.0, 2.0, int32(3)

	// Assign all values within the locked context.
	h.baseConfig = config
	h.dynamicConfig = config
	h.rng = rng
	h.lastActionTime = time.Now()
	h.currentButtonState = schemas.ButtonNone
	h.noiseX = perlin.NewPerlin(alpha, beta, n, seed)
	h.noiseY = perlin.NewPerlin(alpha, beta, n, seed+1)

	return h
}

// NewTestHumanoid creates a Humanoid instance with deterministic dependencies for testing.
func NewTestHumanoid(executor Executor, seed int64) *Humanoid {
	config := DefaultConfig()
	source := rand.NewSource(seed)
	rng := rand.New(source)

	// Set the pre-seeded RNG in the config before calling New.
	config.Rng = rng

	h := New(config, zap.NewNop(), executor)

	// Lock again to safely modify state for testing purposes.
	h.mu.Lock()
	defer h.mu.Unlock()

	// The RNG from config is already set by New, but we can re-assign
	// noise generators for absolute test determinism.
	h.noiseX = perlin.NewPerlin(2, 2, 3, seed)
	h.noiseY = perlin.NewPerlin(2, 2, 3, seed+1)

	// Set specific dynamic config values for predictable test behavior.
	h.dynamicConfig.FittsA = 100.0
	h.dynamicConfig.FittsB = 150.0
	h.dynamicConfig.PerlinAmplitude = 2.0
	h.dynamicConfig.GaussianStrength = 0.5

	return h
}

// ensureVisible is a private helper that checks options and performs scrolling if needed.
// It's the core of the new "implicit scrolling" design.
// NOTE: This is an internal method and should NOT lock the mutex, as it's
// called by public methods that already hold the lock.
func (h *Humanoid) ensureVisible(ctx context.Context, selector string, opts *InteractionOptions) error {
	// Default behavior is to ensure visibility. This check makes the API easier to use,
	// as callers can just pass 'nil' for default options.
	if opts == nil || opts.EnsureVisible {
		// Calls the unexported method from scrolling.go
		return h.intelligentScroll(ctx, selector)
	}
	return nil
}