// internal/humanoid/humanoid.go
package humanoid

import (
	"sync"
	"time"
	"math/rand"

	"github.com/aquilax/go-perlin"
	// "github.com/chromedp/cdproto/cdp" // Removed
	"go.uber.org/zap"
)

// maxVelocity defines the maximum physiological mouse velocity (pixels per second).
const maxVelocity = 6000.0

// NOTE: MouseButton type and constants are now defined in types.go.

// Humanoid manages the state and execution of human-like interactions.
type Humanoid struct {
	// Base configuration (defines the session persona)
	baseConfig Config
	// Dynamic configuration (current state, affected by fatigue)
	dynamicConfig Config

	// Browser context, logging, and execution
	// browserContextID cdp.BrowserContextID // Removed
	logger            *zap.Logger
	executor          Executor // Facilitates interaction via the Executor interface.

	// Internal state synchronization
	mu sync.Mutex

	// Current cursor position and state
	currentPos          Vector2D
	currentButtonState  MouseButton // Uses agnostic type from types.go

	// Fatigue modeling
	fatigueLevel float64 // Ranges from 0.0 (rested) to 1.0 (exhausted)

	// State tracking
	lastActionTime        time.Time
	lastMovementDistance  float64 // Tracks the distance of the last MoveTo action for Fitts's Law.
	noiseTime             float64

	// Noise generation
	rng     *rand.Rand
	noiseX  *perlin.Perlin
	noiseY  *perlin.Perlin
}

// New creates a new Humanoid instance with the given configuration and executor.
// The executor is required for all browser interactions.
// We remove the dependency on cdp.BrowserContextID.
func New(config Config, logger *zap.Logger, executor Executor) *Humanoid {
	// 1. Initialize RNG
	var seed int64
	var rng *rand.Rand
	if config.Rng == nil {
		seed = time.Now().UnixNano()
		source := rand.NewSource(seed)
		rng = rand.New(source)
	} else {
		// If an RNG is provided, use it. Use a randomized seed for Perlin noise.
		seed = time.Now().UnixNano()
		rng = config.Rng
	}

	// 2. Finalize the Session Persona
	config.NormalizeTypoRates()
	config.FinalizeSessionPersona(rng)

	// Standard Perlin parameters
	alpha, beta, n := 2.0, 2.0, int32(3)

	h := &Humanoid{
		baseConfig:          config,
		dynamicConfig:       config, // Start with the base config
		logger:              logger,
		executor:            executor, // Initialize the executor
		rng:                 rng,
		lastActionTime:      time.Now(),
		currentButtonState:  ButtonNone, // Use constant from types.go
		noiseX:              perlin.NewPerlin(alpha, beta, n, seed),
		noiseY:              perlin.NewPerlin(alpha, beta, n, seed+1), // Offset seed for Y noise
	}
	return h
}
