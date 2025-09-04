// pkg/humanoid/humanoid.go
package humanoid

import (
	"log"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/aquilax/go-perlin"
)

const (
	// A small value to prevent division by zero and floating point instabilities.
	epsilon = 1e-9

	// The minimum time interval between dispatching mouse events.
	minDispatchInterval = 10 * time.Millisecond
	
	// The maximum speed (pixels per second) for mouse movements.
	maxVelocity = 2000.0
)

// Humanoid simulates human-like interaction with a browser page.
// It's designed to be stateful and thread safe.
type Humanoid struct {
	mu           sync.Mutex
	logger       *log.Logger
	currentPos   Vector2D
	rng          *rand.Rand
	noiseX       *perlin.Perlin
	noiseY       *perlin.Perlin
	fatigueLevel float64 // Represents user fatigue, from 0.0 (fresh) to 1.0 (exhausted).
	baseConfig   Config
	dynamicConfig Config // A copy of base config, modified by fatigue.
}

// NewHumanoid creates and initializes a new Humanoid instance.
func NewHumanoid(logger *log.Logger, cfg Config) *Humanoid {
	// Seed the random number generator if one isn't provided
	if cfg.Rng == nil {
		cfg.Rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	// Finalize the session parameters to ensure consistency.
	cfg.FinalizeSessionPersona(cfg.Rng)

	// Initialize Perlin noise generators with different seeds
	pX := perlin.NewPerlin(2, 2, 3, cfg.Rng.Int63())
	pY := perlin.NewPerlin(2, 2, 3, cfg.Rng.Int63())

	return &Humanoid{
		logger:       logger,
		currentPos:   Vector2D{X: -1, Y: -1}, // Start with an invalid position
		rng:          cfg.Rng,
		noiseX:       pX,
		noiseY:       pY,
		fatigueLevel: 0.0,
		baseConfig:   cfg,
		dynamicConfig: cfg, // Initially, dynamic config is the same as base
	}
}

// criticallyDampedStep helper function for the ζ=1 case, used for stability when ζ approaches 1.
func criticallyDampedStep(omega, dt float64, goalPoint, displacement, velocity Vector2D) (Vector2D, Vector2D) {
	expTerm := math.Exp(-omega * dt)
	c1 := displacement
	c2 := velocity.Add(displacement.Mul(omega))
	c3 := c2.Mul(dt).Add(c1)

	newPos := goalPoint.Add(c3.Mul(expTerm))
	// Derivative of the position equation for velocity
	newVelocity := c2.Sub(c3.Mul(omega)).Mul(expTerm)
	return newPos, newVelocity
}
