package humanoid

import (
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
	baseConfig         Config
	dynamicConfig      Config
	logger             *zap.Logger
	executor           Executor
	mu                 sync.Mutex
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

	h := &Humanoid{
		baseConfig:         config,
		dynamicConfig:      config,
		logger:             logger,
		executor:           executor,
		rng:                rng,
		lastActionTime:     time.Now(),
		currentButtonState: schemas.ButtonNone,
		noiseX:             perlin.NewPerlin(alpha, beta, n, seed),
		noiseY:             perlin.NewPerlin(alpha, beta, n, seed+1),
	}
	return h
}