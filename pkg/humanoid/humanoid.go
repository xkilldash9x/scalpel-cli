package humanoid

import (
	"log"
	"math/rand"
	"sync"
	"time"

	"github.com/aquilax/go-perlin"
	"github.com/xkilldash9x/scalpel-cli/pkg/interfaces"
	"go.uber.org/zap"
)

// Humanoid simulates human-like interaction with a browser page.
type Humanoid struct {
	browser       interfaces.Executor
	logger        *zap.Logger
	mu            sync.Mutex
	currentPos    Vector2D
	rng           *rand.Rand
	noiseX        *perlin.Perlin
	noiseY        *perlin.Perlin
	fatigueLevel  float64
	baseConfig    Config
	dynamicConfig Config
}

// NewHumanoid creates and initializes a new Humanoid instance.
func NewHumanoid(browser interfaces.Executor, logger *zap.Logger, cfg Config) *Humanoid {
	if cfg.Rng == nil {
		cfg.Rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	cfg.FinalizeSessionPersona(cfg.Rng)

	pX := perlin.NewPerlin(2, 2, 3, cfg.Rng.Int63())
	pY := perlin.NewPerlin(2, 2, 3, cfg.Rng.Int63())

	return &Humanoid{
		browser:       browser,
		logger:        logger,
		currentPos:    Vector2D{X: -1, Y: -1}, // Start with an invalid position
		rng:           cfg.Rng,
		noiseX:        pX,
		noiseY:        pY,
		fatigueLevel:  0.0,
		baseConfig:    cfg,
		dynamicConfig: cfg,
	}
}