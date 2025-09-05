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
	// Import necessary cdproto packages
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// maxVelocity defines the maximum physiological mouse velocity (pixels per second).
const maxVelocity = 6000.0

// Humanoid manages the state and execution of human-like interactions.
type Humanoid struct {
	// Base configuration (defines the session persona)
	baseConfig Config
	// Dynamic configuration (current state, affected by fatigue)
	dynamicConfig Config

	// Browser context and logging
	browserContextID target.BrowserContextID
	logger           *zap.Logger

	// Internal state synchronization
	mu sync.Mutex

	// Current cursor position and state
	currentPos         Vector2D
	currentButtonState input.MouseButton // Tracks the currently pressed mouse button

	// Fatigue modeling
	fatigueLevel float64 // Ranges from 0.0 (rested) to 1.0 (exhausted)

	// State tracking
	lastMovementDistance float64 // Distance of the last completed move operation

	// Randomization and noise generators
	rng    *rand.Rand
	noiseX *perlin.Perlin
	noiseY *perlin.Perlin
}

// New creates a new Humanoid instance.
func New(config Config, browserContextID target.BrowserContextID, logger *zap.Logger) *Humanoid {
	// 1. Initialize RNG
	var seed int64
	var rng *rand.Rand
	if config.Rng == nil {
		seed = time.Now().UnixNano()
		source := rand.NewSource(seed)
		rng = rand.New(source)
	} else {
		seed = config.Rng.Int63()
		rng = config.Rng
	}

	// 2. Finalize the Session Persona
	config.NormalizeTypoRates()
	config.FinalizeSessionPersona(rng)

	// Standard Perlin parameters
	alpha, beta, n := 2.0, 2.0, int32(3)

	h := &Humanoid{
		baseConfig:           config,
		dynamicConfig:        config, // Initialize dynamic config
		browserContextID:     browserContextID,
		logger:               logger,
		rng:                  rng,
		currentPos:           Vector2D{X: 0.0, Y: 0.0},
		currentButtonState:   input.MouseButtonNone, // Correct constant usage
		fatigueLevel:         0.0,
		lastMovementDistance: 0.0,
		noiseX:               perlin.NewPerlin(alpha, beta, n, seed),
		noiseY:               perlin.NewPerlin(alpha, beta, n, seed+1), // Offset seed for Y noise
	}

	return h
}

// InitializePosition sets the initial cursor position realistically within the viewport.
func (h *Humanoid) InitializePosition(ctx context.Context) error {
	// 1. Get the layout metrics.
	layout, err := page.GetLayoutMetrics().Do(ctx)
	if err != nil {
		h.logger.Warn("Humanoid: failed to get layout metrics", zap.Error(err))
	}

	var width, height float64
	if layout != nil && layout.VisualViewport != nil {
		width = layout.VisualViewport.ClientWidth
		height = layout.VisualViewport.ClientHeight
	}

	if width <= 0 || height <= 0 {
		width, height = 1024, 768
	}

	// 2. Determine starting position (center biased, randomized).
	h.mu.Lock()
	startX := (width / 2.0) + h.rng.NormFloat64()*(width/8.0)
	startY := (height / 2.0) + h.rng.NormFloat64()*(height/8.0)

	// Clamp to viewport bounds.
	startX = math.Max(1.0, math.Min(startX, width-1.0))
	startY = math.Max(1.0, math.Min(startY, height-1.0))

	h.currentPos = Vector2D{X: startX, Y: startY}
	h.mu.Unlock()

	// 3. Dispatch the initial mouse move event.
	dispatchMove := input.DispatchMouseEvent(input.MouseMoved, startX, startY)
	if err := dispatchMove.Do(ctx); err != nil {
		return fmt.Errorf("humanoid: failed to dispatch initial mouse move: %w", err)
	}
	return nil
}

// GetCurrentPos safely retrieves the humanoid's current cursor position.
func (h *Humanoid) GetCurrentPos() Vector2D {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.currentPos
}