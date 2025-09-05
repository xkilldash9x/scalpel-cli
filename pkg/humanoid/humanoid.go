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
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
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
	browserContextID cdp.BrowserContextID
	logger           *zap.Logger

	// Internal state synchronization
	mu sync.Mutex

	// Current cursor position and state
	currentPos Vector2D
	// UPDATED: Use input.MouseButton, which is a string type.
	// This was the main culprit for the compilation errors.
	currentButtonState input.MouseButton // Tracks the currently pressed mouse button

	// Fatigue modeling
	fatigueLevel float64 // Ranges from 0.0 (rested) to 1.0 (exhausted)

	// State tracking
	lastActionTime       time.Time
	lastMovementDistance float64 // Tracks the distance of the last MoveTo action for Fitts's Law.

	// Noise generation
	rng    *rand.Rand
	noiseX *perlin.Perlin
	noiseY *perlin.Perlin
}

// New creates a new Humanoid instance with the given configuration.
func New(config Config, logger *zap.Logger, browserContextID cdp.BrowserContextID) *Humanoid {
	seed := time.Now().UnixNano()
	h := &Humanoid{
		baseConfig:       config,
		dynamicConfig:    config, // Start with the base config
		browserContextID: browserContextID,
		logger:           logger,
		rng:              rand.New(rand.NewSource(seed)),
		lastActionTime:   time.Now(),
		// UPDATED: Initialize with the correct "none" string constant.
		currentButtonState: input.MouseButtonNone,
	}

	// Initialize Perlin noise generators
	// These values are just some defaults that i've found to work well.
	alpha, beta := 2.0, 2.0 // Controls the smoothness of the noise
	n := int32(3)           // Number of octaves
	h.noiseX = perlin.NewPerlin(alpha, beta, n, seed)
	h.noiseY = perlin.NewPerlin(alpha, beta, n, seed+1) // Offset seed for Y noise

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

	// 3. Dispatch the initial mouse move event to set the cursor position.
	// We don't really care about the path here, just setting the initial state.
	return input.DispatchMouseEvent(input.MouseMoved, startX, startY).
		WithButton(input.MouseButtonNone).
		Do(ctx)
}