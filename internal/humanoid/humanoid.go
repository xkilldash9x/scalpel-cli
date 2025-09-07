// -- pkg/humanoid/humanoid.go --
package humanoid

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/aquilax/go-perlin"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// maxVelocity defines the maximum physiological mouse velocity (pixels per second).
const maxVelocity = 6000.0

// MouseButton represents the state of a mouse button, mirroring the CDP protocol strings.
type MouseButton string

const (
	MouseButtonNone MouseButton = "none"
	MouseButtonLeft MouseButton = "left"
)

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
	currentPos         Vector2D
	currentButtonState MouseButton // Tracks the currently pressed mouse button

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
		baseConfig:         config,
		dynamicConfig:      config, // Start with the base config
		browserContextID:   browserContextID,
		logger:             logger,
		rng:                rng,
		lastActionTime:     time.Now(),
		currentButtonState: MouseButtonNone,
		noiseX:             perlin.NewPerlin(alpha, beta, n, seed),
		noiseY:             perlin.NewPerlin(alpha, beta, n, seed+1), // Offset seed for Y noise
	}

	return h
}

// GetCurrentPos safely retrieves the humanoid's current cursor position.
func (h *Humanoid) GetCurrentPos() Vector2D {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.currentPos
}

// SetButtonState returns an Action that executes the provided button action
// AND updates the internal button state tracker.
func (h *Humanoid) SetButtonState(newState MouseButton, action chromedp.Action) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// 1. Execute the actual browser action (MouseDown/Up).
		if err := action.Do(ctx); err != nil {
			return err
		}

		// 2. Update internal state tracker if successful.
		h.mu.Lock()
		h.currentButtonState = newState
		h.mu.Unlock()
		return nil
	})
}

// InitializePosition sets the initial cursor position realistically within the viewport.
func (h *Humanoid) InitializePosition(ctx context.Context) error {
	// 1. Get the layout metrics.
	// VERIFIED: Using the modern 7-value return signature.
	_, _, _, _, cssVisualViewport, _, err := page.GetLayoutMetrics().Do(ctx)
	if err != nil {
		h.logger.Warn("Humanoid: failed to get layout metrics", zap.Error(err))
	}

	var width, height float64
	// Use the cssVisualViewport returned from the modern signature.
	if cssVisualViewport != nil {
		width = cssVisualViewport.ClientWidth
		height = cssVisualViewport.ClientHeight
	}

	// Fallback resolution if metrics fail or are zero.
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
	return chromedp.MouseEvent(input.MouseMoved, startX, startY).Do(ctx)
}