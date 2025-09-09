// Filename: internal/humanoid/trajectory_test.go
package humanoid

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/aquilax/go-perlin"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

// =============================================================================
// Test Infrastructure: Mocks and Helpers
// =============================================================================

// mockExecutor implements the Executor interface for testing purposes.
type mockExecutor struct {
	dispatchedEvents []*input.DispatchMouseEventParams
	sleepDurations   []time.Duration
	returnErr        error
	mu               sync.Mutex

	// For advanced scenario control.
	cancelOnCall int
	failOnCall   int
	callCount    int
	cancelFunc   context.CancelFunc
}

// newMockExecutor creates a new mock executor.
func newMockExecutor() *mockExecutor {
	return &mockExecutor{
		dispatchedEvents: make([]*input.DispatchMouseEventParams, 0),
		sleepDurations:   make([]time.Duration, 0),
	}
}

// DispatchMouseEvent records the mouse event dispatch call.
func (m *mockExecutor) DispatchMouseEvent(ctx context.Context, p *input.DispatchMouseEventParams) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	if m.returnErr != nil && m.failOnCall > 0 && m.callCount >= m.failOnCall {
		return m.returnErr
	}
	m.dispatchedEvents = append(m.dispatchedEvents, p)
	// Check cancellation based on the count of dispatched events.
	if m.cancelOnCall > 0 && len(m.dispatchedEvents) == m.cancelOnCall && m.cancelFunc != nil {
		m.cancelFunc()
	}
	return nil
}

// Sleep records the sleep duration instead of actually sleeping.
func (m *mockExecutor) Sleep(ctx context.Context, d time.Duration) error {
	// Check for context cancellation.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sleepDurations = append(m.sleepDurations, d)
	return nil
}

// Stubs for other Executor methods.
func (m *mockExecutor) ExecuteAction(ctx context.Context, a chromedp.Action) error {
	return nil
}
func (m *mockExecutor) GetLayoutMetrics(ctx context.Context) (*page.LayoutViewport, *page.VisualViewport, *dom.Rect, error) {
	return nil, nil, nil, nil
}
func (m *mockExecutor) GetBoxModel(ctx context.Context, nodeID cdp.NodeID) (*dom.BoxModel, error) {
	return nil, nil
}
func (m *mockExecutor) CallFunctionOn(ctx context.Context, params *runtime.CallFunctionOnParams) (*runtime.RemoteObject, *runtime.ExceptionDetails, error) {
	return nil, nil, nil
}
func (m *mockExecutor) QueryNodes(ctx context.Context, selector string) ([]*cdp.Node, error) {
	return nil, nil
}
func (m *mockExecutor) DispatchKeyEvent(ctx context.Context, p *input.DispatchKeyEventParams) error {
	return nil
}

// newTestHumanoid creates a Humanoid instance with deterministic dependencies for testing.
func newTestHumanoid(executor Executor) *Humanoid {
	const seed = 12345
	config := DefaultConfig()
	config.FittsRandomness = 0.15

	h := New(config, zap.NewNop(), cdp.BrowserContextID("test-session"))

	rng := rand.New(rand.NewSource(seed))
	h.rng = rng
	h.noiseX = perlin.NewPerlin(2, 2, 3, seed)
	h.noiseY = perlin.NewPerlin(2, 2, 3, seed+1)
	h.noiseTime = 0.0
	h.dynamicConfig.FittsA = 100.0
	h.dynamicConfig.FittsB = 150.0
	h.dynamicConfig.PerlinAmplitude = 2.0
	h.dynamicConfig.GaussianStrength = 0.5

	return h
}

// floatAlmostEqual checks if two float64 values are within a tolerance.
func floatAlmostEqual(a, b, tolerance float64) bool {
	return math.Abs(a-b) <= tolerance
}

// =============================================================================
// Unit Tests for Algorithmic Core
// =============================================================================

func TestComputeEaseInOutCubic(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		input    float64
		expected float64
	}{
		{0.0, 0.0},
		{0.25, 0.0625},
		{0.5, 0.5},
		{0.75, 0.9375},
		{1.0, 1.0},
	}
	for _, tc := range testCases {
		assert.True(t, floatAlmostEqual(tc.expected, computeEaseInOutCubic(tc.input), 1e-9), "ease for %.2f", tc.input)
	}
}