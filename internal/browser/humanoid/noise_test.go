// FILE: ./internal/browser/humanoid/noise_test.go
package humanoid

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper mock source for testing specific RNG outputs (needed for edge case testing)
type mockSource struct {
	value float64
}

func newMockSource(v float64) *mockSource {
	return &mockSource{value: v}
}

func (m *mockSource) Int63() int64 {
	// rand.Float64() implementation: float64(src.Int63()&(1<<53-1)) / (1<<53)
	// To ensure rand.Float64() < 1.0, the generated int64 (when masked) must be < 1<<53.
	val := int64(m.value * float64(1<<53))
	// If float rounding caused it to equal 1<<53, decrement it, provided the original value was < 1.0.
	if val == (1<<53) && m.value < 1.0 {
		val--
	}
	return val
}

func (m *mockSource) Seed(seed int64) {}

func TestNewPinkNoiseGenerator(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	t.Run("StandardInitialization", func(t *testing.T) {
		n := 12
		p := NewPinkNoiseGenerator(rng, n)
		assert.NotNil(t, p)
		assert.Equal(t, n, p.n)

		// Check if probabilities are normalized (sum to 1)
		totalP := 0.0
		for _, prob := range p.p {
			totalP += prob
		}
		assert.InDelta(t, 1.0, totalP, 1e-9)

		// Check if initial pink value is the sum of initial white noise values
		initialSum := 0.0
		for _, val := range p.values {
			initialSum += val
		}
		assert.Equal(t, initialSum, p.pink)
	})

	t.Run("InvalidN", func(t *testing.T) {
		// Should default to 12 if N <= 0
		p := NewPinkNoiseGenerator(rng, 0)
		assert.Equal(t, 12, p.n)
	})
}

func TestPinkNoiseGenerator_Next(t *testing.T) {
	// Use a fixed seed
	rng := rand.New(rand.NewSource(42))
	p := NewPinkNoiseGenerator(rng, 8)

	// Generate a sequence of values
	iterations := 100
	values := make([]float64, iterations)

	for i := 0; i < iterations; i++ {
		val := p.Next()
		values[i] = val
		// Check reasonable bounds (statistically unlikely to exceed +/- 3.0)
		assert.Less(t, val, 3.0)
		assert.Greater(t, val, -3.0)
	}

	// Check that the values are actually changing
	assert.NotEqual(t, values[0], values[1])
}

func TestPinkNoiseGenerator_NextWhite(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	p := NewPinkNoiseGenerator(rng, 1)

	// Check that nextWhite generates values between -1.0 and 1.0
	for i := 0; i < 100; i++ {
		val := p.nextWhite()
		assert.GreaterOrEqual(t, val, -1.0)
		assert.LessOrEqual(t, val, 1.0)
	}
}

// Test the edge case where the random number approaches 1.0
func TestPinkNoiseGenerator_Next_EdgeCase(t *testing.T) {
	// Create an RNG that will return a value very close to 1.0 (but strictly less than 1.0)
	// This tests the boundary condition (Lines 59, 65-67 in noise.go)
	mockRNG := rand.New(newMockSource(0.9999999999999999))
	n := 4
	p := NewPinkNoiseGenerator(mockRNG, n)

	// This call should execute the boundary check logic without panicking.
	assert.NotPanics(t, func() {
		p.Next()
	})
}
