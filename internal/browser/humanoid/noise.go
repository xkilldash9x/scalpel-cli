// File: internal/browser/humanoid/noise.go
package humanoid

import (
	"math"
	"math/rand"
)

// PinkNoiseGenerator produces a sequence of 1/f noise, also known as pink noise.
// This type of noise is characterized by its long-term correlations and is frequently
// observed in natural and physiological systems, making it ideal for simulating
// realistic, low-frequency drift in human motor control (e.g., cursor hesitation).
//
// This implementation uses the Voss-McCartney algorithm, which works by summing
// several sources of white noise that are updated at different frequencies.
type PinkNoiseGenerator struct {
	rng    *rand.Rand
	values []float64 // The current value of each underlying white noise source.
	p      []float64 // The probability of updating each source at a given step.
	pink   float64   // The current accumulated pink noise value.
	n      int       // The number of white noise sources (oscillators).
	scale  float64   // A normalization factor to keep the output range consistent.
}

// NewPinkNoiseGenerator creates and initializes a new PinkNoiseGenerator.
//
// Parameters:
//   - rng: A random number generator source.
//   - n: The number of underlying white noise sources to use. A higher number
//     provides a better approximation of true 1/f noise but is computationally
//     more expensive. A value of 12 is a common and effective choice.
//
// Returns a fully initialized PinkNoiseGenerator ready to produce noise.
func NewPinkNoiseGenerator(rng *rand.Rand, n int) *PinkNoiseGenerator {
	if n <= 0 {
		n = 12
	}
	p := &PinkNoiseGenerator{
		rng:    rng,
		values: make([]float64, n),
		p:      make([]float64, n),
		n:      n,
		// Approximate normalization factor (Scaling by sqrt(N) keeps amplitude relatively consistent).
		scale: 1.0 / math.Sqrt(float64(n)),
	}

	// Initialize probabilities based on frequency distribution (Geometric progression).
	totalP := 0.0
	for i := 0; i < n; i++ {
		p.p[i] = math.Pow(2, float64(-i))
		totalP += p.p[i]
	}
	// Normalize probabilities.
	for i := 0; i < n; i++ {
		p.p[i] /= totalP
	}

	// Initialize sources with random white noise.
	for i := 0; i < n; i++ {
		p.values[i] = p.nextWhite()
		p.pink += p.values[i]
	}

	return p
}

// nextWhite generates normalized white noise (-1.0 to 1.0).
func (p *PinkNoiseGenerator) nextWhite() float64 {
	return p.rng.Float64()*2.0 - 1.0
}

// Next calculates and returns the next sample in the pink noise sequence.
// Each call to Next updates the internal state of one of the underlying white
// noise sources (selected probabilistically) and returns the new sum, producing
// a stateful, correlated noise value.
//
// Returns a normalized pink noise value, typically in the range of [-1.0, 1.0].
func (p *PinkNoiseGenerator) Next() float64 {
	// Select a source to update based on probabilities (Stochastic Voss algorithm).
	r := p.rng.Float64()
	cumulativeP := 0.0
	updateIndex := 0
	for i := 0; i < p.n; i++ {
		cumulativeP += p.p[i]
		if r < cumulativeP {
			updateIndex = i
			break
		}
	}

	// Ensure index is within bounds (float precision safety).
	if updateIndex >= p.n {
		updateIndex = p.n - 1
	}

	// Update the selected source.
	oldValue := p.values[updateIndex]
	newValue := p.nextWhite()
	p.values[updateIndex] = newValue

	// Update the pink noise sum.
	p.pink += (newValue - oldValue)

	return p.pink * p.scale
}
