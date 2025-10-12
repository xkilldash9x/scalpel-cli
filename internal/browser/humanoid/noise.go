// File: internal/browser/humanoid/noise.go
package humanoid

import (
	"math"
	"math/rand"
)

// PinkNoiseGenerator implements the Voss-McCartney algorithm (stochastic version) for generating 1/f noise.
// This type of noise exhibits long-term correlations found in human physiological processes.
type PinkNoiseGenerator struct {
	rng    *rand.Rand
	values []float64 // Current value of each white noise source (oscillator)
	p      []float64 // Probability of change for each source
	pink   float64   // Current pink noise value (sum of sources)
	n      int       // Number of sources
	scale  float64   // Normalization scale factor
}

// NewPinkNoiseGenerator creates a new PinkNoiseGenerator with N sources (N=12 is typical).
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

// Next generates the next normalized pink noise sample.
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
