// internal/humanoid/config.go
package humanoid

import (
	"math"
	"math/rand"
)

// Config holds the parameters defining the behavior of the simulation.
type Config struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	Rng     *rand.Rand

	// Fitts's Law Parameters
	FittsAMean, FittsAStdDev float64
	FittsBMean, FittsBStdDev float64
	FittsRandomness          float64

	// Motor Control Dynamics
	OmegaMean, OmegaStdDev float64
	ZetaMean, ZetaStdDev   float64

	// Noise and Tremor
	GaussianStrengthMean, GaussianStrengthStdDev float64
	PerlinAmplitudeMean, PerlinAmplitudeStdDev   float64
	ClickNoiseMean, ClickNoiseStdDev             float64

	// Typing Behavior
	TypoRateMean, TypoRateStdDev   float64
	KeyHoldMeanMs, KeyHoldStdDevMs float64

	// Instance Parameters
	FittsA, FittsB             float64
	Omega, Zeta                float64
	GaussianStrength           float64
	PerlinAmplitude            float64
	ClickNoise                 float64
	TypoRate                   float64
	KeyHoldMean, KeyHoldStdDev float64

	// Clicking Behavior
	ClickHoldMinMs int `json:"click_hold_min_ms" yaml:"click_hold_min_ms"`
	ClickHoldMaxMs int `json:"click_hold_max_ms" yaml:"click_hold_max_ms"`

	// Typo Probabilities
	TypoNeighborRate               float64 `json:"typoNeighborRate" yaml:"typoNeighborRate"`
	TypoTransposeRate              float64 `json:"typoTransposeRate" yaml:"typoTransposeRate"`
	TypoOmissionRate               float64 `json:"typoOmissionRate" yaml:"typoOmissionRate"`
	TypoInsertionRate              float64 `json:"typoInsertionRate" yaml:"typoInsertionRate"`
	TypoCorrectionProbability      float64 `json:"typoCorrectionProbability" yaml:"typoCorrectionProbability"`
	TypoOmissionNoticeProbability  float64 `json:"typoOmissionNoticeProbability" yaml:"typoOmissionNoticeProbability"`
	TypoInsertionNoticeProbability float64 `json:"typoInsertionNoticeProbability" yaml:"typoInsertionNoticeProbability"`
	TypoShiftCorrectionProbability float64 `json:"typoShiftCorrectionProbability" yaml:"typoShiftCorrectionProbability"`

	// Scrolling Behavior
	ScrollReadDensityFactor     float64
	ScrollMouseWheelProbability float64
	ScrollRegressionProbability float64
	ScrollOvershootProbability  float64

	// Fatigue Modeling
	FatigueIncreaseRate float64
	FatigueRecoveryRate float64

	MicroCorrectionThreshold float64

	// Key Pause (IKD) Parameters
	KeyPauseMean          float64 `json:"keyPauseMean" yaml:"keyPauseMean"`
	KeyPauseStdDev        float64 `json:"keyPauseStdDev" yaml:"keyPauseStdDev"`
	KeyPauseMin           float64 `json:"keyPauseMin" yaml:"keyPauseMin"`
	KeyPauseNgramFactor2  float64 `json:"keyPauseNgramFactor2" yaml:"keyPauseNgramFactor2"`
	KeyPauseNgramFactor3  float64 `json:"keyPauseNgramFactor3" yaml:"keyPauseNgramFactor3"`
	KeyPauseFatigueFactor float64 `json:"keyPauseFatigueFactor" yaml:"keyPauseFatigueFactor"`

	// Typo Correction Behavior (Pause scaling factors)
	TypoCorrectionPauseMeanScale  float64 `json:"typoCorrectionPauseMeanScale" yaml:"typoCorrectionPauseMeanScale"`
	TypoCorrectionPauseStdDevScale float64 `json:"typoCorrectionPauseStdDevScale" yaml:"typoCorrectionPauseStdDevScale"`
}

// DefaultConfig returns a configuration representing an average user.
func DefaultConfig() Config {
	c := Config{
		Rng:                            nil,
		FittsAMean:                     100.0, FittsAStdDev: 15.0,
		FittsBMean:                     120.0, FittsBStdDev: 20.0,
		OmegaMean:                      28.0, OmegaStdDev: 4.0,
		ZetaMean:                       1.0, ZetaStdDev: 0.1,
		GaussianStrengthMean:           0.5, GaussianStrengthStdDev: 0.1,
		PerlinAmplitudeMean:            2.5, PerlinAmplitudeStdDev: 0.5,
		ClickNoiseMean:                 2.0, ClickNoiseStdDev: 0.5,
		TypoRateMean:                   0.04, TypoRateStdDev: 0.01,
		KeyHoldMeanMs:                  55.0, KeyHoldStdDevMs: 15.0,
		ClickHoldMinMs:                 50, ClickHoldMaxMs: 120,
		TypoNeighborRate:               0.40,
		TypoTransposeRate:              0.25,
		TypoOmissionRate:               0.20,
		TypoInsertionRate:              0.15,
		TypoCorrectionProbability:      0.85,
		TypoOmissionNoticeProbability:  0.70,
		TypoInsertionNoticeProbability: 0.80,
		TypoShiftCorrectionProbability: 0.80,
		ScrollReadDensityFactor:        0.5,
		ScrollMouseWheelProbability:    0.70,
		ScrollRegressionProbability:    0.10,
		ScrollOvershootProbability:     0.25,
		FatigueIncreaseRate:            0.005,
		FatigueRecoveryRate:            0.01,
		MicroCorrectionThreshold:       50.0,
		// New Key Pause (IKD) Parameters
		KeyPauseMean:          70.0,
		KeyPauseStdDev:        28.0,
		KeyPauseMin:           35.0,
		KeyPauseNgramFactor2:  0.7,
		KeyPauseNgramFactor3:  0.55,
		KeyPauseFatigueFactor: 0.3,
		// New Typo Correction Behavior
		TypoCorrectionPauseMeanScale:  1.8,
		TypoCorrectionPauseStdDevScale: 0.6,
	}
	c.NormalizeTypoRates()
	return c
}

// FinalizeSessionPersona generates the fixed instance parameters for a session.
func (c *Config) FinalizeSessionPersona(rng *rand.Rand) {
	c.Rng = rng
	c.FittsA = sampleGaussian(rng, c.FittsAMean, c.FittsAStdDev)
	c.FittsB = sampleGaussian(rng, c.FittsBMean, c.FittsBStdDev)
	c.Omega = sampleGaussian(rng, c.OmegaMean, c.OmegaStdDev)
	c.Zeta = sampleGaussian(rng, c.ZetaMean, c.ZetaStdDev)
	c.GaussianStrength = sampleGaussian(rng, c.GaussianStrengthMean, c.GaussianStrengthStdDev)
	c.PerlinAmplitude = sampleGaussian(rng, c.PerlinAmplitudeMean, c.PerlinAmplitudeStdDev)
	c.ClickNoise = sampleGaussian(rng, c.ClickNoiseMean, c.ClickNoiseStdDev)
	c.TypoRate = sampleGaussian(rng, c.TypoRateMean, c.TypoRateStdDev)
	c.KeyHoldMean = sampleGaussian(rng, c.KeyHoldMeanMs, c.KeyHoldStdDevMs)
	c.KeyHoldStdDev = c.KeyHoldStdDevMs

	// Ensure parameters are within reasonable bounds
	c.Omega = math.Max(5.0, c.Omega)
	c.ClickNoise = math.Max(0.0, c.ClickNoise)
	c.TypoRate = math.Max(0.0, math.Min(0.25, c.TypoRate))
	c.KeyHoldMean = math.Max(20.0, c.KeyHoldMean)

	if c.ClickHoldMaxMs <= c.ClickHoldMinMs {
		c.ClickHoldMaxMs = c.ClickHoldMinMs + 1
	}
}

// NormalizeTypoRates ensures the conditional typo probabilities sum up to 1.
func (c *Config) NormalizeTypoRates() {
	total := c.TypoNeighborRate + c.TypoTransposeRate + c.TypoOmissionRate + c.TypoInsertionRate
	if total <= 1e-9 {
		if c.TypoRateMean > 0 || c.TypoRate > 0 {
			c.TypoNeighborRate = 0.25
			c.TypoTransposeRate = 0.25
			c.TypoOmissionRate = 0.25
			c.TypoInsertionRate = 0.25
		}
		return
	}
	c.TypoNeighborRate /= total
	c.TypoTransposeRate /= total
	c.TypoOmissionRate /= total
	c.TypoInsertionRate /= total
}

// sampleGaussian samples a value from a Gaussian distribution.
func sampleGaussian(rng *rand.Rand, mean, stdDev float64) float64 {
	if rng == nil {
		return mean
	}
	return mean + rng.NormFloat64()*stdDev
}