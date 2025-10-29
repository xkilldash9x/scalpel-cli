// FILE: ./internal/browser/humanoid/potentialfield_test.go
package humanoid

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPotentialField_InitializationAndAdd(t *testing.T) {
	pf := NewPotentialField()
	assert.NotNil(t, pf)
	assert.Empty(t, pf.sources)

	pos := Vector2D{X: 10, Y: 20}
	pf.AddSource(pos, 100.0, 50.0)

	assert.Len(t, pf.sources, 1)
	source := pf.sources[0]
	assert.Equal(t, pos, source.Position)
}

func TestPotentialField_CalculateNetForce(t *testing.T) {
	pf := NewPotentialField()
	cursorPos := Vector2D{X: 0, Y: 0}

	t.Run("NoSources", func(t *testing.T) {
		force := pf.CalculateNetForce(cursorPos)
		assert.Equal(t, Vector2D{}, force)
	})

	// Add an attractor at (10, 0)
	pf.AddSource(Vector2D{X: 10, Y: 0}, 100.0, 50.0)

	t.Run("SingleAttractor", func(t *testing.T) {
		force := pf.CalculateNetForce(cursorPos)
		// Distance = 10. Falloff = 50.
		// Magnitude = 100 * exp(-10/50) = 100 * exp(-0.2) approx 81.873
		expectedMagnitude := 100.0 * math.Exp(-0.2)
		// Force vector direction (1, 0).
		assert.InDelta(t, expectedMagnitude, force.X, 1e-5)
		assert.Equal(t, 0.0, force.Y)
	})

	// COVERAGE: Test interaction between multiple sources (Attractor + Repulsor)
	t.Run("MultipleSources", func(t *testing.T) {
		// Start fresh for this subtest
		pfMulti := NewPotentialField()
		cursorPos := Vector2D{X: 0, Y: 0}

		// Attractor at (10, 0), Strength 100, Falloff 50. Force approx (81.873, 0).
		pfMulti.AddSource(Vector2D{X: 10, Y: 0}, 100.0, 50.0)
		// Repulsor at (0, 10), Strength -50, Falloff 50.
		// Distance 10. Magnitude = -50 * exp(-0.2) approx -40.9365.
		// Direction (0, 1). Force approx (0, -40.9365).
		pfMulti.AddSource(Vector2D{X: 0, Y: 10}, -50.0, 50.0)

		force := pfMulti.CalculateNetForce(cursorPos)

		expectedX := 100.0 * math.Exp(-0.2)
		expectedY := -50.0 * math.Exp(-0.2)

		assert.InDelta(t, expectedX, force.X, 1e-5)
		assert.InDelta(t, expectedY, force.Y, 1e-5)
	})

	t.Run("CursorAtSourcePosition", func(t *testing.T) {
		// Test when the cursor is exactly at a source position (dist < 1e-9 check)
		// Use the original pf which has a source at (10, 0).
		cursorAtSource := Vector2D{X: 10, Y: 0}
		force := pf.CalculateNetForce(cursorAtSource)
		// Force should be zero at the source position itself.
		assert.Equal(t, Vector2D{}, force)
	})
}
