// FILE: ./internal/browser/humanoid/vector_test.go
package humanoid

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVector2D_Operations(t *testing.T) {
	v1 := Vector2D{X: 3, Y: 4}
	v2 := Vector2D{X: 1, Y: 2}

	t.Run("Add", func(t *testing.T) {
		assert.Equal(t, Vector2D{X: 4, Y: 6}, v1.Add(v2))
	})

	t.Run("Sub", func(t *testing.T) {
		assert.Equal(t, Vector2D{X: 2, Y: 2}, v1.Sub(v2))
	})

	t.Run("Mul", func(t *testing.T) {
		assert.Equal(t, Vector2D{X: 6, Y: 8}, v1.Mul(2.0))
	})

	t.Run("Dot", func(t *testing.T) {
		// 3*1 + 4*2 = 11
		assert.Equal(t, 11.0, v1.Dot(v2))
	})

	t.Run("MagSq", func(t *testing.T) {
		// 3*3 + 4*4 = 25
		assert.Equal(t, 25.0, v1.MagSq())
	})

	t.Run("Mag", func(t *testing.T) {
		assert.Equal(t, 5.0, v1.Mag())
	})

	t.Run("Dist", func(t *testing.T) {
		// sqrt((3-1)^2 + (4-2)^2) = sqrt(8)
		assert.InDelta(t, math.Sqrt(8.0), v1.Dist(v2), 1e-9)
	})

	t.Run("Angle", func(t *testing.T) {
		v := Vector2D{X: 1, Y: 1}
		assert.InDelta(t, math.Pi/4, v.Angle(), 1e-9)
	})
}

func TestVector2D_Normalize(t *testing.T) {
	t.Run("Standard", func(t *testing.T) {
		v := Vector2D{X: 3, Y: 4}
		norm := v.Normalize()
		assert.InDelta(t, 1.0, norm.Mag(), 1e-9)
		assert.InDelta(t, 0.6, norm.X, 1e-9)
		assert.InDelta(t, 0.8, norm.Y, 1e-9)
	})

	t.Run("ZeroVector", func(t *testing.T) {
		// Handles mag < 1e-9
		v := Vector2D{X: 0, Y: 0}
		norm := v.Normalize()
		assert.Equal(t, Vector2D{}, norm)
	})
}

func TestVector2D_Limit(t *testing.T) {
	v := Vector2D{X: 10, Y: 0}

	t.Run("BelowLimit", func(t *testing.T) {
		assert.Equal(t, v, v.Limit(15.0))
	})

	t.Run("AboveLimit", func(t *testing.T) {
		limited := v.Limit(5.0)
		assert.Equal(t, Vector2D{X: 5, Y: 0}, limited)
	})

	t.Run("ZeroVector", func(t *testing.T) {
		// Handles magSq > 0 check
		v := Vector2D{X: 0, Y: 0}
		limited := v.Limit(5.0)
		assert.Equal(t, Vector2D{}, limited)
	})
}
