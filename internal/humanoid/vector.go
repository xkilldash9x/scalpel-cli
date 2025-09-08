// internal/humanoid/vector.go
package humanoid

import "math"

// Vector2D represents a point or vector in 2D space.
type Vector2D struct {
	X, Y float64
}

// Add returns the vector sum of v and other.
func (v Vector2D) Add(other Vector2D) Vector2D {
	return Vector2D{X: v.X + other.X, Y: v.Y + other.Y}
}

// Sub returns the vector difference of v and other.
func (v Vector2D) Sub(other Vector2D) Vector2D {
	return Vector2D{X: v.X - other.X, Y: v.Y - other.Y}
}

// Mul returns the vector v scaled by the scalar factor.
func (v Vector2D) Mul(scalar float64) Vector2D {
	return Vector2D{X: v.X * scalar, Y: v.Y * scalar}
}

// MagSq calculates the squared magnitude (length) of the vector.
func (v Vector2D) MagSq() float64 {
	return v.X*v.X + v.Y*v.Y
}

// Mag calculates the magnitude (length) of the vector.
func (v Vector2D) Mag() float64 {
	// Use math.Hypot for numerical stability.
	return math.Hypot(v.X, v.Y)
}

// Normalize returns a unit vector (magnitude 1) in the same direction as v.
func (v Vector2D) Normalize() Vector2D {
	mag := v.Mag()
	if mag < 1e-9 {
		return Vector2D{}
	}
	return v.Mul(1.0 / mag)
}

// Dist calculates the Euclidean distance between v and other (treated as points).
func (v Vector2D) Dist(other Vector2D) float64 {
	return math.Hypot(v.X-other.X, v.Y-other.Y)
}

// Limit truncates the magnitude of the vector if it exceeds the max value.
func (v Vector2D) Limit(max float64) Vector2D {
	magSq := v.MagSq()

	if magSq > max*max && magSq > 0 {
		mag := math.Sqrt(magSq)
		return v.Mul(max / mag)
	}
	return v
}

// Angle returns the angle of the vector in radians.
func (v Vector2D) Angle() float64 {
	return math.Atan2(v.Y, v.X)
}