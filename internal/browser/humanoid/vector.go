// internal/browser/humanoid/vector.go
package humanoid

import "math"

// Vector2D represents a point or vector in a 2D Cartesian coordinate system.
// It is used throughout the humanoid simulation to represent positions, velocities,
// accelerations, and forces.
type Vector2D struct {
	// X is the horizontal component of the vector.
	X float64
	// Y is the vertical component of the vector.
	Y float64
}

// Add performs vector addition, returning a new Vector2D `v + other`.
func (v Vector2D) Add(other Vector2D) Vector2D {
	return Vector2D{X: v.X + other.X, Y: v.Y + other.Y}
}

// Sub performs vector subtraction, returning a new Vector2D `v - other`.
func (v Vector2D) Sub(other Vector2D) Vector2D {
	return Vector2D{X: v.X - other.X, Y: v.Y - other.Y}
}

// Mul performs scalar multiplication, returning a new Vector2D `v * scalar`.
func (v Vector2D) Mul(scalar float64) Vector2D {
	return Vector2D{X: v.X * scalar, Y: v.Y * scalar}
}

// Dot calculates the dot product (scalar product) of `v` and `other`.
func (v Vector2D) Dot(other Vector2D) float64 {
	return v.X*other.X + v.Y*other.Y
}

// MagSq calculates the squared magnitude (length) of the vector, `|v|^2`.
// This is computationally cheaper than Mag() as it avoids a square root, making
// it suitable for distance comparisons.
func (v Vector2D) MagSq() float64 {
	return v.X*v.X + v.Y*v.Y
}

// Mag calculates the magnitude (Euclidean length) of the vector, `|v|`.
func (v Vector2D) Mag() float64 {
	// Use math.Hypot for better numerical stability with very large or small components.
	return math.Hypot(v.X, v.Y)
}

// Normalize returns a unit vector (a vector with a magnitude of 1) that has
// the same direction as `v`. If `v` is the zero vector, it returns the zero vector.
func (v Vector2D) Normalize() Vector2D {
	mag := v.Mag()
	// Check for a near-zero magnitude to avoid division by zero.
	if mag < 1e-9 {
		return Vector2D{}
	}
	return v.Mul(1.0 / mag)
}

// Dist calculates the Euclidean distance between the points represented by `v` and `other`.
func (v Vector2D) Dist(other Vector2D) float64 {
	return math.Hypot(v.X-other.X, v.Y-other.Y)
}

// Limit returns a new vector that has the same direction as `v` but with a
// magnitude that is capped at the specified `max` value. If the original
// magnitude is less than `max`, the original vector is returned.
func (v Vector2D) Limit(max float64) Vector2D {
	magSq := v.MagSq()

	if magSq > max*max && magSq > 0 {
		mag := math.Sqrt(magSq)
		return v.Mul(max / mag)
	}
	return v
}

// Angle calculates the angle of the vector in radians with respect to the
// positive X-axis. The angle is in the range [-Pi, Pi].
func (v Vector2D) Angle() float64 {
	return math.Atan2(v.Y, v.X)
}
