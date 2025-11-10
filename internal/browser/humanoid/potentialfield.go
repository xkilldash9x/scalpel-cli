// internal/browser/humanoid/potentialfield.go
package humanoid

import "math"

// ForceSource represents a single point of influence within a PotentialField.
// It can act as either an attractor (positive strength) or a repulsor (negative
// strength), affecting the trajectory of mouse movements that pass nearby.
type ForceSource struct {
	// Position is the coordinate of the force source.
	Position Vector2D
	// Strength determines the magnitude of the force. Positive values create
	// attraction, while negative values create repulsion.
	Strength float64
	// Falloff controls how quickly the force diminishes with distance. A larger
	// value results in a wider area of influence.
	Falloff float64
}

// PotentialField simulates a 2D field of forces that can influence and deform
// the trajectory of a mouse movement. This can be used to model scenarios where
// the cursor is "pulled" towards an interactive element or "pushed" away from
// an obstacle, making the path more dynamic and realistic.
type PotentialField struct {
	sources []ForceSource
}

// NewPotentialField creates and returns an empty PotentialField.
func NewPotentialField() *PotentialField {
	return &PotentialField{
		sources: make([]ForceSource, 0),
	}
}

// AddSource adds a new force source (an attractor or repulsor) to the field.
//
// Parameters:
//   - pos: The coordinate of the force source.
//   - strength: The magnitude of the force (positive for attraction, negative for repulsion).
//   - falloff: The distance parameter controlling the force's area of influence.
func (pf *PotentialField) AddSource(pos Vector2D, strength, falloff float64) {
	pf.sources = append(pf.sources, ForceSource{
		Position: pos,
		Strength: strength,
		Falloff:  falloff,
	})
}

// CalculateNetForce computes the combined force vector exerted by all sources in
// the field on a given point. The force from each source is calculated using an
// exponential decay model, and the resulting vectors are summed.
//
// Parameters:
//   - cursorPos: The position at which to calculate the net force.
//
// Returns a Vector2D representing the direction and magnitude of the net force.
func (pf *PotentialField) CalculateNetForce(cursorPos Vector2D) Vector2D {
	netForce := Vector2D{}
	for _, source := range pf.sources {
		vecToSource := source.Position.Sub(cursorPos)
		dist := vecToSource.Mag()
		if dist < 1e-9 {
			continue // Avoid division by zero.
		}
		// Exponential decay function: F = S * exp(-d/L)
		magnitude := source.Strength * math.Exp(-dist/source.Falloff)
		// Calculate the force vector.
		force := vecToSource.Mul(magnitude / dist)
		netForce = netForce.Add(force)
	}
	return netForce
}