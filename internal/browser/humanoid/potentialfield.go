// internal/browser/humanoid/potentialfield.go
package humanoid

import "math"

// ForceSource represents an attractor or repulsor in the potential field.
type ForceSource struct {
	Position Vector2D
	Strength float64 // Positive for attraction, negative for repulsion.
	Falloff  float64 // Controls the rate of decay (larger means slower decay/wider influence).
}

// PotentialField manages a collection of force sources used to deform movement trajectories.
type PotentialField struct {
	sources []ForceSource
}

// NewPotentialField creates an empty PotentialField.
func NewPotentialField() *PotentialField {
	return &PotentialField{
		sources: make([]ForceSource, 0),
	}
}

// AddSource adds a new force source to the field.
func (pf *PotentialField) AddSource(pos Vector2D, strength, falloff float64) {
	pf.sources = append(pf.sources, ForceSource{
		Position: pos,
		Strength: strength,
		Falloff:  falloff,
	})
}

// CalculateNetForce computes the combined force vector acting on a cursor position.
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