package humanoid

import (
	"context"
	"fmt"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

// boxToCenter calculates the geometric center of an element's geometry.
func boxToCenter(geo *schemas.ElementGeometry) (center Vector2D, valid bool) {
	if geo == nil || len(geo.Vertices) < 8 {
		return Vector2D{}, false
	}
	centerX := (geo.Vertices[0] + geo.Vertices[2] + geo.Vertices[4] + geo.Vertices[6]) / 4
	centerY := (geo.Vertices[1] + geo.Vertices[3] + geo.Vertices[5] + geo.Vertices[7]) / 4
	return Vector2D{X: centerX, Y: centerY}, true
}

// getElementBoxByVector creates a virtual ElementGeometry around a specific coordinate.
func (h *Humanoid) getElementBoxByVector(ctx context.Context, vec Vector2D) (*schemas.ElementGeometry, error) {
	const virtualBoxSize = 10.0
	halfSize := virtualBoxSize / 2.0
	return &schemas.ElementGeometry{
		Vertices: []float64{
			vec.X - halfSize, vec.Y - halfSize,
			vec.X + halfSize, vec.Y - halfSize,
			vec.X + halfSize, vec.Y + halfSize,
			vec.X - halfSize, vec.Y + halfSize,
		},
		Width:  int64(virtualBoxSize),
		Height: int64(virtualBoxSize),
	}, nil
}

// getElementBoxBySelector finds an element and retrieves its geometry via the executor.
func (h *Humanoid) getElementBoxBySelector(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
	geo, err := h.executor.GetElementGeometry(ctx, selector)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("humanoid: geometry retrieval failed for '%s': %w", selector, err)
	}
	if geo == nil {
		return nil, fmt.Errorf("humanoid: executor returned nil geometry for '%s'", selector)
	}
	if len(geo.Vertices) < 8 {
		return nil, fmt.Errorf("humanoid: element '%s' returned invalid geometry", selector)
	}
	if geo.Width <= 0 || geo.Height <= 0 {
		h.logger.Debug("Humanoid: Element found but has zero size.",
			zap.String("selector", selector),
			zap.Int64("width", geo.Width),
			zap.Int64("height", geo.Height))
		return nil, fmt.Errorf("humanoid: element '%s' is not interactable (zero size)", selector)
	}
	return geo, nil
}

// getCenterOfElement is a convenience wrapper to get the center point of an element, ensuring it's visible first.
func (h *Humanoid) getCenterOfElement(ctx context.Context, selector string, opts *InteractionOptions) (Vector2D, error) {
	if err := h.ensureVisible(ctx, selector, opts); err != nil {
		return Vector2D{}, err
	}
	geo, err := h.getElementBoxBySelector(ctx, selector)
	if err != nil {
		return Vector2D{}, err
	}
	center, valid := boxToCenter(geo)
	if !valid {
		return Vector2D{}, fmt.Errorf("humanoid: element '%s' has invalid geometry structure", selector)
	}
	return center, nil
}
