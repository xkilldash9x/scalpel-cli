// internal/humanoid/helpers.go
package humanoid

import (
	"context"
	"fmt"
	// Removed math and time as retry logic is removed.

	// "github.com/chromedp/cdproto/cdp" // Removed
	// "github.com/chromedp/cdproto/dom" // Removed
	"go.uber.org/zap"
)

// boxToCenter calculates the geometric center (centroid) of an ElementGeometry.
func boxToCenter(geo *ElementGeometry) (center Vector2D, valid bool) {
	if geo == nil || len(geo.Vertices) < 8 {
		return Vector2D{}, false
	}
	// Calculate the average of the x and y coordinates.
	// Vertices is defined as [x0, y0, x1, y1, x2, y2, x3, y3].
	centerX := (geo.Vertices[0] + geo.Vertices[2] + geo.Vertices[4] + geo.Vertices[6]) / 4
	centerY := (geo.Vertices[1] + geo.Vertices[3] + geo.Vertices[5] + geo.Vertices[7]) / 4
	return Vector2D{X: centerX, Y: centerY}, true
}

// getElementBoxByVector creates a virtual ElementGeometry around a specific coordinate.
// (This function does not interact with the browser).
func (h *Humanoid) getElementBoxByVector(ctx context.Context, vec Vector2D) (*ElementGeometry, error) {
	// Create a virtual box of 10x10 pixels centered on the vector
	const virtualBoxSize = 10.0
	halfSize := virtualBoxSize / 2.0
	return &ElementGeometry{
		Vertices: []float64{
			vec.X - halfSize, vec.Y - halfSize, // top-left
			vec.X + halfSize, vec.Y - halfSize, // top-right
			vec.X + halfSize, vec.Y + halfSize, // bottom-right
			vec.X - halfSize, vec.Y + halfSize, // bottom-left
		},
		Width:  int64(virtualBoxSize),
		Height: int64(virtualBoxSize),
	}, nil
}

// A utility to find an element by selector and get its ElementGeometry.
// It relies on the executor's implementation of GetElementGeometry, which handles waiting and retrieval.
func (h *Humanoid) getElementBoxBySelector(ctx context.Context, selector string) (*ElementGeometry, error) {
	// The Executor implementation is expected to handle waiting for the element to be visible and interactable.

	geo, err := h.executor.GetElementGeometry(ctx, selector)

	if err != nil {
		// If the context was cancelled during the executor call, return the context error.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Otherwise, return a descriptive error indicating the failure.
		return nil, fmt.Errorf("humanoid: lookup or geometry retrieval failed for '%s': %w", selector, err)
	}

	// Perform basic validation on the returned geometry.
	if geo == nil {
		return nil, fmt.Errorf("humanoid: executor returned nil geometry and nil error for '%s'", selector)
	}

	if len(geo.Vertices) < 8 {
		return nil, fmt.Errorf("humanoid: element '%s' returned invalid geometry (missing vertices)", selector)
	}

	// Check for zero size elements.
	if geo.Width <= 0 || geo.Height <= 0 {
		h.logger.Debug("Humanoid: Element found but has zero or negative size.",
			zap.String("selector", selector),
			zap.Int64("width", geo.Width),
			zap.Int64("height", geo.Height))
		return nil, fmt.Errorf("humanoid: element '%s' has non-positive size (not interactable)", selector)
	}

	return geo, nil
}

// Convenience wrapper.
func (h *Humanoid) getCenterOfElement(ctx context.Context, selector string) (Vector2D, error) {
	geo, err := h.getElementBoxBySelector(ctx, selector)
	if err != nil {
		return Vector2D{}, err
	}
	center, valid := boxToCenter(geo)
	if !valid {
		// This should be caught by getElementBoxBySelector validation, but we keep it as a safeguard.
		return Vector2D{}, fmt.Errorf("humanoid: element '%s' has invalid geometry structure", selector)
	}
	return center, nil
}
