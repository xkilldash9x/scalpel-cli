// Filename: internal/humanoid/helpers.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"go.uber.org/zap"
)

// boxToCenter calculates the geometric center (centroid) of a DOM BoxModel.
func boxToCenter(box *dom.BoxModel) (center Vector2D, valid bool) {
	if box == nil || len(box.Content) < 8 {
		return Vector2D{}, false
	}
	// The content quad is [x1, y1, x2, y1, x2, y2, x1, y2].
	// Center is ((x1+x2)/2, (y1+y2)/2).
	centerX := (box.Content[0] + box.Content[2]) / 2.0
	centerY := (box.Content[1] + box.Content[5]) / 2.0
	return Vector2D{X: centerX, Y: centerY}, true
}

// getElementBoxByVector creates a virtual BoxModel around a specific coordinate.
// This is useful for corrective movements where the target is a point, not an element.
func (h *Humanoid) getElementBoxByVector(ctx context.Context, vec Vector2D) (*dom.BoxModel, error) {
	// Create a tiny 2x2 box around the vector point.
	// This gives the target calculation logic a small "element" to work with.
	halfWidth := 1.0
	halfHeight := 1.0
	return &dom.BoxModel{
		Content: []float64{
			vec.X - halfWidth, vec.Y - halfHeight, // Top-left
			vec.X + halfWidth, vec.Y - halfHeight, // Top-right
			vec.X + halfWidth, vec.Y + halfHeight, // Bottom-right
			vec.X - halfWidth, vec.Y + halfHeight, // Bottom-left
		},
		Width:  int64(2 * halfWidth),
		Height: int64(2 * halfHeight),
	}, nil
}

// getElementBoxBySelector is a utility to find an element by selector and get its BoxModel.
func (h *Humanoid) getElementBoxBySelector(ctx context.Context, selector string) (*dom.BoxModel, error) {

	// REFACTORED: Use the executor to query nodes (which includes WaitVisible in the production implementation).
	nodes, err := h.executor.QueryNodes(ctx, selector)

	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// If no nodes were found, it's a definitive failure.
		if len(nodes) == 0 {
			// If WaitVisible fails (implicitly via QueryNodes), it usually means the element isn't visible.
			return nil, fmt.Errorf("humanoid: failed to find visible nodes for selector '%s': %w", selector, err)
		}
		// If nodes were found despite the error, proceed.
		h.logger.Debug("Humanoid: QueryNodes returned error but found nodes, proceeding.", zap.Error(err))
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("humanoid: selector '%s' matched no nodes", selector)
	}

	// Use the robust getElementBox helper on the first node found.
	// REFACTORED: Use the internal helper method which now uses the executor.
	box, err := h.getElementBox(ctx, nodes[0].NodeID)
	if err != nil {
		return nil, fmt.Errorf("humanoid: failed to get element geometry for '%s': %w", selector, err)
	}
	return box, nil
}

// getElementBox retrieves the BoxModel for a given node ID with retry logic.
// Converted from package-level function (getElementBox) to method (h.getElementBox) to access h.executor.
func (h *Humanoid) getElementBox(ctx context.Context, nodeID cdp.NodeID) (*dom.BoxModel, error) {
	var box *dom.BoxModel
	var err error

	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		// REFACTORED: Use the executor to get the box model.
		box, err = h.executor.GetBoxModel(ctx, nodeID)

		if err == nil {
			// Check if the BoxModel is valid (has dimensions).
			if box != nil && len(box.Content) >= 8 && box.Width > 0 && box.Height > 0 {
				return box, nil
			}
			err = fmt.Errorf("element has no geometric representation (BoxModel invalid or zero size)")
		}

		h.logger.Debug("Humanoid: Failed to get valid BoxModel, retrying...", zap.Int("attempt", i+1), zap.Error(err))

		// Wait before retrying (Exponential backoff).
		sleepDuration := time.Millisecond * time.Duration(50*math.Pow(2, float64(i)))
		// REFACTORED: Use the executor sleep.
		if err := h.executor.Sleep(ctx, sleepDuration); err != nil {
			// Context was cancelled during sleep
			return nil, err
		}
	}

	return nil, fmt.Errorf("failed to get element box after %d attempts: %w", maxRetries, err)
}

// getCenterOfElement is a convenience wrapper.
func (h *Humanoid) getCenterOfElement(ctx context.Context, selector string) (Vector2D, error) {
	box, err := h.getElementBoxBySelector(ctx, selector)
	if err != nil {
		return Vector2D{}, err
	}
	center, valid := boxToCenter(box)
	if !valid {
		return Vector2D{}, fmt.Errorf("humanoid: element '%s' has invalid geometry", selector)
	}
	return center, nil
}
