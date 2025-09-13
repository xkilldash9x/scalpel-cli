// internal/humanoid/helpers.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	// Required for NodeID and Node types
	"github.com/chromedp/cdproto/cdp"
	// Required for BoxModel and low-level DOM access. Necessary for precise geometry.
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// boxToCenter calculates the geometric center (centroid) of a DOM BoxModel.
func boxToCenter(box *dom.BoxModel) (center Vector2D, valid bool) {
	if box == nil || len(box.Content) < 8 {
		return Vector2D{}, false
	}
	// Calculate the average of the x and y coordinates.
	// Content is defined as [x0, y0, x1, y1, x2, y2, x3, y3].
	centerX := (box.Content[0] + box.Content[2] + box.Content[4] + box.Content[6]) / 4
	centerY := (box.Content[1] + box.Content[3] + box.Content[5] + box.Content[7]) / 4
	return Vector2D{X: centerX, Y: centerY}, true
}

// getElementBoxByVector creates a virtual BoxModel around a specific coordinate.
func (h *Humanoid) getElementBoxByVector(ctx context.Context, vec Vector2D) (*dom.BoxModel, error) {
	// Create a virtual box of 10x10 pixels centered on the vector
	const virtualBoxSize = 10.0
	halfSize := virtualBoxSize / 2.0
	return &dom.BoxModel{
		Content: []float64{
			vec.X - halfSize, vec.Y - halfSize, // top-left
			vec.X + halfSize, vec.Y - halfSize, // top-right
			vec.X + halfSize, vec.Y + halfSize, // bottom-right
			vec.X - halfSize, vec.Y + halfSize, // bottom-left
		},
		Width:  int64(virtualBoxSize),
		Height: int64(virtualBoxSize),
	}, nil
}

// getElementBoxBySelector is a utility to find an element by selector and get its BoxModel.
func (h *Humanoid) getElementBoxBySelector(ctx context.Context, selector string) (*dom.BoxModel, error) {
	// Nodes must be a slice of pointers for chromedp.Nodes.
	var nodes []*cdp.Node

	// Sequence WaitVisible and Nodes using chromedp.Tasks.
	tasks := chromedp.Tasks{
		chromedp.WaitVisible(selector, chromedp.ByQuery),
		chromedp.Nodes(selector, &nodes, chromedp.ByQuery),
	}
	err := tasks.Do(ctx)

	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(nodes) == 0 {
            // If WaitVisible fails, it usually means the element isn't visible even after scrolling attempts.
			return nil, fmt.Errorf("humanoid: failed to find visible nodes for selector '%s': %w", selector, err)
		}
		// If nodes were found despite the error (e.g., timeout during Nodes retrieval but after WaitVisible succeeded), proceed.
		h.logger.Debug("Humanoid: chromedp.Nodes returned error but found nodes, proceeding.", zap.Error(err))
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("humanoid: selector '%s' matched no nodes", selector)
	}

	// Use the robust getElementBox helper on the first node found.
	box, err := getElementBox(ctx, nodes[0].NodeID, h.logger)
	if err != nil {
		return nil, fmt.Errorf("humanoid: failed to get element geometry for '%s': %w", selector, err)
	}
	return box, nil
}

// getElementBox retrieves the BoxModel for a given node ID with retry logic.
func getElementBox(ctx context.Context, nodeID cdp.NodeID, logger *zap.Logger) (*dom.BoxModel, error) {
	var box *dom.BoxModel
	var err error

	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		// Use the constructor pattern for low-level DOM commands.
		box, err = dom.GetBoxModel().WithNodeID(nodeID).Do(ctx)

		if err == nil {
			// Check if the BoxModel is valid (has dimensions).
			if box != nil && len(box.Content) >= 8 && box.Width > 0 && box.Height > 0 {
				return box, nil
			}
			err = fmt.Errorf("element has no geometric representation (BoxModel invalid or zero size)")
		}

		logger.Debug("Humanoid: Failed to get valid BoxModel, retrying...", zap.Int("attempt", i+1), zap.Error(err))

		// Wait before retrying (Exponential backoff).
		sleepDuration := time.Millisecond * time.Duration(50*math.Pow(2, float64(i)))
		if err := chromedp.Sleep(sleepDuration).Do(ctx); err != nil {
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