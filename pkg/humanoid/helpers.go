// pkg/humanoid/helpers.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"
)

// boxToCenter calculates the geometric center of a DOM BoxModel (quadrilateral).
func boxToCenter(box *dom.BoxModel) (center Vector2D, valid bool) {
	// BoxModel Content contains the 4 corners (x0, y0, x1, y1, x2, y2, x3, y3).
	if box == nil || len(box.Content) < 8 {
		return Vector2D{}, false
	}
	// Calculate the average of the x and y coordinates (centroid).
	centerX := (box.Content[0] + box.Content[2] + box.Content[4] + box.Content[6]) / 4
	centerY := (box.Content[1] + box.Content[3] + box.Content[5] + box.Content[7]) / 4
	return Vector2D{X: centerX, Y: centerY}, true
}

// boxToDimensions returns the center, width, and height of a BoxModel.
func boxToDimensions(box *dom.BoxModel) (center Vector2D, width, height float64) {
	if box == nil {
		return Vector2D{}, 0, 0
	}
	center, valid := boxToCenter(box)
	if !valid {
		return Vector2D{}, 0, 0
	}
	// Width and Height are provided directly in the BoxModel struct.
	return center, float64(box.Width), float64(box.Height)
}

// fittsLawMT calculates the Movement Time (MT) according to Fitts's Law.
// MT = A + B * ID, where ID (Index of Difficulty) = log2(D/W + 1).
func (h *Humanoid) fittsLawMT(distance, width float64) float64 {
	// Ensure a minimum effective width to prevent extreme ID values for tiny targets.
	minWidth := 5.0
	effectiveWidth := math.Max(width, minWidth)

	// Index of Difficulty (ID).
	id := math.Log2(distance/effectiveWidth + 1)

	h.mu.Lock()
	// Use dynamic config parameters (affected by fatigue and session persona).
	A := h.dynamicConfig.FittsA
	B := h.dynamicConfig.FittsB
	// Generate the random number while locked.
	randNorm := h.rng.NormFloat64()
	h.mu.Unlock()

	// Predicted Movement Time (MT).
	mt := A + B*id

	// Introduce variability (Coefficient of Variation CV ~ 12%).
	variability := 0.12
	stdDev := mt * variability
	finalMT := randNorm*stdDev + mt

	// Ensure MT is not unrealistically fast (bounded by minimum latency).
	return math.Max(A*0.8, finalMT)
}

// getElementBoxBySelector is a utility to find an element by selector and get its BoxModel.
func (h *Humanoid) getElementBoxBySelector(ctx context.Context, selector string) (*dom.BoxModel, error) {
	var nodes []*cdp.Node
	// WaitVisible ensures the element is rendered and in the viewport before getting the box model.
	err := chromedp.Nodes(selector, &nodes, chromedp.ByQuery, chromedp.WaitVisible).Do(ctx)

	if err != nil {
		// Check if nodes were found despite the error (e.g., context timeout during long wait, but element exists).
		if len(nodes) == 0 {
			return nil, fmt.Errorf("humanoid: failed to find visible nodes for selector '%s': %w", selector, err)
		}
		// If nodes were found, log the error but proceed.
		h.logger.Debug("Humanoid: chromedp.Nodes returned error but found nodes, proceeding.", zap.Error(err))
	}

	if len(nodes) == 0 {
		// Final check in case err was nil but nodes list is empty.
		return nil, fmt.Errorf("humanoid: selector '%s' matched no nodes", selector)
	}

	// Use the robust getElementBox helper to retrieve the geometry.
	box, err := getElementBox(ctx, nodes[0].NodeID, h.logger)
	if err != nil {
		return nil, fmt.Errorf("humanoid: failed to get element geometry for '%s': %w", selector, err)
	}
	return box, nil
}

// getElementBox retrieves the BoxModel for a given node ID with retry logic.
// This handles transient states where the element exists but its geometry is temporarily unavailable.
func getElementBox(ctx context.Context, nodeID cdp.NodeID, logger *zap.Logger) (*dom.BoxModel, error) {
	var box *dom.BoxModel
	var err error

	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		box, err = dom.GetBoxModel().WithNodeID(nodeID).Do(ctx)

		if err == nil {
			// Check if the BoxModel is valid (has geometry and non-zero size).
			if box != nil && len(box.Content) >= 8 && box.Width > 0 && box.Height > 0 {
				return box, nil
			}
			// If geometry is invalid, it might be transient (e.g., during animation or layout shift).
			err = fmt.Errorf("element has no geometric representation (BoxModel invalid or zero size)")
		}

		logger.Debug("Humanoid: Failed to get valid BoxModel, retrying...", zap.Int("attempt", i+1), zap.Error(err))

		// Wait before retrying (Exponential backoff).
		select {
		case <-time.After(time.Millisecond * time.Duration(50*math.Pow(2, float64(i)))):
			continue
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, fmt.Errorf("failed to get element box after %d attempts: %w", maxRetries, err)
}
