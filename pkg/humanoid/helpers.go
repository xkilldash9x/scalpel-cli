// pkg/humanoid/helpers.go
package humanoid

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/chromedp/cdproto/input"
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
	return center, float64(box.Width), float64(box.Height)
}

// fittsLawMT calculates the Movement Time (MT) according to Fitts's Law.
// MT = A + B * ID, where ID (Index of Difficulty) = log2(D/W + 1).
func (h *Humanoid) fittsLawMT(distance, width float64) float64 {
	// Ensure a minimum effective width.
	minWidth := 5.0
	effectiveWidth := math.Max(width, minWidth)

	// Index of Difficulty (ID).
	id := math.Log2(distance/effectiveWidth + 1)

	h.mu.Lock()
	// Use dynamic config parameters (affected by fatigue).
	A := h.dynamicConfig.FittsA
	B := h.dynamicConfig.FittsB
	randNorm := h.rng.NormFloat64()
	h.mu.Unlock()

	// Predicted Movement Time (MT).
	mt := A + B*id

	// Introduce variability (Coefficient of Variation CV ~ 12%).
	variability := 0.12
	stdDev := mt * variability
	finalMT := randNorm*stdDev + mt

	// Ensure MT is not unrealistically fast.
	return math.Max(A*0.8, finalMT)
}

// getElementBoxBySelector is a utility to find an element by selector and get its BoxModel.
func (h *Humanoid) getElementBoxBySelector(ctx context.Context, selector string) (*dom.BoxModel, error) {
	var nodes []*cdp.Node
	// WaitVisible ensures the element is rendered and in the viewport.
	err := chromedp.Nodes(selector, &nodes, chromedp.ByQuery, chromedp.WaitVisible).Do(ctx)

	if err != nil {
		if len(nodes) == 0 {
			return nil, fmt.Errorf("humanoid: failed to find visible nodes for selector '%s': %w", selector, err)
		}
		// If nodes were found despite the error (e.g., timeout), proceed.
		h.logger.Debug("Humanoid: chromedp.Nodes returned error but found nodes, proceeding.", zap.Error(err))
	}

	if len(nodes) == 0 {
		return nil, fmt.Errorf("humanoid: selector '%s' matched no nodes", selector)
	}

	// Use the robust getElementBox helper.
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
		box, err = dom.GetBoxModel().WithNodeID(nodeID).Do(ctx)

		if err == nil {
			// Check if the BoxModel is valid.
			if box != nil && len(box.Content) >= 8 && box.Width > 0 && box.Height > 0 {
				return box, nil
			}
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