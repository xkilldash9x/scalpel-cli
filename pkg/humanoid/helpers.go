package humanoid

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/runtime"
)
// NOTE: This is a partial file containing only the missing function. 
// Add this function to your existing helpers.go file.

// getCenterOfElement finds an element by selector and returns its center coordinates.
func (h *Humanoid) getCenterOfElement(ctx context.Context, selector string) (Vector2D, error) {
	var res *runtime.RemoteObject
	expression := fmt.Sprintf(`
		(() => {
			const el = document.querySelector('%s');
			if (!el) return null;
			const rect = el.getBoundingClientRect();
			return JSON.stringify({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 });
		})();
	`, selector)

	err := h.browser.Evaluate(ctx, expression, &res)
	if err != nil {
		return Vector2D{}, fmt.Errorf("failed to execute javascript to find element center: %w", err)
	}

	if res.Type == "string" {
		var point struct {
			X float64 `json:"x"`
			Y float64 `json:"y"`
		}
		if err := json.Unmarshal([]byte(res.Value.(string)), &point); err != nil {
			return Vector2D{}, fmt.Errorf("failed to unmarshal element coordinates: %w", err)
		}
		return Vector2D{X: point.X, Y: point.Y}, nil
	}

	return Vector2D{}, fmt.Errorf("element with selector '%s' not found", selector)
}
