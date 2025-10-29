// FILE: ./internal/browser/humanoid/helpers_test.go
package humanoid

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"go.uber.org/zap"
)

func TestBoxToCenter(t *testing.T) {
	t.Run("ValidGeometry", func(t *testing.T) {
		// A 10x10 box starting at (5, 5)
		geo := &schemas.ElementGeometry{
			Vertices: []float64{5, 5, 15, 5, 15, 15, 5, 15},
		}
		center, valid := boxToCenter(geo)
		assert.True(t, valid)
		assert.Equal(t, Vector2D{X: 10, Y: 10}, center)
	})

	t.Run("NilGeometry", func(t *testing.T) {
		_, valid := boxToCenter(nil)
		assert.False(t, valid)
	})

	t.Run("InsufficientVertices", func(t *testing.T) {
		geo := &schemas.ElementGeometry{Vertices: []float64{1, 2}}
		_, valid := boxToCenter(geo)
		assert.False(t, valid)
	})
}

func TestGetElementBoxBySelector(t *testing.T) {
	ctx := context.Background()
	mock := newMockExecutor(t)
	h := NewTestHumanoid(mock, 12345)
	h.logger = zap.NewNop()
	selector := "#test"

	t.Run("Success", func(t *testing.T) {
		// Default mock behavior returns valid geometry (10x10)
		mock.MockGetElementGeometry = nil
		geo, err := h.getElementBoxBySelector(ctx, selector)
		assert.NoError(t, err)
		assert.Equal(t, int64(10), geo.Width)
	})

	t.Run("ExecutorError", func(t *testing.T) {
		expectedErr := errors.New("failed")
		mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
			return nil, expectedErr
		}
		_, err := h.getElementBoxBySelector(ctx, selector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "geometry retrieval failed")
	})

	t.Run("ContextCancelled", func(t *testing.T) {
		cCtx, cancel := context.WithCancel(ctx)
		cancel()
		// Reset mock to use default behavior which checks ctx.Err()
		mock.MockGetElementGeometry = nil
		_, err := h.getElementBoxBySelector(cCtx, selector)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("NilGeometryReturned", func(t *testing.T) {
		mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
			return nil, nil
		}
		_, err := h.getElementBoxBySelector(ctx, selector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "returned nil geometry")
	})

	t.Run("InvalidVertices", func(t *testing.T) {
		mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
			return &schemas.ElementGeometry{Vertices: []float64{1, 2}, Width: 10, Height: 10}, nil
		}
		_, err := h.getElementBoxBySelector(ctx, selector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid geometry (expected 8 vertices")
	})

	t.Run("ZeroSize", func(t *testing.T) {
		mock.MockGetElementGeometry = func(ctx context.Context, selector string) (*schemas.ElementGeometry, error) {
			return &schemas.ElementGeometry{
				Vertices: []float64{0, 0, 0, 0, 0, 0, 0, 0},
				Width:    0, Height: 10,
			}, nil
		}
		_, err := h.getElementBoxBySelector(ctx, selector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "is not interactable (zero size)")
	})
}
