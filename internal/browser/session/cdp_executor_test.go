// internal/browser/session/cdp_executor_test.go
package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
)

// TestCDPExecutor uses mocks to test the executor's logic, particularly context handling and timeouts.
func TestCDPExecutor(t *testing.T) {
	logger := zaptest.NewLogger(t)
	masterCtx := context.Background()

	t.Run("Sleep", func(t *testing.T) {
		var capturedActions []chromedp.Action
		mockFunc := func(ctx context.Context, actions ...chromedp.Action) error {
			capturedActions = actions
			// Simulate the action running
			return nil
		}

		executor := &cdpExecutor{
			ctx:            masterCtx,
			logger:         logger,
			runActionsFunc: mockFunc,
		}

		duration := 100 * time.Millisecond
		err := executor.Sleep(context.Background(), duration)
		require.NoError(t, err)

		require.Len(t, capturedActions, 1)
		// Check if the action is a sleep action (chromedp.Sleep returns chromedp.Tasks)
		assert.IsType(t, (chromedp.ActionFunc)(nil), capturedActions[0])
	})

	t.Run("DispatchMouseEvent_Success", func(t *testing.T) {
		var capturedActions []chromedp.Action
		mockFunc := func(ctx context.Context, actions ...chromedp.Action) error {
			capturedActions = actions
			return nil
		}

		executor := &cdpExecutor{
			ctx:            masterCtx,
			logger:         logger,
			runActionsFunc: mockFunc,
		}

		data := schemas.MouseEventData{
			Type:       schemas.MousePress,
			X:          10.5,
			Y:          20.5,
			Button:     schemas.ButtonLeft,
			ClickCount: 1,
		}

		err := executor.DispatchMouseEvent(context.Background(), data)
		require.NoError(t, err)

		require.Len(t, capturedActions, 1)
		// Verify the action type and parameters
		action, ok := capturedActions[0].(*input.DispatchMouseEventParams) // FIX: Was DispatchMouseParams
		require.True(t, ok, "Action should be DispatchMouseEventParams")

		assert.Equal(t, input.MouseType(data.Type), action.Type)
		assert.Equal(t, data.X, action.X)
		assert.Equal(t, input.MouseButton(data.Button), action.Button)
	})

	t.Run("DispatchMouseEvent_Wheel", func(t *testing.T) {
		var capturedActions []chromedp.Action
		mockFunc := func(ctx context.Context, actions ...chromedp.Action) error {
			capturedActions = actions
			return nil
		}

		executor := &cdpExecutor{
			ctx:            masterCtx,
			logger:         logger,
			runActionsFunc: mockFunc,
		}

		data := schemas.MouseEventData{
			Type:   schemas.MouseWheel,
			X:      50,
			Y:      50,
			DeltaY: 100,
		}

		err := executor.DispatchMouseEvent(context.Background(), data)
		require.NoError(t, err)

		action, ok := capturedActions[0].(*input.DispatchMouseEventParams) // FIX: Was DispatchMouseParams
		require.True(t, ok)

		assert.Equal(t, input.MouseType("mouseWheel"), action.Type) // FIX: Was MouseTypeMouseWheel
		assert.Equal(t, data.DeltaY, action.DeltaY)
	})

	// Test the internal timeout (10s for mouse events)
	t.Run("DispatchMouseEvent_Timeout", func(t *testing.T) {
		mockFunc := func(ctx context.Context, actions ...chromedp.Action) error {
			// Simulate a long-running action that respects the context timeout
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(15 * time.Second): // Longer than the 10s internal timeout
				return errors.New("action took too long (mock error)")
			}
		}

		executor := &cdpExecutor{
			ctx:            masterCtx,
			logger:         logger,
			runActionsFunc: mockFunc,
		}

		data := schemas.MouseEventData{Type: schemas.MouseMove, X: 1, Y: 1}

		// Use a context that won't time out before the internal timeout
		opCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		startTime := time.Now()
		err := executor.DispatchMouseEvent(opCtx, data)
		duration := time.Since(startTime)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out after 10s")
		// Check that it actually timed out around 10s (allow buffer for test execution)
		assert.InDelta(t, float64(10*time.Second), float64(duration), float64(1*time.Second))
	})

	// Test the internal timeout (10s for send keys)
	t.Run("SendKeys_Timeout", func(t *testing.T) {
		mockFunc := func(ctx context.Context, actions ...chromedp.Action) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(15 * time.Second):
				return errors.New("mock error")
			}
		}

		executor := &cdpExecutor{
			ctx:            masterCtx,
			logger:         logger,
			runActionsFunc: mockFunc,
		}

		startTime := time.Now()
		err := executor.SendKeys(context.Background(), "test")
		duration := time.Since(startTime)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "timed out after 10s")
		assert.InDelta(t, float64(10*time.Second), float64(duration), float64(1*time.Second))
	})

	// Test the internal timeout (10s for geometry)
	t.Run("GetElementGeometry_Timeout", func(t *testing.T) {
		mockFunc := func(ctx context.Context, actions ...chromedp.Action) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(15 * time.Second):
				return errors.New("mock error")
			}
		}

		executor := &cdpExecutor{
			ctx:            masterCtx,
			logger:         logger,
			runActionsFunc: mockFunc,
		}

		startTime := time.Now()
		_, err := executor.GetElementGeometry(context.Background(), "#test")
		duration := time.Since(startTime)

		require.Error(t, err)
		// Check the specific error message format used in GetElementGeometry
		assert.Contains(t, err.Error(), "timeout getting geometry for '#test'")
		assert.InDelta(t, float64(10*time.Second), float64(duration), float64(1*time.Second))
	})

	// Test the internal timeout (20s for execute script)
	t.Run("ExecuteScript_Timeout", func(t *testing.T) {
		mockFunc := func(ctx context.Context, actions ...chromedp.Action) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(25 * time.Second): // Longer than the 20s internal timeout
				return errors.New("mock error")
			}
		}

		executor := &cdpExecutor{
			ctx:            masterCtx,
			logger:         logger,
			runActionsFunc: mockFunc,
		}

		startTime := time.Now()
		_, err := executor.ExecuteScript(context.Background(), "console.log('test')", nil)
		duration := time.Since(startTime)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "timeout during ExecuteScript")
		assert.InDelta(t, float64(20*time.Second), float64(duration), float64(1*time.Second))
	})

	t.Run("ExecuteScript_WithArgsWarning", func(t *testing.T) {
		// This test primarily aims to trigger the warning log when args are provided.
		mockFunc := func(ctx context.Context, actions ...chromedp.Action) error {
			return nil
		}

		executor := &cdpExecutor{
			ctx:            masterCtx,
			logger:         logger, // zaptest logger will show the warning in test output
			runActionsFunc: mockFunc,
		}

		_, err := executor.ExecuteScript(context.Background(), "console.log(arguments[0])", []interface{}{"arg1"})
		require.NoError(t, err)
		// The test runner output should contain: "WARN cdpExecutor.ExecuteScript received arguments..."
	})
}
