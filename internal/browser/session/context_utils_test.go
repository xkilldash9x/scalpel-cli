// internal/browser/session/context_utils_test.go
package session

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCombineContext verifies the behavior of CombineContext.
func TestCombineContext(t *testing.T) {
	// Define a key for context values
	type ctxKey string
	const key ctxKey = "testKey"
	const value = "testValue"

	// 1. Test value inheritance from ctx1 (Primary)
	t.Run("InheritsValuesFromPrimary", func(t *testing.T) {
		ctx1 := context.WithValue(context.Background(), key, value)
		ctx2 := context.Background()

		combinedCtx, cancel := CombineContext(ctx1, ctx2)
		defer cancel()

		assert.Equal(t, value, combinedCtx.Value(key), "Combined context should inherit values from ctx1")
		assert.Nil(t, combinedCtx.Err(), "Context should not be done yet")
	})

	// 2. Test cancellation when ctx1 (Primary) is canceled
	t.Run("CancelledByPrimary", func(t *testing.T) {
		ctx1, cancel1 := context.WithCancel(context.Background())
		ctx2 := context.Background()

		combinedCtx, cancelCombined := CombineContext(ctx1, ctx2)
		defer cancelCombined()

		cancel1() // Cancel the primary context

		// Wait briefly for the cancellation to propagate
		assert.Eventually(t, func() bool {
			return combinedCtx.Err() != nil
		}, 100*time.Millisecond, 10*time.Millisecond, "Combined context should be cancelled when ctx1 is cancelled")
		assert.ErrorIs(t, combinedCtx.Err(), context.Canceled)
	})

	// 3. Test cancellation when ctx2 (Secondary) is canceled
	t.Run("CancelledBySecondary", func(t *testing.T) {
		ctx1 := context.Background()
		ctx2, cancel2 := context.WithCancel(context.Background())

		combinedCtx, cancelCombined := CombineContext(ctx1, ctx2)
		defer cancelCombined()

		cancel2() // Cancel the secondary context

		// Wait briefly for the cancellation to propagate (handled by the internal goroutine)
		assert.Eventually(t, func() bool {
			return combinedCtx.Err() != nil
		}, 100*time.Millisecond, 10*time.Millisecond, "Combined context should be cancelled when ctx2 is cancelled")
		assert.ErrorIs(t, combinedCtx.Err(), context.Canceled)
	})

	// 4. Test deadline inheritance from ctx1 (Primary)
	t.Run("DeadlineFromPrimary", func(t *testing.T) {
		deadline := time.Now().Add(50 * time.Millisecond)
		ctx1, cancel1 := context.WithDeadline(context.Background(), deadline)
		defer cancel1()
		ctx2 := context.Background()

		combinedCtx, cancelCombined := CombineContext(ctx1, ctx2)
		defer cancelCombined()

		combinedDeadline, ok := combinedCtx.Deadline()
		require.True(t, ok, "Combined context should have a deadline")
		// Allow a small tolerance for time comparison
		assert.InDelta(t, deadline.UnixNano(), combinedDeadline.UnixNano(), float64(10*time.Millisecond.Nanoseconds()), "Deadline should match ctx1")

		// Wait for the deadline
		<-combinedCtx.Done()
		assert.ErrorIs(t, combinedCtx.Err(), context.DeadlineExceeded)
	})

	// 5. Test deadline when ctx2 (Secondary) has an earlier deadline
	t.Run("DeadlineFromSecondary", func(t *testing.T) {
		// ctx1 has a long deadline
		ctx1, cancel1 := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel1()

		// ctx2 has a short deadline
		deadline2 := time.Now().Add(50 * time.Millisecond)
		ctx2, cancel2 := context.WithDeadline(context.Background(), deadline2)
		defer cancel2()

		combinedCtx, cancelCombined := CombineContext(ctx1, ctx2)
		defer cancelCombined()

		// Wait for the deadline from ctx2
		<-combinedCtx.Done()

		// Check that it finished because ctx2 finished
		assert.ErrorIs(t, ctx2.Err(), context.DeadlineExceeded, "ctx2 should have exceeded deadline")
		// Note: CombineContext uses WithCancel(ctx1), so when the internal goroutine calls cancel(), the error is Canceled, not DeadlineExceeded, even if ctx2 timed out.
		assert.ErrorIs(t, combinedCtx.Err(), context.Canceled, "Combined context should be Canceled when the secondary context finishes")
	})

	// 6. Test explicit cancellation of the combined context
	t.Run("ExplicitCancellation", func(t *testing.T) {
		ctx1 := context.Background()
		ctx2 := context.Background()

		combinedCtx, cancelCombined := CombineContext(ctx1, ctx2)
		cancelCombined()

		// Should be done immediately
		assert.ErrorIs(t, combinedCtx.Err(), context.Canceled)
	})
}

// TestDetach verifies the behavior of Detach and valueOnlyContext.
func TestDetach(t *testing.T) {
	// Define a key for context values
	type ctxKey string
	const key ctxKey = "testKey"
	const value = "testValue"

	// 1. Test value inheritance
	t.Run("InheritsValues", func(t *testing.T) {
		parentCtx := context.WithValue(context.Background(), key, value)
		detachedCtx := Detach(parentCtx)

		assert.Equal(t, value, detachedCtx.Value(key), "Detached context should inherit values")
	})

	// 2. Test cancellation isolation
	t.Run("IgnoresParentCancellation", func(t *testing.T) {
		parentCtx, cancelParent := context.WithCancel(context.Background())
		detachedCtx := Detach(parentCtx)

		cancelParent()

		// Parent should be canceled
		assert.ErrorIs(t, parentCtx.Err(), context.Canceled)

		// Detached context should not be canceled
		assert.Nil(t, detachedCtx.Err(), "Detached context should have nil Err")
		assert.Nil(t, detachedCtx.Done(), "Detached context should have nil Done channel")
	})

	// 3. Test deadline isolation
	t.Run("IgnoresParentDeadline", func(t *testing.T) {
		parentCtx, cancelParent := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancelParent()

		detachedCtx := Detach(parentCtx)

		// Wait for parent deadline
		<-parentCtx.Done()
		assert.ErrorIs(t, parentCtx.Err(), context.DeadlineExceeded)

		// Detached context should not have a deadline
		deadline, ok := detachedCtx.Deadline()
		assert.False(t, ok, "Detached context should not have a deadline")
		assert.True(t, deadline.IsZero(), "Deadline should be zero time")
		assert.Nil(t, detachedCtx.Err(), "Detached context should not be done")
	})

	// 4. Test behavior when derived from detached context
	t.Run("DerivedFromDetached", func(t *testing.T) {
		parentCtx, cancelParent := context.WithCancel(context.Background())
		detachedCtx := Detach(parentCtx)

		// Create a derived context with a timeout
		derivedCtx, cancelDerived := context.WithTimeout(detachedCtx, 50*time.Millisecond)
		defer cancelDerived()

		cancelParent() // Cancel the original parent

		// Wait for the derived context deadline
		<-derivedCtx.Done()

		assert.Nil(t, detachedCtx.Err(), "Detached context remains unaffected")
		assert.ErrorIs(t, derivedCtx.Err(), context.DeadlineExceeded, "Derived context respects its own timeout")
	})
}
