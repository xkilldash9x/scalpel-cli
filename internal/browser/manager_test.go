package browser_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_LaunchAndShutdown verifies the basic lifecycle: launch, create a
// session, close the session, and shut down the manager.
func TestManager_LaunchAndShutdown(t *testing.T) {
	t.Parallel()
	fixture := setupBrowserManager(t)

	// Initialize and then immediately close a session to verify responsiveness.
	sessionCtx, sessionCancel := context.WithTimeout(fixture.MgrCtx, 20*time.Second)
	defer sessionCancel()
	session, err := fixture.Manager.InitializeSession(sessionCtx)
	require.NoError(t, err)
	require.NotNil(t, session)

	// Close the session.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()
	session.Close(closeCtx)
}

// TestManager_GracefulShutdownWithActiveSessions verifies that the manager correctly
// waits for active sessions to be closed before completing its shutdown process.
func TestManager_GracefulShutdownWithActiveSessions(t *testing.T) {
	t.Parallel()
	fixture := setupBrowserManager(t)

	// Initialize a session but don't close it yet.
	session, err := fixture.Manager.InitializeSession(fixture.MgrCtx)
	require.NoError(t, err)

	shutdownDone := make(chan struct{})
	go func() {
		// This shutdown call should block until the session is closed.
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		fixture.Manager.Shutdown(shutdownCtx)
		close(shutdownDone)
	}()

	// Give the shutdown goroutine a moment to start and block on the WaitGroup.
	time.Sleep(500 * time.Millisecond)
	select {
	case <-shutdownDone:
		t.Fatal("Shutdown should block while a session is active")
	default:
		// This is expected
	}

	// Now, close the session, which should unblock the Shutdown call.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer closeCancel()
	session.Close(closeCtx)

	// The shutdown process should now complete gracefully.
	select {
	case <-shutdownDone:
		// Success! The channel was closed, meaning Shutdown completed.
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout: Manager did not shut down gracefully after the session was closed.")
	}
}

// TestManager_ForcedShutdownTimeout verifies that Shutdown respects the context
// timeout and terminates even if sessions are still active.
func TestManager_ForcedShutdownTimeout(t *testing.T) {
	t.Parallel()
	fixture := setupBrowserManager(t)

	// Initialize a session and intentionally "leak" it (don't close it).
	_, err := fixture.Manager.InitializeSession(fixture.MgrCtx)
	require.NoError(t, err)

	// Call Shutdown with a very short timeout.
	startTime := time.Now()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	fixture.Manager.Shutdown(shutdownCtx)
	duration := time.Since(startTime)

	// Verify that the shutdown was forced by the timeout. The duration should be
	// very close to the timeout value we provided.
	assert.InDelta(t, 2*time.Second, duration, float64(500*time.Millisecond),
		"Shutdown should have been forced by the context timeout after ~2s")
}
