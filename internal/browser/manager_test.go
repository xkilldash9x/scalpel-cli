// internal/browser/manager_test.go
package browser_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/internal/browser"
)

// TestManager_LaunchAndShutdown verifies the basic lifecycle without using the fixture helper.
func TestManager_LaunchAndShutdown(t *testing.T) {
	logger, cfg := setupTestConfig(t)

	// 1. Launch
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	mgr, err := browser.NewManager(ctx, logger, cfg)
	require.NoError(t, err, "Failed to launch Browser Manager")
	require.NotNil(t, mgr)

	// 2. Initialize and Close a Session (Verifies responsiveness)
	sessionCtx, sessionCancel := context.WithTimeout(ctx, 15*time.Second)
	defer sessionCancel()
	session, err := mgr.InitializeSession(sessionCtx)
	require.NoError(t, err)
	err = session.Close(sessionCtx)
	require.NoError(t, err)

	// 3. Shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	err = mgr.Shutdown(shutdownCtx)
	require.NoError(t, err, "Failed to shutdown Browser Manager")
}

// TestManager_GracefulShutdownWithActiveSessions verifies the manager waits for sessions to close.
func TestManager_GracefulShutdownWithActiveSessions(t *testing.T) {
	fixture := setupBrowserManager(t)

	// Initialize a session but don't close it yet.
	session := fixture.initializeSession(t)

	// Start shutdown in a separate goroutine.
	shutdownDone := make(chan struct{})
	go func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()
		fixture.Manager.Shutdown(shutdownCtx)
		close(shutdownDone)
	}()

	// Wait briefly to ensure Shutdown() is waiting on the WaitGroup.
	time.Sleep(500 * time.Millisecond)

	select {
	case <-shutdownDone:
		t.Fatal("Shutdown completed prematurely while a session was active.")
	default:
		// Expected: Shutdown is blocked.
	}

	// Now close the session.
	err := session.Close(fixture.MgrCtx)
	require.NoError(t, err)

	// Shutdown should now complete gracefully.
	select {
	case <-shutdownDone:
		// Success
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for graceful shutdown after closing the session.")
	}
}

// TestManager_ForcedShutdownTimeout verifies the manager terminates if the shutdown context times out.
func TestManager_ForcedShutdownTimeout(t *testing.T) {
	logger, cfg := setupTestConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	mgr, err := browser.NewManager(ctx, logger, cfg)
	require.NoError(t, err)

	// Initialize a session and intentionally do not close it.
	_, err = mgr.InitializeSession(ctx)
	require.NoError(t, err)

	// Start shutdown with a very short timeout.
	startTime := time.Now()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	// This should block until the timeout (2s) and then force termination.
	err = mgr.Shutdown(shutdownCtx)
	duration := time.Since(startTime)

	assert.NoError(t, err) // Shutdown itself doesn't return an error when forced.

	// The duration should be close to the timeout.
	assert.Greater(t, duration, 1900*time.Millisecond, "Shutdown should have waited for the timeout")
	assert.Less(t, duration, 3*time.Second, "Shutdown took significantly longer than the timeout")
}