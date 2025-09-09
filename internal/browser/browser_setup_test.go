// internal/browser/browser_test_setup.go
package browser_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	// Import the package being tested and its dependencies.
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/interfaces"
)

// testFixture holds the environment for browser integration tests.
type testFixture struct {
	Manager *browser.Manager
	Logger  *zap.Logger
	Config  *config.Config
	// Context used for the manager's lifecycle (allocator).
	MgrCtx context.Context
}

// setupTestConfig initializes the configuration and logger.
func setupTestConfig(t *testing.T) (*zap.Logger, *config.Config) {
	t.Helper()
	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))

	// Default configuration optimized for testing.
	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:        true, // Run headless in tests.
			DisableCache:    true,
			IgnoreTLSErrors: true,
		},
		Network: config.NetworkConfig{
			PostLoadWait:          200 * time.Millisecond, // Faster waits for tests.
			CaptureResponseBodies: true,
		},
		Humanoid: humanoid.DefaultConfig(),
	}
	// Speed up humanoid actions significantly.
	cfg.Humanoid.SpeedMultiplier = 10.0

	return logger, cfg
}

// setupBrowserManager initializes and starts the Browser Manager for a test suite.
func setupBrowserManager(t *testing.T) *testFixture {
	t.Helper()
	logger, cfg := setupTestConfig(t)

	// Use a generous timeout for the manager's context.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)

	mgr, err := browser.NewManager(ctx, logger, cfg)
	if err != nil {
		cancel()
		t.Fatalf("Failed to initialize Browser Manager. Ensure Chrome/Chromium is installed: %v", err)
	}

	fixture := &testFixture{
		Manager: mgr,
		Logger:  logger,
		Config:  cfg,
		MgrCtx:  ctx,
	}

	// Ensure the manager is shutdown when the test finishes.
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := mgr.Shutdown(shutdownCtx); err != nil {
			t.Logf("Error during Browser Manager shutdown: %v", err)
		}
		cancel() // Cancel the main allocator context.
	})

	return fixture
}

// initializeSession creates a new browser session using the fixture's manager.
func (f *testFixture) initializeSession(t *testing.T) interfaces.SessionContext {
	t.Helper()

	// Use a specific timeout for session initialization, derived from the manager context.
	sessionInitCtx, cancelInit := context.WithTimeout(f.MgrCtx, 30*time.Second)

	session, err := f.Manager.InitializeSession(sessionInitCtx)
	if err != nil {
		cancelInit()
		t.Fatalf("Failed to initialize session: %v", err)
	}

	// Ensure the session is closed when the test finishes.
	t.Cleanup(func() {
		cancelInit() // Cancel the initialization context.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if err := session.Close(closeCtx); err != nil {
			t.Logf("Error closing session %s: %v", session.ID(), err)
		}
	})
	return session
}

// createTestServer starts a mock HTTP server.
func createTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}