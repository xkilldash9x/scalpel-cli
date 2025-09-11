// internal/browser/browser_set_test.go
package browser_test

import (
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	// Import the package being tested and its dependencies.
	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// testFixture holds the environment for browser integration tests.
type testFixture struct {
	Manager    *browser.Manager
	Logger     *zap.Logger
	Config     *config.Config
	MgrCtx     context.Context
	cancel     context.CancelFunc
	tempDir    string
	shimPath   string
	configPath string
}

// setupTestConfig initializes the configuration and logger.
func setupTestConfig(t *testing.T) (*zap.Logger, *config.Config) {
	t.Helper()
	logger := zaptest.NewLogger(t, zaptest.Level(zap.DebugLevel))

	// Get the default humanoid config to modify it for testing.
	humanoidCfg := humanoid.DefaultConfig()
	// Speed up humanoid actions significantly for testing.
	humanoidCfg.FittsAMean = 20.0    // Drastically reduce base movement delay
	humanoidCfg.FittsBMean = 30.0    // Drastically reduce distance-based movement delay
	humanoidCfg.KeyHoldMeanMs = 10.0 // Make typing almost instant

	// Default configuration optimized for testing.
	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:        true, // Run headless in tests.
			DisableCache:    true,
			IgnoreTLSErrors: true,
			Humanoid:        humanoidCfg, // Use the modified config
		},
		Network: config.NetworkConfig{
			PostLoadWait:          50 * time.Millisecond, // Faster waits for tests
			CaptureResponseBodies: true,
		},
		IAST: config.IASTConfig{},
	}

	return logger, cfg
}

// setupBrowserManager initializes and starts the Browser Manager for a test suite.
func setupBrowserManager(t *testing.T) *testFixture {
	t.Helper()
	logger, cfg := setupTestConfig(t)

	// The manager requires valid paths for IAST files at initialization.
	tempDir, err := ioutil.TempDir("", "manager-test-*")
	require.NoError(t, err)

	shimFile, err := ioutil.TempFile(tempDir, "shim-*.js")
	require.NoError(t, err)
	_, _ = shimFile.WriteString("/* mock shim */")
	shimFile.Close()

	configFile, err := ioutil.TempFile(tempDir, "config-*.json")
	require.NoError(t, err)
	_, _ = configFile.WriteString("{}")
	configFile.Close()

	cfg.IAST.ShimPath = shimFile.Name()
	cfg.IAST.ConfigPath = configFile.Name()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)

	mgr, err := browser.NewManager(ctx, logger, cfg)
	if err != nil {
		cancel()
		t.Fatalf("Failed to initialize Browser Manager. Ensure Chrome/Chromium is installed: %v", err)
	}

	fixture := &testFixture{
		Manager:    mgr,
		Logger:     logger,
		Config:     cfg,
		MgrCtx:     ctx,
		cancel:     cancel,
		tempDir:    tempDir,
		shimPath:   shimFile.Name(),
		configPath: configFile.Name(),
	}

	// Ensure the manager is shutdown when the test finishes.
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		fixture.Manager.Shutdown(shutdownCtx)
		fixture.cancel()
		_ = os.RemoveAll(fixture.tempDir)
	})

	return fixture
}

// initializeSession creates a new browser session using the fixture's manager.
func (f *testFixture) initializeSession(t *testing.T) *browser.AnalysisContext {
	t.Helper()

	// Use a specific timeout for session initialization, derived from the manager context.
	sessionInitCtx, cancelInit := context.WithTimeout(f.MgrCtx, 30*time.Second)
	defer cancelInit()

	session, err := f.Manager.InitializeSession(sessionInitCtx)
	require.NoError(t, err)

	// Ensure the session is closed when the test finishes.
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		session.Close(closeCtx)
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

