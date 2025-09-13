// internal/browser/browser_helper_test.go
package browser_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// testFixture holds the complete environment for browser integration tests.
type testFixture struct {
	Manager *browser.Manager
	Logger  *zap.Logger
	Config  *config.Config
}

// globalFixture is the single instance shared across all tests in the package.
var globalFixture *testFixture

// TestMain is the entry point for the test suite. It sets up a single
// browser manager and cleans it up after all tests have run.
func TestMain(m *testing.M) {
	fixture, cleanup, err := setupSharedBrowserManager()
	if err != nil {
		fmt.Printf("Failed to set up shared browser manager for tests: %v\n", err)
		os.Exit(1)
	}
	globalFixture = fixture

	// Run all tests
	exitCode := m.Run()

	// Teardown the shared manager
    // Added a log here to mark the start of the final shutdown.
    fmt.Println("--- Starting global test teardown ---")
	cleanup()
	os.Exit(exitCode)
}

// setupSharedBrowserManager creates a single browser manager instance for the entire test suite.
func setupSharedBrowserManager() (*testFixture, func(), error) {
	logger, err := zap.NewDevelopment()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create zap logger: %w", err)
	}

	// Configure humanoid behavior to be faster for tests.
	humanoidCfg := humanoid.DefaultConfig()
	humanoidCfg.FittsAMean = 20.0
	humanoidCfg.FittsBMean = 30.0
	humanoidCfg.KeyHoldMeanMs = 10.0

	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:        true,
			DisableCache:    true,
			IgnoreTLSErrors: true,
			Humanoid:        humanoidCfg,
		},
		Network: config.NetworkConfig{
			PostLoadWait:          50 * time.Millisecond,
			CaptureResponseBodies: true,
		},
		IAST: config.IASTConfig{},
	}

	tempDir, err := ioutil.TempDir("", "manager-test-suite-*")
	if err != nil {
		return nil, nil, err
	}

	shimFile, err := ioutil.TempFile(tempDir, "shim-*.js")
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, nil, err
	}
	_, _ = shimFile.WriteString("/* mock IAST shim */")
	shimFile.Close()
	cfg.IAST.ShimPath = shimFile.Name()

	configFile, err := ioutil.TempFile(tempDir, "config-*.json")
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, nil, err
	}
	_, _ = configFile.WriteString("{}")
	configFile.Close()
	cfg.IAST.ConfigPath = configFile.Name()

	// Initialize the Browser Manager. Use context.Background() as it lives for the whole test run.
	mgr, err := browser.NewManager(context.Background(), logger, cfg)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, nil, fmt.Errorf("failed to initialize Browser Manager. Ensure Chrome/Chromium is installed: %v", err)
	}

	fixture := &testFixture{
		Manager: mgr,
		Logger:  logger,
		Config:  cfg,
	}

	cleanupFunc := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		fixture.Manager.Shutdown(shutdownCtx)
		_ = os.RemoveAll(tempDir)
	}

	return fixture, cleanupFunc, nil
}

// initializeSession is a helper to create a new, isolated browser session for a specific test.
func (f *testFixture) initializeSession(t *testing.T) *browser.AnalysisContext {
	t.Helper()
	t.Logf("--> Initializing session for test: %s", t.Name())
	
	sessionInitCtx, cancelInit := context.WithTimeout(context.Background(), 30*time.Second)
	// Use a deferred call here to ensure the context is always cleaned up when this function returns.
	defer cancelInit()

	session, err := f.Manager.InitializeSession(sessionInitCtx)

	if err != nil {
		// We no longer need to call cancelInit() here, as the defer above handles it.
		require.NoError(t, err, "Failed to initialize browser session")
		return nil
	}
    t.Logf("Session initialized successfully: %s", session.ID())

	// Schedule a separate cleanup for the session itself that runs after the test finishes.
	t.Cleanup(func() {
        t.Logf("<-- Starting session cleanup for test: %s", t.Name())
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		session.Close(closeCtx)
        t.Logf("Session cleaned up successfully: %s", session.ID())
	})

	return session
}

// createTestServer starts a mock HTTP server for the duration of a test.
func createTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// createStaticTestServer is a convenience wrapper for serving a single static HTML page.
func createStaticTestServer(t *testing.T, htmlContent string) *httptest.Server {
	t.Helper()
	return createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlContent)
	}))
}