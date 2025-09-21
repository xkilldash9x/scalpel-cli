// internal/browser/browser_helper_test.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

var (
	processSemaphore *semaphore.Weighted
	suiteLogger      *zap.Logger
	suiteConfig      *config.Config
)

// Forcing sequential execution for stability in CI environments.
const maxTestConcurrency = 1
const shutdownTimeout = 15 * time.Second

func TestMain(m *testing.M) {
	suiteLogger = getTestLogger()
	suiteConfig = createTestConfig()

	concurrency := int64(runtime.GOMAXPROCS(0))
	if concurrency > maxTestConcurrency {
		concurrency = maxTestConcurrency
	}
	if concurrency < 1 {
		concurrency = 1
	}
	suiteLogger.Info("Initializing browser test suite.", zap.Int64("concurrency_limit", concurrency))
	processSemaphore = semaphore.NewWeighted(concurrency)

	exitCode := m.Run()
	os.Exit(exitCode)
}

// Updated testFixture to use the new Session struct.
type testFixture struct {
	Session *Session
	Config  *config.Config
	Manager *Manager
	Logger  *zap.Logger
}

type fixtureConfigurator func(*config.Config)

func getTestLogger() *zap.Logger {
	if suiteLogger != nil {
		return suiteLogger
	}
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("failed to initialize zap logger for tests: " + err.Error())
	}
	return logger
}

// createTestConfig generates a configuration optimized for fast integration testing.
func createTestConfig() *config.Config {
	// Start with the default humanoid configuration
	humanoidCfg := humanoid.DefaultConfig()

	// Speed up humanoid simulation significantly for tests to prevent timeouts.
	humanoidCfg.FittsAMean = 10.0
	humanoidCfg.FittsBMean = 20.0
	humanoidCfg.ClickHoldMinMs = 5
	humanoidCfg.ClickHoldMaxMs = 15
	humanoidCfg.KeyHoldMeanMs = 10.0

	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:        true,
			DisableCache:    true,
			IgnoreTLSErrors: true,
			Concurrency:     4,
			Humanoid:        humanoidCfg,
			Debug:           true,
		},
		Network: config.NetworkConfig{
			CaptureResponseBodies: true,
			NavigationTimeout:     20 * time.Second,
			Proxy:                 config.ProxyConfig{Enabled: false},
		},
		// Ensure IAST is disabled for standard tests unless specifically enabled.
		IAST: config.IASTConfig{Enabled: false},
	}
	cfg.Browser.Humanoid.Enabled = true
	return cfg
}

// newTestFixture creates a sandboxed environment for browser tests.
func newTestFixture(t *testing.T, configurators ...fixtureConfigurator) *testFixture {
	t.Helper()

	cfgCopy := *suiteConfig
	for _, configurator := range configurators {
		configurator(&cfgCopy)
	}

	// --- Semaphore Acquisition ---
	acquireCtx, acquireCancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(acquireCancel)

	if err := processSemaphore.Acquire(acquireCtx, 1); err != nil {
		t.Fatalf("Failed to acquire semaphore: %v", err)
	}

	// Register Semaphore Release (LIFO: Runs LAST)
	t.Cleanup(func() {
		processSemaphore.Release(1)
	})

	// --- Browser Lifecycle Management ---
	// Use context.Background() for the browser lifecycle.
	lifecycleCtx := context.Background()
	logger := suiteLogger.With(zap.String("test", t.Name()))

	// Initialize the manager.
	manager, err := NewManager(lifecycleCtx, &cfgCopy, logger)
	require.NoError(t, err, "Failed to initialize per-test browser manager")

	// Register Manager Shutdown (LIFO: Runs SECOND)
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()
		logger.Debug("Starting graceful shutdown of browser manager.")
		if err := manager.Shutdown(shutdownCtx); err != nil {
			t.Logf("Warning: Error during browser manager shutdown: %v", err)
		}
		logger.Debug("Graceful shutdown complete.")
	})

	// Create the session.
	sessionInterface, err := manager.NewAnalysisContext(
		lifecycleCtx, // Pass the lifecycle context
		&cfgCopy,
		schemas.DefaultPersona,
		"",
		"",
	)
	require.NoError(t, err, "Failed to create new analysis context")

	// Type assertion to the concrete Session type.
	session, ok := sessionInterface.(*Session)
	require.True(t, ok, "session must be of type *Session")

	// Register Session Close (LIFO: Runs FIRST)
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), shutdownTimeout/2)
		defer closeCancel()
		if err := session.Close(closeCtx); err != nil {
			t.Logf("Warning: Error during session close: %v", err)
		}
	})

	return &testFixture{
		Session: session,
		Config:  &cfgCopy,
		Manager: manager,
		Logger:  logger,
	}
}

func createTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

func createStaticTestServer(t *testing.T, htmlContent string) *httptest.Server {
	t.Helper()
	return createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, htmlContent)
	}))
}
