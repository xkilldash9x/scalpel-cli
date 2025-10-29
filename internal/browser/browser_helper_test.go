// internal/browser/browser_helper_test.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync" // For sync.Once
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest" // For zaptest.NewLogger
	"golang.org/x/sync/semaphore"
)

var (
	// globalProcessSemaphore limits the number of concurrent browser processes/sessions across all tests.
	// It is initialized once using sync.Once the first time getGlobalProcessSemaphore is called.
	globalProcessSemaphore     *semaphore.Weighted
	globalProcessSemaphoreOnce sync.Once
	// Removed: suiteLogger, suiteConfig, suiteAllocatorCtx, suiteAllocCancel.
	// These are now managed per-test or initialized lazily.
)

// maxTestConcurrency limits the number of concurrent browser processes.
// Increased to 2 to prevent deadlocks in tests requiring multiple sessions (e.g., TestManager/InitializeMultipleSessions).
const maxTestConcurrency = 2 // Was 1
const shutdownTimeout = 15 * time.Second

// Constants for managing robust test timeouts (Context Best Practices, Section 4.2).
const (
	// FIX: Increased from 30s to 90s to accommodate significant overhead when running with -race.
	// BUMPING AGAIN to 120s just to be 100% sure this isn't the source.
	defaultBrowserTestTimeout = 120 * time.Second // Was 90 * time.Second
	testCleanupGracePeriod    = 1 * time.Second
	semaphoreAcquireTimeout   = 10 * time.Second
	// minTestExecutionTime defines a minimum time required for the test logic to run, excluding cleanup.
	minTestExecutionTime = 5 * time.Second
)

// TestMain function is removed as global allocator context is eliminated.
// Test setup is now managed per-test by newTestFixture.

// getGlobalProcessSemaphore initializes the semaphore only once across all tests in the package.
// It uses zap.NewNop() for its internal logging to avoid dependencies on *testing.T within the sync.Once block.
func getGlobalProcessSemaphore() *semaphore.Weighted {
	globalProcessSemaphoreOnce.Do(func() {
		initLogger := zap.NewNop() // Use a nop logger for this one-time global initialization.
		concurrency := int64(runtime.GOMAXPROCS(0))
		if concurrency > maxTestConcurrency {
			concurrency = maxTestConcurrency
		}
		if concurrency < 1 {
			concurrency = 1
		}
		initLogger.Info("Initializing browser test suite semaphore.", zap.Int64("concurrency_limit", concurrency))
		globalProcessSemaphore = semaphore.NewWeighted(concurrency)
	})
	return globalProcessSemaphore
}

// testFixture defines the sandboxed environment for browser tests.
// It no longer contains fields for AllocCtx or AllocCancel as these are managed locally within newTestFixture.
type testFixture struct {
	// Session *session.Session // REMOVED
	Config  *config.Config
	Manager *Manager
	Logger  *zap.Logger
	// RootCtx is the context tied to the test's lifecycle (respecting t.Deadline)
	RootCtx context.Context
}

// fixtureConfigurator is a function type to allow modifying the default config for specific tests.
type fixtureConfigurator func(*config.Config)

// createTestConfig generates a configuration optimized for fast integration testing.
// It no longer relies on a global logger.
func createTestConfig() *config.Config {
	defaultCfg := config.NewDefaultConfig()
	humanoidCfg := defaultCfg.Browser().Humanoid

	// Speed up humanoid simulation significantly for tests to prevent timeouts.
	humanoidCfg.FittsA = 10.0
	humanoidCfg.FittsB = 20.0
	humanoidCfg.ClickHoldMinMs = 5
	humanoidCfg.ClickHoldMaxMs = 15
	humanoidCfg.KeyHoldMu = 10.0

	cfg := &config.Config{
		BrowserCfg: config.BrowserConfig{
			Headless:        true,
			DisableCache:    true,
			IgnoreTLSErrors: true,
			Concurrency:     4,
			Humanoid:        humanoidCfg,
			Debug:           true,
			// Add --disable-dev-shm-usage flag to prevent crashes due to insufficient shared memory, especially with -race.
			Args: []string{"--disable-dev-shm-usage"},
		},
		NetworkCfg: config.NetworkConfig{
			CaptureResponseBodies: true,
			// FIX: Increased from 20s to 60s as stabilization can take longer under -race.
			// BUMPING AGAIN to 120s to be 100% sure this isn't the source.
			NavigationTimeout: 120 * time.Second, // Was 60 * time.Second
			Proxy:             config.ProxyConfig{Enabled: false},
		},
		// Ensure IAST is disabled for standard tests unless specifically enabled.
		IASTCfg: config.IASTConfig{Enabled: false},
	}
	cfg.BrowserCfg.Humanoid.Enabled = true
	return cfg
}

// newTestFixture creates a sandboxed environment for browser tests.
// Each call now initializes its own isolated chromedp.NewExecAllocator and a Manager.
// It no longer creates a default session.
func newTestFixture(t *testing.T, configurators ...fixtureConfigurator) *testFixture {
	t.Helper()

	// Each fixture gets its own logger tied to the test's lifecycle.
	logger := zaptest.NewLogger(t).With(zap.String("test", t.Name()))

	// Implement t.Deadline() pattern for robust test timeouts.
	var testDeadline time.Time
	var ok bool

	timeNow := time.Now()

	if testDeadline, ok = t.Deadline(); !ok {
		testDeadline = timeNow.Add(defaultBrowserTestTimeout)
	}

	rootDeadline := testDeadline.Add(-testCleanupGracePeriod)

	if rootDeadline.Sub(timeNow) < minTestExecutionTime {
		t.Fatalf("Insufficient test timeout: Deadline (%v remaining) minus cleanup grace period (%v) leaves less than %v for execution. Increase 'go test -timeout'.",
			testDeadline.Sub(timeNow).Round(time.Millisecond), testCleanupGracePeriod, minTestExecutionTime)
	}

	// Create the root context for this test fixture. It cancels before the hard deadline.
	rootCtx, rootCancel := context.WithDeadline(context.Background(), rootDeadline)
	t.Cleanup(rootCancel) // Ensure rootCtx is cancelled when the test finishes.

	cfgCopy := *createTestConfig() // Create a fresh, mutable copy of the configuration.
	for _, configurator := range configurators {
		configurator(&cfgCopy)
	}

	// --- Semaphore Acquisition ---
	processSemaphore := getGlobalProcessSemaphore() // Get the lazily initialized global semaphore.

	acquireCtx, acquireCancel := context.WithTimeout(rootCtx, semaphoreAcquireTimeout)
	// Do not use t.Cleanup(acquireCancel). We must cancel immediately after the acquisition attempt
	// to release resources associated with the context timer promptly.

	if err := processSemaphore.Acquire(acquireCtx, 1); err != nil {
		acquireCancel() // Clean up context immediately on failure.
		if acquireCtx.Err() != nil {
			t.Fatalf("Failed to acquire semaphore (timeout or test cancellation): %v", err)
		}
		t.Fatalf("Failed to acquire semaphore: %v", err)
	}
	acquireCancel() // Clean up context immediately on success.

	t.Cleanup(func() {
		processSemaphore.Release(1) // Register Semaphore Release (LIFO: Runs LAST)
	})

	// --- Browser Lifecycle Management (Per-test Isolation) ---

	// REFACTOR (Doc Ref 1.4, 4.1): Ensure complete resource isolation in parallel tests.
	// Running parallel tests contending for the default user data directory can lead
	// to failures (e.g., SingletonLock contention). We must use a unique directory per test.
	// t.TempDir() handles creation and cleanup automatically.
	tempUserDataDir := t.TempDir()
	logger.Debug("Using isolated UserDataDir.", zap.String("dir", tempUserDataDir))

	// Each test fixture gets its own isolated browser allocator and context.
	allocOpts := getBrowserExecOptions(&cfgCopy)
	allocOpts = append(allocOpts, chromedp.UserDataDir(tempUserDataDir))

	// Create allocator context, derived from the root test context.
	allocCtx, allocCancel := chromedp.NewExecAllocator(rootCtx, allocOpts...)

	// --- REFACTORED: Robust, Timed Shutdown Handling ---
	// Register Allocator Shutdown (LIFO: Runs SECOND, after Manager Shutdown)
	t.Cleanup(func() {
		logger.Debug("Starting graceful browser allocator shutdown (chromedp.Cancel).")

		// Use a fresh context with a timeout specifically for the shutdown operation.
		// We cannot use Detach() (value-only context) as it breaks chromedp's internal context mechanisms ("invalid context").
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()

		// We must call chromedp.Cancel on the original allocCtx. We run it in a goroutine
		// to respect the shutdown timeout, as chromedp.Cancel blocks until the browser exits.
		done := make(chan error, 1)
		go func() {
			// If allocCtx is already cancelled (e.g., test timeout), this still ensures
			// we wait for the browser process to exit.
			done <- chromedp.Cancel(allocCtx)
		}()

		select {
		case err := <-done:
			if err != nil {
				// Log failures. Filter expected 'context canceled' error if the allocCtx
				// was indeed cancelled (which chromedp.Cancel propagates).
				if !(err == context.Canceled && allocCtx.Err() != nil) {
					t.Logf("Warning: Error during graceful browser allocator shutdown (chromedp.Cancel): %v", err)
				}
			}
		case <-shutdownCtx.Done():
			// Shutdown timed out.
			t.Logf("Warning: Browser allocator shutdown timed out (%v). Proceeding forcefully.", shutdownTimeout)
		}

		// Call allocCancel as a final measure. It's idempotent.
		allocCancel()
		logger.Debug("Allocator shutdown complete.")
	})
	// --- END REFACTORED SECTION ---

	// --- REMOVED: sessionCtx, sessionCancel := chromedp.NewContext(allocCtx) ---

	// Initialize the manager using the newly created allocCtx.
	manager, err := NewManager(allocCtx, &cfgCopy, logger)
	require.NoError(t, err, "Failed to initialize per-test browser manager")
	t.Cleanup(func() {
		// Register Manager Shutdown (LIFO: Runs FIRST)
		// Use a fresh, short-lived context for shutdown, detached from the test context.
		// This one *is* used correctly, as manager.Shutdown takes a context
		// to manage its own internal shutdown timeouts.
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()
		logger.Debug("Starting graceful shutdown of browser manager.")
		if err := manager.Shutdown(shutdownCtx); err != nil {
			t.Logf("Warning: Error during browser manager shutdown: %v", err)
		}
		logger.Debug("Graceful shutdown complete.")
	})

	return &testFixture{
		// Session: s, // REMOVED
		Config:  &cfgCopy,
		Manager: manager,
		Logger:  logger,
		RootCtx: rootCtx,
	}
}

// createTestServer returns a server using the provided handler.
func createTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close) // Ensure server is closed after test.
	return server
}

// createStaticTestServer returns a server that serves the given HTML content.
func createStaticTestServer(t *testing.T, htmlContent string) *httptest.Server {
	t.Helper()
	return createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, htmlContent)
	}))
}

// getBrowserExecOptions extracts the standard ExecAllocatorOptions from the configuration.
func getBrowserExecOptions(cfg *config.Config) []chromedp.ExecAllocatorOption {
	// Start with a robust set of defaults suitable for CI/testing.
	// We define these explicitly rather than relying solely on chromedp.DefaultExecAllocatorOptions.
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoSandbox,
		chromedp.DisableGPU, // Recommended for stability (Doc Ref: 1.1)
		chromedp.Flag("enable-automation", true),
		// Add other essential defaults:
		chromedp.NoFirstRun,
		chromedp.NoDefaultBrowserCheck,
	}

	// REFACTOR (Doc Ref 1.1): Apply Headless configuration. When using custom options, this must be set explicitly.
	if cfg.BrowserCfg.Headless {
		opts = append(opts, chromedp.Headless)
	}

	// Add additional flags from the config file's 'args' slice.
	for _, arg := range cfg.BrowserCfg.Args {
		// REFACTOR: Improve flag parsing to handle key=value arguments (e.g., --user-agent="...").
		// The original implementation incorrectly treated "key=value" as a boolean flag name.
		key, value, found := strings.Cut(arg, "=")
		if found {
			opts = append(opts, chromedp.Flag(key, value))
		} else {
			// Handle boolean flags like --disable-dev-shm-usage
			opts = append(opts, chromedp.Flag(key, true))
		}
	}
	// Removed commented-out block as it is now handled above.
	return opts
}
