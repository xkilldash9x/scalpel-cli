// internal/browser/browser_helper_test.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	// sync import removed as managerPool is removed
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/semaphore"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// Implementing a Controlled and Stable Test Architecture

// Global state for managing concurrency and lifecycle across the test suite.
var (
	// processSemaphore limits the number of concurrent browser processes (Managers).
	processSemaphore *semaphore.Weighted
	// suiteLogger and suiteConfig are initialized once for the whole suite.
	suiteLogger *zap.Logger
	suiteConfig *config.Config
	// managerPool is removed. We rely on the context cancellation cascade for cleanup.
)

// FIX: Reduced concurrency limit to alleviate resource contention.
const maxTestConcurrency = 4 // Stability cap for concurrent browser processes.

// TestMain controls the lifecycle of the entire test run for this package.
func TestMain(m *testing.M) {
	// 1. Initialize global resources.
	suiteLogger = getTestLogger()
	suiteConfig = createTestConfig()

	// 2. Initialize concurrency control.
	concurrency := int64(runtime.GOMAXPROCS(0))
	if concurrency > maxTestConcurrency {
		concurrency = maxTestConcurrency
	}
	if concurrency < 1 {
		concurrency = 1
	}
	suiteLogger.Info("Initializing browser test suite.", zap.Int64("concurrency_limit", concurrency))
	processSemaphore = semaphore.NewWeighted(concurrency)

	// 3. Run the tests.
	exitCode := m.Run()

	// 4. Teardown (None required). We rely on t.Cleanup and context cancellation propagation
	//    (implemented in newTestFixture and Manager) to gracefully shut down resources.

	// 5. Exit.
	os.Exit(exitCode)
}

// testFixture holds all components for a single, isolated, and sandboxed browser test.
type testFixture struct {
	Session *AnalysisContext
	Config  *config.Config
	Manager *Manager
	Logger  *zap.Logger
}

// fixtureConfigurator is a function type for customizing the configuration in newTestFixture.
type fixtureConfigurator func(*config.Config)

func getTestLogger() *zap.Logger {
	// Use the existing suiteLogger if available, otherwise initialize a fallback.
	if suiteLogger != nil {
		return suiteLogger
	}
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("failed to initialize zap logger for tests: " + err.Error())
	}
	return logger
}

// createTestConfig initializes the configuration used for the test suite.
func createTestConfig() *config.Config {
	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:        true,
			DisableCache:    true,
			IgnoreTLSErrors: true,
			Concurrency:     4,
			Humanoid:        humanoid.DefaultConfig(),
			// Crucial: This flag signals manager.go to use the stabilized configuration filtering.
			Debug: true,
		},
		Network: config.NetworkConfig{
			CaptureResponseBodies: true,
			NavigationTimeout:     15 * time.Second,
			Proxy:                 config.ProxyConfig{Enabled: false},
		},
	}
	cfg.Browser.Humanoid.Enabled = true
	return cfg
}

// newTestFixture creates a fully sandboxed browser environment for a single test.
// It integrates concurrency control with correct context lifecycle management.
func newTestFixture(t *testing.T, configurators ...fixtureConfigurator) *testFixture {
	t.Helper()

	// 0. Configuration Isolation: Create a safe copy for this test.
	cfgCopy := *suiteConfig
	for _, configurator := range configurators {
		configurator(&cfgCopy)
	}

	// 1. Concurrency Limiting: Acquire a semaphore slot.
	acquireCtx, acquireCancel := context.WithTimeout(context.Background(), 60*time.Second)
	// FIX: Use t.Cleanup instead of defer. The fixture function returns before the test completes in parallel execution.
	t.Cleanup(acquireCancel)

	if err := processSemaphore.Acquire(acquireCtx, 1); err != nil {
		t.Fatalf("Failed to acquire semaphore (timed out waiting for available slot): %v", err)
	}

	// Ensure the semaphore is released when the test finishes.
	t.Cleanup(func() {
		processSemaphore.Release(1)
	})

	// 2. Context Lifecycle Management: Create a context scoped to this specific test.
	// We rely on the context cascade initiated by t.Cleanup for graceful shutdown.
	fixtureCtx, fixtureCancel := context.WithCancel(context.Background())
	t.Cleanup(fixtureCancel)

	logger := suiteLogger.With(zap.String("test", t.Name()))

	// 3. Initialize the manager (browser process) using the fixture context.
	// When fixtureCtx is canceled (via t.Cleanup), the Manager's primary context will be canceled.
	manager, err := NewManager(fixtureCtx, logger, &cfgCopy)
	require.NoError(t, err, "Failed to initialize per-test browser manager")

	// 4. Create the session (tab) using the fixture context.
	// When fixtureCtx is canceled, the session context will be canceled, closing the tab.
	session, err := manager.NewAnalysisContext(
		fixtureCtx,
		&cfgCopy,
		schemas.DefaultPersona,
		"",
		"",
	)
	require.NoError(t, err, "Failed to create new analysis context")

	// Explicit t.Cleanup calls for Shutdown/Close are not required as they are handled
	// by the fixtureCtx cancellation cascade and the implementation in Manager.

	analysisContext, ok := session.(*AnalysisContext)
	require.True(t, ok, "session must be of type *AnalysisContext")

	return &testFixture{
		Session: analysisContext,
		Config:  &cfgCopy,
		Manager: manager,
		Logger:  logger,
	}
}

// createTestServer creates an httptest.Server and handles its cleanup.
func createTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// createStaticTestServer creates an httptest.Server for static HTML.
func createStaticTestServer(t *testing.T, htmlContent string) *httptest.Server {
	t.Helper()
	return createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, htmlContent)
	}))
}