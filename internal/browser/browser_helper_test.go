// internal/browser/browser_helper_test.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	// FIX: Import the session package to resolve the undefined Session type.
	"github.com/xkilldash9x/scalpel-cli/internal/browser/session"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

var (
	suiteLogger      *zap.Logger
	suiteConfig      *config.Config
	// Initialize the Manager once for the whole suite for efficiency.
	suiteManager     *Manager
	suiteManagerOnce sync.Once
	suiteManagerErr  error
)

const shutdownTimeout = 30 * time.Second
const initTimeout = 5 * time.Minute // Timeout for initialization (includes browser installation).

// TestMain controls the lifecycle of the test suite, initializing the Manager globally.
func TestMain(m *testing.M) {
	suiteLogger = getTestLogger()
	suiteConfig = createTestConfig()

	// Initialize the suite manager (Playwright driver + Browser instance).
	ctx, cancel := context.WithTimeout(context.Background(), initTimeout)
	defer cancel()

	// Use sync.Once to ensure initialization happens only once.
	suiteManagerOnce.Do(func() {
		suiteLogger.Info("Initializing global browser test suite manager...")
		// NewManager handles installation and launch internally via deferred initialization.
		suiteManager, suiteManagerErr = NewManager(ctx, suiteConfig, suiteLogger)
		if suiteManagerErr != nil {
			suiteLogger.Error("Failed to create global browser manager.", zap.Error(suiteManagerErr))
			// We don't exit here yet, allowing tests to potentially run if they handle the error.
			return
		}

		// Force initialization now to catch errors early.
		if err := suiteManager.initialize(ctx); err != nil {
			suiteManagerErr = err
			suiteLogger.Error("Failed to initialize global browser manager.", zap.Error(suiteManagerErr))
			return
		}
		suiteLogger.Info("Global browser manager initialized.")
	})

	if suiteManagerErr != nil {
		// If initialization failed, we must exit as browser tests cannot run.
		os.Exit(1)
	}

	// Run the tests.
	exitCode := m.Run()

	// Shutdown the suite manager after all tests complete.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if suiteManager != nil {
		suiteLogger.Info("Shutting down global browser manager...")
		if err := suiteManager.Shutdown(shutdownCtx); err != nil {
			suiteLogger.Error("Error during global browser manager shutdown.", zap.Error(err))
		}
	}

	os.Exit(exitCode)
}

type testFixture struct {
	// FIX: Use the correctly namespaced type from the imported session package.
	Session      *session.Session
	Config       *config.Config
	Manager      *Manager
	Logger       *zap.Logger
	FindingsChan chan schemas.Finding
}

type fixtureConfigurator func(*config.Config)

func getTestLogger() *zap.Logger {
	if suiteLogger != nil {
		return suiteLogger
	}
	// Use a development config for detailed logs during testing.
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("failed to initialize zap logger for tests: " + err.Error())
	}
	return logger
}

func createTestConfig() *config.Config {
	// Configuration optimized for testing.
	humanoidCfg := humanoid.DefaultConfig()
	// Speed up humanoid actions for faster tests.
	humanoidCfg.ClickHoldMinMs = 5
	humanoidCfg.ClickHoldMaxMs = 15
	humanoidCfg.KeyHoldMeanMs = 10.0

	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:        true, // Always headless in tests.
			DisableCache:    true,
			IgnoreTLSErrors: true,
			Humanoid:        humanoidCfg,
			Debug:           true,
		},
		Network: config.NetworkConfig{
			CaptureResponseBodies: true,
			NavigationTimeout:     45 * time.Second, // Reasonable default for tests.
			Proxy:                 config.ProxyConfig{Enabled: false},
			IgnoreTLSErrors:       true,
		},
		IAST: config.IASTConfig{Enabled: false},
	}
	cfg.Browser.Humanoid.Enabled = true
	return cfg
}

// newTestFixture creates a new session from the global manager.
func newTestFixture(t *testing.T, configurators ...fixtureConfigurator) *testFixture {
	t.Helper()

	if suiteManager == nil || suiteManagerErr != nil {
		t.Fatalf("Global suite manager is not available. Initialization error: %v", suiteManagerErr)
	}

	cfgCopy := *suiteConfig
	for _, configurator := range configurators {
		configurator(&cfgCopy)
	}

	logger := suiteLogger.With(zap.String("test", t.Name()))
	manager := suiteManager

	findingsChan := make(chan schemas.Finding, 50)
	t.Cleanup(func() { close(findingsChan) })

	// Create a new session (BrowserContext) for the test.
	// The context controls the test's execution lifecycle.
	testCtx, testCancel := context.WithCancel(context.Background())
	t.Cleanup(testCancel)

	sessionInterface, err := manager.NewAnalysisContext(
		testCtx,
		&cfgCopy,
		schemas.DefaultPersona,
		"",
		"",
		findingsChan,
	)
	require.NoError(t, err, "Failed to create new analysis context (session)")

	// FIX: Cast to the correctly namespaced session.Session type.
	sess, ok := sessionInterface.(*session.Session)
	require.True(t, ok, "session must be of type *session.Session")

	// Ensure the session is closed when the test finishes.
	t.Cleanup(func() {
		// Use a background context with timeout for cleanup.
		closeCtx, closeCancel := context.WithTimeout(context.Background(), shutdownTimeout/3)
		defer closeCancel()
		if err := sess.Close(closeCtx); err != nil {
			t.Logf("Warning: Error during session close in cleanup: %v", err)
		}
	})

	return &testFixture{
		Session:      sess,
		Config:       &cfgCopy,
		Manager:      manager,
		Logger:       logger,
		FindingsChan: findingsChan,
	}
}

// Helper functions for creating test servers.
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

