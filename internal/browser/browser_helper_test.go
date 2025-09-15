package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

var (
	testLogger     *zap.Logger
	testManager    *browser.Manager
	testConfig     *config.Config
	parallelTestWG sync.WaitGroup // WaitGroup to synchronize parallel tests
)

// testFixture holds components for a single, isolated browser test.
type testFixture struct {
	Session *browser.AnalysisContext
	Config  *config.Config
}

// TestMain sets up a SINGLE, shared browser manager for all tests.
func TestMain(m *testing.M) {
	var err error
	testLogger = getTestLogger()
	testLogger.Info("TestMain: START")

	const testConcurrency = 4

	browserCfg := config.BrowserConfig{
		Headless:     true,
		DisableCache: true,
		Concurrency:  testConcurrency,
		Humanoid:     humanoid.DefaultConfig(),
		Debug:        true,
	}

	testConfig = &config.Config{
		Browser: browserCfg,
		Network: config.NetworkConfig{
			CaptureResponseBodies: true,
			NavigationTimeout:     30 * time.Second,
		},
	}

	// Create a master context for the entire test suite.
	suiteCtx, suiteCancel := context.WithCancel(context.Background())
	testLogger.Info("TestMain: Suite context created.")

	// Create the manager once for the entire test suite using this master context.
	testManager, err = browser.NewManager(suiteCtx, testLogger, browserCfg)
	if err != nil {
		suiteCancel() // Clean up on failure
		testLogger.Fatal("Failed to initialize browser manager for test suite", zap.Error(err))
	}
	testLogger.Info("TestMain: testManager initialized. Calling m.Run().")

	// Run all tests.
	code := m.Run()
	testLogger.Info("TestMain: m.Run() has completed. Waiting for parallel tests to finish.")

	// Wait for all parallel tests that use newTestFixture to signal they are done.
	parallelTestWG.Wait()
	testLogger.Info("TestMain: All parallel tests finished. Beginning shutdown.")

	// Now that all tests are complete, we can begin the shutdown sequence.
	// 1. Cancel the master context. This signals to any long-running operations in the manager to stop.
	testLogger.Info("TestMain: Calling suiteCancel().")
	suiteCancel()

	// 2. Explicitly shut down the manager.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelShutdown()
	if err := testManager.Shutdown(shutdownCtx); err != nil {
		testLogger.Error("Error during test manager shutdown", zap.Error(err))
	}

	testLogger.Info("TestMain: END")
	os.Exit(code)
}

// getTestLogger creates a logger suitable for test output.
func getTestLogger() *zap.Logger {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("failed to initialize zap logger for tests: " + err.Error())
	}
	return logger
}

// newTestFixture acquires a new session from the shared manager for an individual test.
func newTestFixture(t *testing.T) (*testFixture, func()) {
	t.Helper()
	testLogger.Info("newTestFixture: START", zap.String("test", t.Name()))
	parallelTestWG.Add(1) // Signal that a new test has started.

	sessionCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	session, err := testManager.NewAnalysisContext(
		sessionCtx,
		testConfig,
		stealth.DefaultPersona,
		"",
		"",
	)

	if err != nil {
		cancel()
		parallelTestWG.Done() // Must decrement counter if setup fails.
		t.Fatalf("Failed to create new analysis session: %v", err)
	}

	fixture := &testFixture{
		Session: session,
		Config:  testConfig,
	}

	cleanup := func() {
		testLogger.Info("newTestFixture cleanup: START", zap.String("test", t.Name()))
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		session.Close(closeCtx)
		cancel()
		parallelTestWG.Done() // Signal that this test's cleanup is complete.
		testLogger.Info("newTestFixture cleanup: END", zap.String("test", t.Name()))
	}

	return fixture, cleanup
}

// createTestServer creates an httptest.Server.
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

