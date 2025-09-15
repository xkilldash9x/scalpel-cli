// browser_helper_test.go
package browser_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

var (
	sharedManager *browser.Manager
	testLogger    *zap.Logger
)

// testFixture holds all the necessary components for a single, isolated browser test.
type testFixture struct {
	Session *browser.AnalysisContext
	Config  *config.Config
}

// TestMain sets up the shared browser manager for all tests in the package
// and guarantees its shutdown after all tests have completed.
func TestMain(m *testing.M) {
	var err error
	testLogger = getTestLogger()
	// Use a background context as the manager's lifecycle is for the whole package.
	sharedManager, err = browser.NewManager(context.Background(), testLogger, 4)
	if err != nil {
		testLogger.Fatal("Failed to create shared browser manager for tests", zap.Error(err))
	}

	// m.Run() executes all tests in the package.
	code := m.Run()

	// This block runs AFTER all tests are finished, including parallel ones.
	testLogger.Info("Shutting down shared browser manager after tests.")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := sharedManager.Shutdown(shutdownCtx); err != nil {
		testLogger.Error("Error during shared manager shutdown", zap.Error(err))
	}
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

// newTestFixture creates a fully initialized AnalysisContext for a test.
func newTestFixture(t *testing.T) (*testFixture, func()) {
	t.Helper()

	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:     true,
			DisableCache: true,
			Humanoid:     humanoid.DefaultConfig(),
		},
		Network: config.NetworkConfig{
			CaptureResponseBodies: true,
			PostLoadWait:          250 * time.Millisecond,
		},
	}
	persona := stealth.DefaultPersona
	testCtx, cancelTest := context.WithTimeout(context.Background(), 30*time.Second)

	session, err := sharedManager.NewAnalysisContext(testCtx, cfg, persona, "", "")
	require.NoError(t, err, "Failed to initialize session from manager for test fixture")

	fixture := &testFixture{
		Session: session,
		Config:  cfg,
	}

	cleanup := func() {
		session.Close(context.Background())
		cancelTest()
	}

	return fixture, cleanup
}

// createTestServer creates an httptest.Server for dynamic content tests.
func createTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// createStaticTestServer creates an httptest.Server for serving simple, static HTML.
func createStaticTestServer(t *testing.T, htmlContent string) *httptest.Server {
	t.Helper()
	return createTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, htmlContent)
	}))
}