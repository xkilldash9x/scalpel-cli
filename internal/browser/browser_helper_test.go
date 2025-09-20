// internal/browser/browser_helper_test.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/humanoid"
)

// testFixture holds all components for a single, isolated, and sandboxed browser test.
type testFixture struct {
	Session *AnalysisContext
	Config  *config.Config
	Manager *Manager
	Logger  *zap.Logger
}

func getTestLogger() *zap.Logger {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("failed to initialize zap logger for tests: " + err.Error())
	}
	return logger
}

// newTestFixture creates a fully sandboxed browser environment for a single test.
// It exemplifies the best practices for context management in concurrent tests.
func newTestFixture(t *testing.T) *testFixture {
    t.Helper()

    // 1. A context is created for the fixture's lifecycle.
    fixtureCtx, fixtureCancel := context.WithCancel(context.Background())

    // 2. THE FIX: `t.Cleanup` registers the cancel function with the test `t`.
    // It will now be called only when the subtest that called newTestFixture
    // has finished running.
    t.Cleanup(fixtureCancel)

    logger := getTestLogger()
    cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:        true,
			DisableCache:    true,
			IgnoreTLSErrors: true,
			Concurrency:     4,
			Humanoid:        humanoid.DefaultConfig(),
			Debug:           true,
		},
		Network: config.NetworkConfig{
			CaptureResponseBodies: true,
			NavigationTimeout:     15 * time.Second,
			Proxy:                 config.ProxyConfig{Enabled: false},
		},
	}
	cfg.Browser.Humanoid.Enabled = true

	// 3. The manager and session are created with a context that will remain
    // valid for the entire duration of the test.
    manager, err := NewManager(fixtureCtx, logger, cfg)
    require.NoError(t, err, "Failed to initialize per-test browser manager")

    session, err := manager.NewAnalysisContext(
        fixtureCtx,
        cfg,
        schemas.DefaultPersona,
        "",
        "",
    )
    require.NoError(t, err, "Failed to create new analysis context")

    analysisContext, ok := session.(*AnalysisContext)
    require.True(t, ok, "session must be of type *AnalysisContext")

    return &testFixture{
        Session: analysisContext,
        Config:  cfg,
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
