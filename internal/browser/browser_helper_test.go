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

type testFixture struct {
	Session      *Session
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
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("failed to initialize zap logger for tests: " + err.Error())
	}
	return logger
}

func createTestConfig() *config.Config {
	humanoidCfg := humanoid.DefaultConfig()
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
		IAST: config.IASTConfig{Enabled: false},
	}
	cfg.Browser.Humanoid.Enabled = true
	return cfg
}

func newTestFixture(t *testing.T, configurators ...fixtureConfigurator) *testFixture {
	t.Helper()

	cfgCopy := *suiteConfig
	for _, configurator := range configurators {
		configurator(&cfgCopy)
	}

	acquireCtx, acquireCancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(acquireCancel)

	if err := processSemaphore.Acquire(acquireCtx, 1); err != nil {
		t.Fatalf("Failed to acquire semaphore: %v", err)
	}
	t.Cleanup(func() { processSemaphore.Release(1) })

	lifecycleCtx := context.Background()
	logger := suiteLogger.With(zap.String("test", t.Name()))

	manager, err := NewManager(lifecycleCtx, &cfgCopy, logger)
	require.NoError(t, err, "Failed to initialize per-test browser manager")

	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()
		if err := manager.Shutdown(shutdownCtx); err != nil {
			t.Logf("Warning: Error during browser manager shutdown: %v", err)
		}
	})

	findingsChan := make(chan schemas.Finding, 50)
	t.Cleanup(func() { close(findingsChan) })

	sessionInterface, err := manager.NewAnalysisContext(
		lifecycleCtx,
		&cfgCopy,
		schemas.DefaultPersona,
		"",
		"",
		findingsChan,
	)
	require.NoError(t, err, "Failed to create new analysis context")

	session, ok := sessionInterface.(*Session)
	require.True(t, ok, "session must be of type *Session")

	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), shutdownTimeout/2)
		defer closeCancel()
		if err := session.Close(closeCtx); err != nil {
			t.Logf("Warning: Error during session close: %v", err)
		}
	})

	return &testFixture{
		Session:      session,
		Config:       &cfgCopy,
		Manager:      manager,
		Logger:       logger,
		FindingsChan: findingsChan,
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
