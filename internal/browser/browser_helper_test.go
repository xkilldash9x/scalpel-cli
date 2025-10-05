// internal/browser/test_helper.go
package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/session"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

const (
	// A generous timeout for individual test operations.
	TestTimeout     = 30 * time.Second
	ShutdownTimeout = 10 * time.Second
	InitTimeout     = 5 * time.Minute
)

// TestFixture creates a fully self contained test environment, including a
// Manager, a Session, and an optional HTTP test server. It ensures all
// resources are gracefully torn down when the test completes using t.Cleanup.
type TestFixture struct {
	Ctx          context.Context
	Cancel       context.CancelFunc
	Session      *session.Session
	Config       *config.Config
	Manager      *Manager
	Logger       *zap.Logger
	FindingsChan chan schemas.Finding
	Server       *httptest.Server
	TestWG       *sync.WaitGroup
}

// FixtureConfigurator allows for customizing the test configuration on a
// per fixture basis.
type FixtureConfigurator func(*config.Config)

// NewTestFixture is the central function for creating a test environment.
func NewTestFixture(t *testing.T, configurators ...FixtureConfigurator) *TestFixture {
	t.Helper()

	// -- Configuration and Logger Setup --
	humanoidCfg := humanoid.DefaultConfig()
	humanoidCfg.ClickHoldMinMs = 5
	humanoidCfg.ClickHoldMaxMs = 15
	humanoidCfg.KeyHoldMeanMs = 10.0

	cfg := &config.Config{
		Browser: config.BrowserConfig{
			Headless:        true,
			DisableCache:    true,
			IgnoreTLSErrors: true,
			Humanoid:        humanoidCfg,
			Debug:           true,
		},
		Network: config.NetworkConfig{
			CaptureResponseBodies: true,
			NavigationTimeout:     45 * time.Second,
			PostLoadWait:          50 * time.Millisecond,
			IgnoreTLSErrors:       true,
		},
		IAST: config.IASTConfig{Enabled: false},
	}
	cfg.Browser.Humanoid.Enabled = true

	for _, configurator := range configurators {
		configurator(cfg)
	}

	logger, err := zap.NewDevelopment()
	require.NoError(t, err, "Failed to create logger for tests")
	logger = logger.With(zap.String("test", t.Name()))

	// -- Context and WaitGroup --
	var testWG sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), TestTimeout)

	// -- Manager and Session Creation --
	initCtx, initCancel := context.WithTimeout(context.Background(), InitTimeout)
	defer initCancel()
	manager, err := NewManager(initCtx, logger, cfg)
	require.NoError(t, err, "Failed to create new test-specific manager")

	findingsChan := make(chan schemas.Finding, 50)

	sessionInterface, err := manager.NewAnalysisContext(
		ctx,
		cfg,
		schemas.DefaultPersona,
		"",
		"",
		findingsChan,
	)
	require.NoError(t, err, "Failed to create new analysis context (session)")

	sess, ok := sessionInterface.(*session.Session)
	require.True(t, ok, "session must be of type *session.Session")

	// -- Graceful Cleanup (LIFO Order) --
	t.Cleanup(func() {
		// 1. (Runs Last) Manager Shutdown
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
		defer shutdownCancel()
		logger.Debug("Shutting down manager.")
		if shutdownErr := manager.Shutdown(shutdownCtx); shutdownErr != nil {
			t.Logf("Warning: error during manager shutdown in cleanup: %v", shutdownErr)
		}
	})

	t.Cleanup(func() {
		// 2. Close findings channel
		close(findingsChan)
	})

	t.Cleanup(func() {
		// 3. Wait for any test goroutines, then close the session.
		logger.Debug("Test function completed. Waiting for TestWG (Graceful Teardown).")
		testWG.Wait()
		logger.Debug("TestWG complete. Proceeding to close session.")
		closeCtx, closeCancel := context.WithTimeout(context.Background(), ShutdownTimeout/2)
		defer closeCancel()
		if closeErr := sess.Close(closeCtx); closeErr != nil {
			t.Logf("Warning: Error during session close in cleanup: %v", closeErr)
		}
	})

	t.Cleanup(func() {
		// 4. (Runs First) Cancel the primary test context.
		cancel()
	})

	return &TestFixture{
		Ctx:          ctx,
		Cancel:       cancel,
		Session:      sess,
		Config:       cfg,
		Manager:      manager,
		Logger:       logger,
		FindingsChan: findingsChan,
		TestWG:       &testWG,
	}
}

// CreateServer is a helper for creating a standard httptest.Server that is
// automatically closed when the test finishes.
func (f *TestFixture) CreateServer(t *testing.T, handler http.Handler) {
	t.Helper()
	f.Server = httptest.NewServer(handler)
	t.Cleanup(f.Server.Close)
}

// CreateStaticServer is a convenience wrapper for serving simple, static HTML.
func (f *TestFixture) CreateStaticServer(t *testing.T, htmlContent string) {
	t.Helper()
	f.CreateServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, htmlContent)
	}))
}
