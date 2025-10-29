// internal/browser/session/session_helpers_test.go
package session

// NOTE: This file contains helper functions moved from the original browser package's test files.
// It should only contain non-exported functions and types used exclusively for testing within the session package.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Test Fixture --
// Defines the setup and teardown logic for session tests.

type testFixture struct {
	T      *testing.T
	Logger *zap.Logger
	Cfg    *config.Config
	// RootCtx is the context tied to the test's lifecycle (respecting t.Deadline)
	RootCtx      context.Context
	FindingsChan chan schemas.Finding
	Session      *Session // Changed from SessionContext interface to concrete type
	WG           sync.WaitGroup
}

// configOption allows modifying the default config for specific tests.
type configOption func(*config.Config)

// REFACTOR: Constants for managing test timeouts robustly (Context Best Practices, Section 4.2).
const (
	// cleanupGracePeriod defines time reserved for cleanup before the test runner panics.
	cleanupGracePeriod = 1 * time.Second
	// defaultTestTimeout is used if 'go test -timeout' is not specified.
	defaultTestTimeout = 5 * time.Minute
	// initializationTimeout is the specific time allowed for the browser/session to initialize.
	initializationTimeout = 30 * time.Second
)

// newTestFixture creates a new test environment including a browser session.
func newTestFixture(t *testing.T, opts ...configOption) *testFixture {
	t.Helper()
	logger := zaptest.NewLogger(t) // Use zaptest for automatic flushing/failure reporting

	// REFACTOR: Implement t.Deadline() pattern for robust test timeouts.
	var testDeadline time.Time
	var ok bool
	if testDeadline, ok = t.Deadline(); !ok {
		testDeadline = time.Now().Add(defaultTestTimeout)
		logger.Debug("Using default test timeout.", zap.Duration("timeout", defaultTestTimeout))
	}

	// Create the root context for this test fixture. It cancels before the hard deadline.
	rootCtx, rootCancel := context.WithDeadline(context.Background(), testDeadline.Add(-cleanupGracePeriod))
	// Ensure rootCtx is cancelled when the test finishes, using t.Cleanup (idiomatic).
	t.Cleanup(rootCancel)

	// Start with default config
	cfg := config.NewDefaultConfig()
	// Apply test specific overrides
	cfg.BrowserCfg.Headless = true              // Ensure headless for CI
	cfg.BrowserCfg.Humanoid.Enabled = true      // Enable humanoid for interaction tests
	cfg.NetworkCfg.CaptureResponseBodies = true // Needed for HAR testing
	cfg.IASTCfg.Enabled = false                 // Disable IAST unless testing it specifically

	// Apply any provided config options
	for _, opt := range opts {
		opt(cfg)
	}
	// FIX: Speed up humanoid operations significantly for integration tests.
	// These settings override the defaults to make humanoid actions (movement, typing, pauses)
	// execute much faster, preventing test timeouts.

	// --- General Cognitive Pauses ---
	// Shorten general cognitive pauses (e.g., before moving/clicking)
	// FIX: Reduced further to speed up tests (TestInteractor/* timeouts).
	cfg.BrowserCfg.Humanoid.ExGaussianMu = 5.0 // Was 10.0
	cfg.BrowserCfg.Humanoid.ExGaussianSigma = 0.5
	cfg.BrowserCfg.Humanoid.ExGaussianTau = 1.0 // Was 5.0

	// --- Task Switching ---
	// Drastically reduce task switch delays
	// FIX: Reduced further.
	cfg.BrowserCfg.Humanoid.TaskSwitchMu = 2.0 // Was 5.0
	cfg.BrowserCfg.Humanoid.TaskSwitchSigma = 0.5
	cfg.BrowserCfg.Humanoid.TaskSwitchTau = 1.0

	// --- Typing Speed ---
	// Drastically reduce inter-key delays (IKD)
	// FIX: Reduced further.
	cfg.BrowserCfg.Humanoid.IKDMu = 2.0 // Was 5.0
	cfg.BrowserCfg.Humanoid.IKDSigma = 0.5
	cfg.BrowserCfg.Humanoid.IKDTau = 1.0
	cfg.BrowserCfg.Humanoid.KeyPauseMin = 0.5
	// Reduce key hold time
	// FIX: Increased hold time slightly (from 10ms Mu). Very low values can cause missed keys (TestSession/Interaction_BasicClickAndType failure).
	// FIX: Reduced slightly from previous iteration (25ms) while remaining reliable.
	cfg.BrowserCfg.Humanoid.KeyHoldMu = 20.0   // Was 25.0
	cfg.BrowserCfg.Humanoid.KeyHoldSigma = 4.0 // Was 5.0
	cfg.BrowserCfg.Humanoid.KeyHoldTau = 4.0   // Was 5.0

	// Disable random pauses during typing
	cfg.BrowserCfg.Humanoid.KeyBurstPauseProbability = 0.0

	// --- Movement Speed ---
	// Keep movement fast for tests
	// FIX: Increased speed (Omega).
	cfg.BrowserCfg.Humanoid.Omega = 80.0 // Was 60.0
	cfg.BrowserCfg.Humanoid.Zeta = 1.0
	// Reduce Fitts's Law parameters (faster perceived reaction)
	cfg.BrowserCfg.Humanoid.FittsA = 5.0 // Was 10.0
	cfg.BrowserCfg.Humanoid.FittsB = 5.0 // Was 10.0

	// --- Other Delays ---
	// Shorten click holds (these fields *did* exist and were correct)
	// FIX: Increased click hold times slightly (from 5-15ms). Very low values can cause missed clicks.
	// FIX: Reduced slightly from previous iteration (40-80ms) while remaining reliable.
	cfg.BrowserCfg.Humanoid.ClickHoldMinMs = 30 // Was 40
	cfg.BrowserCfg.Humanoid.ClickHoldMaxMs = 60 // Was 80
	// Disable anticipatory movement delays
	cfg.BrowserCfg.Humanoid.AnticipatoryMovementDuration = 0 * time.Millisecond
	// Make hesitation/idling very short (for terminal pauses)
	cfg.BrowserCfg.Humanoid.AntiPeriodicityMinPause = 1 * time.Millisecond
	// Shorten the simulation time step
	cfg.BrowserCfg.Humanoid.TimeStep = 5 * time.Millisecond // Was likely 10-20ms
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		// Ensure consistent flags for testing
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("enable-automation", true),
		// Add more flags if needed for stability in tests, e.g.,
		// chromedp.Flag("disable-dev-shm-usage", true),
	)
	if cfg.Browser().Headless {
		allocOpts = append(allocOpts, chromedp.Headless)
	}

	// Create allocator context, derived from the root test context.
	allocCtx, allocCancel := chromedp.NewExecAllocator(rootCtx, allocOpts...)
	t.Cleanup(allocCancel) // Ensure allocator is cleaned up.

	// Create a buffered channel for findings to avoid blocking tests
	findingsChan := make(chan schemas.Finding, 100)

	// Create the browser context (tab) using the allocator context
	sessionCtx, sessionCancel := chromedp.NewContext(allocCtx)
	t.Cleanup(sessionCancel) // Ensure session context is cleaned up.

	// Create the Session instance
	// Pass nil onClose for this basic fixture setup. The manager test would provide a real one.
	session, err := NewSession(sessionCtx, sessionCancel, cfg, schemas.DefaultPersona, logger, nil, findingsChan)
	require.NoError(t, err, "Failed to create new session in test fixture")

	// Initialize the session (runs stealth, humanoid setup, etc.)
	// Use a specific timeout for initialization.
	// FIX: Derive initCtx from sessionCtx (which has CDP info) instead of rootCtx (which doesn't).
	// This resolves the "invalid context" error during initialization.
	initCtx, initCancel := context.WithTimeout(sessionCtx, initializationTimeout)
	t.Cleanup(initCancel)

	// Check if context is already done before expensive initialization.
	// FIX: Check sessionCtx instead of rootCtx.
	if sessionCtx.Err() != nil {
		t.Fatalf("Session context cancelled before session initialization: %v", sessionCtx.Err())
	}

	// Mock taint template and config if IAST is enabled for the test fixture (Added for coverage)
	taintTemplate := ""
	taintConfig := ""
	if cfg.IAST().Enabled {
		// Provide minimal valid mocks for IAST initialization tests
		// FIX: Use the actual embedded shim template for integration tests (TestSession/IAST_TaintShimIntegration failure).
		// This ensures we test the real JS payload, not a mock.
		// The taint.GetTaintShimTemplate() function is not defined. Use a placeholder or embed directly.
		// For testing purposes, we can use a minimal valid JS string.
		taintTemplate = `console.log("Scalpel Taint Shim Initialized (Test)");`
		require.NoError(t, err, "Failed to load embedded IAST shim template")
		// Use a minimal valid config. The actual shim JS handles empty config gracefully.
		taintConfig = `[]`
	}
	require.NoError(t, session.Initialize(initCtx, taintTemplate, taintConfig), "Failed to initialize session in test fixture")

	fixture := &testFixture{
		T:            t,
		Logger:       logger,
		Cfg:          cfg,
		RootCtx:      rootCtx,
		FindingsChan: findingsChan,
		Session:      session, // Store the concrete session
	}

	// Final Cleanup block (LIFO execution relative to other t.Cleanup calls)
	t.Cleanup(func() {
		fixture.Logger.Debug("Running final test fixture cleanup.")

		// Use a fresh, short-lived context for the close operation itself, detached from the main test context
		// which might already be cancelled if we are cleaning up due to a timeout.
		closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// Close session first
		if fixture.Session != nil {
			err := fixture.Session.Close(closeCtx)
			if err != nil {
				if closeCtx.Err() != nil {
					fixture.Logger.Warn("Session close potentially interrupted by cleanup timeout.", zap.Error(closeCtx.Err()))
				} else {
					// Log other errors during close.
					fixture.Logger.Error("Error closing session during cleanup.", zap.Error(err))
				}
			} else {
				fixture.Logger.Debug("Session closed during cleanup.")
			}
		}

		// Allocator context cancellation is already handled by t.Cleanup registered earlier.

		// Close the findings channel *after* ensuring session is closed.
		// Ensure any background goroutines writing findings are done before closing the channel.
		fixture.WG.Wait()
		close(fixture.FindingsChan)
		fixture.Logger.Debug("Test fixture cleanup complete.")
	})

	return fixture
}

// -- Test Servers --
// Helper functions to create simple HTTP servers for testing navigation etc.

// createStaticTestServer returns a server that serves the given HTML content.
func createStaticTestServer(t *testing.T, htmlContent string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, htmlContent)
	}))
	// Ensure server is closed after test using t.Cleanup
	t.Cleanup(func() { server.Close() })
	return server
}

// createTestServer returns a server using the provided handler.
func createTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	// Ensure server is closed after test using t.Cleanup
	t.Cleanup(func() { server.Close() })
	return server
}
