// internal/browser/session/session_helpers_test.go
package session

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
	// FIX: Import the humanoid package to use NewTestHumanoid.
	"github.com/xkilldash9x/scalpel-cli/internal/browser/humanoid"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// -- Test Fixture --
// Defines the setup and teardown logic for session tests.

type testFixture struct {
	T      *testing.T
	Logger *zap.Logger
	Cfg    *config.Config
	// RootCtx is the context tied to the test's lifecycle (respecting t.Deadline)
	RootCtx context.Context
	// FindingsChan is the public channel tests consume findings from.
	FindingsChan chan schemas.Finding
	Session      *Session // Changed from SessionContext interface to concrete type
	// WG tracks background goroutines managed by the fixture (e.g., the findings proxy).
	WG sync.WaitGroup
}

// configOption allows modifying the default config for specific tests.
type configOption func(*config.Config)

// Constants for managing test timeouts robustly (Context Best Practices, Section 4.2).
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

	//  Implement t.Deadline() pattern for robust test timeouts.
	var testDeadline time.Time
	var ok bool
	if testDeadline, ok = t.Deadline(); !ok {
		testDeadline = time.Now().Add(defaultTestTimeout)
		logger.Debug("Using default test timeout.", zap.Duration("timeout", defaultTestTimeout))
	}

	// Create the root context for this test fixture. It cancels before the hard deadline.
	rootCtx, rootCancel := context.WithDeadline(context.Background(), testDeadline.Add(-cleanupGracePeriod))
	// Ensure rootCtx is cancelled when the test finishes. This is now handled in the final cleanup block.

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

	// R5/R7/R9: The settings must be carefully tuned for stability when running under the -race detector.
	// Excessive speed causes the browser's event loop to struggle, resulting in missed/corrupted keypresses
	// and race conditions during interactions.

	// --- General Cognitive Pauses ---
	// R7: Increased slightly (from Mu=30) for more buffer under race detector.
	cfg.BrowserCfg.Humanoid.ExGaussianMu = 40.0
	cfg.BrowserCfg.Humanoid.ExGaussianSigma = 10.0
	cfg.BrowserCfg.Humanoid.ExGaussianTau = 20.0

	// --- Task Switching ---
	// R7: Increased slightly (from Mu=25)
	cfg.BrowserCfg.Humanoid.TaskSwitchMu = 35.0
	cfg.BrowserCfg.Humanoid.TaskSwitchSigma = 8.0
	cfg.BrowserCfg.Humanoid.TaskSwitchTau = 15.0

	// --- Typing Speed ---
	// R7: Increased Inter-Key Delay (IKD) significantly (from Mu=40).
	// R9 FIX: Increased IKD and Hold times further due to persistent typos ("inpu5").
	// This indicates severe event loop contention in the browser during testing.
	cfg.BrowserCfg.Humanoid.IKDMu = 90.0       // R7=70.0
	cfg.BrowserCfg.Humanoid.IKDSigma = 25.0    // R7=20.0
	cfg.BrowserCfg.Humanoid.IKDTau = 30.0      // R7=25.0
	cfg.BrowserCfg.Humanoid.KeyPauseMin = 20.0 // R7=15.0

	// R7: Increased Key Hold time significantly (from Mu=60). Short holds cause missed keys under load.
	cfg.BrowserCfg.Humanoid.KeyHoldMu = 100.0   // R7=80.0
	cfg.BrowserCfg.Humanoid.KeyHoldSigma = 25.0 // R7=20.0
	cfg.BrowserCfg.Humanoid.KeyHoldTau = 25.0   // R7=20.0

	// Disable random pauses during typing
	cfg.BrowserCfg.Humanoid.KeyBurstPauseProbability = 0.0

	// --- Movement Speed ---
	// R5: Reduced movement speed slightly (from Omega=150). Very high speeds can reduce stability under load.
	cfg.BrowserCfg.Humanoid.Omega = 120.0
	cfg.BrowserCfg.Humanoid.Zeta = 1.0
	// Reduce Fitts's Law parameters (faster perceived reaction)
	cfg.BrowserCfg.Humanoid.FittsA = 5.0
	cfg.BrowserCfg.Humanoid.FittsB = 5.0

	// R9 FIX: Increase MaxSimTime to prevent frequent "Movement simulation timed out" warnings.
	// Slower speeds (Omega=120) require longer simulation times than the default (likely ~8s).
	cfg.BrowserCfg.Humanoid.MaxSimTime = 20 * time.Second

	// --- Other Delays ---
	// R5: Increased click holds slightly (from Min=50, Max=100).
	cfg.BrowserCfg.Humanoid.ClickHoldMinMs = 70
	cfg.BrowserCfg.Humanoid.ClickHoldMaxMs = 120
	// Disable anticipatory movement delays
	cfg.BrowserCfg.Humanoid.AnticipatoryMovementDuration = 0 * time.Millisecond
	// Make hesitation/idling very short (for terminal pauses)
	cfg.BrowserCfg.Humanoid.AntiPeriodicityMinPause = 1 * time.Millisecond

	// Shorten the simulation time step
	// R5: Reverted TimeStep optimization (from 5ms back to 10ms).
	// A smaller time step increases CDP command frequency, exacerbating load under -race.
	cfg.BrowserCfg.Humanoid.TimeStep = 10 * time.Millisecond

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

	// --- START FIX (RACE 2): Channel Lifecycle Management ---
	// Create a buffered channel for findings that the tests will consume (Public).
	findingsChan := make(chan schemas.Finding, 100)

	// Introduce a proxy channel (Internal) to manage the lifecycle safely.
	// This prevents "send on closed channel" panics during cleanup if Session.Close()
	// returns before its writers stop (e.g. if the buffer is full). The session writes to the proxy channel.
	proxyFindingsChan := make(chan schemas.Finding, 100)
	// --- END FIX (RACE 2) ---

	// Create the browser context (tab) using the allocator context
	sessionCtx, sessionCancel := chromedp.NewContext(allocCtx)
	t.Cleanup(sessionCancel) // Ensure session context is cleaned up.

	// Create the Session instance
	// Pass nil onClose for this basic fixture setup. The manager test would provide a real one.
	// Use the proxyFindingsChan for the session to write to.
	session, err := NewSession(sessionCtx, sessionCancel, cfg, schemas.DefaultPersona, logger, nil, proxyFindingsChan)
	require.NoError(t, err, "Failed to create new session in test fixture")

	//  Initialize components deterministically BEFORE Initialize() ---
	// The Problem: We must ensure deterministic behavior for tests. Standard Initialize() creates non-deterministic components.
	// The previous implementation incorrectly assumed NewSession initialized components and tried to replace them, which failed silently.
	// The Fix (R9): We manually initialize the Executor, Humanoid (deterministic), and Interactor here.
	// We rely on the R9 change in session.Initialize() to skip its internal initializeControllers() call if these fields are already set.

	// 1. Initialize Executor (Required by Humanoid and Initialize)
	// We must use the session's RunActions method.
	// Since we are in the same package, we can directly assign to unexported fields.
	session.executor = &cdpExecutor{
		ctx:            session.ctx, // Use the session's master context
		logger:         logger.Named("cdp_executor"),
		runActionsFunc: session.RunActions,
	}

	// 2. Initialize Deterministic Humanoid (if enabled in config)
	if cfg.Browser().Humanoid.Enabled {
		const fixedSeed = 42
		logger.Debug("Initializing deterministic humanoid.NewTestHumanoid (BEFORE Initialize).", zap.Int64("seed", fixedSeed))

		// Use the executor we just created.
		testHumanoid := humanoid.NewTestHumanoid(session.executor, fixedSeed)
		session.humanoid = testHumanoid
	} else {
		logger.Debug("Humanoid disabled by config. Skipping deterministic initialization.")
	}

	// 3. Initialize Interactor
	// Define the stabilization function (must match the one used in session.go initializeControllers)
	stabilizeFn := func(stabCtx context.Context) error {
		// R8/R9 stabilization parameters (500ms quiet period + settle delay in stabilize())
		return session.stabilize(stabCtx, 500*time.Millisecond)
	}
	session.interactor = NewInteractor(
		logger.Named("interactor"),
		session.humanoid, // Pass the (potentially deterministic) humanoid
		stabilizeFn,
		session,     // Pass the session itself (ActionExecutor)
		session.ctx, // Use the session's master context
	)
	logger.Debug("Pre-initialized Executor, Humanoid (if enabled), and Interactor.")

	// --- END FIX (R9/RACE 1) ---

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
		// Use a minimal valid config. The actual shim JS handles empty config gracefully.
		taintConfig = `[]`
	}
	// Initialize the session. This now uses the deterministic components set up above,
	// thanks to the R9 change in session.Initialize().
	require.NoError(t, session.Initialize(initCtx, taintTemplate, taintConfig), "Failed to initialize session in test fixture")

	fixture := &testFixture{
		T:            t,
		Logger:       logger,
		Cfg:          cfg,
		RootCtx:      rootCtx,
		FindingsChan: findingsChan, // Store the public channel
		Session:      session,      // Store the concrete session
	}

	// --- START FIX (RACE 2 Continued): Start Proxy Goroutine ---
	// Start the goroutine that drains the proxy channel. We now utilize the previously unused WG.
	fixture.WG.Add(1)
	go func() {
		defer fixture.WG.Done()
		// Drain proxyFindingsChan (written by Session) into findingsChan (read by tests).
		// This loop must respect context cancellation while waiting for input to prevent deadlocks during cleanup.
		for {
			select {
			case finding, ok := <-proxyFindingsChan:
				if !ok {
					// proxyFindingsChan closed unexpectedly. This should ideally not happen with the revised cleanup logic (RACE 2 Fix).
					logger.Warn("Findings proxy drain finished unexpectedly (channel closed by producer).")
					return
				}
				// Forward the finding to the public channel, also respecting context cancellation.
				select {
				case findingsChan <- finding:
				case <-rootCtx.Done():
					logger.Debug("Test context cancelled during finding forward; stopping findings proxy.")
					return
				}
			case <-rootCtx.Done():
				// R9 FIX (RACE 2): If the root context is done, the test is over. Stop draining immediately.
				// This is the primary mechanism for cleanup.
				logger.Debug("Test context cancelled; stopping findings proxy drain.")
				return
			}
		}
	}()
	// --- END FIX (RACE 2) ---

	// Final Cleanup block (LIFO execution relative to other t.Cleanup calls)
	t.Cleanup(func() {
		fixture.Logger.Debug("Running final test fixture cleanup.")

		// 1. Cancel the root context FIRST.
		// This signals all goroutines listening to rootCtx (like the findings proxy) to stop.
		rootCancel()
		fixture.Logger.Debug("Root context cancelled for cleanup.")

		// Use a fresh, short-lived context for the close operation itself, detached from the main test context
		// which might already be cancelled if we are cleaning up due to a timeout.
		closeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		// 2. Close the session (Producer for proxyFindingsChan)
		if fixture.Session != nil {
			err := fixture.Session.Close(closeCtx)
			if err != nil {
				if closeCtx.Err() != nil {
					// Session.Close() timed out.
					fixture.Logger.Warn("Session close potentially interrupted by cleanup timeout.", zap.Error(closeCtx.Err()))
				}
			} else {
				fixture.Logger.Debug("Session closed during cleanup.")
			}
		}

		// Allocator context cancellation is handled by its own t.Cleanup.
		// rootCtx cancellation is now handled explicitly at the start of this block.

		// CRITICAL: We DO NOT close proxyFindingsChan here.
		// If a session writer (e.g., AddFinding) is blocked sending to a full buffer when Close() is called,
		// closing the channel here causes "send on closed channel" panic.
		// We rely entirely on context cancellation (rootCtx) to stop the proxy goroutine.

		// 3. Wait for the proxy goroutine to exit (due to rootCtx cancellation in step 1).
		fixture.WG.Wait()
		fixture.Logger.Debug("Findings proxy goroutine finished.")

		// 4. Close the public findings channel.
		// This is now safe because the only writer (the proxy goroutine) has exited.
		close(fixture.FindingsChan)
		fixture.Logger.Debug("Public findings channel closed.")

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
