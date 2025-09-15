package browser

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Manager controls the lifecycle of the browser process and manages browser sessions.
// It adheres to Principle 1: One Process, Many Tabs.
type Manager struct {
	logger *zap.Logger
	// semaphore controls the maximum number of concurrent active sessions.
	semaphore chan struct{}
	// allocatorCtx is the context used for the ExecAllocator, governing the browser process lifetime.
	allocatorCtx context.Context
	// browserCtx is the main context for the browser instance itself (CDP session).
	browserCtx context.Context
	// cancelBrowser cancels the browserCtx and the allocatorCtx.
	cancelBrowser context.CancelFunc
	// contextCreationLock ensures that creating new targets/contexts via CDP commands is thread-safe.
	contextCreationLock sync.Mutex
	// wg tracks active AnalysisContext sessions for graceful shutdown (Principle 4).
	wg sync.WaitGroup
}

// NewManager initializes the browser manager and starts the browser process.
// initCtx should be the application's master context (e.g., from signal.NotifyContext) for Principle 4 adherence.
func NewManager(
	initCtx context.Context,
	logger *zap.Logger,
	cfg config.BrowserConfig,
) (*Manager, error) {
	l := logger.With(zap.String("component", "browser_manager"))
	l.Info("Initializing new browser manager...", zap.Error(initCtx.Err()))

	concurrencyLimit := cfg.Concurrency
	if concurrencyLimit <= 0 {
		concurrencyLimit = 4 // Default concurrency
		l.Warn("Invalid concurrency limit configured, defaulting.", zap.Int("default", concurrencyLimit))
	}

	// --- 1. Configure ExecAllocator Options ---
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		// Standard flags for automated environments
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)

	if cfg.Headless {
		opts = append(opts, chromedp.Headless)
	} else {
		opts = append(opts, chromedp.Flag("headless", false))
	}

	// --- 2. Create the ExecAllocator (Principle 1) ---
	// We use initCtx as the parent, so if the application receives a shutdown signal, the allocator is cancelled.
	allocatorCtx, cancelAlloc := chromedp.NewExecAllocator(initCtx, opts...)

	// --- 3. Create the Browser Context ---
	var browserOpts []chromedp.ContextOption

	// Principle 5: Integrate logging.
	browserOpts = append(browserOpts,
		chromedp.WithLogf(func(format string, args ...interface{}) {
			l.Debug(fmt.Sprintf(format, args...), zap.String("source", "chromedp_log"))
		}),
		chromedp.WithErrorf(func(format string, args ...interface{}) {
			l.Error(fmt.Sprintf(format, args...), zap.String("source", "chromedp_error"))
		}),
	)

	// Enable verbose CDP debugging if requested (Principle 5).
	if cfg.Debug {
		browserOpts = append(browserOpts,
			chromedp.WithDebugf(func(format string, args ...interface{}) {
				l.Debug(fmt.Sprintf(format, args...), zap.String("source", "chromedp_debug_cdp"))
			}),
		)
	}

	browserCtx, cancelBrowserCtx := chromedp.NewContext(allocatorCtx, browserOpts...)
	l.Info("Browser context created.", zap.Error(browserCtx.Err()))

	// Combine cancellations for unified shutdown.
	cancelAll := func() {
		l.Warn("Executing cancelAll function; browser context will be cancelled.")
		cancelBrowserCtx()
		cancelAlloc()
	}

	m := &Manager{
		logger:        l,
		allocatorCtx:  allocatorCtx,
		browserCtx:    browserCtx,
		cancelBrowser: cancelAll,
		semaphore:     make(chan struct{}, concurrencyLimit),
	}

	// --- 4. Start and Verify the Browser (Robust Startup) ---
	if err := m.startAndVerifyBrowser(); err != nil {
		// If startup fails, clean up.
		m.cancelBrowser()
		return nil, fmt.Errorf("failed to start and verify browser instance: %w", err)
	}

	l.Info("Browser manager initialized and ready.", zap.Int("concurrency_limit", concurrencyLimit), zap.Bool("headless", cfg.Headless))
	return m, nil
}

// startAndVerifyBrowser ensures the browser process is running and responsive.
func (m *Manager) startAndVerifyBrowser() error {
	// Principle 3: Enforce a startup timeout.
	startupCtx, cancel := context.WithTimeout(m.browserCtx, 45*time.Second)
	defer cancel()

	// Using GetVersion is a lightweight way to ensure the connection is established and the browser is responsive.
	err := chromedp.Run(startupCtx,
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Correctly handle the 6 return values from the Do() method.
			_, product, _, _, _, err := browser.GetVersion().Do(ctx)
			if err == nil {
				m.logger.Debug("Browser verification successful.", zap.String("product", product))
			}
			return err
		}),
	)
	if err != nil {
		return err
	}
	return nil
}

// NewAnalysisContext creates a new isolated browser session (incognito tab/context).
func (m *Manager) NewAnalysisContext(
	// sessionCtx controls the deadline for acquiring a slot and initializing the session (Principle 3).
	sessionCtx context.Context,
	cfg *config.Config,
	persona stealth.Persona,
	taintTemplate string,
	taintConfig string,
) (*AnalysisContext, error) {
	m.logger.Debug("NewAnalysisContext: ENTER", zap.Error(m.browserCtx.Err()))
	if m.browserCtx.Err() != nil {
		m.logger.Error("NewAnalysisContext: Manager's context is already cancelled on entry.", zap.Error(m.browserCtx.Err()))
		return nil, fmt.Errorf("cannot create new session: browser manager is shut down")
	}

	// 1. Acquire Semaphore Slot
	m.logger.Debug("NewAnalysisContext: Attempting to acquire semaphore slot...")
	if err := m.acquireSlot(sessionCtx); err != nil {
		return nil, err
	}
	m.logger.Debug("NewAnalysisContext: Semaphore slot acquired.")

	// Ensure the semaphore is released if initialization fails.
	sessionInitialized := false
	defer func() {
		if !sessionInitialized {
			m.releaseSlot()
		}
	}()

	// 2. Create the AnalysisContext structure.
	ac := NewAnalysisContext(
		m.allocatorCtx,
		m.browserCtx,
		cfg,
		m.logger,
		persona,
		taintTemplate,
		taintConfig,
		&m.contextCreationLock,
		m,
	)
	m.logger.Debug("NewAnalysisContext: Calling ac.Initialize()...")

	// 3. Initialize the browser context and target.
	if err := ac.Initialize(sessionCtx); err != nil {
		// Initialize handles its internal cleanup (internalClose) on failure.
		return nil, fmt.Errorf("failed to initialize analysis context: %w", err)
	}
	m.logger.Debug("NewAnalysisContext: ac.Initialize() returned successfully.")

	// 4. Register the active session.
	m.wg.Add(1)
	sessionInitialized = true // Initialization succeeded, responsibility for releasing the slot is transferred to ac.Close().
	m.logger.Debug("NewAnalysisContext: END")
	return ac, nil
}

// acquireSlot waits for an available slot in the concurrency semaphore.
func (m *Manager) acquireSlot(ctx context.Context) error {
	select {
	case m.semaphore <- struct{}{}:
		// Slot acquired
		return nil
	case <-ctx.Done():
		return fmt.Errorf("failed to acquire session slot: %w", ctx.Err())
	case <-m.browserCtx.Done():
		// Check if the manager itself is shutting down.
		return fmt.Errorf("failed to acquire session slot: manager is shutting down")
	}
}

// releaseSlot releases a slot back to the semaphore.
func (m *Manager) releaseSlot() {
	select {
	case <-m.semaphore:
	// Slot released
	default:
		// This should ideally not happen if acquire/release logic is balanced.
		m.logger.Error("Attempted to release semaphore slot when none appeared acquired.")
	}
}

// unregisterSession is called by an AnalysisContext when it's closed (implements SessionLifecycleObserver).
func (m *Manager) unregisterSession(ac *AnalysisContext) {
	m.releaseSlot()
	m.wg.Done()
	m.logger.Debug("Session unregistered.", zap.String("session_id", ac.ID()))
}

// Shutdown gracefully closes all active sessions and terminates the browser process.
// Adheres to Principle 4: Shut Down Gracefully.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutdown sequence initiated.")
	m.logger.Info("Shutting down browser manager. Waiting for active sessions to complete.")

	// Wait for all active sessions (AnalysisContexts) to call Close() and unregister.
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("All browser sessions closed gracefully.")
	case <-ctx.Done():
		// The provided context expired. We proceed with forceful shutdown.
		m.logger.Warn("Timeout waiting for browser sessions to close. Forcing shutdown.", zap.Error(ctx.Err()))
	}

	// Shut down the browser process by cancelling the contexts.
	m.logger.Info("Terminating browser process.")
	m.cancelBrowser()

	// Wait briefly to confirm the allocator context is done (process exited).
	select {
	case <-m.allocatorCtx.Done():
		m.logger.Info("Browser manager shutdown complete.")
	case <-time.After(10 * time.Second):
		// Hard timeout if the process hangs.
		m.logger.Error("Timeout waiting for browser process to terminate after cancellation.")
	}

	return nil
}

