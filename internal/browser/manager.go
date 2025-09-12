package browser

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
)

// maxConcurrentSessions defines how many browser sessions we allow to be
// initialized at the same time. This acts as a "start gate" to prevent race conditions.
const maxConcurrentSessions = 4

type Manager struct {
	cfg                     *config.Config
	logger                  *zap.Logger
	allocatorCtx            context.Context
	allocatorCancel         context.CancelFunc
	browserControllerCtx    context.Context
	browserControllerCancel context.CancelFunc
	wg                      sync.WaitGroup
	sessionGate             chan struct{}

	taintShimTemplate string
	taintConfigJSON   string

	// isShutdown is an atomic flag to prevent logging spurious errors during a planned shutdown.
	isShutdown atomic.Bool
}

// NewManager initializes the browser process and the main control connection.
func NewManager(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*Manager, error) {
	l := logger.With(zap.String("component", "browser_manager"))

	allocatorOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.CombinedOutput(os.Stderr),
		chromedp.Flag("headless", cfg.Browser.Headless),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.UserAgent(stealth.DefaultPersona.UserAgent),
	)

	if execPath := os.Getenv("CHROME_EXEC"); execPath != "" {
		l.Debug("Using browser executable from CHROME_EXEC env var.", zap.String("path", execPath))
		allocatorOpts = append(allocatorOpts, chromedp.ExecPath(execPath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocatorOpts...)
	browserControllerCtx, browserControllerCancel := chromedp.NewContext(allocCtx)

	cleanup := func() {
		browserControllerCancel()
		allocCancel()
	}

	verifyCtx, verifyCancel := context.WithTimeout(browserControllerCtx, 15*time.Second)
	defer verifyCancel()

	var productVersion string
	if err := chromedp.Run(verifyCtx,
		chromedp.Navigate("about:blank"),
		chromedp.ActionFunc(func(c context.Context) (err error) {
			productVersion, _, _, _, _, err = browser.GetVersion().Do(c)
			return err
		}),
	); err != nil {
		l.Error("Failed to verify browser connection.", zap.Error(err))
		cleanup()
		return nil, fmt.Errorf("failed to connect to and verify browser instance. Ensure Chrome/Chromium is installed: %w", err)
	}
	l.Debug("Browser process connection verified.", zap.String("version", productVersion))

	m := &Manager{
		cfg:                     cfg,
		logger:                  l,
		allocatorCtx:            allocCtx,
		allocatorCancel:         allocCancel,
		browserControllerCtx:    browserControllerCtx,
		browserControllerCancel: browserControllerCancel,
		sessionGate:             make(chan struct{}, maxConcurrentSessions),
	}

	// Launch our new "black box recorder" to monitor the contexts.
	m.monitorContexts()

	if err := m.loadInstrumentationFiles(); err != nil {
		m.Shutdown(context.Background())
		return nil, fmt.Errorf("failed to load instrumentation files: %w", err)
	}

	m.logger.Info("Browser manager initialized and ready for parallel sessions.", zap.Int("concurrency_limit", maxConcurrentSessions))
	return m, nil
}

// monitorContexts runs in the background to provide diagnostics on premature context cancellation.
func (m *Manager) monitorContexts() {
	go func() {
		select {
		case <-m.allocatorCtx.Done():
			// Check the isShutdown flag. If it's false, this was an unplanned event.
			if !m.isShutdown.Load() {
				m.logger.Warn(
					"!!! Allocator context cancelled unexpectedly. The browser process likely crashed. !!!",
					zap.Error(m.allocatorCtx.Err()),
				)
			}
		case <-m.browserControllerCtx.Done():
			if !m.isShutdown.Load() {
				m.logger.Warn(
					"!!! Browser controller context cancelled unexpectedly. !!!",
					zap.Error(m.browserControllerCtx.Err()),
				)
			}
		}
	}()
}

func (m *Manager) loadInstrumentationFiles() error {
	if m.cfg.IAST.ShimPath == "" {
		m.logger.Debug("IAST ShimPath is empty, skipping instrumentation file load.")
		return nil
	}
	templateBytes, err := os.ReadFile(m.cfg.IAST.ShimPath)
	if err != nil {
		return fmt.Errorf("could not read taint shim template at %s: %w", m.cfg.IAST.ShimPath, err)
	}
	m.taintShimTemplate = string(templateBytes)

	if m.cfg.IAST.ConfigPath == "" {
		m.logger.Debug("IAST ConfigPath is empty, skipping taint config load.")
		m.taintConfigJSON = "[]"
		return nil
	}
	configBytes, err := os.ReadFile(m.cfg.IAST.ConfigPath)
	if err != nil {
		return fmt.Errorf("could not read taint config at %s: %w", m.cfg.IAST.ConfigPath, err)
	}
	m.taintConfigJSON = string(configBytes)

	m.logger.Debug("IAST instrumentation files loaded successfully.")
	return nil
}

// InitializeSession creates a new, isolated browser session (AnalysisContext).
func (m *Manager) InitializeSession(ctx context.Context) (*AnalysisContext, error) {
	if m.browserControllerCtx.Err() != nil {
		return nil, fmt.Errorf("browser controller connection is closed before initialization: %w", m.browserControllerCtx.Err())
	}

	m.logger.Debug("Waiting for session gate to open...")
	m.sessionGate <- struct{}{}
	defer func() { <-m.sessionGate }()
	m.logger.Debug("Session gate acquired. Initializing new browser session.")

	if m.browserControllerCtx.Err() != nil {
		if m.allocatorCtx.Err() != nil {
			return nil, fmt.Errorf("cannot initialize session, browser process is closed: %w", m.allocatorCtx.Err())
		}
		return nil, fmt.Errorf("cannot initialize session, browser controller connection is closed: %w", m.browserControllerCtx.Err())
	}

	ac := NewAnalysisContext(
		m.allocatorCtx,
		m.browserControllerCtx,
		m.cfg,
		m.logger,
		stealth.DefaultPersona,
		m.taintShimTemplate,
		m.taintConfigJSON,
	)

	m.wg.Add(1)
	if err := ac.Initialize(ctx); err != nil {
		m.wg.Done()
		return nil, fmt.Errorf("failed to initialize analysis context: %w", err)
	}

	go func() {
		defer m.wg.Done()
		<-ac.GetContext().Done()
		m.logger.Debug("Detected closed session.", zap.String("session_id", ac.ID()))
	}()

	m.logger.Info("New browser session created and instrumented.", zap.String("session_id", ac.ID()))
	return ac, nil
}

// Shutdown closes all active sessions and stops the browser process.
func (m *Manager) Shutdown(ctx context.Context) {
	// Set the flag to true so our monitor knows this is a planned shutdown.
	m.isShutdown.Store(true)
	m.logger.Info("Shutting down browser manager...")

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("All browser sessions closed gracefully.")
	case <-ctx.Done():
		m.logger.Warn("Shutdown context cancelled before all sessions could close.", zap.Error(ctx.Err()))
	}

	if m.browserControllerCancel != nil {
		m.logger.Debug("Closing browser controller connection.")
		m.browserControllerCancel()
	}

	if m.allocatorCancel != nil {
		m.logger.Debug("Stopping browser process.")
		m.allocatorCancel()
	}
}

