package browser

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Manager is responsible for the lifecycle of the headless browser instance
// and the creation of isolated browsing sessions (AnalysisContexts).
type Manager struct {
	cfg             *config.Config
	logger          *zap.Logger
	allocatorCtx    context.Context
	allocatorCancel context.CancelFunc
	browserCtx      context.Context // Main context for browser commands
	browserCancel   context.CancelFunc
	wg              sync.WaitGroup

	// Pre-loaded instrumentation scripts
	taintShimTemplate string
	taintConfigJSON   string
}

// NewManager initializes a new browser manager and starts the headless browser instance.
func NewManager(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*Manager, error) {
	l := logger.With(zap.String("component", "browser_manager"))

	// Create an allocator context that will manage the lifecycle of the browser process.
	allocatorOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", cfg.Browser.Headless),
		chromedp.Flag("disable-gpu", true),
		// Add --no-sandbox flag for compatibility with Docker/CI environments.
		chromedp.Flag("no-sandbox", true),
		chromedp.UserAgent(stealth.DefaultPersona.UserAgent),
	)

	// Allow overriding the executable path via an environment variable.
	// This is a robust way to handle non-standard browser installations, especially in test environments.
	if execPath := os.Getenv("CHROME_EXEC"); execPath != "" {
		l.Debug("Using browser executable from CHROME_EXEC env var.", zap.String("path", execPath))
		allocatorOpts = append(allocatorOpts, chromedp.ExecPath(execPath))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, allocatorOpts...)

	// Create the main browser context from the allocator for sending commands.
	browserCtx, browserCancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(logger.Sugar().Debugf))

	// Run an empty task to launch the browser and establish the connection.
	if err := chromedp.Run(browserCtx); err != nil {
		allocCancel() // Clean up allocator if browser fails to start.
		return nil, fmt.Errorf("failed to start browser instance via chromedp: %w", err)
	}

	m := &Manager{
		cfg:             cfg,
		logger:          l,
		allocatorCtx:    allocCtx,
		allocatorCancel: allocCancel,
		browserCtx:      browserCtx,
		browserCancel:   browserCancel,
	}

	// Pre-load IAST scripts from disk to avoid file I/O for every new session.
	if err := m.loadInstrumentationFiles(); err != nil {
		// If scripts can't be loaded, the manager can't function correctly.
		m.Shutdown(context.Background()) // Attempt a cleanup
		return nil, fmt.Errorf("failed to load instrumentation files: %w", err)
	}

	m.logger.Info("Browser manager initialized")
	return m, nil
}

// loadInstrumentationFiles reads the IAST shim and config from disk once at startup.
func (m *Manager) loadInstrumentationFiles() error {
	// Load the JavaScript taint shim template.
	templateBytes, err := os.ReadFile(m.cfg.IAST.ShimPath)
	if err != nil {
		return fmt.Errorf("could not read taint shim template at %s: %w", m.cfg.IAST.ShimPath, err)
	}
	m.taintShimTemplate = string(templateBytes)

	// Load the taint tracking configuration.
	configBytes, err := os.ReadFile(m.cfg.IAST.ConfigPath)
	if err != nil {
		return fmt.Errorf("could not read taint config at %s: %w", m.cfg.IAST.ConfigPath, err)
	}
	m.taintConfigJSON = string(configBytes)

	m.logger.Debug("IAST instrumentation files loaded successfully.")
	return nil
}

// InitializeSession creates, instruments, and returns a new, isolated browser tab (AnalysisContext).
func (m *Manager) InitializeSession(ctx context.Context) (*AnalysisContext, error) {
	m.logger.Debug("Initializing new browser session.")

	// Create a new analysis context for the session.
	ac := NewAnalysisContext(
		m.browserCtx, // Pass the valid browser command context.
		m.cfg,
		m.logger,
		stealth.DefaultPersona,
		m.taintShimTemplate,
		m.taintConfigJSON,
	)

	// Perform the heavyweight initialization (creating the tab, applying stealth, etc.).
	if err := ac.Initialize(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize analysis context: %w", err)
	}

	// Track the session's lifecycle to ensure graceful shutdown.
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		// Wait until the session's internal context is done, then ensure it's closed.
		<-ac.GetContext().Done()
		// Use a background context for cleanup to ensure it runs even if the parent is cancelled.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		ac.Close(cleanupCtx)
		m.logger.Debug("Cleaned up closed session.", zap.String("session_id", ac.ID()))
	}()

	m.logger.Info("New browser session created and instrumented.", zap.String("session_id", ac.ID()))
	return ac, nil
}

// Shutdown gracefully closes the browser allocator and all associated sessions.
func (m *Manager) Shutdown(ctx context.Context) {
	m.logger.Info("Shutting down browser manager...")

	// Cancel the allocator context, which signals all browser instances and tabs to close.
	m.allocatorCancel()

	// Wait for all session tracking goroutines to complete.
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
}

