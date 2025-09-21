// Package browser provides the primitives for managing and interacting with a headless
// browser instance. It is responsible for the browser's lifecycle, creating isolated
// analysis sessions, and applying anti-detection measures.
package browser

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

const (
	verificationTimeout    = 30 * time.Second
	sessionInitTimeout     = 30 * time.Second
	shutdownSessionTimeout = 10 * time.Second
)

// Manager is in charge of the browser's lifecycle. It holds contexts for the
// allocator (the browser process) and the browser connection itself.
type Manager struct {
	logger          *zap.Logger
	cfg             *config.Config
	allocatorCtx    context.Context
	allocatorCancel context.CancelFunc
	browserCtx      context.Context
	browserCancel   context.CancelFunc
	sessions        map[string]*AnalysisContext
	mu              sync.Mutex
}

var _ schemas.BrowserManager = (*Manager)(nil)
var _ SessionLifecycleObserver = (*Manager)(nil)

// NewManager fires up the browser manager and the underlying browser process.
// It establishes a single, long lived connection to the browser.
func NewManager(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*Manager, error) {
	m := &Manager{
		logger:   logger.Named("browser_manager"),
		cfg:      cfg,
		sessions: make(map[string]*AnalysisContext),
	}

	opts := m.generateAllocatorOptions()
	// The allocator context's lifecycle is tied to the parent context. Canceling it
	// will terminate the browser process.
	m.allocatorCtx, m.allocatorCancel = chromedp.NewExecAllocator(ctx, opts...)

	// From the allocator, we create a single browser context that represents the
	// connection to the browser instance. New tabs will be created from this context.
	m.browserCtx, m.browserCancel = chromedp.NewContext(m.allocatorCtx, chromedp.WithLogf(m.logger.Sugar().Debugf))

	// We'll "warm up" the browser connection to ensure it's ready.
	// A timed context is derived from our main browser context for this check.
	runCtx, runCancel := context.WithTimeout(m.browserCtx, verificationTimeout)
	defer runCancel()

	err := chromedp.Run(runCtx, chromedp.ActionFunc(func(c context.Context) error {
		m.logger.Info("Browser manager initialized and connection verified.",
			zap.Bool("headless", cfg.Browser.Headless),
			zap.Bool("proxy_enabled", cfg.Network.Proxy.Enabled),
			// Log if the stabilized test/debug configuration is active.
			zap.Bool("is_test_config", cfg.Browser.Debug),
		)
		return nil
	}))

	if err != nil {
		m.browserCancel()   // Clean up the browser context.
		m.allocatorCancel() // If we can't connect, kill the browser process.
		return nil, fmt.Errorf("failed to verify connection to browser instance: %w", err)
	}

	return m, nil
}

// NewAnalysisContext creates a new, isolated browser tab (session).
// It no longer accepts a `sessionCtx` because the lifecycle is managed explicitly.
func (m *Manager) NewAnalysisContext(
	ctx context.Context,
	cfgInterface interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
) (schemas.SessionContext, error) {
	appConfig, ok := cfgInterface.(*config.Config)
	if !ok {
		return nil, fmt.Errorf("invalid configuration object type provided: %T", cfgInterface)
	}

	ac, err := m.createBrowserSession(appConfig, persona)
	if err != nil {
		return nil, fmt.Errorf("failed to create browser session: %w", err)
	}

	m.mu.Lock()
	m.sessions[ac.ID()] = ac
	m.mu.Unlock()

	if taintTemplate != "" && taintConfig != "" {
		if err := ac.InitializeTaint(taintTemplate, taintConfig); err != nil {
			m.logger.Error("Failed to initialize taint instrumentation", zap.Error(err))
			// Use a detached, timed context for the close operation on failure to ensure cleanup.
			closeCtx, closeCancel := context.WithTimeout(context.Background(), shutdownSessionTimeout)
			defer closeCancel()
			ac.Close(closeCtx)
			return nil, fmt.Errorf("failed to initialize taint instrumentation: %w", err)
		}
	}

	return ac, nil
}

// Shutdown gracefully terminates all active sessions and the main browser process.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager...")
	m.mu.Lock()
	sessionsToClose := make([]*AnalysisContext, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessionsToClose = append(sessionsToClose, session)
	}
	m.sessions = make(map[string]*AnalysisContext)
	m.mu.Unlock()

	var wg sync.WaitGroup
	for _, session := range sessionsToClose {
		wg.Add(1)
		go func(s *AnalysisContext) {
			defer wg.Done()
			closeCtx, cancel := context.WithTimeout(ctx, shutdownSessionTimeout)
			defer cancel()
			if err := s.Close(closeCtx); err != nil {
				m.logger.Warn("Error closing browser session during shutdown",
					zap.String("session_id", s.ID()),
					zap.Error(err),
				)
			}
		}(session)
	}
	wg.Wait()

	// Shut down contexts in the correct order: browser connection, then process.
	if m.browserCancel != nil {
		m.browserCancel()
	}
	if m.allocatorCancel != nil {
		m.allocatorCancel()
	}

	m.logger.Info("Browser manager shutdown complete.")
	return nil
}

// NavigateAndExtract creates a temporary session to perform a task.
func (m *Manager) NavigateAndExtract(ctx context.Context, targetURL string) ([]string, error) {
	m.logger.Debug("NavigateAndExtract called", zap.String("url", targetURL))

	session, err := m.NewAnalysisContext(ctx, m.cfg, schemas.DefaultPersona, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create session for NavigateAndExtract: %w", err)
	}

	// Make sure the temporary session is closed.
	// REFACTORED: Use a detached, timed context for closing to ensure graceful shutdown
	// even if the parent context (ctx) is already cancelled.
	closeCtx, closeCancel := context.WithTimeout(context.Background(), shutdownSessionTimeout)
	defer closeCancel()
	defer session.Close(closeCtx)

	// REFACTORED: Use the CombineContext utility for robust context management.
	// This ensures the operation respects both the session lifecycle and the incoming request's deadline (ctx),
	// replacing the previous manual goroutine implementation.
	operationCtx, operationCancel := CombineContext(session.GetContext(), ctx)
	defer operationCancel()

	var attributes []map[string]string
	tasks := chromedp.Tasks{
		chromedp.Navigate(targetURL),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.AttributesAll("a[href]", &attributes, chromedp.ByQueryAll),
	}

	// All actions for this task run under our new, cancellable operation context.
	if err := chromedp.Run(operationCtx, tasks); err != nil {
		// If the error was caused by the incoming context being cancelled,
		// it's good practice to return that original error.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("failed to run navigation and extraction tasks: %w", err)
	}

	hrefs := make([]string, 0, len(attributes))
	for _, attrMap := range attributes {
		if href, found := attrMap["href"]; found {
			hrefs = append(hrefs, href)
		}
	}

	m.logger.Debug("Extracted links", zap.Int("count", len(hrefs)))
	return hrefs, nil
}

func (m *Manager) unregisterSession(ac *AnalysisContext) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, ac.ID())
	m.logger.Debug("Unregistered session", zap.String("session_id", ac.ID()))
}

// createBrowserSession now follows the modern, simplified pattern.
func (m *Manager) createBrowserSession(appConfig *config.Config, persona schemas.Persona) (*AnalysisContext, error) {
	// 1. Create a new context (a "tab") from the main browser context.
	// This context directly controls the lifecycle of the tab.
	tabCtx, tabCancel := chromedp.NewContext(m.browserCtx)

	// 2. Perform initialization within a timed context derived from the tab context.
	initCtx, initCancel := context.WithTimeout(tabCtx, sessionInitTimeout)
	defer initCancel()

	if persona.UserAgent == "" {
		persona = schemas.DefaultPersona
	}

	tasks := chromedp.Tasks{
		chromedp.Navigate("about:blank"),
		stealth.Apply(persona, m.logger),
	}

	if err := chromedp.Run(initCtx, tasks); err != nil {
		tabCancel() // If init fails, we must explicitly cancel the tab context.
		return nil, fmt.Errorf("failed to initialize browser session: %w", err)
	}

	sessionID := uuid.New().String()
	// 3. The AnalysisContext is now simpler: it just receives the tab's context and cancel func.
	ac := NewAnalysisContext(tabCtx, tabCancel, m.logger, appConfig, persona, m, sessionID)
	return ac, nil
}

// generateAllocatorOptions assembles the command line arguments for launching Chrome
// to ensure stability and evade detection.
func (m *Manager) generateAllocatorOptions() []chromedp.ExecAllocatorOption {
	browserCfg := m.cfg.Browser
	proxyCfg := m.cfg.Network.Proxy

	// Start with a clean slate of options. Building the options explicitly is robust.
	opts := []chromedp.ExecAllocatorOption{
		// Since the test runner executes from within the package directory,
		// the relative path is now correct.
		chromedp.ExecPath("./run-chrome.sh"),

		// 1. Core stealth and automation overrides.
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),

		// Set a default user agent.
		chromedp.UserAgent(schemas.DefaultPersona.UserAgent),
	}

	// 2. Apply configuration-specific flags.
	if browserCfg.Headless {
		// Use the "new" headless mode for better stealth and consistency (Modern practice).
		opts = append(opts, chromedp.Flag("headless", "new"))
	}
	if browserCfg.IgnoreTLSErrors {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}

	// 3. Apply stability and environment-specific flags.
	opts = append(opts,
		// Stability flags beneficial in all environments, especially containers.
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-gpu", browserCfg.Headless), // Disable GPU in headless mode.
	)

	// Environment differentiation (Debug/Test vs. Production).
	if browserCfg.Debug {
		// In test/debug environments (often containerized CI), NoSandbox is crucial for stability.
		opts = append(opts, chromedp.NoSandbox)
	} else {
		// In production, ensure key operational flags for a clean run are present.
		opts = append(opts,
			chromedp.Flag("disable-background-networking", true),
			chromedp.Flag("disable-sync", true),
			chromedp.Flag("no-first-run", true),
			chromedp.Flag("no-default-browser-check", true),
		)
	}

	// 4. Apply Proxy settings.
	if proxyCfg.Enabled && proxyCfg.Address != "" {
		proxyURL := "http://" + proxyCfg.Address
		if _, err := url.Parse(proxyURL); err == nil {
			opts = append(opts, chromedp.ProxyServer(proxyURL))
			// When using a proxy (especially for interception), ignoring cert errors is often necessary.
			opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
		} else {
			m.logger.Error("Invalid proxy address, proxy will not be used", zap.String("address", proxyCfg.Address))
		}
	}

	return opts
}

