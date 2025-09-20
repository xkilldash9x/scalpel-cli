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
	// How long to wait for the initial browser connection to be established.
	verificationTimeout = 30 * time.Second
	// How long to wait for a new session (tab) to initialize.
	sessionInitTimeout = 30 * time.Second
	// The grace period for a single session to close during a full shutdown.
	shutdownSessionTimeout = 10 * time.Second
	// The grace period for a temporary session to clean up after a utility function runs.
	cleanupTimeout = 5 * time.Second
)

// Manager is in charge of the browser's lifecycle,
// spinning up new isolated sessions, and making sure everything shuts down cleanly.
type Manager struct {
	logger *zap.Logger
	cfg    *config.Config

	// This context represents the lifecycle of the browser executable itself.
	// It serves as the root of the context tree for all browser operations.
	// When its cancel function is called, the entire browser process is terminated.
	allocatorCtx    context.Context
	allocatorCancel context.CancelFunc

	// Keeps track of all the active sessions.
	sessions map[string]*AnalysisContext
	mu       sync.Mutex
}

// -- Interface Compliance --
var _ schemas.BrowserManager = (*Manager)(nil)
var _ SessionLifecycleObserver = (*Manager)(nil)

// NewManager fires up the browser manager and the underlying browser process.
func NewManager(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*Manager, error) {
	m := &Manager{
		logger:   logger.Named("browser_manager"),
		cfg:      cfg,
		sessions: make(map[string]*AnalysisContext),
	}

	opts := m.generateAllocatorOptions()

	// This establishes the root of our context tree for the browser process.
	// The lifecycle of the browser executable is tied to this allocatorCtx.
	m.allocatorCtx, m.allocatorCancel = chromedp.NewExecAllocator(ctx, opts...)

	// "Warm up" the browser connection using a temporary context to ensure it's ready.
	verifyCtx, verifyCancel := chromedp.NewContext(m.allocatorCtx, chromedp.WithLogf(m.logger.Sugar().Debugf))
	defer verifyCancel()

	runCtx, runCancel := context.WithTimeout(verifyCtx, verificationTimeout)
	defer runCancel()

	// Just run a no-op to confirm the connection is live.
	err := chromedp.Run(runCtx, chromedp.ActionFunc(func(ctx context.Context) error {
		m.logger.Info("Browser manager initialized and connection verified.",
			zap.Bool("headless", cfg.Browser.Headless),
			zap.Bool("proxy_enabled", cfg.Network.Proxy.Enabled),
		)
		return nil
	}))

	if err != nil {
		m.allocatorCancel() // If we can't connect, kill the browser process.
		return nil, fmt.Errorf("failed to verify connection to browser instance: %w", err)
	}

	return m, nil
}

// NewAnalysisContext creates a new, fully isolated browser session for analysis tasks.
func (m *Manager) NewAnalysisContext(
	sessionCtx context.Context,
	cfgInterface interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
) (schemas.SessionContext, error) {
	appConfig, ok := cfgInterface.(*config.Config)
	if !ok {
		return nil, fmt.Errorf("invalid configuration object type provided: %T", cfgInterface)
	}

	ac, err := m.createBrowserSession(sessionCtx, appConfig, persona)
	if err != nil {
		return nil, fmt.Errorf("failed to create browser session: %w", err)
	}

	m.mu.Lock()
	m.sessions[ac.ID()] = ac
	m.mu.Unlock()

	if taintTemplate != "" && taintConfig != "" {
		if err := ac.InitializeTaint(taintTemplate, taintConfig); err != nil {
			m.logger.Error("Failed to initialize taint instrumentation", zap.Error(err))
			// If taint setup fails, the session is invalid. Clean it up immediately.
			ac.Close(context.Background())
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

	if m.allocatorCancel != nil {
		m.allocatorCancel()
	}

	m.logger.Info("Browser manager shutdown complete.")
	return nil
}

// NavigateAndExtract is a high level utility for visiting a URL, waiting for it to
// load, and extracting all discoverable links.
func (m *Manager) NavigateAndExtract(ctx context.Context, url string) ([]string, error) {
	m.logger.Debug("NavigateAndExtract called", zap.String("url", url))

	session, err := m.NewAnalysisContext(ctx, m.cfg, schemas.DefaultPersona, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create session for NavigateAndExtract: %w", err)
	}
	// This defer ensures the temporary session is cleaned up, even if the parent
	// context is cancelled. A new "detached" context (from context.Background)
	// with a timeout guarantees a graceful shutdown attempt.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		session.Close(cleanupCtx)
	}()

	var attributes []map[string]string

	tasks := chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.AttributesAll("a[href]", &attributes, chromedp.ByQueryAll),
	}

	if err := chromedp.Run(session.GetContext(), tasks); err != nil {
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

// unregisterSession is a callback for an AnalysisContext to announce its closure.
// This satisfies the SessionLifecycleObserver interface.
func (m *Manager) unregisterSession(ac *AnalysisContext) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[ac.ID()]; exists {
		delete(m.sessions, ac.ID())
		m.logger.Debug("Unregistered session", zap.String("session_id", ac.ID()))
	}
}

// -- Private Helpers --

// createBrowserSession handles creating a new incognito context, applying stealth
// settings, and wrapping it in our AnalysisContext struct.
func (m *Manager) createBrowserSession(sessionCtx context.Context, appConfig *config.Config, persona schemas.Persona) (*AnalysisContext, error) {
	// Create a new incognito browser context (a "tab") from the root allocator.
	// This establishes a parent-child relationship in the context tree.
	ctx, cancel := chromedp.NewContext(m.allocatorCtx, chromedp.WithLogf(m.logger.Sugar().Debugf))

	// Link the lifecycle of this new context to the parent operation's context.
	// When the parent (sessionCtx) is done, the browser tab closes automatically.
	// This is the core of the "cancellation cascade".
	go func() {
		select {
		case <-sessionCtx.Done():
			cancel()
		case <-ctx.Done():
		}
	}()

	initCtx, initCancel := context.WithTimeout(ctx, sessionInitTimeout)
	defer initCancel()

	if persona.UserAgent == "" {
		persona = schemas.DefaultPersona
	}
	applyStealthAction := stealth.Apply(persona, m.logger)

	tasks := chromedp.Tasks{
		chromedp.Navigate("about:blank"),
		applyStealthAction,
	}

	if err := chromedp.Run(initCtx, tasks); err != nil {
		// If the context was cancelled during init, this error is expected.
		// Otherwise, it's a legitimate problem.
		if initCtx.Err() == nil {
			m.logger.Warn("Failed to apply all stealth evasions during session init", zap.Error(err))
		}
	}

	sessionID := uuid.New().String()
	ac := NewAnalysisContext(ctx, cancel, m.logger, appConfig, persona, m, sessionID)

	return ac, nil
}

// generateAllocatorOptions assembles the command line arguments for launching Chrome
// to ensure stability and evade detection.
func (m *Manager) generateAllocatorOptions() []chromedp.ExecAllocatorOption {
	defaultOpts := chromedp.DefaultExecAllocatorOptions[:]
	opts := make([]chromedp.ExecAllocatorOption, len(defaultOpts), len(defaultOpts)+20)
	copy(opts, defaultOpts)

	browserCfg := m.cfg.Browser
	proxyCfg := m.cfg.Network.Proxy

	if browserCfg.Headless {
		opts = append(opts, chromedp.Flag("headless", "new"))
	}

	opts = append(opts,
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-gpu", browserCfg.Headless),
	)

	if browserCfg.IgnoreTLSErrors {
		opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
	}

	if proxyCfg.Enabled && proxyCfg.Address != "" {
		proxyURL := "http://" + proxyCfg.Address
		if _, err := url.Parse(proxyURL); err == nil {
			opts = append(opts, chromedp.ProxyServer(proxyURL))
			opts = append(opts, chromedp.Flag("ignore-certificate-errors", true))
		} else {
			m.logger.Error("Invalid proxy address, proxy will not be used", zap.String("address", proxyCfg.Address))
		}
	}

	return opts
}
