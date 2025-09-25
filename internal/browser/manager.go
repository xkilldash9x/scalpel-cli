// internal/browser/manager.go
package browser

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Manager handles the browser process lifecycle and session creation using Playwright.
type Manager struct {
	pw      *playwright.Playwright
	browser playwright.Browser
	logger  *zap.Logger
	cfg     *config.Config

	sessions map[string]*Session
	mu       sync.RWMutex
	wg       sync.WaitGroup // WaitGroup to ensure all sessions are closed before shutting down the browser.

	// Initialization state management
	initOnce sync.Once
	initErr  error
}

const playwrightInstallTimeout = 5 * time.Minute
const shutdownGracePeriod = 15 * time.Second

// NewManager creates a new browser manager. Initialization is deferred until the first session is requested.
func NewManager(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*Manager, error) {
	m := &Manager{
		logger:   logger.Named("browser_manager"),
		cfg:      cfg,
		sessions: make(map[string]*Session),
	}
	m.logger.Info("Browser manager created (initialization deferred).")
	return m, nil
}

// initialize starts the Playwright driver and launches the browser instance.
func (m *Manager) initialize(ctx context.Context) error {
	m.initOnce.Do(func() {
		m.logger.Info("Initializing Playwright and launching browser...")

		// 1. Ensure Playwright browsers are installed (Production Readiness).
		if err := m.ensureInstallation(ctx); err != nil {
			m.initErr = err
			return
		}

		// 2. Start the Playwright driver.
		pw, err := playwright.Run()
		if err != nil {
			m.initErr = fmt.Errorf("failed to start playwright driver: %w", err)
			return
		}
		m.pw = pw

		// 3. Launch the browser instance (Chromium).
		launchOptions := m.prepareLaunchOptions()
		browser, err := pw.Chromium.Launch(launchOptions)
		if err != nil {
			pw.Stop() // Clean up the driver if browser launch fails.
			m.initErr = fmt.Errorf("failed to launch browser instance: %w", err)
			return
		}
		m.browser = browser

		m.logger.Info("Browser manager initialized successfully.", zap.String("browser_version", browser.Version()))
	})
	return m.initErr
}

func (m *Manager) ensureInstallation(ctx context.Context) error {
	m.logger.Info("Verifying Playwright browser installation...")
	installCtx, installCancel := context.WithTimeout(ctx, playwrightInstallTimeout)
	defer installCancel()

	// Run the install command in a goroutine as it blocks.
	installErrChan := make(chan error, 1)
	go func() {
		// We specifically install chromium for consistency.
		options := &playwright.RunOptions{
			Browsers: []string{"chromium"},
		}
		if err := playwright.Install(options); err != nil {
			installErrChan <- fmt.Errorf("failed to install playwright browsers: %w", err)
		} else {
			installErrChan <- nil
		}
	}()

	select {
	case err := <-installErrChan:
		return err
	case <-installCtx.Done():
		return fmt.Errorf("timeout waiting for Playwright installation: %w", installCtx.Err())
	}
}

func (m *Manager) prepareLaunchOptions() playwright.BrowserTypeLaunchOptions {
	launchOptions := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(m.cfg.Browser.Headless),
		Args:     m.cfg.Browser.Args,
		Timeout:  playwright.Float(60000), // 60 seconds launch timeout.
	}

	// Add default arguments often necessary for stability, especially in containers.
	defaultArgs := []string{
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--enable-automation", // Explicitly enabling automation features.
	}

	// Merge default args with user-provided args (simple merge, duplicates are okay for browser args).
	launchOptions.Args = append(defaultArgs, launchOptions.Args...)
	return launchOptions
}

// NewAnalysisContext creates a new isolated browser context (session) for analysis.
func (m *Manager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
	findingsChan chan<- schemas.Finding,
) (schemas.SessionContext, error) {

	// Ensure initialization happens first.
	if err := m.initialize(sessionCtx); err != nil {
		return nil, err
	}

	config, ok := cfg.(*config.Config)
	if !ok {
		return nil, fmt.Errorf("invalid config type passed to NewAnalysisContext")
	}

	// Create the session object.
	session, err := NewSession(sessionCtx, config, persona, m.logger, findingsChan)
	if err != nil {
		return nil, fmt.Errorf("failed to create new session structure: %w", err)
	}

	m.wg.Add(1) // Increment WG before registering the session.

	// Define the onClose callback for cleanup and WG management.
	session.onClose = func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.sessions, session.ID())
		m.wg.Done()
		m.logger.Debug("Session removed from manager.", zap.String("session_id", session.ID()))
	}

	// Initialize the session (creates BrowserContext, Page, applies stealth, starts harvesting).
	if err := session.Initialize(sessionCtx, m.browser, taintTemplate, taintConfig); err != nil {
		// If initialization fails, close the session immediately to release resources and decrement WG.
		// Use a background context for cleanup as sessionCtx might be the cause of failure.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		session.Close(cleanupCtx)
		return nil, fmt.Errorf("failed to initialize session: %w", err)
	}

	m.mu.Lock()
	m.sessions[session.ID()] = session
	m.mu.Unlock()

	m.logger.Info("New session created.", zap.String("session_id", session.ID()))
	return session, nil
}

// NavigateAndExtract is a convenience method that creates a temporary session
// to navigate to a URL and extract all link hrefs from the page.
func (m *Manager) NavigateAndExtract(ctx context.Context, url string) ([]string, error) {
	findingsChan := make(chan schemas.Finding, 1)
	defer close(findingsChan)

	// Create a temporary session.
	sessionCtx, err := m.NewAnalysisContext(ctx, m.cfg, schemas.DefaultPersona, "", "", findingsChan)
	if err != nil {
		return nil, fmt.Errorf("failed to create session for navigation: %w", err)
	}
	// Ensure the temporary session is closed.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		sessionCtx.Close(cleanupCtx)
	}()

	if err := sessionCtx.Navigate(ctx, url); err != nil {
		return nil, fmt.Errorf("failed to navigate to %s: %w", url, err)
	}

	var hrefs []string
	// JavaScript script to extract all absolute links.
	script := `
		() => {
			const links = [];
			// Select only anchors with an href attribute.
			document.querySelectorAll('a[href]').forEach(a => {
				// Accessing 'a.href' returns the absolute URL.
				if (a.href) {
					links.push(a.href);
				}
			});
			return links;
		}
	`
	if err := sessionCtx.ExecuteScript(ctx, script, &hrefs); err != nil {
		return nil, fmt.Errorf("failed to extract links: %w", err)
	}

	return hrefs, nil
}

// Shutdown gracefully closes all sessions and the browser process.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager.")

	// If initialization never succeeded, ensure cleanup happens if necessary.
	if m.pw == nil {
		m.logger.Info("Manager not fully initialized, skipping full shutdown sequence.")
		return nil
	}

	// 1. Close all active sessions.
	m.mu.RLock()
	sessionsToClose := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessionsToClose = append(sessionsToClose, s)
	}
	m.mu.RUnlock()

	// Initiate close concurrently.
	for _, s := range sessionsToClose {
		go func(s *Session) {
			// Use the provided context for closing, allowing timeout control.
			if err := s.Close(ctx); err != nil {
				m.logger.Warn("Error during session close in shutdown.", zap.String("session_id", s.ID()), zap.Error(err))
			}
		}(s)
	}

	// 2. Wait for all sessions to finish closing (monitored by m.wg).
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("All sessions closed gracefully.")
	case <-ctx.Done():
		m.logger.Warn("Timeout waiting for sessions to close. Proceeding with forceful shutdown.", zap.Error(ctx.Err()))
	}

	// 3. Close the browser instance and driver.
	// Use a fresh context for final cleanup steps.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), shutdownGracePeriod)
	defer cleanupCancel()

	var shutdownErr error

	if m.browser != nil {
		if err := m.browser.Close(cleanupCtx); err != nil {
			m.logger.Error("Failed to close browser instance.", zap.Error(err))
			shutdownErr = fmt.Errorf("failed to close browser: %w", err)
		}
	}

	if err := m.pw.Stop(cleanupCtx); err != nil {
		m.logger.Error("Failed to stop Playwright driver.", zap.Error(err))
		if shutdownErr == nil {
			shutdownErr = fmt.Errorf("failed to stop playwright driver: %w", err)
		}
	}

	m.logger.Info("Browser manager shutdown complete.")
	return shutdownErr
}