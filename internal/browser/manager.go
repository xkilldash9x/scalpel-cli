// internal/browser/manager.go
package browser

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/antchfx/htmlquery" // Added for NavigateAndExtract helper
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/dom"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/jsexec"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/session"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Manager handles the browser session lifecycle using the Pure Go implementation.
type Manager struct {
	logger    *zap.Logger
	cfg       *config.Config
	jsRuntime *jsexec.Runtime // Shared JS runtime (Goja).

	sessions map[string]*session.Session // Updated type
	mu       sync.RWMutex
	wg       sync.WaitGroup // WaitGroup to ensure all sessions are closed before shutting down.

	// Initialization state management
	initOnce sync.Once
	initErr  error
}

const shutdownGracePeriod = 15 * time.Second

// NewManager creates a new browser manager.
func NewManager(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*Manager, error) {
	m := &Manager{
		logger:   logger.Named("browser_manager_purego"),
		cfg:      cfg,
		sessions: make(map[string]*session.Session),
		// Initialize the shared JavaScript runtime (Goja).
		jsRuntime: jsexec.NewRuntime(logger),
	}
	m.logger.Info("Browser manager created (Pure Go implementation).")
	return m, nil
}

// initialize prepares the engine components.
func (m *Manager) initialize(ctx context.Context) error {
	m.initOnce.Do(func() {
		m.logger.Info("Browser manager initialized.")
		// In Pure Go mode, there are no external browser processes or drivers to install/start.
	})
	return m.initErr
}

// NewAnalysisContext creates a new isolated browser context (session) for analysis.
func (m *Manager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg interface{},
	persona schemas.Persona,
	// Taint parameters are generally ignored in Pure Go mode due to lack of JS instrumentation capabilities.
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

	if taintTemplate != "" || taintConfig != "" {
		m.logger.Warn("Taint analysis (IAST) parameters provided but are not supported in Pure Go browser mode.")
	}

	// Create the session object using the internal session package.
	sess, err := session.NewSession(sessionCtx, config, persona, m.logger, findingsChan)
	if err != nil {
		return nil, fmt.Errorf("failed to create new session structure: %w", err)
	}

	m.wg.Add(1) // Increment WG before registering the session.

	// Define the onClose callback for cleanup and WG management.
	sessionID := sess.ID()
	onCloseCallback := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.sessions, sessionID)
		m.wg.Done()
		m.logger.Debug("Session removed from manager.", zap.String("session_id", sessionID))
	}

	// Set the callback on the session.
	sess.SetOnClose(onCloseCallback)

	m.mu.Lock()
	m.sessions[sessionID] = sess
	m.mu.Unlock()

	m.logger.Info("New session created.", zap.String("session_id", sessionID))
	return sess, nil
}

// NavigateAndExtract is a convenience method that creates a temporary session
// to navigate to a URL and extract all link hrefs from the page.
func (m *Manager) NavigateAndExtract(ctx context.Context, targetURL string) ([]string, error) {
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

	// Navigate to the provided URL.
	if err := sessionCtx.Navigate(ctx, targetURL); err != nil {
		return nil, fmt.Errorf("failed to navigate to %s: %w", targetURL, err)
	}

	// In the Pure Go implementation, JS execution (Goja) is sandboxed and lacks DOM access.
	// We must use the session's internal DOM parser (htmlquery) to extract links.

	// The sessionCtx must implement dom.CorePagePrimitives to access the DOM state.
	primitives, ok := sessionCtx.(dom.CorePagePrimitives)
	if !ok {
		return nil, fmt.Errorf("internal error: session context does not implement CorePagePrimitives")
	}

	// 1. Get the DOM snapshot.
	reader, err := primitives.GetDOMSnapshot(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get DOM snapshot: %w", err)
	}
	if closer, ok := reader.(io.Closer); ok {
		defer closer.Close()
	}

	// 2. Parse the HTML.
	doc, err := htmlquery.Parse(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	// 3. Extract links using XPath.
	var hrefs []string
	links := htmlquery.Find(doc, "//a[@href]")

	// Get the base URL for resolving relative links.
	currentURLStr := primitives.GetCurrentURL()
	baseURL, err := url.Parse(currentURLStr)
	if err != nil {
		m.logger.Warn("Failed to parse current URL for link resolution", zap.Error(err), zap.String("url", currentURLStr))
		// Continue extraction but links might remain relative if parsing fails.
	}

	for _, link := range links {
		href := htmlquery.SelectAttr(link, "href")
		// FIX: An empty href attribute should resolve to the current page's URL.
		// The original code incorrectly skipped these attributes. By removing the
		// conditional check, we allow the URL resolution logic below to handle it correctly.

		// Resolve relative URLs to absolute URLs.
		if baseURL != nil {
			parsedHref, err := url.Parse(href)
			if err == nil {
				absoluteURL := baseURL.ResolveReference(parsedHref)
				hrefs = append(hrefs, absoluteURL.String())
			} else {
				hrefs = append(hrefs, href) // Append original if parsing fails
			}
		} else {
			hrefs = append(hrefs, href)
		}
	}

	return hrefs, nil
}

// Shutdown gracefully closes all sessions.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager.")

	// If initialization never fully completed, exit early.
	if m.jsRuntime == nil {
		m.logger.Info("Manager not fully initialized, skipping full shutdown sequence.")
		return nil
	}

	// 1. Close all active sessions.
	m.mu.RLock()
	sessionsToClose := make([]*session.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessionsToClose = append(sessionsToClose, s)
	}
	m.mu.RUnlock()

	// Initiate close concurrently.
	for _, s := range sessionsToClose {
		go func(s *session.Session) {
			// Use the provided context for closing.
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

	// Use the provided context to time bound the wait.
	select {
	case <-done:
		m.logger.Info("All sessions closed gracefully.")
	case <-ctx.Done():
		m.logger.Warn("Timeout waiting for sessions to close. Proceeding with shutdown.", zap.Error(ctx.Err()))
	}

	// No external browser processes to stop.

	m.logger.Info("Browser manager shutdown complete.")
	return nil
}


