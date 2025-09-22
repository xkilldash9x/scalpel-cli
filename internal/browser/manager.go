// internal/browser/manager.go
package browser

import (
	"context"
	"fmt"
	"sync"

	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Manager handles the browser process lifecycle and session creation.
type Manager struct {
	allocCtx    context.Context
	allocCancel context.CancelFunc
	logger      *zap.Logger
	cfg         *config.Config

	sessions map[string]*Session
	mu       sync.RWMutex
}

// NewManager creates a new browser manager and starts the underlying browser process pool.
func NewManager(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*Manager, error) {
	opts := []chromedp.ExecAllocatorOption{
		chromedp.NoSandbox,
		chromedp.DisableGPU,
		chromedp.Flag("enable-automation", true),
	}

	for _, arg := range cfg.Browser.Args {
		opts = append(opts, chromedp.Flag(arg, true))
	}

	if cfg.Browser.Headless {
		opts = append(opts, chromedp.Headless)
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)

	m := &Manager{
		allocCtx:    allocCtx,
		allocCancel: cancel,
		logger:      logger.Named("browser_manager"),
		cfg:         cfg,
		sessions:    make(map[string]*Session),
	}

	m.logger.Info("Browser manager initialized.")
	return m, nil
}

// NewAnalysisContext creates a new browser tab (session) for analysis.
func (m *Manager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
	findingsChan chan<- schemas.Finding,
) (schemas.SessionContext, error) {
	config, ok := cfg.(*config.Config)
	if !ok {
		return nil, fmt.Errorf("invalid config type passed to NewAnalysisContext")
	}

	browserCtx, browserCancel := chromedp.NewContext(m.allocCtx)
	combinedCtx, combinedCancel := CombineContext(browserCtx, sessionCtx)

	onClose := func() {
		browserCancel()
	}

	session, err := NewSession(combinedCtx, combinedCancel, config, persona, m.logger, onClose, findingsChan)
	if err != nil {
		combinedCancel()
		browserCancel()
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	session.onClose = func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.sessions, session.ID())
		browserCancel()
		m.logger.Debug("Session removed from manager.", zap.String("session_id", session.ID()))
	}

	if err := session.Initialize(combinedCtx, taintTemplate, taintConfig); err != nil {
		session.Close(context.Background())
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

	sessionCtx, err := m.NewAnalysisContext(ctx, m.cfg, schemas.DefaultPersona, "", "", findingsChan)
	if err != nil {
		return nil, fmt.Errorf("failed to create session for navigation: %w", err)
	}
	defer sessionCtx.Close(context.Background())

	if err := sessionCtx.Navigate(ctx, url); err != nil {
		return nil, fmt.Errorf("failed to navigate to %s: %w", url, err)
	}

	var hrefs []string
	script := `
		(() => {
			const links = [];
			document.querySelectorAll('a').forEach(a => {
				if (a.href) {
					links.push(a.href);
				}
			});
			return links;
		})()
	`
	if err := sessionCtx.ExecuteScript(ctx, script, &hrefs); err != nil {
		return nil, fmt.Errorf("failed to extract links: %w", err)
	}

	return hrefs, nil
}

// Shutdown gracefully closes all sessions and the browser process.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager.")

	m.mu.RLock()
	sessionsToClose := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessionsToClose = append(sessionsToClose, s)
	}
	m.mu.RUnlock()

	for _, s := range sessionsToClose {
		s.Close(ctx)
	}

	m.allocCancel()
	return nil
}

