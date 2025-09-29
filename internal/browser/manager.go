// internal/browser/manager.go
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/antchfx/htmlquery"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/dom"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/session"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Manager handles the browser session lifecycle using the Pure Go implementation.
type Manager struct {
	logger *zap.Logger
	cfg    *config.Config

	sessions map[string]*session.Session
	mu       sync.RWMutex
	wg       sync.WaitGroup // WaitGroup to ensure all sessions are closed before shutting down.

	initOnce sync.Once
	initErr  error
}

// NewManager creates a new browser manager.
func NewManager(ctx context.Context, cfg *config.Config, logger *zap.Logger) (*Manager, error) {
	m := &Manager{
		logger:   logger.Named("browser_manager_purego"),
		cfg:      cfg,
		sessions: make(map[string]*session.Session),
	}
	m.logger.Info("Browser manager created (Pure Go implementation).")
	return m, nil
}

// initialize prepares the engine components.
func (m *Manager) initialize(ctx context.Context) error {
	m.initOnce.Do(func() {
		m.logger.Info("Browser manager initialized.")
	})
	return m.initErr
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

	if err := m.initialize(sessionCtx); err != nil {
		return nil, err
	}

	config, ok := cfg.(*config.Config)
	if !ok {
		return nil, fmt.Errorf("invalid config type passed to NewAnalysisContext")
	}

	if taintTemplate != "" || taintConfig != "" {
		m.logger.Warn("Taint analysis (IAST) parameters are not supported in Pure Go browser mode.")
	}

	sess, err := session.NewSession(sessionCtx, config, persona, m.logger, findingsChan)
	if err != nil {
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	m.wg.Add(1)

	sessionID := sess.ID()
	onCloseCallback := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.sessions, sessionID)
		m.wg.Done()
		m.logger.Debug("Session removed from manager.", zap.String("session_id", sessionID))
	}

	sess.SetOnClose(onCloseCallback)

	m.mu.Lock()
	m.sessions[sessionID] = sess
	m.mu.Unlock()

	m.logger.Info("New session created.", zap.String("session_id", sessionID))
	return sess, nil
}

// NavigateAndExtract creates a temporary session to navigate and extract all link hrefs.
func (m *Manager) NavigateAndExtract(ctx context.Context, targetURL string) ([]string, error) {
	findingsChan := make(chan schemas.Finding, 1)
	defer close(findingsChan)

	sessionCtx, err := m.NewAnalysisContext(ctx, m.cfg, schemas.DefaultPersona, "", "", findingsChan)
	if err != nil {
		return nil, fmt.Errorf("failed to create session for navigation: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sessionCtx.Close(cleanupCtx)
	}()

	if err := sessionCtx.Navigate(ctx, targetURL); err != nil {
		return nil, fmt.Errorf("failed to navigate to %s: %w", targetURL, err)
	}

	// This JavaScript snippet finds all anchor tags, fully resolves their href attributes
	// relative to the document's location, and returns them as an array of strings.
	const script = `Array.from(document.querySelectorAll('a[href]')).map(a => a.href);`

	resultJSON, err := sessionCtx.ExecuteScript(ctx, script, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute link extraction script: %w", err)
	}

	var hrefs []string
	if err := json.Unmarshal(resultJSON, &hrefs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal links from script result: %w", err)
	}

	return hrefs, nil
}

// Shutdown gracefully closes all sessions.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager.")

	m.mu.RLock()
	sessionsToClose := make([]*session.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessionsToClose = append(sessionsToClose, s)
	}
	m.mu.RUnlock()

	for _, s := range sessionsToClose {
		go func(s *session.Session) {
			if err := s.Close(ctx); err != nil {
				m.logger.Warn("Error during session close in shutdown.", zap.String("session_id", s.ID()), zap.Error(err))
			}
		}(s)
	}

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("All sessions closed gracefully.")
	case <-ctx.Done():
		m.logger.Warn("Timeout waiting for sessions to close.", zap.Error(ctx.Err()))
	}

	m.logger.Info("Browser manager shutdown complete.")
	return nil
}
