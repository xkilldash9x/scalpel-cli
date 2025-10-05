// Filename: browser/manager.go
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/session"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Manager handles the lifecycle of multiple browser sessions. It ensures that
// sessions are created correctly and shut down gracefully. It's safe for concurrent use.
type Manager struct {
	ctx    context.Context
	cancel context.CancelFunc
	logger *zap.Logger
	cfg    *config.Config // Manager-level default configuration.

	sessions    map[string]*session.Session
	sessionsMux sync.Mutex
	wg          sync.WaitGroup
}

// Ensure Manager implements the required interfaces from the schemas package.
var _ schemas.BrowserManager = (*Manager)(nil)
var _ schemas.BrowserInteractor = (*Manager)(nil)

// NewManager creates and initializes a new browser session manager.
// It now accepts a default config to be used by convenience methods.
func NewManager(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*Manager, error) {
	log := logger.Named("browser_manager_purego")
	log.Info("Browser manager created (Pure Go implementation).")

	// The manager's context is detached from the creation context on purpose,
	// so it can outlive the creation call. We do a one time check to ensure
	// the creation context hasn't already been cancelled.
	select {
	case <-ctx.Done():
		log.Warn("Initialization context cancelled before manager creation.", zap.Error(ctx.Err()))
		return nil, ctx.Err()
	default:
	}

	managerCtx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		ctx:      managerCtx,
		cancel:   cancel,
		logger:   log,
		cfg:      cfg,
		sessions: make(map[string]*session.Session),
	}

	log.Info("Browser manager initialized.")
	return m, nil
}

// NewAnalysisContext creates a new, isolated browser session (like a new tab).
func (m *Manager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
	findingsChan chan<- schemas.Finding,
) (schemas.SessionContext, error) {
	appConfig, ok := cfg.(*config.Config)
	if !ok {
		return nil, fmt.Errorf("invalid config type provided: expected *config.Config")
	}

	if taintTemplate != "" || taintConfig != "" {
		m.logger.Warn("Taint analysis (IAST) parameters are not supported in Pure Go browser mode.")
	}

	// This derived context ensures the session is canceled if either the specific
	// session context is canceled or the entire manager is shut down.
	derivedCtx, cancelSession := context.WithCancel(context.Background())

	go func() {
		select {
		case <-sessionCtx.Done(): // The context for this specific operation.
			cancelSession()
		case <-m.ctx.Done(): // The manager's global context.
			cancelSession()
		case <-derivedCtx.Done(): // The session's own context.
		}
	}()

	// FIX: The technical review on browser failures indicated a critical data race
	// could occur from concurrent, unsynchronized access to the underlying JS engine
	// during session creation. While the exact cause is likely in the session package,
	// we can guarantee safety by serializing the creation of new sessions. This lock
	// ensures that `session.NewSession` is never called concurrently, eliminating the race.
	m.sessionsMux.Lock()
	defer m.sessionsMux.Unlock()

	// Double check for manager shutdown after acquiring the lock.
	if m.ctx.Err() != nil {
		cancelSession()
		return nil, fmt.Errorf("manager is shutting down: %w", m.ctx.Err())
	}

	s, err := session.NewSession(derivedCtx, appConfig, persona, m.logger, findingsChan)
	if err != nil {
		cancelSession()
		return nil, fmt.Errorf("failed to create new pure-go session: %w", err)
	}

	m.wg.Add(1)
	sessionID := s.ID()

	onCloseCallback := func() {
		cancelSession()
		m.sessionsMux.Lock()
		delete(m.sessions, sessionID)
		m.sessionsMux.Unlock()
		m.wg.Done()
		m.logger.Debug("Session removed from manager", zap.String("session_id", sessionID))
	}
	s.SetOnClose(onCloseCallback)

	m.sessions[sessionID] = s

	m.logger.Info("New session created", zap.String("sessionID", sessionID))
	return s, nil
}

// Shutdown gracefully closes all active browser sessions.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager.")

	// Signal all managed sessions that shutdown has started.
	m.cancel()

	// Safely copy the list of sessions to close to avoid holding the lock
	// while closing them.
	m.sessionsMux.Lock()
	sessionsToClose := make([]*session.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessionsToClose = append(sessionsToClose, s)
	}
	m.sessionsMux.Unlock()

	m.logger.Debug("Closing sessions concurrently.", zap.Int("count", len(sessionsToClose)))
	for _, s := range sessionsToClose {
		// Launch as a goroutine so one slow session doesn't block others.
		go func(sess *session.Session) {
			if err := sess.Close(ctx); err != nil {
				// Only log errors if the context wasn't already canceled (e.g., by timeout).
				if ctx.Err() == nil {
					m.logger.Warn("Error during session close initiated by manager shutdown", zap.String("session_id", sess.ID()), zap.Error(err))
				}
			}
		}(s)
	}

	// Wait for all sessions to signal they are done via the waitgroup.
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
		return ctx.Err()
	}

	m.logger.Info("Browser manager shutdown complete.")
	return nil
}

// NavigateAndExtract creates a temporary session to navigate and extract all link hrefs.
// It manages the session's lifecycle internally, ensuring it's closed after the operation.
func (m *Manager) NavigateAndExtract(ctx context.Context, targetURL string) (resolvedLinks []string, err error) {
	m.logger.Info("NavigateAndExtract started.")
	start := time.Now()

	// This deferred logger provides excellent visibility into the operation's outcome.
	defer func() {
		if err != nil {
			m.logger.Error("NavigateAndExtract finished with an error",
				zap.Duration("totalDuration", time.Since(start)),
				zap.Error(err),
			)
		} else {
			m.logger.Info("NavigateAndExtract finished successfully",
				zap.Duration("totalDuration", time.Since(start)),
				zap.Int("resolved_link_count", len(resolvedLinks)),
			)
		}
	}()

	sessionCfg := m.cfg
	if sessionCfg == nil {
		// Fallback to a minimal config if the manager has none.
		sessionCfg = &config.Config{
			Network: config.NetworkConfig{
				PostLoadWait: 200 * time.Millisecond,
			},
		}
	}

	// Findings for this temporary session can be discarded.
	dummyFindingsChan := make(chan schemas.Finding, 32)
	defer close(dummyFindingsChan)

	// Pass the input 'ctx' as the sessionCtx for NewAnalysisContext.
	sessionCtx, err := m.NewAnalysisContext(ctx, sessionCfg, schemas.DefaultPersona, "", "", dummyFindingsChan)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary session: %w", err)
	}

	// Use a separate, background context for cleanup. This ensures the session
	// close logic runs even if the parent 'ctx' has timed out.
	defer func() {
		m.logger.Debug("Closing temporary session.", zap.String("session_id", sessionCtx.ID()))
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if closeErr := sessionCtx.Close(closeCtx); closeErr != nil {
			m.logger.Warn("Error closing temporary session", zap.Error(closeErr), zap.String("session_id", sessionCtx.ID()))
			// If the main operation succeeded, propagate the close error.
			if err == nil {
				err = closeErr
			}
		}
	}()

	// REFACTOR: Use the provided 'ctx' for the operations instead of calling GetContext().
	// This adheres to Go best practices and respects the operation's deadline/cancellation.
	opCtx := ctx
	m.logger.Debug("Starting link extraction.", zap.String("session_id", sessionCtx.ID()), zap.String("url", targetURL))

	navStart := time.Now()
	// Use opCtx for Navigate.
	if err = sessionCtx.Navigate(opCtx, targetURL); err != nil {
		m.logger.Error("Navigation failed during link extraction.", zap.Error(err), zap.Duration("duration", time.Since(navStart)), zap.String("session_id", sessionCtx.ID()))
		return nil, fmt.Errorf("failed to navigate to %s: %w", targetURL, err)
	}
	m.logger.Debug("Navigation succeeded.", zap.Duration("duration", time.Since(navStart)), zap.String("session_id", sessionCtx.ID()))

	stabStart := time.Now()
	// Use opCtx for WaitForAsync.
	if stabErr := sessionCtx.WaitForAsync(opCtx, 0); stabErr != nil {
		// Check if the context was cancelled before returning a generic stabilization error.
		if opCtx.Err() != nil {
			return nil, opCtx.Err()
		}
		return nil, fmt.Errorf("stabilization after navigation failed: %w", stabErr)
	}
	m.logger.Debug("Stabilization after navigation succeeded.", zap.Duration("duration", time.Since(stabStart)), zap.String("session_id", sessionCtx.ID()))

	scriptStart := time.Now()
	const script = `(function() {
        var links = [];
        var elements = document.querySelectorAll('a[href]');
        for (var i = 0; i < elements.length; i++) {
            var el = elements[i];
            if (el) {
                var href = el.getAttribute('href');
                if (href) {
                    links.push(href);
                }
            }
        }
        return links;
    })();`

	// Use opCtx for ExecuteScript.
	resultJSON, err := sessionCtx.ExecuteScript(opCtx, script, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute link extraction script: %w", err)
	}
	m.logger.Debug("Script execution finished.", zap.Duration("duration", time.Since(scriptStart)), zap.String("session_id", sessionCtx.ID()))

	// Use opCtx for WaitForAsync.
	if stabErr := sessionCtx.WaitForAsync(opCtx, 0); stabErr != nil {
		if opCtx.Err() != nil {
			return nil, opCtx.Err()
		}
		return nil, fmt.Errorf("stabilization after script execution failed: %w", stabErr)
	}
	m.logger.Debug("Stabilization after script execution succeeded.", zap.String("session_id", sessionCtx.ID()))

	decodeStart := time.Now()
	var rawLinks []string
	if err = json.Unmarshal(resultJSON, &rawLinks); err != nil {
		return nil, fmt.Errorf("failed to decode script result into string slice: %w", err)
	}
	m.logger.Debug("Successfully decoded script result.", zap.Duration("duration", time.Since(decodeStart)), zap.Int("raw_link_count", len(rawLinks)), zap.String("session_id", sessionCtx.ID()))

	baseURL, parseErr := url.Parse(targetURL)
	if parseErr != nil {
		m.logger.Warn("Failed to parse target URL for link resolution, returning raw links", zap.String("url", targetURL), zap.Error(parseErr))
		return rawLinks, nil
	}

	seen := make(map[string]bool)
	for _, href := range rawLinks {
		trimmedHref := strings.TrimSpace(href)
		// Filter out irrelevant or malformed hrefs.
		if trimmedHref == "" || strings.HasPrefix(trimmedHref, "#") || strings.HasPrefix(trimmedHref, "javascript:") || strings.HasPrefix(trimmedHref, "mailto:") {
			continue
		}

		u, resolveErr := baseURL.Parse(trimmedHref)
		if resolveErr != nil {
			m.logger.Debug("Skipping invalid href found on page", zap.String("href", href), zap.Error(resolveErr))
			continue
		}

		// Only consider http and https schemes.
		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}

		// Normalize the URL by removing the fragment.
		u.Fragment = ""
		resolvedStr := u.String()

		if !seen[resolvedStr] {
			resolvedLinks = append(resolvedLinks, resolvedStr)
			seen[resolvedStr] = true
		}
	}
	m.logger.Debug("Link extraction and resolution complete.", zap.Int("resolved_link_count", len(resolvedLinks)), zap.String("session_id", sessionCtx.ID()))
	return resolvedLinks, nil
}