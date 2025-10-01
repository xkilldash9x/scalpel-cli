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

	// FIX (1): Decouple lifecycle context from initialization context.
	// The Manager's lifecycle should not be tied to the initialization timeout (ctx).
	// We create a new long-lived context derived from context.Background().
	managerCtx, cancel := context.WithCancel(context.Background())

	// We still respect the input context if it's already cancelled during initialization.
	select {
	case <-ctx.Done():
		cancel() // Cleanup the newly created context.
		log.Warn("Initialization context cancelled before manager creation.", zap.Error(ctx.Err()))
		return nil, ctx.Err()
	default:
		// Proceed if the context is fine.
	}

	m := &Manager{
		ctx:      managerCtx,
		cancel:   cancel,
		logger:   log,
		cfg:      cfg, // Store the default config.
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

	// FIX (2): Context Propagation.
	// We must ensure the session terminates if the specific request times out (sessionCtx),
	// OR if the entire manager shuts down (m.ctx).

	// Create a derived context that we control the cancellation of.
	derivedCtx, cancelSession := context.WithCancel(context.Background())

	// Monitor the parent contexts. If either is done, cancel the session's derived context.
	go func() {
		select {
		case <-sessionCtx.Done():
			// The caller's context (e.g., request timeout, test timeout) is done.
			cancelSession()
		case <-m.ctx.Done():
			// The manager is shutting down.
			cancelSession()
		case <-derivedCtx.Done():
			// The session was closed explicitly via Close() calling onCloseCallback.
		}
	}()

	// The session is created using this derived context.
	s, err := session.NewSession(derivedCtx, appConfig, persona, m.logger, findingsChan)
	if err != nil {
		cancelSession() // Clean up the context immediately if session creation fails.
		return nil, fmt.Errorf("failed to create new pure-go session: %w", err)
	}

	m.wg.Add(1)
	sessionID := s.ID()

	// This is your cleaner callback logic for session cleanup.
	onCloseCallback := func() {
		// Ensure the session context is cancelled when the session is closed.
		cancelSession()

		m.sessionsMux.Lock()
		delete(m.sessions, sessionID)
		m.sessionsMux.Unlock()
		m.wg.Done()
		m.logger.Debug("Session removed from manager", zap.String("session_id", sessionID))
	}
	s.SetOnClose(onCloseCallback)

	m.sessionsMux.Lock()
	m.sessions[sessionID] = s
	m.sessionsMux.Unlock()

	m.logger.Info("New session created", zap.String("sessionID", sessionID))
	return s, nil
}

// Shutdown gracefully closes all active browser sessions.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager.")

	// 1. Signal intent to shut down by canceling the manager's context.
	// This now propagates to all session contexts due to Fix (2).
	m.cancel()

	// 2. Explicitly initiate closure for all active sessions.
	// We must take a snapshot of the sessions while holding the lock,
	// because the m.sessions map will be modified concurrently by the onClose callbacks.
	m.sessionsMux.Lock()
	sessionsToClose := make([]*session.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessionsToClose = append(sessionsToClose, s)
	}
	m.sessionsMux.Unlock()

	// Initiate the close concurrently.
	for _, s := range sessionsToClose {
		go func(sess *session.Session) {
			// Use the provided context (ctx) for the deadline of the Close operation.
			// session.Close handles stopping the event loop and calling onClose (which calls m.wg.Done()).
			if err := sess.Close(ctx); err != nil {
				// Log potential errors (like timeout waiting for the event loop), but do not stop the overall shutdown.
				// Only log if the error was not simply the shutdown context expiring.
				if ctx.Err() == nil {
					m.logger.Warn("Error during session close initiated by manager shutdown", zap.String("session_id", sess.ID()), zap.Error(err))
				}
			}
		}(s)
	}

	// 3. Wait for all sessions to report closure via m.wg.
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
// ...
// NOTE: This method now uses the default configuration provided when the manager was created.
func (m *Manager) NavigateAndExtract(ctx context.Context, targetURL string) (resolvedLinks []string, err error) {
	m.logger.Info("NavigateAndExtract started.")
	start := time.Now()

	// Use a defer for logging. It will execute when the function returns and log the final status.
	defer func() {
		// 'err' is a named return value, so its final value is available here.
		if err != nil {
			m.logger.Error("NavigateAndExtract finished with an error",
				zap.Duration("totalDuration", time.Since(start)),
				zap.Error(err),
			)
		} else {
			m.logger.Info("NavigateAndExtract finished successfully",
				zap.Duration("totalDuration", time.Since(start)),
			)
		}
	}()

	// Use the manager's default config. If it's nil, create a minimal
	// default to prevent a panic.
	sessionCfg := m.cfg
	if sessionCfg == nil {
		sessionCfg = &config.Config{
			Network: config.NetworkConfig{
				PostLoadWait: 200 * time.Millisecond,
			},
		}
	}

	dummyFindingsChan := make(chan schemas.Finding, 32)

	// Create a temporary session for this operation.
	var sessionCtx schemas.SessionContext
	sessionCtx, err = m.NewAnalysisContext(ctx, sessionCfg, schemas.DefaultPersona, "", "", dummyFindingsChan)
	if err != nil {
		close(dummyFindingsChan) // Close immediately if creation fails.
		err = fmt.Errorf("failed to create temporary session: %w", err)
		return nil, err
	}
	// This defer ensures the session is closed when this function exits,
	// but after all other operations are complete.
	defer func() {
		// Use a background context for cleanup to ensure it can complete even if the parent 'ctx' timed out.
		// Give it a reasonable timeout.
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = sessionCtx.Close(closeCtx)
		// FIX (5): Close the channel only after the session (producer) has stopped.
		close(dummyFindingsChan)
	}()

	m.logger.Info("NavigateAndExtract: Session created", zap.Duration("duration", time.Since(start)))

	// -- Begin Session Operations --
    // ... (Rest of the function remains the same as the original input) ...

	navStart := time.Now()
	if err = sessionCtx.Navigate(ctx, targetURL); err != nil {
		m.logger.Error("NavigateAndExtract: Navigation failed", zap.Error(err), zap.Duration("duration", time.Since(navStart)))
		err = fmt.Errorf("failed to navigate to %s: %w", targetURL, err)
		return nil, err // Return will trigger deferred cleanup and logging.
	}
	m.logger.Info("NavigateAndExtract: Navigation succeeded", zap.Duration("duration", time.Since(navStart)))

	// Wait for the page to stabilize (network idle, JS event loop empty).
	stabStart := time.Now()
	if stabErr := sessionCtx.WaitForAsync(ctx, 0); stabErr != nil {
		// If the context was canceled, that's the root cause.
		if ctx.Err() != nil {
			err = ctx.Err()
		} else {
			err = fmt.Errorf("stabilization after navigation failed: %w", stabErr)
		}
		m.logger.Error("NavigateAndExtract: Stabilization failed", zap.Error(err), zap.Duration("duration", time.Since(stabStart)))
		return nil, err
	}
	m.logger.Info("NavigateAndExtract: Stabilization succeeded", zap.Duration("duration", time.Since(stabStart)))

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

	var resultJSON []byte
	resultJSON, err = sessionCtx.ExecuteScript(ctx, script, nil)
	m.logger.Info("NavigateAndExtract: Script execution finished", zap.Duration("duration", time.Since(scriptStart)))

	if err != nil {
		err = fmt.Errorf("failed to execute link extraction script: %w", err)
		return nil, err // Return will trigger deferred cleanup and logging.
	}

	decodeStart := time.Now()
	var rawLinks []string
	if err = json.Unmarshal(resultJSON, &rawLinks); err != nil {
		err = fmt.Errorf("failed to decode script result into string slice: %w", err)
		return nil, err // Return will trigger deferred cleanup and logging.
	}
	m.logger.Info("NavigateAndExtract: JSON decoded", zap.Duration("duration", time.Since(decodeStart)))

	baseURL, parseErr := url.Parse(targetURL)
	if parseErr != nil {
		m.logger.Warn("Failed to parse target URL for link resolution, returning raw links", zap.String("url", targetURL), zap.Error(parseErr))
		return rawLinks, nil // Best effort: return the unresolved links.
	}

	// Process and resolve the links.
	seen := make(map[string]bool)
	for _, href := range rawLinks {
		trimmedHref := strings.TrimSpace(href)
		if trimmedHref == "" || strings.HasPrefix(trimmedHref, "#") || strings.HasPrefix(trimmedHref, "javascript:") || strings.HasPrefix(trimmedHref, "mailto:") {
			continue
		}

		u, resolveErr := baseURL.Parse(trimmedHref)
		if resolveErr != nil {
			m.logger.Debug("Skipping invalid href found on page", zap.String("href", href), zap.Error(resolveErr))
			continue
		}

		if u.Scheme != "http" && u.Scheme != "https" {
			continue
		}

		u.Fragment = ""
		resolvedStr := u.String()

		if !seen[resolvedStr] {
			resolvedLinks = append(resolvedLinks, resolvedStr)
			seen[resolvedStr] = true
		}
	}

	// On success, 'err' remains nil. The function returns, triggering deferred cleanup and logging.
	return resolvedLinks, nil
}