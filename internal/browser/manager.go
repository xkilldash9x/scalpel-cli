// internal/browser/manager.go
package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time" // Import time package for concurrent shutdown timeouts

	"github.com/chromedp/chromedp"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/browser/session"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// Constants for internal timeout management.
const (
	// REFACTOR: This is no longer used for init, as it conflicts with
	// subsequent operation contexts due to chromedp's context latching.
	// sessionInitTimeout = 30 * time.Second
	cleanupTimeout = 5 * time.Second
)

// Manager handles the browser process lifecycle and session creation.
type Manager struct {
	allocCtx context.Context
	// allocCancel context.CancelFunc // REFACTOR: Removed. Lifecycle is managed externally.
	logger   *zap.Logger
	cfg      config.Interface // Use the interface
	sessions map[string]*session.Session
	mu       sync.RWMutex
}

// NewManager creates a new browser manager using the provided allocator context.
// REFACTOR: Updated signature to accept allocCtx instead of creating it.
func NewManager(allocCtx context.Context, cfg config.Interface, logger *zap.Logger) (*Manager, error) {
	// REFACTOR: Removed ExecAllocator creation logic (lines 26-44 in original).

	// Ensure the provided allocator context is valid.
	if allocCtx == nil {
		return nil, fmt.Errorf("browser manager requires a valid allocator context (e.g., from chromedp.NewExecAllocator)")
	}
	// Idiomatic check for already cancelled context.
	if allocCtx.Err() != nil {
		return nil, fmt.Errorf("browser manager requires a non-cancelled allocator context")
	}

	m := &Manager{
		allocCtx: allocCtx,
		// allocCancel: Removed.
		logger:   logger.Named("browser_manager"),
		cfg:      cfg, // Store the interface
		sessions: make(map[string]*session.Session),
	}

	m.logger.Info("Browser manager initialized.")
	return m, nil
}

// NewAnalysisContext creates a new browser tab (session) for analysis.
// FIX: Added findingsChan chan<- schemas.Finding to match schemas.BrowserManager interface.
func (m *Manager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg interface{},
	persona schemas.Persona,
	taintTemplate string,
	taintConfig string,
	findingsChan chan<- schemas.Finding, // Added parameter
) (schemas.SessionContext, error) {
	// FIX: Renamed variable from 'config' to 'appConfig' to avoid shadowing package name.
	var appConfig config.Interface
	var ok bool

	appConfig, ok = cfg.(config.Interface) // Use config.Interface
	if !ok {
		// Fallback check for concrete type if interface assertion fails (e.g., from NavigateAndExtract)
		if concreteCfg, ok := cfg.(*config.Config); ok {
			appConfig = concreteCfg // Use the concrete type as it satisfies the interface
		} else {
			return nil, fmt.Errorf("invalid config type passed to NewAnalysisContext: expected config.Interface or *config.Config")
		}
	}

	// 1. Create the browser context (tab).

	// REFACTOR (Doc Ref 4.2): Enable verbose CDP logging if the debug flag is set.
	// This is "invaluable" for diagnosing complex issues by logging all raw CDP messages.
	var browserOpts []chromedp.ContextOption
	if appConfig.Browser().Debug {
		// Adapt the zap logger to the format required by chromedp.WithDebugf.
		debugLogger := m.logger.Named("cdp_verbose").Sugar().Debugf
		browserOpts = append(browserOpts, chromedp.WithDebugf(debugLogger))
	}

	browserCtx, cancelBrowser := chromedp.NewContext(m.allocCtx, browserOpts...)

	// 2. Combine contexts. browserCtx must be primary (parent) to inherit CDP values.
	// We use the standardized session.CombineContext.
	combinedCtx, combinedCancel := session.CombineContext(browserCtx, sessionCtx)

	// 3. Prepare initialization context.
	// REFACTOR: Removed intermediate initCtx.
	// Due to a quirk in chromedp, the context used for the *first*
	// chromedp.Run (in s.Initialize) "latches" its deadline,
	// overriding deadlines of subsequent chromedp.Run calls (in s.Navigate).
	// By using combinedCtx (the session's master context) for
	// Initialize, we ensure the "latched" context is the long-lived
	// session context. Operations like Navigate will properly
	// derive from this and respect their own timeouts.
	//
	// We lose the granular sessionInitTimeout, but Initialize will
	// still be bound by the overall sessionCtx lifetime.
	//
	// initCtx, initCancel := context.WithTimeout(combinedCtx, sessionInitTimeout) // REMOVED
	// defer initCancel() // REMOVED

	// 4. Create the master cancel function for the session that ensures cleanup of ALL resources.
	masterCancel := func() {
		// initCancel() // REMOVED
		combinedCancel()
		cancelBrowser() // Ensure the browser tab is closed.
	}

	// 5. Create the session instance.
	// Passing nil for onClose initially, will set it later.
	// Use 's' instead of 'session' to avoid shadowing package name.
	// FIX: Pass findingsChan to NewSession.
	s, err := session.NewSession(combinedCtx, masterCancel, appConfig, persona, m.logger, nil, findingsChan)
	if err != nil {
		masterCancel() // Clean up resources on failure
		return nil, fmt.Errorf("failed to create new session: %w", err)
	}

	// 6. Setup onClose callback for manager bookkeeping using the setter.
	s.SetOnClose(func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.sessions, s.ID())
		m.logger.Debug("Session removed from manager.", zap.String("session_id", s.ID()))
	})

	// 7. Initialize the session using the session's master context.
	// Initialization respects the combined context.
	// REFACTOR: Pass combinedCtx instead of initCtx.
	if err := s.Initialize(combinedCtx, taintTemplate, taintConfig); err != nil {
		// If init fails, use a fresh, timed context for cleanup.
		// s.Close() will call masterCancel().
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cleanupCancel()
		s.Close(cleanupCtx) // Close will call masterCancel and onClose.
		return nil, fmt.Errorf("failed to initialize session: %w", err)
	}

	m.mu.Lock()
	m.sessions[s.ID()] = s
	m.mu.Unlock()

	m.logger.Info("New session created.", zap.String("session_id", s.ID()))
	return s, nil
}

// NavigateAndExtract is a convenience method that creates a temporary session
// to navigate to a URL and extract all link hrefs from the page.
// This function is synchronous and blocking.
func (m *Manager) NavigateAndExtract(ctx context.Context, url string) ([]string, error) {
	// REFACTOR: Decouple the session lifetime from the input operation context 'ctx'.
	// We pass context.Background() so the session remains alive until explicitly closed.
	// Operations (Navigate, ExecuteScript) will still respect 'ctx'.
	session, err := m.NewAnalysisContext(context.Background(), m.cfg, schemas.DefaultPersona, "", "", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create session for navigation: %w", err)
	}

	// Ensure the session is closed robustly when the function returns.
	defer func() {
		// Use a fresh, timed context for closing, as the input 'ctx' might be cancelled if we are returning an error.
		closeCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		session.Close(closeCtx)
	}()

	// Operations must respect the input 'ctx'.
	if err := session.Navigate(ctx, url); err != nil {
		return nil, fmt.Errorf("failed to navigate to URL: %w", err)
	}

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

	// ExecuteScript signature is (ctx, script, args) -> (json.RawMessage, error).
	rawResult, err := session.ExecuteScript(ctx, script, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to execute script for link extraction: %w", err)
	}

	// Unmarshal the result.
	var hrefs []string
	if err := json.Unmarshal(rawResult, &hrefs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal extracted links: %w", err)
	}

	return hrefs, nil
}

// Shutdown gracefully closes all sessions. It does NOT close the browser process if the allocator is shared.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager.")

	m.mu.RLock()
	sessionsToClose := make([]*session.Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessionsToClose = append(sessionsToClose, s)
	}
	m.mu.RUnlock()

	// REFACTOR: Use a WaitGroup to close sessions concurrently for faster shutdown.
	var wg sync.WaitGroup
	for _, s := range sessionsToClose {
		wg.Add(1)
		go func(sess *session.Session) {
			defer wg.Done()
			// REFACTOR: Use the provided context 'ctx' directly. This ensures the overall
			// shutdown respects the caller's deadline without introducing intermediate timeouts.
			if err := sess.Close(ctx); err != nil {
				// Log errors during session close, but don't fail the overall shutdown.
				m.logger.Warn("Error closing session during manager shutdown.",
					zap.String("session_id", sess.ID()),
					zap.Error(err))
			}
		}(s)
	}
	wg.Wait()

	// m.allocCancel() // REFACTOR: Do not cancel the shared allocator context.
	return nil
}

// DefaultAllocatorOptions translates the BrowserConfig into chromedp.ExecAllocatorOption
// This function was added to fix an 'undefined' error in internal/mcp/server.go.
func DefaultAllocatorOptions(cfg config.BrowserConfig) []chromedp.ExecAllocatorOption {
	// Start by making a copy of chromedp's default allocator options
	// vvv REPLACE THIS LINE vvv
	// opts := append([]chromedp.ExecAllocatorOption(nil), chromedp.DefaultExecAllocatorOptions...)
	// vvv WITH THIS LINE vvv
	opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)

	// Apply config settings
	if !cfg.Headless {
		// The default is headless, so we add flags to disable it.
		opts = append(opts,
			chromedp.Flag("headless", false),
		)
	}

	if cfg.DisableCache {
		opts = append(opts,
			chromedp.Flag("disk-cache-size", "0"),
			chromedp.Flag("media-cache-size", "0"),
			chromedp.Flag("disable-cache", true),
		)
	}

	if cfg.IgnoreTLSErrors {
		opts = append(opts,
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.Flag("allow-insecure-localhost", true),
		)
	}

	// Add custom args from config
	for _, arg := range cfg.Args {
		// This assumes args are flags without values, like "disable-gpu"
		opts = append(opts, chromedp.Flag(arg, true))
	}

	// Viewport
	if w, ok := cfg.Viewport["width"]; ok {
		if h, ok := cfg.Viewport["height"]; ok {
			opts = append(opts, chromedp.WindowSize(w, h))
		}
	}

	// Ensure common flags are present (some are in default, but safe)
	opts = append(opts,
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-setuid-sandbox", true),
	)

	return opts
}
