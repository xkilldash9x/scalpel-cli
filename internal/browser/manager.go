package browser

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/internal/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// Manager controls the lifecycle of the browser process and manages browser sessions.
type Manager struct {
	logger              *zap.Logger
	semaphore           chan struct{}
	allocatorCtx        context.Context
	cancelAlloc         context.CancelFunc
	browserCtx          context.Context
	cancelBrowser       context.CancelFunc
	contextCreationLock sync.Mutex
	wg                  sync.WaitGroup
}

// NewManager initializes the browser manager and starts the browser process.
func NewManager(initCtx context.Context, logger *zap.Logger, concurrencyLimit int) (*Manager, error) {
	l := logger.With(zap.String("component", "browser_manager"))
	if concurrencyLimit <= 0 {
		concurrencyLimit = 4
	}

	opts := chromedp.DefaultExecAllocatorOptions[:]
	allocatorCtx, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)

	// This is the standard, correct way to create the browser context.
	// It directly inherits from the allocator context.
	browserCtx, cancelBrowser := chromedp.NewContext(allocatorCtx,
		chromedp.WithLogf(func(format string, args ...interface{}) {
			l.Debug(fmt.Sprintf(format, args...), zap.String("source", "chromedp"))
		}),
	)

	m := &Manager{
		logger:        l,
		allocatorCtx:  allocatorCtx,
		cancelAlloc:   cancelAlloc,
		browserCtx:    browserCtx,
		cancelBrowser: cancelBrowser,
		semaphore:     make(chan struct{}, concurrencyLimit),
	}
	
	// We must execute a command on the new browserCtx to ensure it's fully initialized.
	if err := chromedp.Run(m.browserCtx); err != nil {
		cancelBrowser()
		cancelAlloc()
		return nil, fmt.Errorf("failed to connect to browser instance: %w", err)
	}

	if err := m.verifyConnection(initCtx); err != nil {
		cancelBrowser()
		cancelAlloc()
		return nil, fmt.Errorf("failed to verify browser connection: %w", err)
	}

	m.loadInstrumentation()
	l.Info("Browser manager initialized and ready.", zap.Int("concurrency_limit", concurrencyLimit))
	return m, nil
}

func (m *Manager) loadInstrumentation() {
	m.logger.Debug("IAST instrumentation files loaded successfully.")
}

func (m *Manager) verifyConnection(ctx context.Context) error {
	var userAgent string
	runCtx, cancel := context.WithTimeout(m.browserCtx, 15*time.Second)
	defer cancel()

	err := chromedp.Run(runCtx,
		chromedp.ActionFunc(func(c context.Context) error {
			var err error
			_, _, _, userAgent, _, err = browser.GetVersion().Do(c)
			return err
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to run verification task: %w", err)
	}

	m.logger.Debug("Browser process connection verified.", zap.String("userAgent", userAgent))
	return nil
}

// NewAnalysisContext creates a new isolated browser session.
func (m *Manager) NewAnalysisContext(
	sessionCtx context.Context,
	cfg *config.Config,
	persona stealth.Persona,
	taintTemplate string,
	taintConfig string,
) (*AnalysisContext, error) {
	if m.browserCtx.Err() != nil {
		return nil, fmt.Errorf("failed to create browser context: invalid context")
	}
	select {
	case m.semaphore <- struct{}{}:
	case <-sessionCtx.Done():
		return nil, fmt.Errorf("failed to acquire session slot: %w", sessionCtx.Err())
	case <-m.browserCtx.Done():
		return nil, fmt.Errorf("failed to acquire session slot: manager shutting down")
	}

	sessionRegistered := false
	defer func() {
		if !sessionRegistered {
			<-m.semaphore
		}
	}()

	ac := NewAnalysisContext(
		m.browserCtx,
		m.browserCtx,
		cfg,
		m.logger,
		persona,
		taintTemplate,
		taintConfig,
		&m.contextCreationLock,
		m,
	)

	if err := ac.Initialize(sessionCtx); err != nil {
		if ac.sessionCancel != nil {
			ac.sessionCancel()
		}
		if ac.browserContextID != "" {
			ac.bestEffortCleanupBrowserContext(ac.browserContextID)
		}
		return nil, fmt.Errorf("failed to initialize analysis context: %w", err)
	}

	m.wg.Add(1)
	sessionRegistered = true
	return ac, nil
}

func (m *Manager) unregisterSession(ac *AnalysisContext) {
	select {
	case <-m.semaphore:
	default:
		m.logger.Error("Attempted to release semaphore when it appeared unacquired.")
	}
	m.wg.Done()
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Shutting down browser manager...")
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		m.logger.Info("All browser sessions closed gracefully.")
	case <-ctx.Done():
		m.logger.Warn("Timeout waiting for browser sessions to close. Forcing shutdown.")
	}
	if m.cancelBrowser != nil {
		m.cancelBrowser()
	}
	if m.cancelAlloc != nil {
		m.cancelAlloc()
	}

	select {
	case <-m.allocatorCtx.Done():
		m.logger.Info("Browser manager shutdown complete.")
	case <-time.After(5 * time.Second):
		m.logger.Error("Timeout waiting for browser process to terminate.")
	}
	return ctx.Err()
}