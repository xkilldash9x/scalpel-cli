// pkg/browser/manager.go
package browser

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/pkg/browser/cdp"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser/shim"
	"github.com/xkilldash9x/scalpel-cli/pkg/browser/stealth"
	"github.com/xkilldash9x/scalpel-cli/pkg/config"
)

// Manager handles the lifecycle of the headless browser process, ensuring efficient resource utilization and stealth.
type Manager struct {
	logger       *zap.Logger
	globalConfig *config.Config

	// allocatorCtx manages the entire browser process. All session contexts are derived from this.
	allocatorCtx    context.Context
	allocatorCancel context.CancelFunc

	// Caches for instrumentation.
	runtimeTemplateCache  string
	staticTaintConfigJSON string

	// The browser persona to apply for stealth.
	persona stealth.Persona

	// wg tracks active analysis sessions for a graceful shutdown.
	wg sync.WaitGroup
}

// generateSecureSeed creates a high-entropy seed for the PRNG in the JS evasions script.
func generateSecureSeed() int64 {
	var b [8]byte
	// Use crypto/rand for a high-entropy seed.
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to time-based seed if crypto/rand fails (less secure). This should be rare.
		return time.Now().UnixNano()
	}
	// Convert the random bytes to an int64.
	return int64(binary.LittleEndian.Uint64(b[:]))
}

// NewManager initializes the browser manager, launches the browser process, and prepares instrumentation.
func NewManager(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*Manager, error) {
	m := &Manager{
		logger:       logger.Named("browser_manager"),
		globalConfig: cfg,
		// Define the default persona with a secure random seed.
		persona: stealth.Persona{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			Platform:  "Win32",
			Languages: []string{"en-US", "en"},
			Screen:    stealth.ScreenProperties{Width: 1920, Height: 1080},
			NoiseSeed: generateSecureSeed(),
		},
	}

	// Load the instrumentation configuration.
	m.loadInstrumentationConfig()

	// Launch the browser process.
	if err := m.launchBrowser(ctx); err != nil {
		return nil, fmt.Errorf("failed to launch browser: %w", err)
	}

	return m, nil
}

// loadInstrumentationConfig prepares the taint shim template and configuration.
func (m *Manager) loadInstrumentationConfig() {
	m.logger.Info("Loading Pinnacle Unified Runtime (Taint Shim) configuration.")

	script, err := shim.GetTaintShimTemplate()
	if err != nil {
		m.logger.Error("CRITICAL: Failed to load Pinnacle Runtime Template. IAST will be disabled.", zap.Error(err))
		m.runtimeTemplateCache = ""
	} else {
		m.runtimeTemplateCache = script
	}

	m.staticTaintConfigJSON = `[
        {"Name": "document.write", "Setter": false, "Type": "DOMXSS"},
        {"Name": "Element.prototype.innerHTML", "Setter": true, "Type": "DOMXSS"},
        {"Name": "Element.prototype.outerHTML", "Setter": true, "Type": "DOMXSS"},
        {"Name": "window.eval", "Setter": false, "Type": "CodeExecution"},
        {"Name": "Function", "Setter": false, "Type": "CodeExecution"},
        {"Name": "window.location.href", "Setter": true, "Type": "OpenRedirect"},
        {"Name": "window.location.assign", "Setter": false, "Type": "OpenRedirect"},
        {"Name": "window.alert", "Setter": false, "Type": "DebugSink"}
    ]`
}

// launchBrowser prepares allocator options and starts the headless browser process.
func (m *Manager) launchBrowser(ctx context.Context) error {
	m.logger.Info("Initializing browser allocator...")

	opts := m.buildAllocatorOptions()

	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	m.allocatorCtx = allocCtx
	m.allocatorCancel = cancel

	testCtx, cancelTest := context.WithTimeout(allocCtx, 30*time.Second)
	defer cancelTest()
	if err := chromedp.Run(testCtx, chromedp.Navigate("about:blank")); err != nil {
		m.allocatorCancel()
		return fmt.Errorf("browser failed to start or respond: %w", err)
	}

	m.logger.Info("Browser launched successfully and is responsive.")
	return nil
}

// buildAllocatorOptions assembles the necessary flags for a stealthy, configurable browser instance.
func (m *Manager) buildAllocatorOptions() []chromedp.ExecAllocatorOption {
	defaultOpts := chromedp.DefaultExecAllocatorOptions[:]
	var opts []chromedp.ExecAllocatorOption

	for _, opt := range defaultOpts {
		if flag, ok := opt.(chromedp.Flag); ok && flag.Name == "enable-automation" {
			continue
		}
		opts = append(opts, opt)
	}

	opts = append(opts,
		chromedp.Flag("headless", m.globalConfig.Browser.Headless),
		chromedp.Flag("ignore-certificate-errors", m.globalConfig.Browser.IgnoreTLSErrors),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-gpu", m.globalConfig.Browser.Headless),
		chromedp.UserAgent(m.persona.UserAgent),
	)

	for _, arg := range m.globalConfig.Browser.Args {
		parts := strings.SplitN(arg, "=", 2)
		flagName := strings.TrimPrefix(parts[0], "--")

		if len(parts) == 2 {
			opts = append(opts, chromedp.Flag(flagName, parts[1]))
		} else {
			opts = append(opts, chromedp.Flag(flagName, true))
		}
	}

	if runtime.GOOS == "linux" {
		opts = append(opts,
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-setuid-sandbox", true),
		)
	}

	return opts
}

// InitializeSession creates a new, fully isolated, and instrumented browser context (tab).
func (m *Manager) InitializeSession(taskCtx context.Context) (SessionContext, error) {
	ac := cdp.NewAnalysisContext(
		m.allocatorCtx,
		m.globalConfig,
		m.logger,
		m.persona,
		m.runtimeTemplateCache,
		m.staticTaintConfigJSON,
	)

	if err := ac.Initialize(taskCtx); err != nil {
		return nil, fmt.Errorf("failed to initialize analysis session: %w", err)
	}

	m.wg.Add(1)

	return &sessionWrapper{SessionContext: ac, wg: &m.wg}, nil
}

// Shutdown waits for all active sessions to complete and then terminates the browser process.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Browser manager shutdown initiated. Waiting for active sessions to complete...")

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		m.logger.Info("All sessions have completed.")
	case <-ctx.Done():
		m.logger.Warn("Shutdown deadline exceeded. Forcing browser termination.", zap.Error(ctx.Err()))
	}

	if m.allocatorCancel != nil {
		m.logger.Info("Shutting down main browser process...")
		m.allocatorCancel()
		<-m.allocatorCtx.Done()
	}
	return nil
}

// -- sessionWrapper --
type sessionWrapper struct {
	SessionContext
	wg     *sync.WaitGroup
	closed bool
	mu     sync.Mutex
}

// Close gracefully closes the underlying session and signals its completion to the manager.
func (sw *sessionWrapper) Close(ctx context.Context) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.closed {
		return nil
	}

	err := sw.SessionContext.Close(ctx)

	sw.closed = true
	sw.wg.Done()
	return err
}