// pkg/browser/manager.go
package browser

import (
	"context"
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

// NewManager initializes the browser manager, launches the browser process, and prepares instrumentation.
func NewManager(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*Manager, error) {
	m := &Manager{
		logger:       logger.Named("browser_manager"),
		globalConfig: cfg,
		// Define the default persona. This should eventually be configurable.
		persona: stealth.Persona{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			Platform:  "Win32",
			Languages: []string{"en-US", "en"},
			Screen:    stealth.ScreenProperties{Width: 1920, Height: 1080, DevicePixelRatio: 1.0},
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

	// Load the template from the embedded file system.
	script, err := shim.GetTaintShimTemplate()
	if err != nil {
		m.logger.Error("CRITICAL: Failed to load Pinnacle Runtime Template. IAST will be disabled.", zap.Error(err))
		m.runtimeTemplateCache = ""
	} else {
		m.runtimeTemplateCache = script
	}

	// Define the sink configuration. In a production system, this should be loaded from a dynamic rule source.
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

	// Create the allocator context.
	allocCtx, cancel := chromedp.NewExecAllocator(ctx, opts...)
	m.allocatorCtx = allocCtx
	m.allocatorCancel = cancel

	// Create a temporary context with a timeout to verify the browser starts and is responsive.
	testCtx, cancelTest := context.WithTimeout(allocCtx, 30*time.Second)
	testCtx, cancelTestCtx := chromedp.NewContext(testCtx)
	defer cancelTestCtx()
	defer cancelTest()

	// Run a simple task to confirm the browser is alive.
	if err := chromedp.Run(testCtx, chromedp.Navigate("about:blank")); err != nil {
		m.allocatorCancel() // Ensure cleanup if the test fails
		return fmt.Errorf("browser failed to start or respond: %w", err)
	}

	m.logger.Info("Browser launched successfully and is responsive.")
	return nil
}

// buildAllocatorOptions assembles the necessary flags for a stealthy, configurable browser instance.
func (m *Manager) buildAllocatorOptions() []chromedp.ExecAllocatorOption {
	// Start with default options, filtering out flags that reveal automation.
	defaultOpts := chromedp.DefaultExecAllocatorOptions[:]
	var opts []chromedp.ExecAllocatorOption

	// Filter out the "enable-automation" flag.
	for _, opt := range defaultOpts {
		if flag, ok := opt.(chromedp.Flag); ok && flag.Name == "enable-automation" {
			continue
		}
		opts = append(opts, opt)
	}

	// Apply essential stealth and configuration flags.
	opts = append(opts,
		chromedp.Flag("headless", m.globalConfig.Browser.Headless),
		chromedp.Flag("ignore-certificate-errors", m.globalConfig.Browser.IgnoreTLSErrors),
		// Crucial stealth flag: Disable the Blink feature used to detect automation (navigator.webdriver).
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-gpu", m.globalConfig.Browser.Headless),
		chromedp.UserAgent(m.persona.UserAgent), // Apply UserAgent at launch.
	)

	// Add custom arguments from config.yaml.
	for _, arg := range m.globalConfig.Browser.Args {
		parts := strings.SplitN(arg, "=", 2)
		flagName := strings.TrimPrefix(parts[0], "--")

		if len(parts) == 2 {
			opts = append(opts, chromedp.Flag(flagName, parts[1]))
		} else {
			opts = append(opts, chromedp.Flag(flagName, true))
		}
	}

	// Add flags required for running inside containers (e.g., Docker on Linux).
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
	// Initialize the concrete implementation (AnalysisContext).
	ac := cdp.NewAnalysisContext(
		m.allocatorCtx,
		m.globalConfig,
		m.logger,
		m.persona,
		m.runtimeTemplateCache,
		m.staticTaintConfigJSON,
	)

	// Initialize the context (creates the actual browser tab and applies instrumentation).
	if err := ac.Initialize(taskCtx); err != nil {
		return nil, fmt.Errorf("failed to initialize analysis session: %w", err)
	}

	// Increment the WaitGroup counter.
	m.wg.Add(1)

	// Wrap the session context to ensure the WaitGroup is decremented when the session closes.
	return &sessionWrapper{SessionContext: ac, wg: &m.wg}, nil
}

// Shutdown waits for all active sessions to complete and then terminates the browser process.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.logger.Info("Browser manager shutdown initiated. Waiting for active sessions to complete...")

	// Wait for all sessions (tracked by wg) to finish, respecting the caller's deadline.
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

	// Terminate the main browser process.
	if m.allocatorCancel != nil {
		m.logger.Info("Shutting down main browser process...")
		m.allocatorCancel()
		// Wait for the allocator context to confirm termination.
		<-m.allocatorCtx.Done()
	}
	return nil
}

// -- sessionWrapper --
// A decorator for SessionContext that ensures the Manager's WaitGroup is decremented exactly once upon closing.
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
